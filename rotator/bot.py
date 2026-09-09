"""Telegram-бот: единственный интерфейс управления.

Long-polling идёт через релей, поэтому на российском сервере ничего проксировать
не нужно — api.telegram.org оттуда всё равно недоступен.

Мастер настройки устроен так, чтобы руками не вводить ничего, кроме двух токенов:
сервер, зона и DNS-запись выбираются кнопками из того, что вернул API.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from . import guide, log, modes, probes
from .config import Secrets, domain_of, masked
from .engine import Engine
from .relay import Relay

logger = log.get("bot")

# Порядок обязательных шагов. CF_ZONE_ID выставляется по дороге, отдельным
# шагом не показывается — пользователю про zone_id знать незачем.
REQUIRED_STEPS = [
    ("UPCLOUD_TOKEN", "Токен UpCloud"),
    ("SERVER_UUID", "Сервер"),
    ("CF_TOKEN", "Токен Cloudflare"),
    ("CF_A_RECORD_ID", "Домен и DNS-запись"),
]

OPTIONAL_KEYS = [
    ("UPCLOUD_ADMIN_TOKEN", "Админ-токен UpCloud", "чтобы recreate работал под субаккаунтом"),
    ("UPCLOUD_SUBACCOUNT", "Логин субаккаунта", "в паре с админ-токеном"),
    ("CF_AAAA_RECORD_ID", "AAAA-запись", "обновлять заодно и IPv6"),
    ("SSH_KEY_PATH", "SSH-ключ, приватный", "нужен только режиму floating"),
    ("SSH_PUBKEY", "SSH-ключ, публичный", "прописать новому серверу при recreate"),
]

HELP = """Команды

Наблюдение
/status — адрес, зона, состояние сервера, последние пробы
/probe — прогнать пробы прямо сейчас
/ip — что у сервера и что реально стоит в DNS
/log — последние строки журнала

Управление
/rotate — сменить адрес
/mode — режим автоматики
/pause, /resume — выключить и включить автоматику
/rollback — пересоздать сервер из последнего шаблона

Настройка
/setup — пошаговая настройка доступов
/check — проверить всё разом
/zones, /plans — что доступно в UpCloud

Справка
/guide — как это работает, режимы, ключи, проверки"""

FIELD_PROMPTS = {
    "UPCLOUD_TOKEN": (
        "Токен UpCloud — им агент останавливает сервер, заказывает адреса и создаёт серверы.\n\n"
        "Где взять: панель UpCloud → People → API tokens → Create token.\n"
        "Начинается с ucat_\n\n"
        "Пришлите его сообщением — я удалю его сразу после чтения."
    ),
    "CF_TOKEN": (
        "Токен Cloudflare — им агент переписывает DNS-запись после смены адреса.\n\n"
        "Где взять: dash.cloudflare.com → My Profile → API Tokens → Create Token "
        "→ Create Custom Token.\n"
        "Права: Zone → DNS → Edit, и больше ничего.\n"
        "Zone Resources: Include → Specific zone → ваш домен.\n"
        "Global API Key не подойдёт — он даёт слишком много.\n\n"
        "Пришлите токен — я удалю сообщение сразу после чтения."
    ),
    "UPCLOUD_ADMIN_TOKEN": (
        "Админ-токен UpCloud (необязательно).\n\n"
        "Нужен, только если основной токен выпущен под субаккаунтом. После recreate "
        "появляется новый сервер, которого в правах субаккаунта нет — с этим токеном "
        "агент выдаст права сам.\n\n"
        "Пришлите токен или /skip."
    ),
    "UPCLOUD_SUBACCOUNT": (
        "Логин субаккаунта UpCloud (необязательно) — кому выдавать права после recreate.\n\n"
        "Пришлите логин или /skip, если работаете под основным аккаунтом."
    ),
    "SSH_KEY_PATH": (
        "Путь к приватному SSH-ключу на ЭТОМ сервере (необязательно).\n\n"
        "Нужен только режиму floating. Заведите отдельный ключ, не тот, которым ходите руками:\n"
        "  ssh-keygen -t ed25519 -f /etc/vpn-rotator/id_vpn -N \"\"\n\n"
        "Пришлите путь или /skip."
    ),
    "SSH_PUBKEY": (
        "Публичный SSH-ключ (необязательно) — пропишется новому серверу при recreate, "
        "чтобы вы не потеряли к нему доступ.\n\n"
        "Строка целиком, начинается с ssh-ed25519 или ssh-rsa.\n"
        "Пришлите её или /skip."
    ),
    "VPN_DOMAIN": "Домен, чью DNS-запись переписывать. Например vpn.example.com",
    "SERVER_UUID": "UUID сервера в UpCloud.",
    "CF_ZONE_ID": "Zone ID зоны в Cloudflare — со страницы обзора домена.",
    "CF_A_RECORD_ID": "ID A-записи в Cloudflare.",
    "CF_AAAA_RECORD_ID": "ID AAAA-записи в Cloudflare. /skip — не обновлять IPv6.",
}


class Bot:
    def __init__(self, relay: Relay, secrets: Secrets, engine: Engine, cfg):
        self.relay = relay
        self.secrets = secrets
        self.engine = engine
        self.cfg = cfg
        self.token = secrets.get("TG_BOT_TOKEN")
        self.admin = str(secrets.get("TG_ADMIN_ID"))
        self.offset = 0
        self._picks: dict[str, list] = {}
        self._lock = threading.Lock()

    # Ожидаемое поле живёт в state, а не в памяти: перезапуск сервиса посреди
    # мастера не должен молча съедать следующее сообщение пользователя.
    @property
    def awaiting(self) -> str:
        return self.engine.state["awaiting"] or ""

    @awaiting.setter
    def awaiting(self, value: str) -> None:
        self.engine.state["awaiting"] = value or ""

    # --- транспорт ----------------------------------------------------------

    def api(self, method: str, payload: dict[str, Any] | None = None, timeout: float | None = None) -> Any:
        response = self.relay.request(
            "tg", "POST", f"/bot{self.token}/{method}", json=payload or {}, timeout=timeout
        )
        try:
            body = response.json()
        except ValueError:
            logger.warning("Telegram %s вернул не-JSON (HTTP %s)", method, response.status_code)
            return None
        if not body.get("ok"):
            logger.warning("Telegram %s: %s", method, body.get("description"))
            return None
        return body.get("result")

    def send(self, text: str, keyboard: list[list[dict]] | None = None, chat: str = "") -> int:
        payload: dict[str, Any] = {
            "chat_id": chat or self.admin,
            "text": text[:4000],
            "disable_web_page_preview": True,
        }
        if keyboard:
            payload["reply_markup"] = {"inline_keyboard": keyboard}
        result = self.api("sendMessage", payload)
        return (result or {}).get("message_id", 0)

    def edit(self, message_id: int, text: str, keyboard: list[list[dict]] | None = None) -> None:
        if not message_id:
            return
        self.api("editMessageText", {
            "chat_id": self.admin,
            "message_id": message_id,
            "text": text[:4000],
            "disable_web_page_preview": True,
            "reply_markup": {"inline_keyboard": keyboard or []},
        })

    def delete(self, chat_id: Any, message_id: int) -> None:
        self.api("deleteMessage", {"chat_id": chat_id, "message_id": message_id})

    def answer_callback(self, callback_id: str, text: str = "") -> None:
        self.api("answerCallbackQuery", {"callback_query_id": callback_id, "text": text[:190]})

    # --- цикл ---------------------------------------------------------------

    def run(self, stop_event: threading.Event) -> None:
        poll = int(self.cfg.get("telegram.poll_timeout_sec", 25))
        me = self.api("getMe")
        if me:
            logger.info("бот @%s на связи", me.get("username", "?"))
        else:
            logger.error("Telegram недоступен — проверьте релей и токен бота")

        failures = 0
        while not stop_event.is_set():
            try:
                updates = self.api(
                    "getUpdates",
                    {
                        "offset": self.offset,
                        "timeout": poll,
                        "allowed_updates": ["message", "callback_query"],
                    },
                    timeout=poll + 20,
                ) or []
                if failures >= 3:
                    self.send(f"🟢 связь с Telegram восстановилась (было {failures} обрывов подряд)")
                failures = 0
                for update in updates:
                    self.offset = update["update_id"] + 1
                    try:
                        self.handle(update)
                    except Exception as exc:                   # noqa: BLE001
                        logger.exception("ошибка обработки апдейта: %s", exc)
                        self.send(f"❌ {exc}")
            except Exception as exc:                           # noqa: BLE001
                failures += 1
                logger.warning("long-poll сорвался (%s подряд): %s", failures, exc)
                stop_event.wait(min(5 * failures, 60))

    def handle(self, update: dict[str, Any]) -> None:
        if "callback_query" in update:
            return self.on_callback(update["callback_query"])
        message = update.get("message") or {}
        chat_id = str((message.get("chat") or {}).get("id", ""))
        if chat_id != self.admin:
            logger.info("сообщение от постороннего чата %s — игнорирую", chat_id)
            return
        text = (message.get("text") or "").strip()
        if not text:
            return
        # В журнал — факт получения, но не содержимое: там бывают токены.
        logger.info("сообщение от админа: %s символов, ждём поле %r",
                    len(text), self.awaiting or "—")
        if self.awaiting and not text.startswith("/"):
            return self.on_setup_value(message, text)
        self.on_command(text)

    # --- команды ------------------------------------------------------------

    def on_command(self, text: str) -> None:
        command, _, argument = text.partition(" ")
        command = command.split("@")[0].lower()
        argument = argument.strip()

        if command.startswith("/guide"):
            return self.cmd_guide(command)
        if command in ("/start", "/help"):
            self.send(HELP, [[{"text": "❓ Как это всё работает", "callback_data": "guide:overview"}],
                             [{"text": "⚙️ Настройка", "callback_data": "wiz:board"}]])
        elif command == "/status":
            self.send(self.status_text())
        elif command == "/probe":
            self.cmd_probe()
        elif command == "/ip":
            self.cmd_ip()
        elif command == "/rotate":
            self.cmd_rotate(argument)
        elif command == "/mode":
            self.cmd_mode(argument)
        elif command == "/zones":
            self.cmd_zones()
        elif command == "/plans":
            self.cmd_plans()
        elif command == "/pause":
            self.engine.state["paused"] = True
            self.send("⏸ автоматика на паузе. Пробы продолжаются, ротация — нет.")
        elif command == "/resume":
            self.engine.state["paused"] = False
            self.send("▶️ автоматика включена.")
        elif command == "/log":
            lines = log.tail(25)
            self.send("Журнал:\n\n" + ("\n".join(lines) if lines else "пусто"))
        elif command == "/setup":
            self.setup_board()
        elif command == "/check":
            self.cmd_check()
        elif command == "/rollback":
            self.cmd_rollback()
        elif command in ("/cancel", "/skip", "/auto"):
            self.cmd_wizard_control(command)
        else:
            self.send("Не знаю такой команды.\n\n" + HELP)

    def cmd_guide(self, command: str) -> None:
        page = command.replace("/guide", "").lstrip("_")
        if page in guide.PAGES:
            return self.show_guide(page)
        rows = [[{"text": title, "callback_data": f"guide:{key}"}] for key, (title, _) in guide.PAGES.items()]
        rows.append([{"text": "⚙️ Перейти к настройке", "callback_data": "wiz:board"}])
        self.send(guide.MENU, rows)

    def show_guide(self, page: str) -> None:
        title, body = guide.PAGES[page]
        others = [[{"text": t, "callback_data": f"guide:{k}"}]
                  for k, (t, _) in guide.PAGES.items() if k != page]
        self.send(body, others + [[{"text": "⚙️ Настройка", "callback_data": "wiz:board"}]])

    def status_text(self) -> str:
        state = self.engine.state
        probe = state["last_probe"] or {}
        age = int(time.time() - (state["last_probe_ts"] or time.time()))
        mode = state["mode"] or self.cfg.get("rotation.mode", "auto")
        history = state["history"]
        lines = [
            f"Адрес:    {state['ipv4'] or '—'}" + (f"  /  {state['ipv6']}" if state["ipv6"] else ""),
            f"Домен:    {domain_of(self.cfg, self.secrets) or '—'}",
            f"Зона:     {state['zone'] or '—'}   план: {state['plan'] or '—'}",
            f"Сервер:   {probe.get('server_state') or '—'}",
            f"Режим:    {mode}" + ("   ⏸ пауза" if state["paused"] else ""),
            "",
            f"Вердикт:  {probes.VERDICT_TEXT.get(state['last_verdict'], '—')}",
            f"Пробы:    " + _probe_line(probe) + f"  ({age} с назад)",
            f"Серия неудач: {state['fail_streak']}/{self.cfg.get('detector.fail_threshold')}",
            f"Ротаций сегодня: {state.rotations_today()}/{self.cfg.get('rotation.max_per_day')}",
        ]
        if self.cfg.get("dry_run"):
            lines.append("⚠️ dry_run включён — ротации только имитируются")
        if state["pending"]:
            lines.append(f"⚠️ незавершённая ротация: {state['pending'].get('mode')} / {state['pending'].get('step')}")
        if history:
            last = history[0]
            when = time.strftime("%d.%m %H:%M", time.localtime(last["ts"]))
            lines += ["", f"Последняя: {when} {last['mode']} {last['from']} → {last['to']} ({last['reason']})"]
        return "\n".join(lines)

    def cmd_probe(self) -> None:
        message_id = self.send("Проверяю…")
        result = self.engine.probe()
        verdict = probes.VERDICT_TEXT.get(result.verdict, result.verdict)
        suffix = "" if result.confident else "\n(уверенности нет — сузить причину нечем)"
        rotatable = "смена адреса поможет" if result.verdict in probes.ROTATABLE else "смена адреса не поможет"
        self.edit(message_id, f"{result.short()}\n\nВердикт: {verdict}\n{rotatable}{suffix}")

    def cmd_ip(self) -> None:
        try:
            info = self.engine.refresh()
        except Exception as exc:                               # noqa: BLE001
            return self.send(f"❌ UpCloud не ответил: {exc}")
        lines = [f"UpCloud:   {info['ipv4']}" + (f" / {info['ipv6']}" if info["ipv6"] else "")]
        zone_id = self.secrets.get("CF_ZONE_ID")
        for key, rtype in (("CF_A_RECORD_ID", "A"), ("CF_AAAA_RECORD_ID", "AAAA")):
            record_id = self.secrets.get(key)
            if not (zone_id and record_id):
                continue
            try:
                record = self.engine.cf.get_record(zone_id, record_id)
                mark = "✅" if record.get("content") in (info["ipv4"], info["ipv6"]) else "❌ расходится"
                lines.append(f"DNS {rtype:<4}: {record.get('content')} (TTL {record.get('ttl')}) {mark}")
            except Exception as exc:                           # noqa: BLE001
                lines.append(f"DNS {rtype:<4}: ошибка — {exc}")
        self.send("\n".join(lines))

    def cmd_mode(self, argument: str) -> None:
        choices = ("auto",) + modes.ALL_MODES
        if argument in choices:
            self.engine.state["mode"] = "" if argument == "auto" else argument
            return self.send(f"Режим автоматики: {argument}")
        keyboard = [[{"text": c, "callback_data": f"mode:{c}"}] for c in choices]
        keyboard.append([{"text": "❓ чем они отличаются", "callback_data": "guide:modes"}])
        self.send("Какой режим использовать автоматике?", keyboard)

    def cmd_zones(self) -> None:
        try:
            zones = self.engine.uc.zones()
        except Exception as exc:                               # noqa: BLE001
            return self.send(f"❌ {exc}")
        public = [z for z in zones if z.get("public") in ("yes", True, "1")]
        current = self.engine.state["zone"]
        lines = [("→ " if z["id"] == current else "   ") + f"{z['id']:<12} {z.get('description', '')}" for z in public]
        self.send("Зоны UpCloud:\n\n" + "\n".join(lines))

    def cmd_plans(self) -> None:
        try:
            plans = self.engine.uc.plans()
        except Exception as exc:                               # noqa: BLE001
            return self.send(f"❌ {exc}")
        current = self.engine.state["plan"]
        lines = [
            ("→ " if p["name"] == current else "   ")
            + f"{p['name']:<16} {p.get('core_number')} vCPU, {p.get('memory_amount')} МБ, {p.get('storage_size')} ГБ"
            for p in plans[:40]
        ]
        self.send("Планы UpCloud:\n\n" + "\n".join(lines))

    # --- ротация ------------------------------------------------------------

    def cmd_rotate(self, argument: str) -> None:
        missing = [name for key, name in REQUIRED_STEPS if not self.secrets.get(key)]
        if missing:
            return self.send(
                "Сначала настройка — не хватает: " + ", ".join(missing),
                [[{"text": "⚙️ Настроить", "callback_data": "wiz:board"}]],
            )
        blocked = self.engine.guard(force=False)
        hint = f"\n\nПредохранитель: {blocked}\nПодтверждение всё равно запустит ротацию." if blocked else ""

        if argument in modes.ALL_MODES:
            return self.ask_confirm(argument, "")

        keyboard = [
            [{"text": "replace-ip · ~3 мин · бесплатно", "callback_data": "rot:replace-ip"}],
            [{"text": "recreate · ~10 мин · смена зоны", "callback_data": "rot:recreate"}],
            [{"text": "floating · без даунтайма · ~$3.5/мес", "callback_data": "rot:floating"}],
            [{"text": "❓ чем они отличаются", "callback_data": "guide:modes"}],
            [{"text": "отмена", "callback_data": "cancel"}],
        ]
        mode, zone = self.engine.choose()
        auto = f"Автоматика выбрала бы: {mode or 'ничего — эскалировать некуда'}" + (f" → {zone}" if zone else "")
        self.send(f"Как менять адрес?\n\n{auto}{hint}", keyboard)

    def ask_zone(self) -> None:
        try:
            zones = [z for z in self.engine.uc.zones() if z.get("public") in ("yes", True, "1")]
        except Exception as exc:                               # noqa: BLE001
            return self.send(f"❌ {exc}")
        current = self.engine.state["zone"]
        preferred = [z for z in self.cfg.get("rotation.zone_rotation", []) if z != current]
        ordered = [z for z in zones if z["id"] in preferred] + [z for z in zones if z["id"] not in preferred]
        keyboard = [
            [{
                "text": ("• " if z["id"] == current else "") + f"{z['id']} — {z.get('description', '')}",
                "callback_data": f"rot:recreate:{z['id']}",
            }]
            for z in ordered[:12]
        ]
        keyboard.append([{"text": "отмена", "callback_data": "cancel"}])
        self.send("В какую зону переезжаем?\n(• — текущая: адрес сменится, а подсеть нет)", keyboard)

    def ask_confirm(self, mode: str, zone: str) -> None:
        state = self.engine.state
        details = {
            "replace-ip": "Сервер остановится и запустится. Даунтайм ~2-3 минуты, адрес сменится, денег не стоит.",
            "recreate": "Снимется шаблон диска, поднимется новый сервер, старый будет удалён. "
                        "Даунтайм ~5-10 минут в своей зоне и заметно дольше при переезде. Адрес бесплатный.",
            "floating": "Плавающий адрес поднимется на живом сервере через SSH. Даунтайма нет, "
                        "адрес тарифицируется помесячно.",
        }[mode]
        target = f"\nЗона: {zone}" if zone else ""
        keyboard = [
            [{"text": "да, запускаю", "callback_data": f"go:{mode}:{zone}"}],
            [{"text": "отмена", "callback_data": "cancel"}],
        ]
        self.send(
            f"Режим: {mode}{target}\nТекущий адрес: {state['ipv4'] or '—'}\n\n{details}\n\nПодтверждаете?",
            keyboard,
        )

    def start_rotation(self, mode: str, zone: str) -> None:
        header = f"Ротация {mode}" + (f" → {zone}" if zone else "")
        message_id = self.send(f"{header}\n\n…")
        lines: list[str] = []

        def progress(text: str) -> None:
            lines.append(f"• {text}")
            self.edit(message_id, f"{header}\n\n" + "\n".join(lines[-14:]))

        def worker() -> None:
            try:
                result = self.engine.rotate(mode, zone, reason="manual", force=True, progress=progress)
                if result.get("dry_run"):
                    progress("dry_run включён — ничего не менялось")
                    return
                progress(f"✅ {result['old_ip']} → {result['new_ip']}")
                self.send(self.status_text())
            except Exception as exc:                           # noqa: BLE001
                logger.exception("ротация не удалась")
                progress(f"❌ {exc}")

        threading.Thread(target=worker, name="rotate", daemon=True).start()

    def cmd_rollback(self) -> None:
        templates = self.engine.state["templates"]
        if not templates:
            return self.send("Шаблонов нет — откатываться не к чему.")
        newest = templates[0]
        when = time.strftime("%d.%m %H:%M", time.localtime(newest["created"]))
        self.send(
            f"Откат пересоздаст сервер из шаблона {newest['uuid'][:8]}… ({newest['zone']}, снят {when}).\n"
            "Клиенты, добавленные после снятия шаблона, пропадут.\n\n"
            "Это тот же recreate — подтвердите зону:",
            [
                [{"text": f"откатить в {newest['zone']}", "callback_data": f"rot:recreate:{newest['zone']}"}],
                [{"text": "отмена", "callback_data": "cancel"}],
            ],
        )

    # --- мастер настройки ---------------------------------------------------

    def setup_board(self) -> None:
        """Доска состояния: что готово, что осталось, одна кнопка «дальше»."""
        done = [key for key, _ in REQUIRED_STEPS if self.secrets.get(key)]
        lines = [f"⚙️ Настройка — {len(done)} из {len(REQUIRED_STEPS)}", ""]
        for number, (key, title) in enumerate(REQUIRED_STEPS, 1):
            mark = "✅" if self.secrets.get(key) else "▫️"
            extra = ""
            if key == "SERVER_UUID" and self.secrets.get(key):
                extra = f" — {self.engine.state['ipv4'] or self.secrets.get(key)[:8] + '…'}"
            if key == "CF_A_RECORD_ID" and self.secrets.get(key):
                extra = f" — {domain_of(self.cfg, self.secrets)}"
            lines.append(f"{mark} {number}. {title}{extra}")

        filled = [t for k, t, _ in OPTIONAL_KEYS if self.secrets.get(k)]
        lines += ["", f"Необязательное: {len(filled)} из {len(OPTIONAL_KEYS)}"]
        if filled:
            lines.append("  " + ", ".join(filled))

        rows: list[list[dict]] = []
        if len(done) < len(REQUIRED_STEPS):
            nxt = next(t for k, t in REQUIRED_STEPS if not self.secrets.get(k))
            rows.append([{"text": f"▶️ Дальше: {nxt}", "callback_data": "wiz:next"}])
            lines += ["", "Жмите «Дальше» — я проведу по шагам."]
        else:
            lines += ["", "Всё обязательное готово. Проверьте доступы: /check"]
            rows.append([{"text": "✅ Проверить всё", "callback_data": "wiz:check"}])
        rows.append([{"text": "⚙️ Необязательное", "callback_data": "wiz:opt"}])
        rows.append([{"text": "❓ Зачем эти ключи", "callback_data": "guide:keys"}])
        self.send("\n".join(lines), rows)

    def wizard_next(self) -> None:
        """Следующий незакрытый обязательный шаг. Вызывается после каждого успеха."""
        if not self.secrets.get("UPCLOUD_TOKEN"):
            return self.ask_field("UPCLOUD_TOKEN")
        if not self.secrets.get("SERVER_UUID"):
            return self.pick_server()
        if not self.secrets.get("CF_TOKEN"):
            return self.ask_field("CF_TOKEN")
        if not self.secrets.get("CF_ZONE_ID"):
            return self.pick_zone()
        if not self.secrets.get("CF_A_RECORD_ID"):
            return self.pick_record()
        self.send(
            "🎉 Обязательное настроено.\n\n"
            "Дальше стоит: проверить доступы, заглянуть в необязательные ключи "
            "и пройти проверки до боевого режима.",
            [
                [{"text": "✅ Проверить доступы", "callback_data": "wiz:check"}],
                [{"text": "⚙️ Необязательное", "callback_data": "wiz:opt"}],
                [{"text": "📋 Что проверить до боя", "callback_data": "guide:checklist"}],
            ],
        )

    def pick_server(self) -> None:
        """Сервер выбирается кнопкой — UUID руками не вводят."""
        try:
            servers = self.engine.uc.servers()
        except Exception as exc:                               # noqa: BLE001
            return self.send(
                f"❌ не получилось получить список серверов: {exc}\n\n"
                "Проверьте токен UpCloud.",
                [[{"text": "Ввести токен заново", "callback_data": "set:UPCLOUD_TOKEN"}]],
            )
        if not servers:
            return self.send("В аккаунте UpCloud нет серверов — создайте сервер и вернитесь.")
        self._picks["server"] = servers
        rows = [
            [{
                "text": f"{s.get('hostname') or s.get('title')} · {s.get('zone')} · {s.get('state')}",
                "callback_data": f"pick:server:{i}",
            }]
            for i, s in enumerate(servers[:20])
        ]
        rows.append([{"text": "отмена", "callback_data": "cancel"}])
        self.send(f"Шаг 2. Какой сервер ротировать?\n\nНашёл {len(servers)} шт.:", rows)

    def pick_zone(self) -> None:
        try:
            zones = self.engine.cf.zones()
        except Exception as exc:                               # noqa: BLE001
            logger.info("список зон не получен: %s", exc)
            return self.ask_field("CF_ZONE_ID")
        if not zones:
            return self.ask_field("CF_ZONE_ID")
        self._picks["zone"] = zones
        rows = [
            [{"text": z.get("name", "?"), "callback_data": f"pick:zone:{i}"}]
            for i, z in enumerate(zones[:20])
        ]
        rows.append([{"text": "ввести Zone ID вручную", "callback_data": "set:CF_ZONE_ID"}])
        self.send("Шаг 3. Какая зона в Cloudflare?", rows)

    def pick_record(self, rtype: str = "A") -> None:
        zone_id = self.secrets.get("CF_ZONE_ID")
        try:
            records = [r for r in self.engine.cf.list_records(zone_id, rtype) if not r.get("proxied")]
            proxied = [r for r in self.engine.cf.list_records(zone_id, rtype) if r.get("proxied")]
        except Exception as exc:                               # noqa: BLE001
            return self.send(f"❌ не получилось получить записи: {exc}")
        if not records:
            note = ""
            if proxied:
                note = ("\n\nЗаписи в зоне есть, но все проксируются (оранжевое облако). "
                        "Через прокси Cloudflare VPN не ходит — выключите его на нужной записи.")
            return self.send(f"В зоне нет подходящих {rtype}-записей.{note}")
        self._picks["rec"] = records
        rows = [
            [{"text": f"{r['name']} → {r['content']}", "callback_data": f"pick:rec:{i}"}]
            for i, r in enumerate(records[:20])
        ]
        self.send(
            f"Шаг 4. Какую запись переписывать при смене адреса?\n\n"
            f"Это должна быть запись, на которую смотрят конфиги клиентов.",
            rows,
        )

    def optional_menu(self) -> None:
        rows = []
        for key, title, why in OPTIONAL_KEYS:
            mark = "✅" if self.secrets.get(key) else "▫️"
            rows.append([{"text": f"{mark} {title}", "callback_data": f"set:{key}"}])
        rows.append([{"text": "◀️ К настройке", "callback_data": "wiz:board"}])
        lines = ["⚙️ Необязательные ключи", "", "Каждый включает отдельную возможность:", ""]
        for key, title, why in OPTIONAL_KEYS:
            mark = "✅" if self.secrets.get(key) else "▫️"
            lines.append(f"{mark} {title} — {why}")
        self.send("\n".join(lines), rows)

    def ask_field(self, key: str) -> None:
        self.awaiting = key
        current = self.secrets.get(key)
        now = f"\n\nСейчас: {masked(current) if 'TOKEN' in key else current}" if current else ""
        optional = any(key == k for k, _, _ in OPTIONAL_KEYS)
        hint = "\n\n/skip — пропустить · /cancel — выйти" if optional else "\n\n/cancel — выйти"
        self.send(f"{FIELD_PROMPTS.get(key, f'Пришлите значение {key}.')}{now}{hint}")

    def on_setup_value(self, message: dict[str, Any], text: str) -> None:
        key, self.awaiting = self.awaiting, ""
        value = text.strip()
        if self.cfg.get("telegram.delete_secret_messages", True) and "TOKEN" in key:
            self.delete(message["chat"]["id"], message["message_id"])
        self.secrets.set(key, value)
        shown = masked(value) if "TOKEN" in key else value
        self.send(f"✅ {key.replace('_', ' ').lower()}: {shown}")
        self.after_field_set(key)

    def cmd_wizard_control(self, command: str) -> None:
        if not self.awaiting:
            return self.send("Мастер не запущен. /setup — начать.")
        key, self.awaiting = self.awaiting, ""
        if command == "/cancel":
            return self.send("Мастер закрыт. /setup — вернуться.")
        if command == "/skip":
            self.secrets.unset(key)
            self.send(f"Пропущено: {key}")
            return self.after_field_set(key)
        if command == "/auto":
            return self.autodiscover_record(key)

    def after_field_set(self, key: str) -> None:
        """После каждого значения — сразу следующий шаг, чтобы не искать команду."""
        if key == "UPCLOUD_TOKEN":
            try:
                account = self.engine.uc.account()
                self.send(f"Токен принят, аккаунт {account.get('username', '?')}.")
            except Exception as exc:                           # noqa: BLE001
                return self.send(
                    f"⚠️ токен сохранён, но UpCloud его не принял: {exc}",
                    [[{"text": "Ввести заново", "callback_data": "set:UPCLOUD_TOKEN"}]],
                )
        if key == "CF_TOKEN":
            try:
                self.engine.cf.verify_token()
                self.send("Токен Cloudflare принят.")
            except Exception as exc:                           # noqa: BLE001
                return self.send(
                    f"⚠️ токен сохранён, но Cloudflare его не принял: {exc}",
                    [[{"text": "Ввести заново", "callback_data": "set:CF_TOKEN"}]],
                )
        if any(key == k for k, _, _ in OPTIONAL_KEYS):
            return self.optional_menu()
        self.wizard_next()

    def autodiscover_record(self, key: str) -> None:
        rtype = "AAAA" if "AAAA" in key else "A"
        zone_id = self.secrets.get("CF_ZONE_ID")
        domain = domain_of(self.cfg, self.secrets)
        if not zone_id:
            return self.send("Сначала выберите зону: /setup")
        try:
            record = self.engine.cf.find_record(zone_id, domain, rtype)
        except Exception as exc:                               # noqa: BLE001
            return self.send(f"❌ не нашёл запись: {exc}")
        if not record:
            return self.send(f"Записи {rtype} для {domain} в зоне нет — создайте её в панели Cloudflare.")
        self.secrets.set(key, record["id"])
        self.send(f"✅ {rtype} {record['name']} → {record['content']} (TTL {record.get('ttl')})")
        self.after_field_set(key)

    # --- проверка доступов --------------------------------------------------

    def cmd_check(self) -> None:
        message_id = self.send("Проверяю доступы…")
        lines: list[str] = []

        for url, status in self.relay.health().items():
            lines.append(f"{'✅' if status == 'ok' else '❌'} релей {url} — {status}")
        lines.append("✅ Telegram отвечает" if self.api("getMe") else "❌ Telegram не отвечает")

        if not self.secrets.get("UPCLOUD_TOKEN"):
            lines.append("❌ токен UpCloud не задан")
        else:
            try:
                lines.append(f"✅ UpCloud: аккаунт {self.engine.uc.account().get('username', '?')}")
            except Exception as exc:                           # noqa: BLE001
                lines.append(f"❌ UpCloud: {exc}")

        if not self.secrets.get("SERVER_UUID"):
            lines.append("❌ сервер не выбран")
        else:
            try:
                info = self.engine.refresh()
                lines.append(f"✅ сервер {info['hostname']}: {info['state']}, {info['ipv4']}, {info['zone']}")
                if not info["mac"]:
                    lines.append("⚠️ MAC публичного интерфейса не определился — replace-ip не сработает")
                if not info["storage_uuid"]:
                    lines.append("⚠️ системный диск не определился — recreate не сработает")
            except Exception as exc:                           # noqa: BLE001
                lines.append(f"❌ сервер недоступен через API: {exc}")

        if self.secrets.get("UPCLOUD_SUBACCOUNT") and not self.secrets.get("UPCLOUD_ADMIN_TOKEN"):
            lines.append("⚠️ задан субаккаунт, но нет админ-токена: после recreate прав на новый "
                         "сервер не будет, следующая ротация упрётся в 403")

        zone_id = self.secrets.get("CF_ZONE_ID")
        if not self.secrets.get("CF_TOKEN"):
            lines.append("❌ токен Cloudflare не задан")
        else:
            try:
                self.engine.cf.verify_token()
                lines.append("✅ Cloudflare: токен действителен")
            except Exception as exc:                           # noqa: BLE001
                lines.append(f"❌ Cloudflare: {exc}")
            record_id = self.secrets.get("CF_A_RECORD_ID")
            if zone_id and record_id:
                try:
                    record = self.engine.cf.get_record(zone_id, record_id)
                    ttl = record.get("ttl")
                    warn = "  ⚠️ TTL большой, поставьте 60" if isinstance(ttl, int) and ttl > 120 else ""
                    proxied = "  ⚠️ включён proxy — VPN через оранжевое облако не работает" if record.get("proxied") else ""
                    lines.append(f"✅ A-запись {record.get('name')} → {record.get('content')} TTL {ttl}{warn}{proxied}")
                except Exception as exc:                       # noqa: BLE001
                    lines.append(f"❌ A-запись: {exc}")
            else:
                lines.append("❌ DNS-запись не выбрана")

        lines.append("✅ SSH-ключ задан — floating доступен" if self.secrets.get("SSH_KEY_PATH")
                     else "➖ SSH-ключа нет — floating недоступен, остальные режимы работают")
        if self.cfg.get("dry_run"):
            lines.append("⚠️ dry_run включён — ротации только имитируются")

        rows = [[{"text": "📋 Что проверить до боя", "callback_data": "guide:checklist"}]]
        if any(line.startswith("❌") for line in lines):
            rows.insert(0, [{"text": "⚙️ Донастроить", "callback_data": "wiz:board"}])
        self.edit(message_id, "Проверка:\n\n" + "\n".join(lines), rows)

    # --- инлайн-кнопки ------------------------------------------------------

    def on_callback(self, callback: dict[str, Any]) -> None:
        chat_id = str(((callback.get("message") or {}).get("chat") or {}).get("id", ""))
        if chat_id != self.admin:
            return
        data = callback.get("data", "")
        logger.info("нажата кнопка %s", data)
        self.answer_callback(callback["id"])

        if data == "cancel":
            self.awaiting = ""
            return self.send("Отменено. /setup — вернуться к настройке.")
        if data.startswith("guide:"):
            return self.show_guide(data.split(":", 1)[1])
        if data == "wiz:board":
            return self.setup_board()
        if data == "wiz:next":
            return self.wizard_next()
        if data == "wiz:opt":
            return self.optional_menu()
        if data == "wiz:check":
            return self.cmd_check()
        if data.startswith("set:"):
            return self.ask_field(data.split(":", 1)[1])
        if data.startswith("pick:"):
            return self.on_pick(data)
        if data.startswith("mode:"):
            choice = data.split(":", 1)[1]
            self.engine.state["mode"] = "" if choice == "auto" else choice
            return self.send(f"Режим автоматики: {choice}")
        if data == "rot:recreate":
            return self.ask_zone()
        if data.startswith("rot:"):
            parts = data.split(":")
            return self.ask_confirm(parts[1], parts[2] if len(parts) > 2 else "")
        if data.startswith("go:"):
            _, mode, zone = (data.split(":") + [""])[:3]
            return self.start_rotation(mode, zone)

    def on_pick(self, data: str) -> None:
        _, kind, index = data.split(":", 2)
        options = self._picks.get(kind) or []
        try:
            chosen = options[int(index)]
        except (ValueError, IndexError):
            return self.send("Список устарел — откройте /setup заново.")

        if kind == "server":
            self.secrets.set("SERVER_UUID", chosen["uuid"])
            self.send(f"✅ сервер: {chosen.get('hostname')} ({chosen.get('zone')})")
            try:
                info = self.engine.refresh()
                self.send(f"Адрес {info['ipv4']}, план {info['plan']}, состояние {info['state']}.")
            except Exception as exc:                           # noqa: BLE001
                self.send(f"⚠️ сервер выбран, но детали не читаются: {exc}")
            return self.wizard_next()

        if kind == "zone":
            self.secrets.set("CF_ZONE_ID", chosen["id"])
            self.send(f"✅ зона: {chosen.get('name')}")
            return self.wizard_next()

        if kind == "rec":
            self.secrets.set("CF_A_RECORD_ID", chosen["id"])
            self.secrets.set("VPN_DOMAIN", chosen["name"])
            ttl = chosen.get("ttl")
            note = "\n⚠️ TTL больше 120 — поставьте 60, иначе клиенты будут долго видеть старый адрес." \
                if isinstance(ttl, int) and ttl > 120 else ""
            self.send(f"✅ запись: {chosen['name']} → {chosen['content']} (TTL {ttl}){note}")
            # AAAA подбирается автоматически: IPv6 у UpCloud бесплатный.
            try:
                aaaa = self.engine.cf.find_record(self.secrets.get("CF_ZONE_ID"), chosen["name"], "AAAA")
                if aaaa:
                    self.secrets.set("CF_AAAA_RECORD_ID", aaaa["id"])
                    self.send(f"✅ заодно нашёл AAAA: {aaaa['name']} → {aaaa['content']}")
            except Exception:                                  # noqa: BLE001
                logger.debug("AAAA не найдена", exc_info=True)
            return self.wizard_next()


def _probe_line(probe: dict[str, Any]) -> str:
    if not probe:
        return "проб ещё не было"
    if not probe.get("ip"):
        return "адрес сервера неизвестен"

    def mark(value: Any) -> str:
        return "✅" if value is True else "❌" if value is False else "➖"

    return (
        f"{probe.get('ip')} · канал {mark(probe.get('sanity'))} · "
        f"рабочий {mark(probe.get('work_port'))} · контрольный {mark(probe.get('control_port'))}"
    )
