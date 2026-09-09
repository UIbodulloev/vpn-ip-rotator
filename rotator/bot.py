"""Telegram-бот: единственный интерфейс управления.

Long-polling идёт через релей, поэтому на российском сервере ничего проксировать
не нужно — api.telegram.org оттуда всё равно недоступен.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from . import log, modes, probes
from .config import SETUP_KEYS, Secrets, masked
from .engine import Engine
from .relay import Relay

logger = log.get("bot")

HELP = """Команды:

/status — адрес, зона, состояние сервера, последние пробы
/probe — прогнать пробы прямо сейчас
/ip — что у сервера и что реально стоит в DNS
/rotate — сменить адрес (выбор режима и зоны)
/mode — режим автоматики: auto / replace-ip / recreate / floating
/zones, /plans — живые списки из UpCloud
/pause, /resume — выключить и включить автоматику
/log — последние строки журнала
/setup — залить доступы
/check — проверить все доступы и права
/rollback — пересоздать сервер из последнего шаблона
/cancel — выйти из мастера /setup"""

FIELD_PROMPTS = {
    "UPCLOUD_TOKEN": "Пришлите токен UpCloud (ucat_…). Сообщение будет удалено сразу после чтения.",
    "UPCLOUD_ADMIN_TOKEN": "Токен основного аккаунта UpCloud — нужен только чтобы выдавать субаккаунту "
                           "права на новый сервер после recreate. Пришлите или /skip.",
    "UPCLOUD_SUBACCOUNT": "Логин субаккаунта UpCloud (или /skip, если работаете под основным).",
    "SERVER_UUID": "UUID VPN-сервера в UpCloud.",
    "CF_TOKEN": "Токен Cloudflare с правом Zone → DNS → Edit на вашу зону.",
    "CF_ZONE_ID": "Zone ID зоны в Cloudflare (со страницы обзора домена).",
    "CF_A_RECORD_ID": "ID A-записи. Пришлите /auto — найду по домену из конфига.",
    "CF_AAAA_RECORD_ID": "ID AAAA-записи. /auto — найти по домену, /skip — не обновлять IPv6.",
    "SSH_KEY_PATH": "Путь к приватному SSH-ключу на этом сервере (нужен только режиму floating). /skip — пропустить.",
    "SSH_PUBKEY": "Публичный SSH-ключ, который прописать новому серверу при recreate. /skip — пропустить.",
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
        self.awaiting: str = ""
        self._lock = threading.Lock()

    # --- транспорт ----------------------------------------------------------

    def api(self, method: str, payload: dict[str, Any] | None = None, timeout: float | None = None) -> Any:
        response = self.relay.request(
            "tg", "POST", f"/bot{self.token}/{method}", json=payload or {}, timeout=timeout
        )
        try:
            body = response.json()
        except ValueError:
            logger.warning("Telegram %s вернул не-JSON: %s", method, response.text[:200])
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
        payload: dict[str, Any] = {
            "chat_id": self.admin,
            "message_id": message_id,
            "text": text[:4000],
            "disable_web_page_preview": True,
        }
        payload["reply_markup"] = {"inline_keyboard": keyboard or []}
        self.api("editMessageText", payload)

    def delete(self, chat_id: Any, message_id: int) -> None:
        self.api("deleteMessage", {"chat_id": chat_id, "message_id": message_id})

    def answer_callback(self, callback_id: str, text: str = "") -> None:
        self.api("answerCallbackQuery", {"callback_query_id": callback_id, "text": text[:190]})

    # --- цикл ---------------------------------------------------------------

    def run(self, stop_event: threading.Event) -> None:
        poll = int(self.cfg.get("telegram.poll_timeout_sec", 50))
        me = self.api("getMe")
        if me:
            logger.info("бот @%s на связи", me.get("username", "?"))
        else:
            logger.error("Telegram недоступен — проверьте релей и токен")

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
                for update in updates:
                    self.offset = update["update_id"] + 1
                    try:
                        self.handle(update)
                    except Exception as exc:                   # noqa: BLE001
                        logger.exception("ошибка обработки апдейта: %s", exc)
                        self.send(f"❌ {exc}")
            except Exception as exc:                           # noqa: BLE001
                logger.warning("long-poll сорвался: %s", exc)
                stop_event.wait(10)

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
        if self.awaiting and not text.startswith("/"):
            return self.on_setup_value(message, text)
        self.on_command(text)

    # --- команды ------------------------------------------------------------

    def on_command(self, text: str) -> None:
        command, _, argument = text.partition(" ")
        command = command.split("@")[0].lower()
        argument = argument.strip()

        if command in ("/start", "/help"):
            self.send(HELP)
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
            self.cmd_setup()
        elif command == "/check":
            self.cmd_check()
        elif command == "/rollback":
            self.cmd_rollback()
        elif command in ("/cancel", "/skip", "/auto"):
            self.cmd_wizard_control(command)
        else:
            self.send("Не знаю такой команды.\n\n" + HELP)

    def status_text(self) -> str:
        state = self.engine.state
        probe = state["last_probe"] or {}
        age = int(time.time() - (state["last_probe_ts"] or time.time()))
        mode = state["mode"] or self.cfg.get("rotation.mode", "auto")
        history = state["history"]
        lines = [
            f"Адрес:    {state['ipv4'] or '—'}" + (f"  /  {state['ipv6']}" if state["ipv6"] else ""),
            f"Домен:    {self.cfg.get('vpn.domain')}",
            f"Зона:     {state['zone'] or '—'}   план: {state['plan'] or '—'}",
            f"Сервер:   {probe.get('server_state') or '—'}",
            f"Режим:    {mode}" + ("   ⏸ пауза" if state["paused"] else ""),
            "",
            f"Вердикт:  {probes.VERDICT_TEXT.get(state['last_verdict'], '—')}",
            f"Пробы:    {probe.get('ip', '—')} · " + _probe_line(probe) + f"  ({age} с назад)",
            f"Серия неудач: {state['fail_streak']}/{self.cfg.get('detector.fail_threshold')}",
            f"Ротаций сегодня: {state.rotations_today()}/{self.cfg.get('rotation.max_per_day')}",
        ]
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
        rotatable = "ротация поможет" if result.verdict in probes.ROTATABLE else "ротация не поможет"
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
        blocked = self.engine.guard(force=False)
        hint = f"\n\nПредохранитель: {blocked}\nПодтверждение всё равно запустит ротацию." if blocked else ""

        if argument in modes.ALL_MODES:
            return self.ask_confirm(argument, "")

        keyboard = [
            [{"text": "replace-ip · ~3 мин · бесплатно", "callback_data": "rot:replace-ip"}],
            [{"text": "recreate · ~10 мин · смена зоны", "callback_data": "rot:recreate"}],
            [{"text": "floating · без даунтайма · ~$3.5/мес", "callback_data": "rot:floating"}],
            [{"text": "отмена", "callback_data": "cancel"}],
        ]
        mode, zone = self.engine.choose()
        auto = f"Автоматика выбрала бы: {mode or 'ничего — эскалировать некуда'}" + (f" → {zone}" if zone else "")
        self.send(f"Как менять адрес?\n\n{auto}{hint}", keyboard)

    def ask_zone(self, callback_id: str) -> None:
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
        self.send("В какую зону переезжаем?\n(• — текущая, переезд в неё меняет адрес, но не подсеть)", keyboard)

    def ask_confirm(self, mode: str, zone: str) -> None:
        state = self.engine.state
        details = {
            "replace-ip": "Сервер остановится и запустится. Даунтайм ~2-3 минуты, адрес сменится, денег не стоит.",
            "recreate": "Снимется шаблон диска, поднимется новый сервер, старый будет удалён. "
                        "Даунтайм ~5-10 минут в той же зоне и заметно дольше при переезде. Адрес бесплатный.",
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
            "Это тот же recreate — выберите зону:",
            [
                [{"text": f"откатить в {newest['zone']}", "callback_data": f"rot:recreate:{newest['zone']}"}],
                [{"text": "отмена", "callback_data": "cancel"}],
            ],
        )

    # --- проверка доступов --------------------------------------------------

    def cmd_check(self) -> None:
        message_id = self.send("Проверяю доступы…")
        lines: list[str] = []

        for url, status in self.relay.health().items():
            lines.append(f"{'✅' if status == 'ok' else '❌'} релей {url} — {status}")

        if self.api("getMe"):
            lines.append("✅ Telegram отвечает")
        else:
            lines.append("❌ Telegram не отвечает")

        token = self.secrets.get("UPCLOUD_TOKEN")
        if not token:
            lines.append("❌ UPCLOUD_TOKEN не задан (/setup)")
        else:
            try:
                account = self.engine.uc.account()
                lines.append(f"✅ UpCloud: аккаунт {account.get('username', '?')}")
            except Exception as exc:                           # noqa: BLE001
                lines.append(f"❌ UpCloud: {exc}")

        uuid = self.secrets.get("SERVER_UUID")
        if not uuid:
            lines.append("❌ SERVER_UUID не задан (/setup)")
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
            lines.append(
                "⚠️ задан субаккаунт, но нет UPCLOUD_ADMIN_TOKEN: после recreate прав на новый "
                "сервер не будет, следующая ротация упрётся в 403"
            )

        zone_id = self.secrets.get("CF_ZONE_ID")
        if not self.secrets.get("CF_TOKEN"):
            lines.append("❌ CF_TOKEN не задан (/setup)")
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
                lines.append("❌ CF_ZONE_ID/CF_A_RECORD_ID не заданы (/setup)")

        if self.secrets.get("SSH_KEY_PATH"):
            lines.append("✅ SSH-ключ задан — режим floating доступен")
        else:
            lines.append("➖ SSH-ключ не задан — режим floating недоступен (остальные работают)")

        self.edit(message_id, "Проверка доступов:\n\n" + "\n".join(lines))

    # --- мастер /setup ------------------------------------------------------

    def cmd_setup(self) -> None:
        rows = []
        for key in SETUP_KEYS:
            value = self.secrets.get(key)
            mark = "✅" if value else "▫️"
            rows.append([{"text": f"{mark} {key}", "callback_data": f"set:{key}"}])
        rows.append([{"text": "готово", "callback_data": "cancel"}])
        self.send(
            "Что заливаем? Значение присылайте обычным сообщением — бот удалит его сразу после чтения.\n"
            "Оговорка: до удаления сообщение успевает полежать на серверах Telegram. "
            "Совсем без этого — `rotator setup --local` на консоли сервера.",
            rows,
        )

    def ask_field(self, key: str) -> None:
        self.awaiting = key
        current = self.secrets.get(key)
        now = f"\n\nСейчас: {masked(current) if 'TOKEN' in key else current}" if current else ""
        self.send(f"{key}\n\n{FIELD_PROMPTS.get(key, 'Пришлите значение.')}{now}\n\n/cancel — выйти.")

    def on_setup_value(self, message: dict[str, Any], text: str) -> None:
        key, self.awaiting = self.awaiting, ""
        if self.cfg.get("telegram.delete_secret_messages", True):
            self.delete(message["chat"]["id"], message["message_id"])
        self.secrets.set(key, text.strip())
        self.after_field_set(key, text.strip())

    def cmd_wizard_control(self, command: str) -> None:
        if not self.awaiting:
            return self.send("Мастер не запущен.")
        key, self.awaiting = self.awaiting, ""
        if command == "/cancel":
            return self.send("Мастер закрыт.")
        if command == "/skip":
            self.secrets.unset(key)
            return self.send(f"{key} пропущен.")
        if command == "/auto":
            return self.autodiscover_record(key)

    def after_field_set(self, key: str, value: str) -> None:
        shown = masked(value) if "TOKEN" in key else value
        self.send(f"✅ {key} = {shown}")
        if key == "SERVER_UUID":
            try:
                info = self.engine.refresh()
                self.send(f"Сервер найден: {info['hostname']}, {info['ipv4']}, {info['zone']}, {info['state']}")
            except Exception as exc:                           # noqa: BLE001
                self.send(f"⚠️ по этому UUID сервер не читается: {exc}")
        if key == "CF_ZONE_ID":
            self.send("Теперь ID записей. /setup → CF_A_RECORD_ID, там можно прислать /auto.")

    def autodiscover_record(self, key: str) -> None:
        rtype = "AAAA" if "AAAA" in key else "A"
        zone_id = self.secrets.get("CF_ZONE_ID")
        domain = self.cfg.get("vpn.domain")
        if not zone_id:
            return self.send("Сначала задайте CF_ZONE_ID.")
        try:
            record = self.engine.cf.find_record(zone_id, domain, rtype)
        except Exception as exc:                               # noqa: BLE001
            return self.send(f"❌ не нашёл запись: {exc}")
        if not record:
            return self.send(f"Записи {rtype} для {domain} в зоне нет — создайте её в панели Cloudflare.")
        self.secrets.set(key, record["id"])
        self.send(f"✅ {key} = {record['id']}\n{rtype} {record['name']} → {record['content']} (TTL {record.get('ttl')})")

    # --- инлайн-кнопки ------------------------------------------------------

    def on_callback(self, callback: dict[str, Any]) -> None:
        chat_id = str(((callback.get("message") or {}).get("chat") or {}).get("id", ""))
        if chat_id != self.admin:
            return
        data = callback.get("data", "")
        self.answer_callback(callback["id"])

        if data == "cancel":
            self.awaiting = ""
            return self.send("Отменено.")
        if data.startswith("set:"):
            return self.ask_field(data.split(":", 1)[1])
        if data.startswith("mode:"):
            choice = data.split(":", 1)[1]
            self.engine.state["mode"] = "" if choice == "auto" else choice
            return self.send(f"Режим автоматики: {choice}")
        if data == "rot:recreate":
            return self.ask_zone(callback["id"])
        if data.startswith("rot:"):
            parts = data.split(":")
            return self.ask_confirm(parts[1], parts[2] if len(parts) > 2 else "")
        if data.startswith("go:"):
            _, mode, zone = (data.split(":") + [""])[:3]
            return self.start_rotation(mode, zone)


def _probe_line(probe: dict[str, Any]) -> str:
    def mark(value: Any) -> str:
        return "✅" if value is True else "❌" if value is False else "➖"

    return (
        f"канал {mark(probe.get('sanity'))} · рабочий {mark(probe.get('work_port'))} · "
        f"контрольный {mark(probe.get('control_port'))}"
    )
