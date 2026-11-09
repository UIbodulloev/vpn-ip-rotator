"""Действия админки: всё, что умеет бот, но с результатом на странице.

Логику не дублируем — вызываем те же команды и методы, что и бот:
client.py и скрипты AmneziaWG на VPN-сервере, сторож устройств, зеркало
подписок, engine.rotate и Bot._server_action_body. Быстрое выполняется сразу,
долгое (ротация, питание сервера, снимки, выпуск AmneziaWG) — фоновой задачей
с живым журналом на странице /jobs/<id>.

О каждом действии бот пишет владельцу в Telegram: админка — второй вход в
управление, и он не должен быть тихим.

Что сюда сознательно не вынесено: ввод токенов и ключей (/setup) и выпуск
нового секрета самой админки. Тот, кто как-то получил сессию в админке, не
должен суметь ни увести доступы к облаку, ни запереть владельца снаружи.
"""
from __future__ import annotations

import json
import re
import secrets as pysecrets
import shlex
import threading
import time
from typing import Any, Callable

from . import log, modes, remote, ui

logger = log.get("admin")

NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
ISSUE_KINDS = {
    "sub": ("Подписка для телефона", "sing-box, Hysteria2 + VLESS, российское напрямую. Основной вариант."),
    "split": ("Подписка + файл AmneziaWG", "Файл — для второго устройства или роутера; российское мимо VPN."),
    "full": ("Подписка + файл AmneziaWG, весь трафик", "То же, но через файл AmneziaWG идёт всё."),
    "awg-split": ("Только AmneziaWG", "Для роутера: файл .conf, российское мимо VPN."),
    "awg-full": ("Только AmneziaWG, весь трафик", "Для роутера: через VPN идёт всё."),
}


class Job:
    def __init__(self, title: str):
        self.id = pysecrets.token_hex(4)
        self.title = title
        self.lines: list[str] = []
        self.status = "running"
        self.started = time.time()
        self.finished = 0.0
        self.result: dict[str, Any] = {}

    def say(self, text: str) -> None:
        self.lines.append(ui.strip_tags(str(text)))


class Ops:
    def __init__(self, bot, stats):
        self.bot = bot
        self.stats = stats
        self.jobs: dict[str, Job] = {}
        self._cache: dict[str, tuple[float, Any]] = {}
        self.lock = threading.Lock()

    # --- служебное ----------------------------------------------------------

    def audit(self, text: str) -> None:
        threading.Thread(target=self.bot.send, args=("🛠 Админка: " + ui.esc(text),), daemon=True).start()

    def cached(self, key: str, ttl: float, fn: Callable[[], Any]) -> Any:
        now = time.time()
        hit = self._cache.get(key)
        if hit and now - hit[0] < ttl:
            return hit[1]
        value = fn()
        self._cache[key] = (now, value)
        return value

    def forget(self, *keys: str) -> None:
        for k in keys:
            self._cache.pop(k, None)

    def ssh(self, command: str, timeout: int = 90) -> remote.Result:
        return self.bot._awg(command, timeout=timeout)

    def run_job(self, title: str, fn: Callable[[Job], dict | None]) -> Job:
        job = Job(title)
        with self.lock:
            self.jobs[job.id] = job
            for old in sorted(self.jobs.values(), key=lambda j: j.started)[:-30]:
                self.jobs.pop(old.id, None)
        self.audit(f"{title} — запущено")

        def worker() -> None:
            try:
                job.result = fn(job) or {}
                job.status = "done" if not job.result.get("failed") else "failed"
            except Exception as exc:                           # noqa: BLE001
                logger.exception("задача админки «%s» упала", title)
                job.say(f"Ошибка: {exc}")
                job.status = "failed"
            job.finished = time.time()
            self.audit(f"{title} — {'готово' if job.status == 'done' else 'НЕ ВЫШЛО'}")

        threading.Thread(target=worker, name=f"job-{job.id}", daemon=True).start()
        return job

    # --- данные -------------------------------------------------------------

    def keys(self) -> list[dict]:
        """Ключи панели: имя, UUID, трафик за всё время, состояние."""
        def load():
            got = self.bot._panel("list")
            out = []
            for line in got.out.splitlines():
                parts = line.split("\t")
                if len(parts) == 4:
                    out.append({"name": parts[0], "uuid": parts[1], "traffic": parts[2], "state": parts[3]})
            return out
        try:
            return self.cached("keys", 30, load)
        except remote.RemoteError:
            return []

    def key(self, name: str) -> dict | None:
        return next((k for k in self.keys() if k["name"] == name), None)

    def bindings(self) -> dict:
        def load():
            got = self.ssh("/opt/panel/sub-mirror.py devices --json", timeout=30)
            return json.loads(got.out.strip() or "{}") if got.ok else {}
        try:
            return self.cached("bindings", 30, load)
        except (remote.RemoteError, ValueError):
            return {}

    def awg31_names(self) -> set[str]:
        def load():
            got = self.ssh("ls /opt/awg31/clients 2>/dev/null", timeout=20)
            return {f[:-5] for f in got.out.split() if f.endswith(".conf")}
        try:
            return self.cached("awg31", 30, load)
        except remote.RemoteError:
            return set()

    def vless_link(self, name: str) -> str:
        try:
            got = self.bot._panel(f"link {shlex.quote(name)}")
        except remote.RemoteError:
            return ""
        return next((l.strip() for l in got.out.splitlines() if l.strip().startswith("vless://")), "")

    def sub_url(self, uuid: str) -> str:
        base = self.bot.secrets.get("SUB_BASE_URL").rstrip("/")
        return f"{base}/sub/{uuid}" if base and uuid else ""

    def server_info(self, fresh: bool = False) -> dict:
        if fresh:
            self.forget("server")
        try:
            return self.cached("server", 60, self.bot.engine.refresh)
        except Exception as exc:                               # noqa: BLE001
            return {"error": str(exc)}

    def zones(self) -> list[dict]:
        try:
            return self.cached("zones", 3600, lambda: [
                z for z in self.bot.engine.uc.zones() if z.get("public") in ("yes", True, "1")])
        except Exception:                                      # noqa: BLE001
            return []

    def awg_conf(self, name: str) -> str:
        if name not in self.awg31_names():
            return ""
        conf, _ = self.bot._awg_conf(name)
        return conf

    # --- действия -----------------------------------------------------------
    # Каждое возвращает (ok, сообщение) для плашки на странице или Job.

    def key_issue(self, name: str, kind: str, to_telegram: bool) -> Job:
        title = f"Выдать «{name}» — {ISSUE_KINDS[kind][0].lower()}"

        def body(job: Job) -> dict:
            result: dict[str, Any] = {"name": name, "kind": kind}
            if kind.startswith("awg-"):
                job.say("выпускаю конфиг AmneziaWG…")
                conf, trouble = self.bot._awg_conf_new(name, kind.split("-", 1)[1])
                if not conf:
                    job.say(f"не вышло: {trouble}")
                    return {"failed": True}
                result["conf"] = True
                self.forget("awg31")
                job.say("готово: конфиг можно скачать ниже")
                if to_telegram:
                    self.bot.awg_send(name)
                    job.say("файл отправлен вам в Telegram — его можно переслать человеку")
                return result
            job.say("выпускаю ключ…")
            made = self.bot._panel(f"add {shlex.quote(name)}")
            if not made.ok or "vless://" not in made.out:
                job.say(f"ключ не выпустился: {made.text(400)}")
                return {"failed": True}
            link = next(l.strip() for l in made.out.splitlines() if l.strip().startswith("vless://"))
            uuid = link.split("://", 1)[1].split("@", 1)[0]
            result.update(uuid=uuid, link=link, sub=self.sub_url(uuid))
            job.say("ключ выпущен, Hysteria2 подхватил его сразу")
            conf = ""
            if kind in ("split", "full"):
                job.say("выпускаю конфиг AmneziaWG…")
                conf, trouble = self.bot._awg_conf_new(name, kind)
                if conf:
                    result["conf"] = True
                    job.say("конфиг AmneziaWG готов")
                else:
                    job.say(f"AmneziaWG не выпустился: {trouble}. Подписка при этом работает.")
            self.forget("keys", "awg31")
            if to_telegram:
                base = self.bot.secrets.get("SUB_BASE_URL").rstrip("/")
                self.bot.send_bundle(base, name, uuid, link if kind != "sub" else "", conf)
                job.say("готовое сообщение для человека отправлено вам в Telegram — перешлите его")
            return result

        return self.run_job(title, body)

    def key_delete(self, name: str) -> tuple[bool, str]:
        done = self.bot._panel(f"del {shlex.quote(name)}")
        self.forget("keys", "bindings")
        if done.ok:
            self.audit(f"удалён ключ {name}")
        return done.ok, (f"Ключ «{name}» удалён — он перестал работать сразу." if done.ok else done.text(300))

    def key_resend(self, name: str) -> tuple[bool, str]:
        threading.Thread(target=self.bot.vless_sub, args=(name,), daemon=True).start()
        return True, "Готовое сообщение для человека придёт вам в Telegram через пару секунд."

    def key_unbind(self, name: str) -> tuple[bool, str]:
        k = self.key(name)
        if not k:
            return False, "Ключа нет."
        done = self.ssh(f"/opt/panel/sub-mirror.py reset {k['uuid']}")
        self.forget("bindings")
        if done.ok:
            self.audit(f"снята привязка ссылки {name}")
        return done.ok, ("Привязка снята — ссылка встанет на следующее устройство." if done.ok else done.text(300))

    def key_limit(self, name: str, n: int) -> tuple[bool, str]:
        k = self.key(name)
        if not k:
            return False, "Ключа нет."
        done = self.ssh(f"/opt/panel/sub-mirror.py limit {k['uuid']} {int(n)}")
        self.forget("bindings")
        if done.ok:
            self.audit(f"{name}: устройств — {n}")
        return done.ok, (f"Теперь по ключу «{name}» можно {n} устр." if done.ok else done.text(300))

    def key_unblock(self, name: str) -> tuple[bool, str]:
        done = self.ssh(f"/opt/panel/device-guard.py unblock {shlex.quote(name)}")
        if done.ok:
            self.audit(f"сняты блокировки ключа {name}")
        return done.ok, (done.text(200) if done.ok else done.text(300))

    def key_sync(self) -> tuple[bool, str]:
        done = self.bot._panel("sync")
        self.forget("keys")
        return done.ok, done.text(300)

    def awg_revoke(self, name: str) -> tuple[bool, str]:
        if name not in self.awg31_names():
            return False, "Такого конфига нет."
        done = self.ssh(f"{self.bot.AWG_DIR}/revoke-client.sh {shlex.quote(name)}")
        self.forget("awg31")
        if done.ok:
            self.audit(f"отозван конфиг AmneziaWG {name}")
        return done.ok, (f"Конфиг «{name}» отозван." if done.ok else done.text(300))

    def awg_send(self, name: str) -> tuple[bool, str]:
        threading.Thread(target=self.bot.awg_send, args=(name,), daemon=True).start()
        return True, "Файл придёт вам в Telegram через пару секунд."

    def server_job(self, action: str, argument: str = "") -> Job:
        titles = {"start": "Запустить сервер", "stop": "Остановить сервер", "reboot": "Перезагрузить сервер",
                  "template": "Сделать Storage Template", "backup-now": "Сделать Backup",
                  "backup-del": "Удалить все Backup", "storage-del": "Удалить всё хранящееся",
                  "containers": "Состояние контейнеров", "docker-restart": "Перезапустить контейнеры",
                  "docker-up": "Поднять остановленные контейнеры", "protocols": "Проверить протоколы",
                  "delete": "Удалить сервер", "create": "Поднять сервер из Storage Template"}
        title = titles.get(action.split(":")[0], "Восстановить диск из Backup")

        def body(job: Job) -> None:
            self.bot._server_action_body(action, argument, job.say)
            self.forget("server")

        return self.run_job(title, body)

    def rotate_job(self, mode: str, zone: str) -> Job:
        title = f"Сменить адрес: {modes.MODE_TITLES.get(mode, mode)}" + (f" → {zone}" if zone else "")

        def body(job: Job) -> dict:
            result = self.bot.engine.rotate(mode, zone, reason="manual", force=True, progress=job.say)
            self.forget("server")
            if result.get("dry_run"):
                job.say("dry_run включён — ничего не менялось")
            else:
                job.say(f"готово: {result['old_ip']} → {result['new_ip']}")
            return {}

        return self.run_job(title, body)

    def probe_job(self) -> Job:
        def body(job: Job) -> None:
            job.say("проверяю доступность VPN снаружи…")
            result = self.bot.engine.probe()
            job.say(result.short())
        return self.run_job("Проверить доступность VPN", body)

    def auto_pause(self, paused: bool) -> tuple[bool, str]:
        self.bot.engine.state["paused"] = paused
        self.audit("автоматика " + ("на паузе" if paused else "включена"))
        return True, "Автоматика на паузе: адрес сам меняться не будет." if paused else "Автоматика включена."

    def auto_mode(self, mode: str) -> tuple[bool, str]:
        if mode not in ("auto",) + modes.ALL_MODES:
            return False, "Неизвестный режим."
        self.bot.engine.state["mode"] = "" if mode == "auto" else mode
        self.audit(f"режим автоматики: {mode}")
        return True, f"Режим автоматики: {mode}."

    def unstick(self) -> tuple[bool, str]:
        self.bot.engine.state.clear_pending()
        self.audit("снята отметка незавершённой ротации")
        return True, "Отметка незавершённой ротации снята."

    def to_telegram(self, what: str) -> tuple[bool, str]:
        fn = {"costs": self.bot.cmd_costs, "servers": self.bot.cmd_servers, "status": lambda: self.bot.send(
            self.bot.status_text())}[what]
        threading.Thread(target=fn, daemon=True).start()
        return True, "Отчёт придёт вам в Telegram через несколько секунд."
