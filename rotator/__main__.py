"""Точка входа: rotator run | probe | rotate | check | setup --local."""

from __future__ import annotations

import argparse
import getpass
import signal
import sys
import threading

from . import log, modes, probes
from .bot import Bot
from .clouddns import Cloudflare
from .config import BOOTSTRAP_KEYS, SETUP_KEYS, Config, Secrets, masked
from .engine import Engine
from .relay import Relay
from .state import State
from .upcloud import UpCloud


def build(cfg: Config, secrets: Secrets) -> tuple[Relay, Engine, State]:
    relay = Relay(
        urls=[u.strip() for u in secrets.get("RELAY_URLS").split(",") if u.strip()],
        key=secrets.get("RELAY_KEY"),
        prefer_direct=bool(cfg.get("prefer_direct", False)),
        allow_direct_fallback=bool(cfg.get("allow_direct_fallback", False)),
    )
    uc = UpCloud(relay, secrets.get("UPCLOUD_TOKEN"), secrets.get("UPCLOUD_ADMIN_TOKEN"))
    cf = Cloudflare(relay, secrets.get("CF_TOKEN"))
    state = State()
    # По умолчанию уведомления идут в stdout; в режиме run их перехватывает бот.
    engine = Engine(cfg, secrets, state, uc, cf, print)
    return relay, engine, state


def cmd_run(cfg: Config, secrets: Secrets) -> int:
    missing = secrets.missing_bootstrap()
    if missing:
        print(f"не хватает бутстрап-значений: {', '.join(missing)}", file=sys.stderr)
        print("заполните /etc/vpn-rotator/secrets.env или запустите: rotator setup --local", file=sys.stderr)
        return 2

    relay, engine, state = build(cfg, secrets)
    bot = Bot(relay, secrets, engine, cfg)
    engine.notify = bot.send

    stop = threading.Event()

    def on_signal(signum, _frame):
        log.get("main").info("сигнал %s — останавливаюсь", signum)
        stop.set()

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)

    threads = [threading.Thread(target=bot.run, args=(stop,), name="bot", daemon=True)]
    if cfg.get("detector.enabled", True):
        threads.append(threading.Thread(target=engine.detector_loop, args=(stop,), name="detector", daemon=True))
    for thread in threads:
        thread.start()

    bot.send(
        "🟢 vpn-ip-rotator запущен\n"
        f"режим: {state['mode'] or cfg.get('rotation.mode')}"
        + ("   ⏸ пауза" if state["paused"] else "")
        + ("\ndry_run включён — ротации только имитируются" if cfg.get("dry_run") else "")
    )

    # Незавершённая ротация опаснее всего: сервер мог остаться остановленным.
    if state["pending"]:
        threading.Thread(target=_resume, args=(engine,), name="resume", daemon=True).start()

    try:
        while not stop.is_set():
            stop.wait(1)
    except KeyboardInterrupt:
        stop.set()
    log.get("main").info("остановлен")
    return 0


def _resume(engine: Engine) -> None:
    try:
        engine.resume_pending()
    except Exception as exc:                                   # noqa: BLE001
        engine.notify(f"❌ доиграть ротацию не удалось: {exc}")


def cmd_probe(cfg: Config, secrets: Secrets) -> int:
    _, engine, _ = build(cfg, secrets)
    result = engine.probe()
    print(result.short())
    print(f"вердикт: {result.verdict} — {probes.VERDICT_TEXT.get(result.verdict, '')}")
    if not result.confident:
        print("(уверенности нет: причину сузить нечем)")
    return 0 if result.verdict == probes.OK else 1


def cmd_rotate(cfg: Config, secrets: Secrets, args: argparse.Namespace) -> int:
    _, engine, _ = build(cfg, secrets)
    try:
        result = engine.rotate(
            args.mode or "",
            args.zone or "",
            reason="cli",
            force=args.force,
            progress=lambda text: print(f"• {text}"),
        )
    except Exception as exc:                                   # noqa: BLE001
        print(f"ошибка: {exc}", file=sys.stderr)
        return 1
    print(result)
    return 0


def cmd_check(cfg: Config, secrets: Secrets) -> int:
    relay, engine, _ = build(cfg, secrets)
    ok = True
    for url, status in relay.health().items():
        print(f"{'✅' if status == 'ok' else '❌'} релей {url} — {status}")
        ok &= status == "ok"
    try:
        print(f"✅ UpCloud: аккаунт {engine.uc.account().get('username', '?')}")
    except Exception as exc:                                   # noqa: BLE001
        print(f"❌ UpCloud: {exc}")
        ok = False
    try:
        engine.cf.verify_token()
        print("✅ Cloudflare: токен действителен")
    except Exception as exc:                                   # noqa: BLE001
        print(f"❌ Cloudflare: {exc}")
        ok = False
    try:
        info = engine.refresh()
        print(f"✅ сервер {info['hostname']}: {info['state']}, {info['ipv4']}, {info['zone']}")
    except Exception as exc:                                   # noqa: BLE001
        print(f"❌ сервер: {exc}")
        ok = False
    return 0 if ok else 1


def cmd_setup_local(secrets: Secrets) -> int:
    """Ввод тех же значений с консоли — для тех, кому не нравится слать ключи в чат."""
    print("Пустой ввод оставляет текущее значение, «-» стирает его.\n")
    for key in BOOTSTRAP_KEYS + SETUP_KEYS:
        current = secrets.get(key)
        shown = masked(current) if "TOKEN" in key or "KEY" == key[-3:] else current
        prompt = f"{key} [{shown or '—'}]: "
        value = getpass.getpass(prompt) if "TOKEN" in key or key == "RELAY_KEY" else input(prompt)
        value = value.strip()
        if not value:
            continue
        if value == "-":
            secrets.unset(key)
            continue
        secrets.set(key, value)
    print(f"\nЗаписано в {secrets.path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rotator", description="ротация IP VPN-сервера на UpCloud")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("run", help="демон: бот + детектор")
    sub.add_parser("probe", help="одна проба и вердикт")
    sub.add_parser("check", help="проверить доступы")
    setup = sub.add_parser("setup", help="ввод доступов")
    setup.add_argument("--local", action="store_true", help="спросить значения в консоли")
    rotate = sub.add_parser("rotate", help="ротация вручную")
    rotate.add_argument("--mode", choices=list(modes.ALL_MODES), help="по умолчанию — выбор автоматики")
    rotate.add_argument("--zone", help="целевая зона для recreate")
    rotate.add_argument("--force", action="store_true", help="игнорировать cooldown и дневной лимит")
    args = parser.parse_args(argv)

    cfg = Config()
    secrets = Secrets()
    log.setup(str(cfg.get("log_level", "INFO")))

    command = args.command or "run"
    if command == "setup":
        return cmd_setup_local(secrets)
    if command == "probe":
        return cmd_probe(cfg, secrets)
    if command == "check":
        return cmd_check(cfg, secrets)
    if command == "rotate":
        return cmd_rotate(cfg, secrets, args)
    return cmd_run(cfg, secrets)


if __name__ == "__main__":
    sys.exit(main())
