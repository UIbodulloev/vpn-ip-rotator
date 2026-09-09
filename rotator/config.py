"""Конфиг (config.toml) и хранилище секретов (secrets.env)."""

from __future__ import annotations

import os
import stat
import threading
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:                                  # Python < 3.11
    import tomli as tomllib                                  # type: ignore[no-redef]

from . import log

# Пути вычисляются при создании объекта, а не при импорте: иначе переменные
# окружения, выставленные позже (в тестах или обёртках), уже не действуют.
def config_path() -> Path:
    return Path(os.environ.get("ROTATOR_CONFIG", "/etc/vpn-rotator/config.toml"))


def secrets_path() -> Path:
    return Path(os.environ.get("ROTATOR_SECRETS", "/etc/vpn-rotator/secrets.env"))


def state_path() -> Path:
    return Path(os.environ.get("ROTATOR_STATE", "/var/lib/vpn-rotator/state.json"))

# Без этих четырёх агент не стартует: без них не поднять даже канал до Telegram.
BOOTSTRAP_KEYS = ("RELAY_URLS", "RELAY_KEY", "TG_BOT_TOKEN", "TG_ADMIN_ID")

# Заливаются через /setup уже из чата.
SETUP_KEYS = (
    "UPCLOUD_TOKEN",
    "UPCLOUD_ADMIN_TOKEN",
    "UPCLOUD_SUBACCOUNT",
    "SERVER_UUID",
    "CF_TOKEN",
    "CF_ZONE_ID",
    "VPN_DOMAIN",
    "CF_A_RECORD_ID",
    "CF_AAAA_RECORD_ID",
    "SSH_KEY_PATH",
    "SSH_PUBKEY",
)

DEFAULTS: dict[str, Any] = {
    "log_level": "INFO",
    "dry_run": False,
    "prefer_direct": False,          # true — если агент стоит НЕ в РФ и релей не нужен
    "vpn": {
        "domain": "example.com",
        "probe_port": 443,           # рабочий порт (Reality)
        "control_port": 22,          # контрольный порт, чтобы отличить блок IP от блока порта
        "udp_port": 0,               # 0 — не проверять
        "update_aaaa": True,
    },
    "detector": {
        "enabled": True,
        "interval_sec": 60,
        "fail_threshold": 5,
        "tcp_timeout_sec": 5.0,
        "sanity_targets": ["77.88.55.242:443", "5.255.255.242:443"],
        "deep_probe": False,
        "reality_probe_cmd": "",
        "awg_probe_cmd": "",
        "deep_probe_timeout_sec": 25,
    },
    "rotation": {
        "mode": "auto",              # auto | clone | move | floating
        "cooldown_hours": 6,
        "max_per_day": 2,
        "escalate_after_hours": 6,   # новый IP умер быстрее — значит подсеть/протокол
        "zone_rotation": ["fi-hel1", "de-fra1", "nl-ams1", "uk-lon1"],
        "keep_templates": 1,
        "wait_stop_sec": 240,
        "wait_start_sec": 300,
        "wait_storage_sec": 3600,
        "wait_service_sec": 240,
        "dns_ttl": 60,
    },
    "telegram": {
        "poll_timeout_sec": 25,
        "delete_secret_messages": True,
    },
}


def _deep_merge(base: dict, overlay: dict) -> dict:
    out = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


class Config:
    def __init__(self, path: Path | None = None):
        self.path = path or config_path()
        raw: dict[str, Any] = {}
        if self.path.exists():
            raw = tomllib.loads(self.path.read_text(encoding="utf-8"))
        self.data = _deep_merge(DEFAULTS, raw)

    def __getitem__(self, key: str) -> Any:
        return self.data[key]

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node


class Secrets:
    """KEY=VALUE файл 0600. Читается при старте, дописывается мастером /setup."""

    def __init__(self, path: Path | None = None):
        self.path = path or secrets_path()
        self._lock = threading.Lock()
        self._values: dict[str, str] = {}
        self.reload()

    def reload(self) -> None:
        values: dict[str, str] = {}
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip().strip("'\"")
        # Переменные окружения (EnvironmentFile в systemd) имеют приоритет.
        for key in BOOTSTRAP_KEYS + SETUP_KEYS:
            if os.environ.get(key):
                values[key] = os.environ[key]
        with self._lock:
            self._values = values
        for key, value in values.items():
            if key.endswith(("TOKEN", "KEY")) and not key.endswith("KEY_PATH"):
                log.register_secret(value)

    def get(self, key: str, default: str = "") -> str:
        with self._lock:
            return self._values.get(key, default)

    def set(self, key: str, value: str) -> None:
        with self._lock:
            self._values[key] = value
        log.register_secret(value)
        self._write()

    def unset(self, key: str) -> None:
        with self._lock:
            self._values.pop(key, None)
        self._write()

    def missing_bootstrap(self) -> list[str]:
        return [k for k in BOOTSTRAP_KEYS if not self.get(k)]

    def _write(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            body = "\n".join(f"{k}={v}" for k, v in sorted(self._values.items()) if v)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text("# vpn-ip-rotator secrets — не коммитить\n" + body + "\n", encoding="utf-8")
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        tmp.replace(self.path)
        os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)


def domain_of(cfg: "Config", secrets: "Secrets") -> str:
    """Домен из мастера имеет приоритет над config.toml: его правят из чата."""
    return secrets.get("VPN_DOMAIN") or str(cfg.get("vpn.domain", ""))


def masked(value: str) -> str:
    if not value:
        return "—"
    return f"{value[:5]}…{value[-4:]}" if len(value) > 12 else "…"
