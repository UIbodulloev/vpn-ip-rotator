"""Выполнение команд на VPN-сервере по SSH.

Нужно для ручного управления: посмотреть контейнеры, поднять их, проверить
протоколы. Ротации по адресам этот модуль не требуется — там всё делается через
API, и на VPN-сервере по-прежнему не хранится ни одного ключа.
"""

from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass

from . import log

logger = log.get("remote")


class RemoteError(RuntimeError):
    pass


@dataclass
class Result:
    code: int
    out: str
    err: str

    @property
    def ok(self) -> bool:
        return self.code == 0

    def text(self, limit: int = 1500) -> str:
        body = (self.out or self.err or "").strip()
        return body[:limit] or f"(пусто, код {self.code})"


def run(host: str, command: str, *, key_path: str, port: int = 22,
        user: str = "root", timeout: int = 60) -> Result:
    """Одна команда на сервере. Никакого интерактива и проброса портов."""
    if not key_path:
        raise RemoteError("не задан SSH-ключ: /setup → необязательное → SSH-ключ, приватный")
    if not host:
        raise RemoteError("неизвестен адрес сервера")

    argv = [
        "ssh",
        "-i", key_path,
        "-p", str(port or 22),
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=10",
        "-o", "BatchMode=yes",
        f"{user}@{host}",
        command,
    ]
    logger.info("ssh %s: %s", host, command[:80])
    try:
        done = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise RemoteError(f"команда не уложилась в {timeout} с") from None
    except OSError as exc:
        raise RemoteError(f"не удалось запустить ssh: {exc}") from None
    return Result(done.returncode,
                  done.stdout.decode(errors="replace"),
                  done.stderr.decode(errors="replace"))


# Готовые проверки, чтобы не собирать шелл-строки по месту.
CONTAINERS = "docker ps -a --format '{{.Names}}\\t{{.Status}}\\t{{.Ports}}'"
CONTAINERS_UP = "docker start $(docker ps -aq) 2>&1 | tail -5; docker ps --format '{{.Names}}\\t{{.Status}}'"
CONTAINERS_RESTART = "docker restart $(docker ps -aq) 2>&1 | tail -5; docker ps --format '{{.Names}}\\t{{.Status}}'"
DISK = "df -h / | tail -1; free -m | sed -n '2p;3p'"
LISTENERS = "ss -lntup 2>/dev/null | grep -E ':(443|35206)' || echo 'порты не слушаются'"


def escape(command: str) -> str:
    return shlex.quote(command)
