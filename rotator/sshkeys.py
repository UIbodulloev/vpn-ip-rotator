"""Приватный SSH-ключ агента: генерация, приём текстом, вывод публичной части.

Ключ нужен только ручному управлению — посмотреть контейнеры и протоколы на
VPN-сервере. Ротации адресов он не требуется: там всё идёт через API.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

from . import log

logger = log.get("sshkeys")

KEY_NAME = "id_vpn"

BEGIN_MARKERS = (
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
)


class KeyError_(RuntimeError):
    pass


def looks_like_private(text: str) -> str:
    """Пустая строка — всё в порядке, иначе объяснение, что не так."""
    body = text.strip()
    if not body.startswith(BEGIN_MARKERS):
        return ("Это не похоже на приватный ключ. Он начинается со строки "
                "-----BEGIN OPENSSH PRIVATE KEY----- и занимает несколько строк.\n\n"
                "Если вы прислали публичный ключ (ssh-ed25519 AAAA…) — нужен именно "
                "приватный, файл без расширения .pub.")
    if "PRIVATE KEY-----" not in body.split("\n")[-1] and "-----END" not in body:
        return "Ключ выглядит обрезанным: нет завершающей строки -----END … PRIVATE KEY-----"
    if len(body.splitlines()) < 3:
        return "Ключ занимает несколько строк — похоже, скопировалась только часть."
    return ""


def _secure_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(content if content.endswith("\n") else content + "\n", encoding="utf-8")
    os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)     # 0600 до того, как файл станет виден
    tmp.replace(path)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def derive_public(private_path: Path) -> str:
    """Публичная часть выводится из приватной — отдельно её присылать не нужно."""
    try:
        done = subprocess.run(
            ["ssh-keygen", "-y", "-f", str(private_path)],
            capture_output=True, timeout=20, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise KeyError_(f"не удалось запустить ssh-keygen: {exc}") from None
    if done.returncode != 0:
        message = done.stderr.decode(errors="replace").strip()
        if "passphrase" in message.lower():
            raise KeyError_("ключ защищён паролем — агент не сможет им пользоваться. "
                            "Нужен ключ без пароля.")
        raise KeyError_(f"ssh-keygen не принял ключ: {message[:200]}")
    return done.stdout.decode(errors="replace").strip()


def install(text: str, directory: Path, name: str = KEY_NAME) -> tuple[Path, str]:
    """Сохранить присланный приватный ключ и вернуть (путь, публичная часть)."""
    problem = looks_like_private(text)
    if problem:
        raise KeyError_(problem)
    private = directory / name
    _secure_write(private, text.strip())
    try:
        public = derive_public(private)
    except KeyError_:
        private.unlink(missing_ok=True)            # мусор не оставляем
        raise
    _secure_write(private.with_suffix(private.suffix + ".pub"), public)
    logger.info("приватный ключ сохранён в %s", private)
    return private, public


def generate(directory: Path, name: str = KEY_NAME, comment: str = "vpn-rotator") -> tuple[Path, str]:
    """Сгенерировать пару на месте: приватный ключ никуда не передаётся."""
    private = directory / name
    directory.mkdir(parents=True, exist_ok=True)
    private.unlink(missing_ok=True)
    Path(str(private) + ".pub").unlink(missing_ok=True)
    try:
        done = subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-f", str(private), "-N", "", "-C", comment],
            capture_output=True, timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise KeyError_(f"не удалось запустить ssh-keygen: {exc}") from None
    if done.returncode != 0:
        raise KeyError_(done.stderr.decode(errors="replace").strip()[:200])
    os.chmod(private, stat.S_IRUSR | stat.S_IWUSR)
    public = Path(str(private) + ".pub").read_text(encoding="utf-8").strip()
    logger.info("сгенерирована пара ключей в %s", private)
    return private, public


def authorize_command(public_key: str) -> str:
    """Команда, которой публичный ключ добавляется на VPN-сервер."""
    return (
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
        f"echo '{public_key}' >> ~/.ssh/authorized_keys && "
        "chmod 600 ~/.ssh/authorized_keys"
    )
