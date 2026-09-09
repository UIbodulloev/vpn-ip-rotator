"""Логирование с маскированием секретов и кольцевым буфером для /log."""

from __future__ import annotations

import logging
import re
import sys
import threading
from collections import deque

# Всё, что похоже на ключ, вырезается из любой строки перед выводом.
_PATTERNS = [
    re.compile(r"ucat_[A-Za-z0-9_\-]{8,}"),
    re.compile(r"\b\d{8,12}:[A-Za-z0-9_\-]{30,}\b"),   # токен Telegram-бота
    re.compile(r"\b[A-Za-z0-9_\-]{37,45}\b"),          # токен Cloudflare
]

_RING: deque[str] = deque(maxlen=400)
_RING_LOCK = threading.Lock()
_EXTRA: list[str] = []
_EXTRA_LOCK = threading.Lock()


def register_secret(value: str | None) -> None:
    """Добавить конкретное значение в список маскируемых."""
    if value and len(value) >= 8:
        with _EXTRA_LOCK:
            if value not in _EXTRA:
                _EXTRA.append(value)


def mask(text: str) -> str:
    with _EXTRA_LOCK:
        extras = list(_EXTRA)
    for secret in extras:
        text = text.replace(secret, _short(secret))
    for pattern in _PATTERNS:
        text = pattern.sub(lambda m: _short(m.group(0)), text)
    return text


def _short(secret: str) -> str:
    return f"{secret[:5]}…{secret[-4:]}" if len(secret) > 12 else "…"


class _MaskingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = mask(str(record.msg))
        if record.args:
            record.args = tuple(mask(str(a)) for a in record.args)
        return True


class _RingHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        line = f"{self.format(record)}"
        with _RING_LOCK:
            _RING.append(line)


def tail(n: int = 20) -> list[str]:
    with _RING_LOCK:
        return list(_RING)[-n:]


def setup(level: str = "INFO") -> None:
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)-12s %(message)s", "%Y-%m-%d %H:%M:%S")

    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(fmt)

    ring = _RingHandler()
    ring.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%H:%M:%S"))

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    for handler in (stream, ring):
        handler.addFilter(_MaskingFilter())
        root.addHandler(handler)

    logging.getLogger("urllib3").setLevel(logging.WARNING)


def get(name: str) -> logging.Logger:
    return logging.getLogger(name)
