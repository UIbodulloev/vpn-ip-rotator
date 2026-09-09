"""Оформление сообщений бота.

Telegram умеет HTML, и выровненные колонки в <pre> читаются на телефоне
куда лучше, чем строки вразнобой. Весь текст, попадающий в сообщение,
обязан пройти через esc() — иначе символ «<» в значении сломает разметку.
"""

from __future__ import annotations

import html
from typing import Iterable

# Единый словарь пометок, чтобы одно и то же состояние везде выглядело одинаково.
YES = "✅"
NO = "❌"
SKIP = "➖"
WARN = "⚠️"
WAIT = "⏳"


def esc(text: object) -> str:
    return html.escape(str(text), quote=False)


def mark(value: object) -> str:
    """Трёхзначная пометка: да / нет / не проверялось."""
    if value is True:
        return YES
    if value is False:
        return NO
    return SKIP


def title(text: str, emoji: str = "") -> str:
    prefix = f"{emoji} " if emoji else ""
    return f"<b>{prefix}{esc(text)}</b>"


def table(rows: Iterable[tuple[str, object]], gap: int = 2) -> str:
    """Две колонки с выравниванием в моноширинном блоке."""
    pairs = [(str(k), "—" if v is None or v == "" else str(v)) for k, v in rows]
    if not pairs:
        return ""
    width = max(len(k) for k, _ in pairs)
    body = "\n".join(f"{k.ljust(width)}{' ' * gap}{v}" for k, v in pairs)
    return f"<pre>{esc(body)}</pre>"


def block(lines: Iterable[str]) -> str:
    """Моноширинный блок из готовых строк."""
    text = "\n".join(str(line) for line in lines)
    return f"<pre>{esc(text)}</pre>" if text else ""


def note(text: str) -> str:
    return f"<i>{esc(text)}</i>"


def joined(*parts: str) -> str:
    """Склейка секций: пустые выбрасываются, между остальными пустая строка."""
    return "\n\n".join(p for p in parts if p)


def steps(items: Iterable[tuple[str, str]]) -> str:
    """Нумерованный список «шаг — что делает»."""
    return "\n".join(f"<b>{i}.</b> {esc(what)}\n    {note(detail)}" if detail else f"<b>{i}.</b> {esc(what)}"
                     for i, (what, detail) in enumerate(items, 1))


def bar(done: int, total: int, width: int = 10) -> str:
    """Полоска прогресса для доски настройки."""
    filled = round(width * done / total) if total else 0
    return "▰" * filled + "▱" * (width - filled)


def strip_tags(text: str) -> str:
    """Запасной вариант: если Telegram не принял разметку, шлём то же без тегов."""
    import re

    plain = re.sub(r"</?(b|i|u|s|code|pre|blockquote|tg-spoiler)>", "", text)
    return html.unescape(plain)
