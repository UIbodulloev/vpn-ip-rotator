"""Фейковый Telegram: очередь апдейтов на вход, журнал вызовов на выход."""

from __future__ import annotations

import json
from typing import Any

from .fake_api import FakeResponse


class FakeTelegram:
    def __init__(self, admin_id: str = "42"):
        self.admin_id = admin_id
        self.pending: list[dict] = []      # апдейты, которые отдаст getUpdates
        self.sent: list[dict] = []         # sendMessage
        self.edited: list[dict] = []       # editMessageText
        self.deleted: list[tuple] = []     # deleteMessage
        self.answered: list[str] = []      # answerCallbackQuery
        self.calls: list[str] = []
        self.timeline: list[str] = []      # всё, что увидел пользователь, по порядку
        self._update_id = 100
        self._message_id = 1000

    # --- подготовка входящих ------------------------------------------------

    def user_says(self, text: str, chat_id: str | None = None) -> None:
        self._update_id += 1
        self._message_id += 1
        self.pending.append({
            "update_id": self._update_id,
            "message": {
                "message_id": self._message_id,
                "chat": {"id": int(chat_id or self.admin_id)},
                "text": text,
            },
        })

    def user_taps(self, data: str, chat_id: str | None = None) -> None:
        self._update_id += 1
        self.pending.append({
            "update_id": self._update_id,
            "callback_query": {
                "id": f"cb{self._update_id}",
                "data": data,
                "message": {
                    "message_id": self._message_id,
                    "chat": {"id": int(chat_id or self.admin_id)},
                },
            },
        })

    # --- то, что видит пользователь -----------------------------------------

    def texts(self) -> list[str]:
        return [m["text"] for m in self.sent]

    def last_text(self) -> str:
        return self.sent[-1]["text"] if self.sent else ""

    def last_visible(self) -> str:
        """Последнее, что реально увидел пользователь — с учётом правок сообщений."""
        return self.timeline[-1] if self.timeline else ""

    def all_visible(self) -> str:
        return "\n".join(self.timeline)

    def keyboards(self) -> list[list]:
        return [m["markup"]["inline_keyboard"] for m in self.sent if m.get("markup")]

    def last_keyboard(self) -> list:
        boards = self.keyboards()
        return boards[-1] if boards else []

    def buttons(self) -> list[tuple[str, str]]:
        """Все кнопки последней клавиатуры как (текст, callback_data)."""
        return [(b["text"], b.get("callback_data", "")) for row in self.last_keyboard() for b in row]

    # --- маршрутизация ------------------------------------------------------

    def request(self, method: str, path: str, payload: dict) -> FakeResponse:
        api_method = path.rsplit("/", 1)[-1]
        self.calls.append(api_method)

        if api_method == "getMe":
            return FakeResponse(200, {"ok": True, "result": {"username": "fakebot", "id": 1}})

        if api_method == "getUpdates":
            batch, self.pending = self.pending, []
            return FakeResponse(200, {"ok": True, "result": batch})

        if api_method == "sendMessage":
            self._message_id += 1
            self.sent.append({
                "chat_id": str(payload.get("chat_id")),
                "text": payload.get("text", ""),
                "markup": payload.get("reply_markup"),
                "message_id": self._message_id,
            })
            self.timeline.append(payload.get("text", ""))
            return FakeResponse(200, {"ok": True, "result": {"message_id": self._message_id}})

        if api_method == "editMessageText":
            self.edited.append({"message_id": payload.get("message_id"), "text": payload.get("text", "")})
            self.timeline.append(payload.get("text", ""))
            return FakeResponse(200, {"ok": True, "result": {"message_id": payload.get("message_id")}})

        if api_method == "deleteMessage":
            self.deleted.append((str(payload.get("chat_id")), payload.get("message_id")))
            return FakeResponse(200, {"ok": True, "result": True})

        if api_method == "answerCallbackQuery":
            self.answered.append(payload.get("callback_query_id", ""))
            return FakeResponse(200, {"ok": True, "result": True})

        return FakeResponse(200, {"ok": True, "result": {}})
