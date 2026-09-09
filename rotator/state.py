"""Состояние на диске. Пишется после каждого шага, чтобы ротацию можно было доиграть."""

from __future__ import annotations

import json
import os
import threading
import time
from datetime import date
from pathlib import Path
from typing import Any

from .config import STATE_PATH

EMPTY: dict[str, Any] = {
    "server_uuid": "",
    "storage_uuid": "",
    "hostname": "",
    "plan": "",
    "zone": "",
    "ipv4": "",
    "ipv6": "",
    "eth0_mac": "",
    "floating_ip": "",
    "templates": [],          # [{"uuid", "zone", "created"}] — свежий первым
    "history": [],            # [{"ts", "mode", "from", "to", "zone", "reason"}]
    "last_rotation_ts": 0,
    "rotations_today": {"date": "", "count": 0},
    "fail_streak": 0,
    "paused": False,
    "mode": "",               # переопределяет rotation.mode из конфига
    "pending": None,          # {"mode", "step", "data"} — незавершённая ротация
    "last_verdict": "",
    "last_probe": {},
    "last_probe_ts": 0,
}


class State:
    def __init__(self, path: Path = STATE_PATH):
        self.path = path
        self._lock = threading.RLock()
        self.data = dict(EMPTY)
        if path.exists():
            try:
                stored = json.loads(path.read_text(encoding="utf-8"))
                self.data = {**EMPTY, **stored}
            except (json.JSONDecodeError, OSError):
                # Битый state лучше пересоздать, чем упасть в рестарт-луп.
                self.path.rename(self.path.with_suffix(".corrupt"))

    def save(self) -> None:
        with self._lock:
            payload = json.dumps(self.data, indent=2, ensure_ascii=False)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(payload, encoding="utf-8")
        os.replace(tmp, self.path)

    def __getitem__(self, key: str) -> Any:
        with self._lock:
            return self.data[key]

    def __setitem__(self, key: str, value: Any) -> None:
        with self._lock:
            self.data[key] = value
        self.save()

    def update(self, **kwargs: Any) -> None:
        with self._lock:
            self.data.update(kwargs)
        self.save()

    # --- ротации ------------------------------------------------------------

    def set_pending(self, mode: str, step: str, **data: Any) -> None:
        with self._lock:
            pending = self.data.get("pending") or {"mode": mode, "data": {}}
            pending["mode"] = mode
            pending["step"] = step
            pending["data"] = {**pending.get("data", {}), **data}
            pending["ts"] = int(time.time())
            self.data["pending"] = pending
        self.save()

    def clear_pending(self) -> None:
        self["pending"] = None

    def record_rotation(self, mode: str, old_ip: str, new_ip: str, zone: str, reason: str) -> None:
        today = date.today().isoformat()
        with self._lock:
            counter = self.data.get("rotations_today") or {}
            count = counter.get("count", 0) if counter.get("date") == today else 0
            self.data["rotations_today"] = {"date": today, "count": count + 1}
            self.data["last_rotation_ts"] = int(time.time())
            self.data["history"] = (
                [{
                    "ts": int(time.time()),
                    "mode": mode,
                    "from": old_ip,
                    "to": new_ip,
                    "zone": zone,
                    "reason": reason,
                }] + self.data.get("history", [])
            )[:50]
        self.save()

    def rotations_today(self) -> int:
        counter = self["rotations_today"] or {}
        return counter.get("count", 0) if counter.get("date") == date.today().isoformat() else 0

    def hours_since_last_rotation(self) -> float:
        last = self["last_rotation_ts"]
        return float("inf") if not last else (time.time() - last) / 3600.0

    def add_template(self, uuid: str, zone: str) -> None:
        with self._lock:
            self.data["templates"] = [{"uuid": uuid, "zone": zone, "created": int(time.time())}] + [
                t for t in self.data.get("templates", []) if t.get("uuid") != uuid
            ]
        self.save()

    def drop_template(self, uuid: str) -> None:
        with self._lock:
            self.data["templates"] = [t for t in self.data.get("templates", []) if t.get("uuid") != uuid]
        self.save()
