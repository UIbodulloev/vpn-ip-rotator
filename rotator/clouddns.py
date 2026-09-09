"""Cloudflare DNS — обновление A/AAAA после смены адреса."""

from __future__ import annotations

from typing import Any

from . import log
from .relay import Relay

logger = log.get("clouddns")

BASE = "/client/v4"


class CloudflareError(RuntimeError):
    def __init__(self, path: str, payload: Any):
        errors = ""
        if isinstance(payload, dict):
            errors = "; ".join(
                f"{e.get('code')}: {e.get('message')}" for e in payload.get("errors", [])
            )
        super().__init__(f"Cloudflare {path}: {errors or str(payload)[:300]}")


class Cloudflare:
    def __init__(self, relay: Relay, token: Any):
        self.relay = relay
        self._token = token

    @property
    def token(self) -> str:
        """Читается заново на каждом вызове — /setup меняет токен на лету."""
        source = self._token
        if callable(source):
            try:
                return str(source() or "")
            except Exception:                                # noqa: BLE001
                return ""
        return str(source or "")

    def _call(self, method: str, path: str, payload: Any = None,
              params: dict[str, Any] | None = None, timeout: float | None = None) -> Any:
        if not self.token:
            raise CloudflareError(path, {"errors": [{"code": 0, "message": "токен Cloudflare не задан"}]})
        response = self.relay.request(
            "cf",
            method,
            BASE + path,
            json=payload,
            params=params,
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"},
            timeout=timeout,
        )
        try:
            body = response.json()
        except ValueError:
            raise CloudflareError(path, response.text[:300]) from None
        if not body.get("success"):
            raise CloudflareError(path, body)
        return body.get("result")

    def verify_token(self, timeout: float | None = None) -> dict[str, Any]:
        return self._call("GET", "/user/tokens/verify", timeout=timeout)

    def get_record(self, zone_id: str, record_id: str) -> dict[str, Any]:
        return self._call("GET", f"/zones/{zone_id}/dns_records/{record_id}")

    def zones(self, timeout: float | None = None) -> list[dict[str, Any]]:
        """Список зон. Токену, урезанному до одной зоны, вернётся она одна —
        этого мастеру достаточно. Если прав не хватит, вызов бросит исключение,
        и мастер откатится на ручной ввод Zone ID."""
        return self._call("GET", "/zones", params={"per_page": 50}, timeout=timeout) or []

    def list_records(self, zone_id: str, rtype: str = "A") -> list[dict[str, Any]]:
        """Чтение записей своей зоны входит в право DNS → Edit, Zone → Read не нужен."""
        return self._call(
            "GET", f"/zones/{zone_id}/dns_records", params={"type": rtype, "per_page": 100}
        ) or []

    def find_record(self, zone_id: str, name: str, rtype: str) -> dict[str, Any]:
        """Право Zone→DNS→Edit включает чтение записей зоны, отдельный Zone→Read не нужен."""
        found = self._call("GET", f"/zones/{zone_id}/dns_records", params={"name": name, "type": rtype})
        return (found or [{}])[0] if found else {}

    def update_record(
        self,
        zone_id: str,
        record_id: str,
        *,
        rtype: str,
        name: str,
        content: str,
        ttl: int = 60,
        proxied: bool = False,
    ) -> dict[str, Any]:
        return self._call(
            "PATCH",
            f"/zones/{zone_id}/dns_records/{record_id}",
            {"type": rtype, "name": name, "content": content, "ttl": ttl, "proxied": proxied},
        )
