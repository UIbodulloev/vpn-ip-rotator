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
    def __init__(self, relay: Relay, token: str):
        self.relay = relay
        self.token = token

    def _call(self, method: str, path: str, payload: Any = None, params: dict[str, Any] | None = None) -> Any:
        if not self.token:
            raise CloudflareError(path, {"errors": [{"code": 0, "message": "токен Cloudflare не задан"}]})
        response = self.relay.request(
            "cf",
            method,
            BASE + path,
            json=payload,
            params=params,
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"},
        )
        try:
            body = response.json()
        except ValueError:
            raise CloudflareError(path, response.text[:300]) from None
        if not body.get("success"):
            raise CloudflareError(path, body)
        return body.get("result")

    def verify_token(self) -> dict[str, Any]:
        return self._call("GET", "/user/tokens/verify")

    def get_record(self, zone_id: str, record_id: str) -> dict[str, Any]:
        return self._call("GET", f"/zones/{zone_id}/dns_records/{record_id}")

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
