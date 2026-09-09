"""Клиент UpCloud API 1.3 — ровно те вызовы, которые нужны ротации."""

from __future__ import annotations

import base64
import time
from typing import Any, Callable

from . import log
from .relay import Relay

logger = log.get("upcloud")


class UpCloudError(RuntimeError):
    def __init__(self, status: int, body: str, path: str):
        super().__init__(f"UpCloud {path} → HTTP {status}: {body[:400]}")
        self.status = status
        self.body = body
        self.path = path


def _auth_header(token: str) -> str:
    """Токен ucat_… идёт как Bearer, легаси-пара user:pass — как Basic."""
    token = token.strip()
    if not token.startswith("ucat_") and ":" in token:
        return "Basic " + base64.b64encode(token.encode()).decode()
    return f"Bearer {token}"


def _resolve(source: Any) -> str:
    """Токен может быть строкой или функцией — тогда он читается на каждом вызове.

    Это важно: после /setup токен меняется на лету, и клиент, запомнивший
    старое значение при старте, продолжал бы ходить с ним до перезапуска.
    """
    if callable(source):
        try:
            return str(source() or "")
        except Exception:                                    # noqa: BLE001
            return ""
    return str(source or "")


class UpCloud:
    def __init__(self, relay: Relay, token: Any, admin_token: Any = ""):
        self.relay = relay
        self._token = token
        self._admin_token = admin_token

    @property
    def token(self) -> str:
        return _resolve(self._token)

    @property
    def admin_token(self) -> str:
        return _resolve(self._admin_token)

    # --- транспорт ----------------------------------------------------------

    def _call(
        self,
        method: str,
        path: str,
        payload: Any = None,
        params: dict[str, Any] | None = None,
        *,
        admin: bool = False,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        token = (self.admin_token or self.token) if admin else self.token
        if not token:
            raise UpCloudError(0, "токен UpCloud не задан", path)
        response = self.relay.request(
            "uc",
            method,
            path,
            json=payload,
            params=params,
            headers={"Authorization": _auth_header(token), "Accept": "application/json"},
            timeout=timeout,
        )
        if response.status_code >= 400:
            raise UpCloudError(response.status_code, response.text, path)
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError:
            return {}

    # --- аккаунт и справочники ---------------------------------------------

    def account(self) -> dict[str, Any]:
        return self._call("GET", "/1.3/account").get("account", {})

    def zones(self) -> list[dict[str, Any]]:
        return self._call("GET", "/1.3/zone").get("zones", {}).get("zone", [])

    def plans(self) -> list[dict[str, Any]]:
        return self._call("GET", "/1.3/plan").get("plans", {}).get("plan", [])

    # --- серверы ------------------------------------------------------------

    def server(self, uuid: str) -> dict[str, Any]:
        return self._call("GET", f"/1.3/server/{uuid}").get("server", {})

    def servers(self) -> list[dict[str, Any]]:
        return self._call("GET", "/1.3/server").get("servers", {}).get("server", [])

    def stop_server(self, uuid: str, stop_type: str = "soft", timeout: int = 60) -> None:
        self._call(
            "POST",
            f"/1.3/server/{uuid}/stop",
            {"stop_server": {"stop_type": stop_type, "timeout": str(timeout)}},
        )

    def start_server(self, uuid: str) -> dict[str, Any]:
        return self._call("POST", f"/1.3/server/{uuid}/start", {}).get("server", {})

    def create_server(self, spec: dict[str, Any]) -> dict[str, Any]:
        return self._call("POST", "/1.3/server", {"server": spec}, timeout=120).get("server", {})

    def delete_server(self, uuid: str, *, storages: bool = True, backups: str = "delete") -> None:
        self._call(
            "DELETE",
            f"/1.3/server/{uuid}",
            params={"storages": "1" if storages else "0", "backups": backups},
        )

    # --- IP-адреса ----------------------------------------------------------

    def assign_ip(
        self,
        *,
        server_uuid: str = "",
        mac: str = "",
        family: str = "IPv4",
        floating: bool = False,
        zone: str = "",
        release_policy: str = "",
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"family": family}
        if floating:
            body["floating"] = "yes"
        if server_uuid:
            body["server"] = server_uuid
        if mac:
            body["mac"] = mac
        if zone:
            body["zone"] = zone
        if release_policy:
            body["release_policy"] = release_policy
        return self._call("POST", "/1.3/ip_address", {"ip_address": body}, timeout=90).get("ip_address", {})

    def release_ip(self, address: str) -> None:
        self._call("DELETE", f"/1.3/ip_address/{address}")

    def modify_ip(self, address: str, **fields: Any) -> dict[str, Any]:
        return self._call("PATCH", f"/1.3/ip_address/{address}", {"ip_address": fields}).get("ip_address", {})

    # --- диски --------------------------------------------------------------

    def storage(self, uuid: str) -> dict[str, Any]:
        return self._call("GET", f"/1.3/storage/{uuid}").get("storage", {})

    def templatize(self, storage_uuid: str, title: str) -> dict[str, Any]:
        return self._call(
            "POST", f"/1.3/storage/{storage_uuid}/templatize", {"storage": {"title": title[:255]}}, timeout=120
        ).get("storage", {})

    def clone_storage(self, storage_uuid: str, zone: str, title: str, tier: str = "") -> dict[str, Any]:
        body: dict[str, Any] = {"zone": zone, "title": title[:255]}
        if tier:
            body["tier"] = tier
        return self._call(
            "POST", f"/1.3/storage/{storage_uuid}/clone", {"storage": body}, timeout=120
        ).get("storage", {})

    def delete_storage(self, storage_uuid: str) -> None:
        self._call("DELETE", f"/1.3/storage/{storage_uuid}")

    # --- права (нужны только после recreate под субаккаунтом) ---------------

    def grant_server_permission(self, user: str, server_uuid: str) -> None:
        self._call(
            "POST",
            "/1.3/permission/grant",
            {
                "permission": {
                    "user": user,
                    "target_type": "server",
                    "target_identifier": server_uuid,
                    "options": {"storage": "yes"},
                }
            },
            admin=True,
        )

    # --- ожидания -----------------------------------------------------------

    def wait_server_state(
        self,
        uuid: str,
        target: str,
        timeout: int,
        *,
        poll: int = 5,
        on_tick: Callable[[str, int], None] | None = None,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        last_state = "?"
        while time.monotonic() < deadline:
            server = self.server(uuid)
            last_state = server.get("state", "?")
            if last_state == target:
                return server
            if last_state == "error":
                raise UpCloudError(0, f"сервер {uuid} перешёл в состояние error", "/1.3/server")
            if on_tick:
                on_tick(last_state, int(deadline - time.monotonic()))
            time.sleep(poll)
        raise TimeoutError(f"сервер {uuid} не дошёл до состояния {target} за {timeout} с (сейчас {last_state})")

    def wait_storage_online(
        self,
        uuid: str,
        timeout: int,
        *,
        poll: int = 10,
        on_tick: Callable[[str, int], None] | None = None,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        last_state = "?"
        while time.monotonic() < deadline:
            storage = self.storage(uuid)
            last_state = storage.get("state", "?")
            if last_state == "online":
                return storage
            if last_state == "error":
                raise UpCloudError(0, f"диск {uuid} перешёл в состояние error", "/1.3/storage")
            if on_tick:
                on_tick(last_state, int(deadline - time.monotonic()))
            time.sleep(poll)
        raise TimeoutError(f"диск {uuid} не вышел в online за {timeout} с (сейчас {last_state})")


# --- разбор ответа сервера --------------------------------------------------


def _ip_list(server: dict[str, Any]) -> list[dict[str, Any]]:
    return (server.get("ip_addresses") or {}).get("ip_address", []) or []


def _iface_list(server: dict[str, Any]) -> list[dict[str, Any]]:
    return ((server.get("networking") or {}).get("interfaces") or {}).get("interface", []) or []


def public_ip(server: dict[str, Any], family: str = "IPv4") -> str:
    for entry in _ip_list(server):
        if entry.get("access") == "public" and entry.get("family") == family:
            return entry.get("address", "")
    return ""


def public_mac(server: dict[str, Any], family: str = "IPv4") -> str:
    """MAC публичного интерфейса — на него сажается новый адрес."""
    for iface in _iface_list(server):
        if iface.get("type") != "public":
            continue
        addresses = (iface.get("ip_addresses") or {}).get("ip_address", []) or []
        if any(a.get("family") == family for a in addresses):
            return iface.get("mac", "")
    return ""


def os_disk(server: dict[str, Any]) -> dict[str, Any]:
    devices = (server.get("storage_devices") or {}).get("storage_device", []) or []
    disks = [d for d in devices if d.get("type") == "disk"]
    if not disks:
        return {}
    # Системный диск — тот, что на первом адресе контроллера (virtio:0 / scsi:0).
    disks.sort(key=lambda d: str(d.get("address", "zzz")))
    return disks[0]


def summarize(server: dict[str, Any]) -> dict[str, Any]:
    disk = os_disk(server)
    return {
        "uuid": server.get("uuid", ""),
        "hostname": server.get("hostname", ""),
        "title": server.get("title", ""),
        "plan": server.get("plan", ""),
        "zone": server.get("zone", ""),
        "state": server.get("state", ""),
        "ipv4": public_ip(server, "IPv4"),
        "ipv6": public_ip(server, "IPv6"),
        "mac": public_mac(server, "IPv4"),
        "storage_uuid": disk.get("storage", ""),
        "storage_size": disk.get("storage_size", 0),
        "storage_tier": disk.get("storage_tier", "") or disk.get("tier", ""),
        "storage_title": disk.get("storage_title", ""),
    }
