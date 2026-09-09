"""Фейковый UpCloud + Cloudflare для тестов: реального аккаунта не требуется."""

from __future__ import annotations

import json
import re
import uuid as uuidlib
from typing import Any


class FakeResponse:
    def __init__(self, status: int, payload: Any = None):
        self.status_code = status
        self._payload = payload
        self.text = "" if payload is None else json.dumps(payload)
        self.content = self.text.encode()
        self.ok = status < 400

    def json(self) -> Any:
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class FakeCloud:
    """Держит серверы, адреса, диски и DNS-записи в памяти."""

    def __init__(self):
        self.subnet = "203.0.113."
        self.next_octet = 10
        self.servers: dict[str, dict] = {}
        self.storages: dict[str, dict] = {}
        self.ips: dict[str, str] = {}          # адрес -> uuid сервера
        self.records: dict[str, dict] = {}
        self.calls: list[tuple[str, str]] = []
        self.fail_on: dict[str, int] = {}      # путь -> сколько раз вернуть 500
        self.telegram = None                   # подставляется FakeTelegram, если нужен бот

    # --- помощники ----------------------------------------------------------

    def new_ip(self) -> str:
        self.next_octet += 1
        return f"{self.subnet}{self.next_octet}"

    def seed(self, *, zone: str = "nl-ams1", plan: str = "1xCPU-1GB") -> tuple[str, str, str]:
        server_uuid = str(uuidlib.uuid4())
        storage_uuid = str(uuidlib.uuid4())
        ip = self.new_ip()
        mac = "52:54:00:aa:00:01"
        self.storages[storage_uuid] = {
            "uuid": storage_uuid, "state": "online", "size": 10,
            "tier": "standard", "title": "osdisk", "type": "normal", "zone": zone,
        }
        self.servers[server_uuid] = {
            "uuid": server_uuid, "state": "started", "zone": zone, "plan": plan,
            "hostname": "amnezia-test", "title": "amnezia-test",
            "ip_addresses": {"ip_address": [
                {"access": "public", "family": "IPv4", "address": ip},
                {"access": "public", "family": "IPv6", "address": "2001:db8::1"},
                {"access": "utility", "family": "IPv4", "address": "10.5.16.10"},
            ]},
            "networking": {"interfaces": {"interface": [
                {"type": "public", "mac": mac,
                 "ip_addresses": {"ip_address": [{"family": "IPv4", "address": ip}]}},
                {"type": "public", "mac": "52:54:00:aa:00:03",
                 "ip_addresses": {"ip_address": [{"family": "IPv6", "address": "2001:db8::1"}]}},
                {"type": "utility", "mac": "52:54:00:aa:00:02",
                 "ip_addresses": {"ip_address": [{"family": "IPv4", "address": "10.5.16.10"}]}},
            ]}},
            "storage_devices": {"storage_device": [{
                "address": "virtio:0", "type": "disk", "storage": storage_uuid,
                "storage_size": 10, "storage_tier": "standard", "storage_title": "osdisk",
            }]},
        }
        self.ips[ip] = server_uuid
        self.records["rec-a"] = {"id": "rec-a", "type": "A", "name": "vpn.example.com",
                                 "content": ip, "ttl": 60, "proxied": False}
        self.records["rec-aaaa"] = {"id": "rec-aaaa", "type": "AAAA", "name": "vpn.example.com",
                                    "content": "2001:db8::1", "ttl": 60, "proxied": False}
        return server_uuid, storage_uuid, ip

    def server_ip(self, server_uuid: str, family: str = "IPv4") -> str:
        server = self.servers.get(server_uuid, {})
        for entry in server.get("ip_addresses", {}).get("ip_address", []):
            if entry["access"] == "public" and entry["family"] == family:
                return entry["address"]
        return ""

    def _attach_ip(self, server_uuid: str, address: str, mac: str) -> None:
        server = self.servers[server_uuid]
        server["ip_addresses"]["ip_address"].append(
            {"access": "public", "family": "IPv4", "address": address}
        )
        for iface in server["networking"]["interfaces"]["interface"]:
            if iface.get("mac") == mac:
                iface["ip_addresses"]["ip_address"].append({"family": "IPv4", "address": address})
        self.ips[address] = server_uuid

    def _detach_ip(self, address: str) -> None:
        server_uuid = self.ips.pop(address, "")
        server = self.servers.get(server_uuid)
        if not server:
            return
        server["ip_addresses"]["ip_address"] = [
            e for e in server["ip_addresses"]["ip_address"] if e["address"] != address
        ]
        for iface in server["networking"]["interfaces"]["interface"]:
            iface["ip_addresses"]["ip_address"] = [
                e for e in iface["ip_addresses"]["ip_address"] if e.get("address") != address
            ]

    # --- маршрутизация ------------------------------------------------------

    def request(self, upstream: str, method: str, path: str, *, json=None, headers=None,
                params=None, timeout=None) -> FakeResponse:
        self.calls.append((method.upper(), path))
        key = f"{method.upper()} {path}"
        if self.fail_on.get(key, 0) > 0:
            self.fail_on[key] -= 1
            return FakeResponse(500, {"error": {"error_message": "искусственный сбой"}})
        if upstream == "uc":
            return self._upcloud(method.upper(), path, json or {}, params or {})
        if upstream == "cf":
            return self._cloudflare(method.upper(), path, json or {}, params or {})
        if upstream == "tg":
            if self.telegram is not None:
                return self.telegram.request(method.upper(), path, json or {})
            return FakeResponse(200, {"ok": True, "result": {"message_id": 1, "username": "fakebot"}})
        return FakeResponse(404, {})

    def _upcloud(self, method: str, path: str, body: dict, params: dict) -> FakeResponse:
        if path == "/1.3/account":
            return FakeResponse(200, {"account": {"username": "fake"}})
        if path == "/1.3/zone":
            return FakeResponse(200, {"zones": {"zone": [
                {"id": "nl-ams1", "description": "Amsterdam", "public": "yes"},
                {"id": "fi-hel1", "description": "Helsinki", "public": "yes"},
                {"id": "de-fra1", "description": "Frankfurt", "public": "yes"},
            ]}})

        if path == "/1.3/server" and method == "GET":
            return FakeResponse(200, {"servers": {"server": [
                {k: v for k, v in s.items() if k not in ("networking", "storage_devices")}
                for s in self.servers.values()
            ]}})

        match = re.fullmatch(r"/1\.3/server/([0-9a-f-]+)", path)
        if match and method == "GET":
            server = self.servers.get(match.group(1))
            return FakeResponse(200, {"server": server}) if server else FakeResponse(404, {})
        if match and method == "DELETE":
            server_uuid = match.group(1)
            server = self.servers.get(server_uuid)
            if not server:
                return FakeResponse(404, {})
            if server["state"] != "stopped":
                return FakeResponse(409, {"error": {"error_code": "SERVER_STATE_ILLEGAL"}})
            for entry in list(server["ip_addresses"]["ip_address"]):
                self.ips.pop(entry["address"], None)
            if params.get("storages") in ("1", 1, True):
                for device in server["storage_devices"]["storage_device"]:
                    self.storages.pop(device["storage"], None)
            del self.servers[server_uuid]
            return FakeResponse(204)

        match = re.fullmatch(r"/1\.3/server/([0-9a-f-]+)/(stop|start)", path)
        if match:
            server = self.servers.get(match.group(1))
            if not server:
                return FakeResponse(404, {})
            server["state"] = "stopped" if match.group(2) == "stop" else "started"
            return FakeResponse(200, {"server": server})

        if path == "/1.3/server" and method == "POST":
            spec = body["server"]
            source = spec["storage_devices"]["storage_device"][0]["storage"]
            if source not in self.storages:
                return FakeResponse(404, {"error": {"error_message": "шаблон не найден"}})
            if self.storages[source].get("zone") != spec["zone"]:
                return FakeResponse(400, {"error": {"error_message": "шаблон из другой зоны"}})
            new_uuid, new_storage, ip = self.seed(zone=spec["zone"], plan=spec["plan"])
            self.servers[new_uuid]["hostname"] = spec["hostname"]
            self.servers[new_uuid]["state"] = "started"
            return FakeResponse(202, {"server": self.servers[new_uuid]})

        if path == "/1.3/ip_address" and method == "POST":
            spec = body["ip_address"]
            address = self.new_ip()
            server_uuid = spec.get("server") or self.ips.get(self.server_ip(spec.get("server", "")), "")
            if not server_uuid and spec.get("mac"):
                for uid, srv in self.servers.items():
                    for iface in srv["networking"]["interfaces"]["interface"]:
                        if iface.get("mac") == spec["mac"]:
                            server_uuid = uid
            if not server_uuid:
                return FakeResponse(400, {"error": {"error_message": "нет сервера"}})
            # Настоящий UpCloud отвергает MAC для обычного адреса — именно на этом
            # сломалась боевая ротация, пока фейк был мягче оригинала.
            if spec.get("mac") and not spec.get("floating"):
                return FakeResponse(409, {"error": {
                    "error_code": "FLOATING_IP_NOT_AVAILABLE",
                    "error_message": "Only floating IP addresses can be assigned to MAC addresses.",
                }})
            if spec.get("floating") and self.servers[server_uuid]["state"] not in ("started", "stopped"):
                return FakeResponse(409, {"error": {"error_code": "SERVER_STATE_ILLEGAL"}})
            self._attach_ip(server_uuid, address, spec.get("mac", ""))
            return FakeResponse(201, {"ip_address": {"address": address, "family": "IPv4"}})

        match = re.fullmatch(r"/1\.3/ip_address/([0-9a-f.:]+)", path)
        if match and method == "DELETE":
            address = match.group(1)
            if address not in self.ips:
                return FakeResponse(404, {})
            self._detach_ip(address)
            return FakeResponse(204)

        match = re.fullmatch(r"/1\.3/storage/([0-9a-f-]+)/(templatize|clone)", path)
        if match:
            source = self.storages.get(match.group(1))
            if not source:
                return FakeResponse(404, {})
            new_uuid = str(uuidlib.uuid4())
            zone = body["storage"].get("zone", source["zone"])
            self.storages[new_uuid] = {
                "uuid": new_uuid, "state": "online", "size": source["size"],
                "tier": source["tier"], "title": body["storage"]["title"], "zone": zone,
                "type": "template" if match.group(2) == "templatize" else "normal",
            }
            return FakeResponse(202, {"storage": self.storages[new_uuid]})

        match = re.fullmatch(r"/1\.3/storage/([0-9a-f-]+)", path)
        if match and method == "GET":
            storage = self.storages.get(match.group(1))
            return FakeResponse(200, {"storage": storage}) if storage else FakeResponse(404, {})
        if match and method == "DELETE":
            return FakeResponse(204) if self.storages.pop(match.group(1), None) else FakeResponse(404, {})

        if path == "/1.3/permission/grant":
            return FakeResponse(201, {"permission": body["permission"]})

        return FakeResponse(404, {"error": {"error_message": f"не заглушено: {path}"}})

    def _cloudflare(self, method: str, path: str, body: dict, params: dict | None = None) -> FakeResponse:
        if path.endswith("/user/tokens/verify"):
            return FakeResponse(200, {"success": True, "result": {"status": "active"}})
        match = re.search(r"/dns_records/([\w-]+)$", path)
        if match:
            record = self.records.get(match.group(1))
            if not record:
                return FakeResponse(404, {"success": False, "errors": [{"code": 81044, "message": "нет записи"}]})
            if method == "PATCH":
                record.update({k: v for k, v in body.items() if k in ("content", "ttl", "proxied", "type", "name")})
            return FakeResponse(200, {"success": True, "result": record})
        if path.endswith("/dns_records"):
            found = list(self.records.values())
            if params.get("type"):
                found = [r for r in found if r["type"] == params["type"]]
            if params.get("name"):
                found = [r for r in found if r["name"] == params["name"]]
            return FakeResponse(200, {"success": True, "result": found})
        if path.endswith("/zones"):
            return FakeResponse(200, {"success": True, "result": [
                {"id": "zone1", "name": "example.com"},
            ]})
        return FakeResponse(404, {"success": False, "errors": [{"code": 0, "message": path}]})
