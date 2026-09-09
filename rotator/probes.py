"""Пробы со стороны РФ и вердикт о причине недоступности.

Смысл не в том, «работает ли VPN», а в том, **почему** он не работает: ротация
адреса лечит ровно один случай из пяти, и запускать её в остальных — значит
впустую жечь адреса.
"""

from __future__ import annotations

import shlex
import socket
import subprocess
import time
from dataclasses import asdict, dataclass, field

from . import log

logger = log.get("probes")

OK = "ok"
OWN_NET_DOWN = "own-net-down"
SERVER_DOWN = "server-down"
IP_BLOCKED = "ip-blocked"
PORT_BLOCKED = "port-blocked"
FINGERPRINT_BLOCKED = "fingerprint-blocked"
UNKNOWN = "unknown"

VERDICT_TEXT = {
    OK: "всё работает",
    OWN_NET_DOWN: "лёг канал самого агента — проверять нечего",
    SERVER_DOWN: "сервер не в состоянии started — это не блокировка",
    IP_BLOCKED: "блокировка IP: закрыты и рабочий, и контрольный порт",
    PORT_BLOCKED: "закрыт только рабочий порт — блок порта/протокола, смена IP не поможет",
    FINGERPRINT_BLOCKED: "TCP открывается, но сессия рвётся — фингерпринт-блок, смена IP не поможет",
    UNKNOWN: "неопределённо — адрес сервера неизвестен или пробы не дали картины",
}

# Вердикты, которые лечатся сменой адреса.
ROTATABLE = {IP_BLOCKED}


def tcp_open(host: str, port: int, timeout: float) -> bool:
    if not host or not port:
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _run(cmd: str, timeout: int) -> bool | None:
    """Внешняя проба уровня 2. None — проба не настроена."""
    if not cmd.strip():
        return None
    try:
        completed = subprocess.run(
            shlex.split(cmd),
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("проба %r не отработала: %s", cmd, exc)
        return False
    if completed.returncode != 0:
        logger.debug("проба %r → код %s", cmd, completed.returncode)
    return completed.returncode == 0


@dataclass
class ProbeResult:
    ts: int = field(default_factory=lambda: int(time.time()))
    ip: str = ""
    sanity: bool = False
    work_port: bool = False
    control_port: bool | None = None      # None — контрольный порт отключён в конфиге
    udp_port: bool | None = None
    server_state: str = ""
    reality: bool | None = None
    awg: bool | None = None
    verdict: str = UNKNOWN
    confident: bool = True

    def as_dict(self) -> dict:
        return asdict(self)

    def short(self) -> str:
        if not self.ip:
            return "адрес сервера неизвестен — пробы не запускались"

        def mark(value: bool | None) -> str:
            return "✅" if value is True else "❌" if value is False else "➖"

        parts = [
            f"канал {mark(self.sanity)}",
            f"рабочий порт {mark(self.work_port)}",
            f"контрольный {mark(self.control_port)}",
            f"сервер {self.server_state or '?'}",
        ]
        if self.reality is not None:
            parts.append(f"reality {mark(self.reality)}")
        if self.awg is not None:
            parts.append(f"awg {mark(self.awg)}")
        return " · ".join(parts)


class Prober:
    def __init__(self, cfg, server_state_fn):
        self.cfg = cfg
        self.server_state_fn = server_state_fn

    def run(self, ip: str) -> ProbeResult:
        det = self.cfg["detector"]
        vpn = self.cfg["vpn"]
        timeout = float(det["tcp_timeout_sec"])
        result = ProbeResult(ip=ip)

        if not ip:
            # Проверять нечего: адрес сервера ещё неизвестен. Это не блокировка.
            result.verdict, result.confident = UNKNOWN, False
            return result

        # S — жив ли собственный канал агента.
        for target in det["sanity_targets"]:
            host, _, port = target.rpartition(":")
            if tcp_open(host, int(port or 443), timeout):
                result.sanity = True
                break
        if not result.sanity:
            result.verdict = OWN_NET_DOWN
            return result

        # C — что говорит о сервере сам UpCloud.
        try:
            result.server_state = self.server_state_fn()
        except Exception as exc:                       # noqa: BLE001 — любая ошибка API не должна ронять цикл
            logger.warning("не удалось получить состояние сервера: %s", exc)
            result.server_state = ""

        # A и B — рабочий и контрольный порты.
        result.work_port = tcp_open(ip, int(vpn["probe_port"]), timeout)
        control_port = int(vpn["control_port"])
        result.control_port = tcp_open(ip, control_port, timeout) if control_port else None
        udp_port = int(vpn.get("udp_port") or 0)
        if udp_port:
            result.udp_port = None                     # UDP без обфускации не проверить, см. уровень 2

        # Уровень 2 — настоящая сессия. Запускается, только если TCP вообще открыт.
        if det["deep_probe"] and result.work_port:
            deep_timeout = int(det["deep_probe_timeout_sec"])
            result.reality = _run(det["reality_probe_cmd"], deep_timeout)
            result.awg = _run(det["awg_probe_cmd"], deep_timeout)

        result.verdict, result.confident = self._verdict(result)
        return result

    @staticmethod
    def _verdict(r: ProbeResult) -> tuple[str, bool]:
        if not r.sanity:
            return OWN_NET_DOWN, True
        if not r.ip:
            return UNKNOWN, False
        if r.server_state and r.server_state != "started":
            return SERVER_DOWN, True
        if r.work_port:
            # Порт открыт, но реальная сессия не поднимается — это фингерпринт.
            if r.reality is False or r.awg is False:
                return FINGERPRINT_BLOCKED, True
            return OK, True
        if r.control_port is True:
            return PORT_BLOCKED, True
        if r.control_port is False:
            if not r.server_state:
                # API молчит — отличить блокировку от лежащего сервера нечем.
                return IP_BLOCKED, False
            return IP_BLOCKED, True
        # Контрольный порт отключён: причину сузить не удалось.
        return IP_BLOCKED, False
