"""Сторож устройств (panel/device-guard.py): кого считать вторым устройством.

Ошибка здесь стоит дорого в обе стороны: пропустить раздачу ключа — полбеды,
а отрезать человека, который просто вышел из дома и перешёл с Wi-Fi на LTE, —
это поломка VPN на ровном месте. Поэтому проверяем именно эти развилки, без
сети и без ядра: источники данных подменяются.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("device_guard", ROOT / "panel" / "device-guard.py")
guard_mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard_mod)

UUID_A = "aaaaaaaa-0000-4000-8000-000000000001"
UUID_B = "bbbbbbbb-0000-4000-8000-000000000002"


class GuardTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        guard_mod.STATE_DIR = base / "state"
        guard_mod.STATE_FILE = guard_mod.STATE_DIR / "state.json"
        guard_mod.EVENTS_FILE = guard_mod.STATE_DIR / "events.jsonl"
        guard_mod.MIRROR_STATE = base / "mirror.json"
        guard_mod.ENV_FILE = base / "none.env"
        guard_mod.log = lambda text: None

        self.vless: dict[str, dict[str, str]] = {}
        self.blocked_rules: list[tuple[str, str, str]] = []
        guard_mod.live_users = lambda: {UUID_A: "anna", UUID_B: "boris"}
        guard_mod.xray_live_ips = lambda now: {k: dict(v) for k, v in self.vless.items()}
        guard_mod.hy2_live_conns = lambda cfg, now: {}
        guard_mod.xray_block = lambda tag, name, net: self.blocked_rules.append((tag, name, net))
        guard_mod.xray_unblock = lambda tag: None
        guard_mod.xray_rules = lambda: {t for t, _n, _net in self.blocked_rules}

        self.guard = guard_mod.Guard()
        self.guard.refresh_users(force=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def seen(self, name: str, *ips: str) -> None:
        self.vless[name] = {guard_mod.net_of(ip): ip for ip in ips}

    def ticks(self, n: int) -> None:
        for _ in range(n):
            self.guard.tick()

    def events(self) -> list[dict]:
        if not guard_mod.EVENTS_FILE.exists():
            return []
        return [json.loads(l) for l in guard_mod.EVENTS_FILE.read_text().splitlines()]

    def test_network_switch_is_not_a_second_device(self) -> None:
        self.seen("anna", "10.1.1.5")            # дома
        self.ticks(3)
        self.seen("anna", "10.1.1.5", "20.2.2.7")  # пару замеров видны обе сети
        self.ticks(2)
        self.seen("anna", "20.2.2.7")            # дальше только LTE
        self.ticks(6)
        self.assertEqual(self.blocked_rules, [])
        self.assertEqual(self.events(), [])

    def test_two_devices_cut_the_newcomer(self) -> None:
        self.seen("anna", "10.1.1.5")
        self.ticks(2)
        self.seen("anna", "10.1.1.5", "20.2.2.7")
        self.ticks(6)
        self.assertEqual(len(self.blocked_rules), 1)
        _tag, name, net = self.blocked_rules[0]
        self.assertEqual((name, net), ("anna", "20.2.2.0/24"))
        ev = self.events()[-1]
        self.assertEqual(ev["kind"], "blocked")
        self.assertEqual(ev["owner"], ["10.1.1.5"])
        self.assertEqual(ev["others"], ["20.2.2.7"])
        # Хозяин входит в Hysteria2, пришлый — нет.
        self.assertTrue(self.guard.auth("10.1.1.5:5000", UUID_A)[0])
        self.assertFalse(self.guard.auth("20.2.2.99:5000", UUID_A)[0])
        # Чужой ключ из той же сети не страдает.
        self.assertTrue(self.guard.auth("20.2.2.7:5000", UUID_B)[0])

    def test_neighbouring_nat_addresses_are_one_device(self) -> None:
        self.seen("anna", "10.1.1.5", "10.1.1.77")   # один /24 у оператора
        self.ticks(8)
        self.assertEqual(self.blocked_rules, [])

    def test_limit_two_from_mirror_is_respected(self) -> None:
        guard_mod.MIRROR_STATE.write_text(json.dumps({"links": {UUID_A: {"limit": 2}}}))
        self.seen("anna", "10.1.1.5", "20.2.2.7")
        self.ticks(8)
        self.assertEqual(self.blocked_rules, [])
        self.seen("anna", "10.1.1.5", "20.2.2.7", "30.3.3.9")
        self.ticks(6)
        self.assertEqual([net for _t, _n, net in self.blocked_rules], ["30.3.3.0/24"])

    def test_notify_mode_only_reports(self) -> None:
        self.guard.cfg["MODE"] = "notify"
        self.seen("anna", "10.1.1.5")
        self.ticks(1)
        self.seen("anna", "10.1.1.5", "20.2.2.7")
        self.ticks(12)
        self.assertEqual(self.blocked_rules, [])
        kinds = [e["kind"] for e in self.events()]
        self.assertEqual(kinds, ["shared"])        # и не чаще раза в час

    def test_auth_unknown_and_disabled_keys(self) -> None:
        self.assertEqual(self.guard.auth("1.2.3.4:1", UUID_A), (True, "anna"))
        self.assertEqual(self.guard.auth("1.2.3.4:1", "not-a-key"), (False, ""))
        self.assertEqual(self.guard.auth("[2001:db8::1]:443", UUID_B.upper()), (True, "boris"))

    def test_block_expires(self) -> None:
        self.seen("anna", "10.1.1.5")
        self.ticks(1)
        self.seen("anna", "10.1.1.5", "20.2.2.7")
        self.ticks(6)
        self.assertFalse(self.guard.auth("20.2.2.7:1", UUID_A)[0])
        for entry in self.guard.state.blocks.values():
            entry["until"] = 0
        self.seen("anna", "10.1.1.5")
        self.ticks(1)
        self.assertTrue(self.guard.auth("20.2.2.7:1", UUID_A)[0])
        self.assertEqual(self.events()[-1]["kind"], "unblocked")

    def test_time_parsing_go_format(self) -> None:
        a = guard_mod.parse_time("2026-11-09T07:51:12.123456789Z")
        b = guard_mod.parse_time("2026-11-09T10:51:12.123+03:00")
        self.assertAlmostEqual(a, b, places=2)


if __name__ == "__main__":
    unittest.main()
