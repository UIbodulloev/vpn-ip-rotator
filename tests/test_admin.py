"""Админка: вход по TOTP, защита от перебора, статистика и страница."""
from __future__ import annotations

import base64
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from rotator import admin
from rotator.stats import Stats, delta

RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()


class TotpTest(unittest.TestCase):
    def test_rfc6238_vector(self):
        # RFC 6238, приложение B: T=59 → 94287082 (8 цифр), 6 цифр — хвост.
        self.assertEqual(admin.totp(RFC_SECRET, 59 // 30, digits=8), "94287082")
        self.assertEqual(admin.totp(RFC_SECRET, 1111111109 // 30, digits=8), "07081804")

    def test_new_secret_is_valid_base32(self):
        s = admin.new_secret()
        self.assertEqual(len(base64.b32decode(s + "=" * (-len(s) % 8))), 20)
        self.assertIn("secret=" + s, admin.otpauth_uri(s))


class AuthTest(unittest.TestCase):
    def setUp(self):
        self.notes: list[str] = []
        self.auth = admin.Auth(lambda: RFC_SECRET, self.notes.append)
        self.now = 1_800_000_000.0

    def code(self, t=None):
        return admin.totp(RFC_SECRET, int((t or self.now) // 30))

    def test_good_code_once_only(self):
        self.assertTrue(self.auth.check_code(self.code(), "1.1.1.1", self.now)[0])
        ok, why = self.auth.check_code(self.code(), "1.1.1.1", self.now)
        self.assertFalse(ok)                                # повтор того же кода
        self.assertIn("использованный", why)

    def test_neighbour_window_accepted(self):
        self.assertTrue(self.auth.check_code(self.code(self.now - 30), "1.1.1.1", self.now)[0])

    def test_ip_lockout_after_five_misses(self):
        for _ in range(5):
            self.assertFalse(self.auth.check_code("000000", "6.6.6.6", self.now)[0])
        ok, why = self.auth.check_code(self.code(), "6.6.6.6", self.now)
        self.assertFalse(ok)
        self.assertIn("с этого адреса", why.lower())
        self.assertTrue(any("6.6.6.6" in n for n in self.notes))
        # Другой адрес не страдает.
        self.assertTrue(self.auth.check_code(self.code(), "7.7.7.7", self.now)[0])

    def test_global_lockout(self):
        for i in range(20):
            self.auth.check_code("000000", f"10.0.{i // 4}.{i}", self.now)
        ok, why = self.auth.check_code(self.code(), "8.8.8.8", self.now)
        self.assertFalse(ok)
        self.assertIn("для всех", self.notes[-1])

    def test_sessions(self):
        token = self.auth.open_session()
        self.assertTrue(self.auth.valid(token))
        self.assertFalse(self.auth.valid("nope"))
        self.auth.close(token)
        self.assertFalse(self.auth.valid(token))

    def test_no_secret_means_no_entry(self):
        auth = admin.Auth(lambda: "", self.notes.append)
        self.assertIn("/admin", auth.check_code("123456", "1.1.1.1")[1])


def snapshot(ts, vless_rx, hy2_rx, awg_rx):
    return {"ts": ts, "vless": {"anna": {"rx": vless_rx, "tx": 10, "enabled": True, "last_seen": ts}},
            "hy2": {"anna": {"rx": hy2_rx, "tx": 0, "online": 1}},
            "awg": [{"server": "amnezia-awg2", "name": "Irina (phone)", "id": "abc", "rx": awg_rx,
                     "tx": 0, "handshake": ts}],
            "guard": {"online": {"anna": {"10.1.1.0/24": "10.1.1.5"}}, "blocks": []},
            "system": {"mem_avail": 300, "mem_total": 843, "swap_used": 300, "disk_pct": 87,
                       "load": [0.3, 0.3, 0.3], "uptime": 1000, "watchdog": {"xray": "отвечает"}},
            "events": [{"t": ts, "kind": "restarted", "text": "служба sub-mirror упала — перезапущено",
                        "source": "здоровье"}]}


class StatsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.stats = Stats(Path(self.tmp.name) / "stats.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_delta_handles_reset(self):
        self.assertEqual(delta(100, 150), 50)
        self.assertEqual(delta(100, 30), 30)

    def test_traffic_goes_to_the_server_address_of_its_time(self):
        now = int(time.time())
        self.stats.ingest(snapshot(now - 7200, 1000, 0, 0), "1.1.1.1")      # точка отсчёта
        self.stats.ingest(snapshot(now - 3600, 3000, 500, 100), "1.1.1.1")
        # Ротация + перезапуск Hysteria2 (счётчик сбросился до 200).
        self.stats.ingest(snapshot(now, 4000, 200, 300), "2.2.2.2")
        servers = self.stats.by_server()
        self.assertEqual(servers["1.1.1.1"]["vless"], 2000)
        self.assertEqual(servers["1.1.1.1"]["hy2"], 500)
        self.assertEqual(servers["2.2.2.2"]["hy2"], 200)
        self.assertEqual(servers["2.2.2.2"]["awg"], 200)
        clients = {(c["proto"], c["client"]): c for c in self.stats.clients()}
        self.assertEqual(clients[("vless", "anna")]["all"], 3000)
        self.assertEqual(clients[("awg", "Irina (phone)")]["all"], 300)
        self.assertEqual(sum(self.stats.by_proto(0).values()), 3000 + 700 + 300)

    def test_rotation_periods(self):
        hist = [{"ts": 300, "from": "2.2.2.2", "to": "3.3.3.3", "zone": "de", "reason": "manual"},
                {"ts": 100, "from": "1.1.1.1", "to": "2.2.2.2", "zone": "fi", "reason": "auto:ip-blocked"}]
        p = admin.rotation_periods(hist, "3.3.3.3", 1000)
        self.assertEqual([x["ip"] for x in p], ["3.3.3.3", "2.2.2.2", "1.1.1.1"])
        self.assertEqual(p[0]["lived"], 700)
        self.assertEqual(p[1]["lived"], 200)
        self.assertIsNone(p[2]["start"])
        self.assertIn("заблокирован", p[2]["why"])

    def test_dashboard_renders(self):
        now = int(time.time())
        self.stats.ingest(snapshot(now - 600, 0, 0, 0), "3.3.3.3")
        self.stats.ingest(snapshot(now, 5 * 2**20, 2**20, 2**20), "3.3.3.3")
        state = {"history": [{"ts": now - 86400, "from": "2.2.2.2", "to": "3.3.3.3", "zone": "de-fra1",
                              "mode": "clone", "reason": "manual"}],
                 "ipv4": "3.3.3.3", "zone": "de-fra1"}
        bot = SimpleNamespace(engine=SimpleNamespace(state=state))
        body = admin.dashboard(bot, self.stats).decode()
        for needle in ("3.3.3.3", "anna", "Irina (phone)", "AmneziaWG", "sub-mirror", "<svg"):
            self.assertIn(needle, body)
        self.assertNotIn("<script", body)


if __name__ == "__main__":
    unittest.main()
