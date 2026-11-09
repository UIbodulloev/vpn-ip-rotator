"""Админка: вход по TOTP, защита, статистика, страницы и действия по HTTP."""
from __future__ import annotations

import base64
import http.client
import http.server
import re
import tempfile
import threading
import time
import unittest
import urllib.parse
from pathlib import Path
from types import SimpleNamespace

from rotator import admin, admin_pages as pages, remote
from rotator.admin_ops import Ops
from rotator.bot import Bot
from rotator.stats import Stats, delta

RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()


class TotpTest(unittest.TestCase):
    def test_rfc6238_vector(self):
        # RFC 6238, приложение B: T=59 → 94287082 (8 цифр).
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
        self.assertFalse(ok)
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
        self.assertTrue(self.auth.check_code(self.code(), "7.7.7.7", self.now)[0])

    def test_global_lockout(self):
        for i in range(20):
            self.auth.check_code("000000", f"10.0.{i // 4}.{i}", self.now)
        ok, _ = self.auth.check_code(self.code(), "8.8.8.8", self.now)
        self.assertFalse(ok)
        self.assertIn("для всех", self.notes[-1])

    def test_sessions_carry_csrf(self):
        token = self.auth.open_session()
        self.assertTrue(self.auth.valid(token))
        self.assertGreater(len(self.auth.session(token)["csrf"]), 20)
        self.assertFalse(self.auth.valid("nope"))
        self.auth.close(token)
        self.assertFalse(self.auth.valid(token))

    def test_no_secret_means_no_entry(self):
        auth = admin.Auth(lambda: "", self.notes.append)
        self.assertIn("/admin", auth.check_code("123456", "1.1.1.1")[1])


def snapshot(ts, vless_rx, hy2_rx, awg_rx):
    return {"ts": ts, "host": "vpn-test",
            "vless": {"anna": {"rx": vless_rx, "tx": 10, "enabled": True, "last_seen": ts}},
            "hy2": {"anna": {"rx": hy2_rx, "tx": 0, "online": 1}},
            "awg": [{"server": "amnezia-awg2", "name": "Irina (phone)", "id": "abc", "rx": awg_rx, "tx": 0,
                     "handshake": ts},
                    {"server": "awg31", "name": "keenetic-home", "id": "def", "rx": awg_rx, "tx": 0,
                     "handshake": ts - 7200}],
            "guard": {"online": {"anna": {"10.1.1.0/24": "10.1.1.5"}}, "blocks": []},
            "system": {"mem_avail": 300, "mem_total": 843, "swap_used": 300, "disk_pct": 87,
                       "load": [0.3, 0.3, 0.3], "uptime": 1000, "watchdog": {"xray": "отвечает", "списки": "свежие"}},
            "events": [{"t": ts, "kind": "restarted", "text": "служба sub-mirror упала — перезапущено",
                        "source": "здоровье"},
                       {"t": ts, "kind": "blocked", "user": "anna", "others": ["20.2.2.7"], "minutes": 30,
                        "source": "устройства"}]}


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
        self.stats.ingest(snapshot(now - 7200, 1000, 0, 0), "1.1.1.1")
        self.stats.ingest(snapshot(now - 3600, 3000, 500, 100), "1.1.1.1")
        self.stats.ingest(snapshot(now, 4000, 200, 300), "2.2.2.2")       # ротация + сброс Hysteria2
        servers = self.stats.by_server()
        self.assertEqual(servers["1.1.1.1"]["vless"], 2000)
        self.assertEqual(servers["1.1.1.1"]["hy2"], 500)
        self.assertEqual(servers["2.2.2.2"]["hy2"], 200)
        clients = {(c["proto"], c["client"]): c for c in self.stats.clients()}
        self.assertEqual(clients[("vless", "anna")]["all"], 3000)
        self.assertEqual(self.stats.client_total([("vless", "anna"), ("hy2", "anna")])["vless"], 3000)
        self.assertEqual(sum(v.get("vless", 0) for _, v in self.stats.daily(2, [("vless", "anna")])), 3000)

    def test_hy2_direction_migrates_once(self):
        now = int(time.time())
        self.stats.ingest(snapshot(now - 3600, 0, 0, 0), "1.1.1.1")
        self.stats.ingest(snapshot(now, 0, 500, 0), "1.1.1.1")        # hy2 rx=500, tx=0
        with self.stats.db() as db:                                   # как будто база старая
            db.execute("delete from meta where k='hy2_client_side'")
        again = Stats(self.stats.path)
        self.assertEqual(again.client_total([("hy2", "anna")])["tx"], 500)
        again2 = Stats(self.stats.path)                               # второй раз не разворачивает
        self.assertEqual(again2.client_total([("hy2", "anna")])["tx"], 500)
        fresh = Stats(Path(self.tmp.name) / "fresh.db")
        with fresh.db() as db:
            self.assertTrue(db.execute("select 1 from meta where k='hy2_client_side'").fetchone())

    def test_rotation_periods(self):
        hist = [{"ts": 300, "from": "2.2.2.2", "to": "3.3.3.3", "zone": "de", "reason": "manual"},
                {"ts": 100, "from": "1.1.1.1", "to": "2.2.2.2", "zone": "fi", "reason": "auto:ip-blocked"}]
        p = admin.rotation_periods(hist, "3.3.3.3", 1000)
        self.assertEqual([x["ip"] for x in p], ["3.3.3.3", "2.2.2.2", "1.1.1.1"])
        self.assertEqual(p[0]["lived"], 700)
        self.assertEqual(p[1]["lived"], 200)
        self.assertIsNone(p[2]["start"])
        self.assertIn("заблокирован", p[2]["why"])


# --- Поддельный бот: всё, к чему админка обращается -----------------------------

class FakeState(dict):
    def clear_pending(self):
        self["pending"] = None


class FakeBot:
    SERVER_ACTIONS = Bot.SERVER_ACTIONS
    AWG_DIR = "/opt/awg31"

    def __init__(self):
        now = int(time.time())
        self.sent: list[str] = []
        self.commands: list[str] = []
        self.cfg = SimpleNamespace(get=lambda k, d=None: {"detector.interval_sec": 60, "detector.fail_threshold": 5,
                                                          "rotation.max_per_day": 6}.get(k, d))
        self.secrets = SimpleNamespace(get=lambda k, d="": {"SUB_BASE_URL": "https://sub.test:8443"}.get(k, d))
        state = FakeState(history=[{"ts": now - 86400, "from": "2.2.2.2", "to": "3.3.3.3", "zone": "de-fra1",
                                    "mode": "clone", "reason": "manual"}],
                          ipv4="3.3.3.3", zone="de-fra1", paused=False, mode="", pending=None,
                          backups=[{"uuid": "11111111-2222-3333-4444-555555555555", "zone": "de-fra1",
                                    "created": now, "size": 10}], templates=[])
        self.engine = SimpleNamespace(
            state=state,
            refresh=lambda: {"hostname": "vpn", "state": "started", "ipv4": "3.3.3.3", "zone": "de-fra1",
                             "plan": "1xCPU-1GB", "storage_size": 10, "storage_tier": "standard"},
            uc=SimpleNamespace(zones=lambda: [{"id": "de-fra1", "description": "Frankfurt", "public": "yes"}]),
            probe=lambda: SimpleNamespace(short=lambda: "всё доступно"))

    def send(self, text, *a, **k):
        self.sent.append(text)
        return 1

    def _panel(self, args, timeout=60):
        self.commands.append("panel " + args)
        if args == "list":
            return remote.Result(0, "anna\t8c360150-56d5-4f24-bb69-b3660c65fbe9\t1.0МБ\tвкл\n", "")
        if args.startswith("add "):
            return remote.Result(0, "vless://9c44f58c-f56d-47f4-9008-e7528e802af3@vpn:443?x#oleg\n", "")
        if args.startswith("link "):
            return remote.Result(0, "vless://8c360150-56d5-4f24-bb69-b3660c65fbe9@vpn:443?x#anna\n", "")
        return remote.Result(0, "ok", "")

    def _awg(self, command, timeout=90):
        self.commands.append(command)
        if command.startswith("ls /opt/awg31"):
            return remote.Result(0, "keenetic-home.conf\n", "")
        return remote.Result(0, "{}", "")

    def _awg_conf(self, name):
        return "[Interface]\nPrivateKey = x\n", ""

    def _awg_conf_new(self, name, mode):
        return self._awg_conf(name)

    def send_bundle(self, *a):
        self.sent.append("bundle")


class PagesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.stats = Stats(Path(self.tmp.name) / "stats.db")
        now = int(time.time())
        self.stats.ingest(snapshot(now - 600, 0, 0, 0), "3.3.3.3")
        self.stats.ingest(snapshot(now, 5 * 2**20, 2**20, 2**20), "3.3.3.3")
        self.bot = FakeBot()
        self.ops = Ops(self.bot, self.stats)

    def tearDown(self):
        self.tmp.cleanup()

    def ctx(self, **q):
        return pages.Ctx(bot=self.bot, stats=self.stats, ops=self.ops, csrf="tok", q=q)

    def test_every_page_renders(self):
        cases = [
            (pages.overview, {}, ["3.3.3.3", "anna", "Выдать ключ", "<svg"]),
            (pages.overview, {"d": "7"}, ["7 дн"]),
            (pages.people_page, {}, ["anna", "Irina (phone)", "keenetic-home"]),
            (pages.people_page, {"f": "online", "q": "ann"}, ["anna"]),
            (pages.person_page, {"k": "key", "n": "anna"}, ["https://sub.test:8443/sub/8c360150", "Удалить ключ"]),
            (pages.person_page, {"k": "awg", "n": "keenetic-home", "s": "awg31"}, ["Скачать .conf", "Отозвать"]),
            (pages.person_page, {"k": "awg", "n": "Irina (phone)", "s": "amnezia-awg2"}, ["приложения Amnezia"]),
            (pages.new_person, {}, ["key.issue", "Только AmneziaWG"]),
            (pages.addresses, {}, ["2.2.2.2", "Сменить адрес", "Frankfurt"]),
            (pages.server_page, {}, ["Перезагрузить", "Восстановить", "Удалить сервер"]),
            (pages.health, {}, ["sub-mirror", "Проверки сторожа здоровья"]),
            (pages.jobs_page, {}, ["Задачи"]),
        ]
        for fn, q, needles in cases:
            title, active, body = fn(self.ctx(**q))
            for n in needles:
                self.assertIn(n, body, f"{fn.__name__}{q}: нет «{n}»")
            self.assertNotIn("<script", body)

    def test_unknown_person(self):
        _, _, body = pages.person_page(self.ctx(k="key", n="nobody"))
        self.assertIn("Не найдено", body)


class HttpTest(unittest.TestCase):
    """Сквозь настоящий HTTP: вход, CSRF, подтверждение, выдача, скачивание."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.stats = Stats(Path(self.tmp.name) / "stats.db")
        self.stats.ingest(snapshot(int(time.time()), 0, 0, 0), "3.3.3.3")
        self.bot = FakeBot()
        self.notes: list[str] = []
        self.auth = admin.Auth(lambda: RFC_SECRET, self.notes.append)
        self.ops = Ops(self.bot, self.stats)
        self.ops.audit = lambda text: self.notes.append(text)
        self.server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), admin.make_handler(self.bot, self.stats, self.auth, self.ops))
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.cookie = ""

    def tearDown(self):
        self.server.shutdown()
        self.tmp.cleanup()

    def req(self, method, path, form=None, referer=""):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=10)
        body = urllib.parse.urlencode(form or {}) if form is not None else None
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if self.cookie:
            headers["Cookie"] = self.cookie
        if referer:
            headers["Referer"] = referer
        conn.request(method, path, body, headers)
        r = conn.getresponse()
        data = r.read().decode()
        cookie = r.getheader("Set-Cookie")
        if cookie and cookie.startswith("adm="):
            self.cookie = cookie.split(";")[0]
        return r.status, r.getheader("Location") or "", data

    def login(self):
        code = admin.totp(RFC_SECRET, int(time.time() // 30))
        status, where, _ = self.req("POST", "/login", {"code": code})
        self.assertEqual((status, where), (303, "/"))
        _, _, page = self.req("GET", "/")
        return re.search(r'name="csrf" value="([^"]+)"', page).group(1)

    def test_pages_require_login(self):
        self.assertEqual(self.req("GET", "/people")[:2], (303, "/login"))
        self.assertEqual(self.req("GET", "/login")[0], 200)

    def test_wrong_code(self):
        status, _, page = self.req("POST", "/login", {"code": "000000"})
        self.assertEqual(status, 401)
        self.assertIn("Неверный", page)

    def test_csrf_and_confirmation_for_delete(self):
        csrf = self.login()
        self.assertTrue(any("Вход в админку" in n for n in self.notes))
        # Без токена CSRF — отказ, ничего не удалено.
        self.req("POST", "/do", {"action": "key.delete", "name": "anna", "csrf": "bad"}, "/person?k=key&n=anna")
        self.assertFalse(any(c.startswith("panel del") for c in self.bot.commands))
        # С токеном — сначала переспрос.
        status, _, page = self.req("POST", "/do", {"action": "key.delete", "name": "anna", "csrf": csrf})
        self.assertEqual(status, 200)
        self.assertIn("Подтвердите", page)
        self.assertFalse(any(c.startswith("panel del") for c in self.bot.commands))
        # Подтвердили — удалено.
        status, where, _ = self.req("POST", "/do", {"action": "key.delete", "name": "anna", "csrf": csrf,
                                                    "confirm": "1"})
        self.assertEqual((status, where), (303, "/people"))
        self.assertIn("panel del anna", self.bot.commands)
        self.assertIn("удалён", self.req("GET", "/people")[2])

    def test_issue_key_runs_as_job(self):
        csrf = self.login()
        status, where, _ = self.req("POST", "/do", {"action": "key.issue", "name": "oleg", "kind": "split",
                                                    "tg": "1", "csrf": csrf})
        self.assertEqual(status, 303)
        self.assertTrue(where.startswith("/jobs/"))
        for _ in range(50):
            page = self.req("GET", where)[2]
            if "готово" in page and "Журнал" in page and "sub/9c44f58c" in page:
                break
            time.sleep(0.05)
        self.assertIn("https://sub.test:8443/sub/9c44f58c-f56d-47f4-9008-e7528e802af3", page)
        self.assertIn("Скачать oleg.conf", page)
        self.assertIn("bundle", self.bot.sent)

    def test_bad_name_rejected(self):
        csrf = self.login()
        self.req("POST", "/do", {"action": "key.issue", "name": "bad name;rm", "kind": "sub", "csrf": csrf})
        self.assertFalse(any(c.startswith("panel add") for c in self.bot.commands))

    def test_download_conf(self):
        self.login()
        status, _, body = self.req("GET", "/download/awg?n=keenetic-home")
        self.assertEqual(status, 200)
        self.assertIn("[Interface]", body)
        self.assertEqual(self.req("GET", "/download/awg?n=unknown")[0], 303)

    def test_logout(self):
        csrf = self.login()
        self.req("POST", "/logout", {"csrf": csrf})
        self.assertEqual(self.req("GET", "/")[:2], (303, "/login"))


if __name__ == "__main__":
    unittest.main()
