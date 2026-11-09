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
        # Живое состояние сервера: выдача, удаление и отзыв его меняют.
        self.keys = {"anna": "8c360150-56d5-4f24-bb69-b3660c65fbe9"}
        self.awg31 = {"keenetic-home"}
        self.panel_down = False
        self.bindings: dict = {}              # как в /var/lib/sub-mirror/devices.json → links
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
        if self.panel_down:
            raise remote.RemoteError("ssh: connect to host timed out")
        if args == "list":
            return remote.Result(0, "".join(f"{n}\t{u}\t1.0МБ\tвкл\n" for n, u in self.keys.items()), "")
        if args.startswith("add "):
            name = args.split(" ", 1)[1]
            self.keys[name] = "9c44f58c-f56d-47f4-9008-e7528e802af3"
            return remote.Result(0, f"vless://{self.keys[name]}@vpn:443?x#{name}\n", "")
        if args.startswith("del "):
            self.keys.pop(args.split(" ", 1)[1], None)
            return remote.Result(0, "удалён", "")
        if args.startswith("link "):
            name = args.split(" ", 1)[1]
            return remote.Result(0, f"vless://{self.keys.get(name, '')}@vpn:443?x#{name}\n", "")
        return remote.Result(0, "ok", "")

    def _awg(self, command, timeout=90):
        self.commands.append(command)
        if command.startswith("ls /opt/awg31"):
            return remote.Result(0, "".join(f"{n}.conf\n" for n in sorted(self.awg31)), "")
        if "sub-mirror.py devices" in command:
            import json
            return remote.Result(0, json.dumps(self.bindings), "")
        if "sub-mirror.py drop" in command:
            _, _, uuid, device = command.split()[-4:]
            link = self.bindings.get(uuid) or {}
            link["devices"] = [d for d in link.get("devices", []) if d["id"] != device]
            return remote.Result(0, "убрано", "")
        if "revoke-client.sh" in command:
            self.awg31.discard(command.rsplit(" ", 1)[1])
            return remote.Result(0, "отозван", "")
        if "stats-snapshot.py" in command:
            # Как настоящий: Hysteria2 помнит трафик удалённых ключей.
            snap = snapshot(int(time.time()), 0, 0, 0)
            snap["vless"] = {n: {"rx": 0, "tx": 0, "enabled": True, "last_seen": 0} for n in self.keys}
            snap["awg"] = [p for p in snap["awg"] if p["server"] != "awg31" or p["name"] in self.awg31]
            import json
            return remote.Result(0, json.dumps(snap), "")
        return remote.Result(0, "{}", "")

    def _awg_conf(self, name):
        return "[Interface]\nPrivateKey = x\n", ""

    def _awg_conf_new(self, name, mode):
        self.awg31.add(name)
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
        self.assertIn("Ключа больше нет", body)
        _, _, body = pages.person_page(self.ctx(k="awg", n="nobody", s="awg31"))
        self.assertIn("конфиг отозван", body)


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

    # --- то, на чём споткнулись вживую: список обязан совпадать с панелью ---

    def people_names(self) -> str:
        return self.req("GET", "/people")[2]

    def test_deleted_key_disappears_at_once(self):
        """Удалили umed-test — он не должен висеть в списке ни секунды, хотя
        снимок старый, а Hysteria2 всё ещё помнит его трафик."""
        csrf = self.login()
        self.assertIn(">anna<", self.people_names())
        self.req("POST", "/do", {"action": "key.delete", "name": "anna", "csrf": csrf, "confirm": "1"})
        page = self.people_names()
        self.assertNotIn(">anna<", page)
        self.assertIn("Ключи 0", page)
        self.assertIn("Ключа больше нет", self.req("GET", "/person?k=key&n=anna")[2])
        # На обзоре нет ни строки в топе, ни ссылки на профиль; в ленте событий
        # прошлое про anna остаётся — это история, а не список.
        overview = self.req("GET", "/")[2]
        self.assertNotIn("<span>anna</span>", overview)
        self.assertNotIn("n=anna", overview)

    def test_hysteria_ghost_never_shown(self):
        self.stats.ingest({**snapshot(int(time.time()), 0, 0, 0),
                           "hy2": {"ghost": {"rx": 1, "tx": 1, "online": 0}}}, "3.3.3.3")
        self.login()
        self.assertNotIn(">ghost<", self.people_names())
        self.assertNotIn("n=ghost", self.people_names())

    def test_issued_key_visible_before_any_traffic(self):
        csrf = self.login()
        where = self.req("POST", "/do", {"action": "key.issue", "name": "oleg", "kind": "sub", "csrf": csrf})[1]
        for _ in range(50):
            if "готово" in self.req("GET", where)[2]:
                break
            time.sleep(0.05)
        self.assertIn(">oleg<", self.people_names())
        self.assertIn("sub/9c44f58c", self.req("GET", "/person?k=key&n=oleg")[2])

    def test_duplicate_name_refused(self):
        csrf = self.login()
        status, where, _ = self.req("POST", "/do", {"action": "key.issue", "name": "anna", "kind": "sub",
                                                    "csrf": csrf})
        self.assertEqual(where, "/people/new")
        self.assertIn("уже есть", self.req("GET", "/people/new")[2])
        self.assertFalse(any(c.startswith("panel add") for c in self.bot.commands))

    def test_revoked_awg_disappears_at_once(self):
        csrf = self.login()
        self.assertIn("n=keenetic-home", self.people_names())
        self.req("POST", "/do", {"action": "awg.revoke", "name": "keenetic-home", "csrf": csrf, "confirm": "1"})
        page = self.people_names()
        self.assertIn("отозван", page)                                 # плашка об успехе
        self.assertNotIn("n=keenetic-home", page)                      # а строки в списке нет
        self.assertIn("Irina (phone)", page)                           # клиенты Amnezia не задеты

    def test_panel_down_falls_back_to_snapshot(self):
        self.login()
        self.bot.panel_down = True
        self.ops.forget("keys", "awg31")
        page = self.people_names()
        self.assertIn(">anna<", page)                                  # из снимка
        self.assertEqual(self.req("GET", "/")[0], 200)

    # --- каждое действие доходит до нужной команды ---------------------------

    def test_every_quick_action(self):
        csrf = self.login()
        cases = [
            ({"action": "key.unbind", "name": "anna"}, "sub-mirror.py reset 8c360150"),
            ({"action": "key.limit", "name": "anna", "n": "2"}, "sub-mirror.py limit 8c360150-56d5-4f24-bb69-b3660c65fbe9 2"),
            ({"action": "key.limit", "name": "anna", "n": "1"}, "sub-mirror.py limit 8c360150-56d5-4f24-bb69-b3660c65fbe9 1"),
            ({"action": "key.unblock", "name": "anna"}, "device-guard.py unblock anna"),
            ({"action": "key.sync"}, "panel sync"),
        ]
        for form, needle in cases:
            self.bot.commands.clear()
            status, _, _ = self.req("POST", "/do", {**form, "csrf": csrf}, "/person?k=key&n=anna")
            self.assertEqual(status, 303, form)
            self.assertTrue(any(needle in c for c in self.bot.commands), f"{form}: не ушло «{needle}»")

    def test_automation_controls(self):
        csrf = self.login()
        self.req("POST", "/do", {"action": "auto.pause", "on": "1", "csrf": csrf})
        self.assertTrue(self.bot.engine.state["paused"])
        self.req("POST", "/do", {"action": "auto.pause", "on": "0", "csrf": csrf})
        self.assertFalse(self.bot.engine.state["paused"])
        self.req("POST", "/do", {"action": "auto.mode", "mode": "move", "csrf": csrf})
        self.assertEqual(self.bot.engine.state["mode"], "move")
        self.req("POST", "/do", {"action": "auto.mode", "mode": "rm -rf", "csrf": csrf})
        self.assertEqual(self.bot.engine.state["mode"], "move")       # мусор не принят

    def test_dangerous_server_actions_ask_first(self):
        csrf = self.login()
        ran = []
        self.bot._server_action_body = lambda action, arg, say: ran.append((action, arg))
        for action in ("server.delete", "server.stop", "server.reboot", "server.storage-del", "server.backup-del",
                       "server.docker-restart"):
            status, _, page = self.req("POST", "/do", {"action": action, "csrf": csrf})
            self.assertEqual(status, 200, action)
            self.assertIn("Подтвердите", page, action)
        time.sleep(0.1)
        self.assertEqual(ran, [], "опасное действие выполнено без подтверждения")
        # Подтвердили — ушло фоновой задачей.
        status, where, _ = self.req("POST", "/do", {"action": "server.reboot", "csrf": csrf, "confirm": "1"})
        self.assertTrue(where.startswith("/jobs/"))
        for _ in range(40):
            if ran:
                break
            time.sleep(0.05)
        self.assertEqual(ran, [("reboot", "")])

    def test_safe_server_actions_run_without_asking(self):
        csrf = self.login()
        ran = []
        self.bot._server_action_body = lambda action, arg, say: ran.append(action)
        for action in ("server.containers", "server.protocols", "server.start"):
            where = self.req("POST", "/do", {"action": action, "csrf": csrf})[1]
            self.assertTrue(where.startswith("/jobs/"), action)
        for _ in range(40):
            if len(ran) == 3:
                break
            time.sleep(0.05)
        self.assertEqual(sorted(ran), ["containers", "protocols", "start"])

    def test_restore_needs_real_backup_id(self):
        csrf = self.login()
        ran = []
        self.bot._server_action_body = lambda action, arg, say: ran.append(action)
        self.req("POST", "/do", {"action": "server.restore", "arg": "../../etc", "csrf": csrf, "confirm": "1"})
        time.sleep(0.1)
        self.assertEqual(ran, [])

    def test_rotation_asks_then_runs(self):
        csrf = self.login()
        rotated = []
        self.bot.engine.rotate = lambda mode, zone, **kw: rotated.append((mode, zone)) or {
            "old_ip": "3.3.3.3", "new_ip": "4.4.4.4"}
        page = self.req("POST", "/do", {"action": "rotate", "mode": "move", "zone": "de-fra1", "csrf": csrf})[2]
        self.assertIn("Подтвердите", page)
        self.assertEqual(rotated, [])
        where = self.req("POST", "/do", {"action": "rotate", "mode": "move", "zone": "de-fra1", "csrf": csrf,
                                         "confirm": "1"})[1]
        for _ in range(40):
            page = self.req("GET", where)[2]
            if "4.4.4.4" in page:
                break
            time.sleep(0.05)
        self.assertEqual(rotated, [("move", "de-fra1")])
        self.assertIn("3.3.3.3 → 4.4.4.4", page)

    def test_every_action_is_reported(self):
        csrf = self.login()
        self.notes.clear()
        self.req("POST", "/do", {"action": "key.delete", "name": "anna", "csrf": csrf, "confirm": "1"})
        self.req("POST", "/do", {"action": "auto.pause", "on": "1", "csrf": csrf})
        joined = " ".join(self.notes)
        self.assertIn("удалён ключ anna", joined)
        self.assertIn("автоматика на паузе", joined)

    # --- устройства: farah-phone и все, у кого два и больше -------------------

    ANNA = "8c360150-56d5-4f24-bb69-b3660c65fbe9"

    def device(self, ua, kind="soft", ident=None, last_ago=60):
        now = time.time()
        return {"kind": kind, "id": ident or ua, "ua": ua, "first": now - 3600, "last": now - last_ago,
                "hits": 3, "nets": {"a1": now}, "today": 1}

    def test_stuck_browser_binding_is_flagged_and_fixable(self):
        """Ссылка farah-phone привязалась к «mozilla», и sing-box получал отказ."""
        self.bot.bindings = {self.ANNA: {"devices": [self.device("mozilla")], "denied": 3,
                                         "last_denied": time.time() - 300}}
        csrf = self.login()
        page = self.req("GET", "/devices")[2]
        self.assertIn("Требует внимания", page)
        self.assertIn("не приложение", page)
        self.assertIn("отказов 3", page)
        self.assertIn('name="device" value="mozilla"', page)
        self.assertIn("/devices", self.req("GET", "/")[2], "на обзоре нет тревоги")
        self.req("POST", "/do", {"action": "key.drop", "name": "anna", "device": "mozilla", "csrf": csrf},
                 "/devices")
        self.assertIn(f"sub-mirror.py drop {self.ANNA} mozilla", " ".join(self.bot.commands))
        self.assertIn("Устройство убрано", self.req("GET", "/devices")[2])

    def test_two_devices_listed_with_actions(self):
        self.bot.bindings = {self.ANNA: {"limit": 2, "devices": [self.device("sing-box"),
                                                                 self.device("v2raytun", "hwid", "d67fff172e81")]}}
        self.login()
        page = self.req("GET", "/devices")[2]
        self.assertIn("Два и более устройства", page)
        self.assertIn("v2RayTun", page)
        self.assertIn("точно, по отпечатку", page)
        self.assertIn("Разрешить 3", page)
        self.assertIn("2 устр.", self.people_names(), "в списке людей нет пометки о двух устройствах")
        self.assertIn("Устройства", self.req("GET", "/person?k=key&n=anna")[2])

    def test_denied_attempts_section(self):
        self.bot.bindings = {self.ANNA: {"devices": [self.device("sing-box")], "denied": 2,
                                         "last_denied": time.time() - 60}}
        self.login()
        page = self.req("GET", "/devices")[2]
        self.assertIn("Пытались поставить на второе устройство", page)
        self.assertNotIn("Требует внимания: место занял не приложение <span class=\"count\">1", page)
        self.assertIn("отказов 2", self.people_names())

    def test_limit_three_and_bad_device_id(self):
        csrf = self.login()
        self.req("POST", "/do", {"action": "key.limit", "name": "anna", "n": "3", "csrf": csrf})
        self.assertIn(f"sub-mirror.py limit {self.ANNA} 3", " ".join(self.bot.commands))
        self.bot.commands.clear()
        self.req("POST", "/do", {"action": "key.limit", "name": "anna", "n": "9", "csrf": csrf})
        self.assertIn(f"sub-mirror.py limit {self.ANNA} 1", " ".join(self.bot.commands))
        self.bot.commands.clear()
        self.req("POST", "/do", {"action": "key.drop", "name": "anna", "device": "x;reboot", "csrf": csrf})
        self.assertFalse(any("drop" in c for c in self.bot.commands))

    def test_unknown_action(self):
        csrf = self.login()
        self.req("POST", "/do", {"action": "rm", "csrf": csrf}, "/server")
        self.assertIn("Неизвестное действие", self.req("GET", "/server")[2])


class SnapshotTest(unittest.TestCase):
    """panel/stats-snapshot.py: в снимок не попадают «призраки» Hysteria2."""

    def test_deleted_keys_are_filtered_out(self):
        import contextlib
        import importlib.util
        import io
        import json
        spec = importlib.util.spec_from_file_location(
            "stats_snapshot", Path(__file__).resolve().parents[1] / "panel" / "stats-snapshot.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.vless = lambda: {"anna": {"rx": 1, "tx": 1, "enabled": True, "last_seen": 0}}
        mod.hy2 = lambda: {"anna": {"rx": 5, "tx": 5, "online": 1}, "umed-test": {"rx": 9, "tx": 9, "online": 0}}
        for name in ("awg", "events"):
            setattr(mod, name, lambda: [])
        mod.guard = lambda: {}
        mod.system = lambda: {}
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            mod.main()
        snap = json.loads(out.getvalue())
        self.assertEqual(sorted(snap["hy2"]), ["anna"])

    def test_panel_unreadable_keeps_hysteria(self):
        import contextlib
        import importlib.util
        import io
        import json
        spec = importlib.util.spec_from_file_location(
            "stats_snapshot2", Path(__file__).resolve().parents[1] / "panel" / "stats-snapshot.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.vless = lambda: {"_error": "database is locked"}
        mod.hy2 = lambda: {"anna": {"rx": 5, "tx": 5, "online": 1}}
        for name in ("awg", "events"):
            setattr(mod, name, lambda: [])
        mod.guard = lambda: {}
        mod.system = lambda: {}
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            mod.main()
        self.assertEqual(sorted(json.loads(out.getvalue())["hy2"]), ["anna"])


if __name__ == "__main__":
    unittest.main()
