"""Telegram: управление ключами и устройствами — ровно то, что владелец жмёт пальцами.

Выдача, комплект для человека и списки покрыты в test_bot_setup. Здесь —
удаление, отзыв, лимиты и блокировки, /admin, автоматика, подтверждения и
защита от подделанных кнопок: имя из callback_data уходит в команду на
VPN-сервере, и туда не должно попасть ничего, кроме имени.
"""
from __future__ import annotations

import unittest

from rotator import bot as botmod, remote
from tests.test_bot_setup import TMP, BotHarness

UUID = "11111111-2222-3333-4444-555555555555"


class TelegramKeysTest(unittest.TestCase):
    def setUp(self):
        self.h = BotHarness()
        self.calls: list[str] = []
        self.replies = {
            "client.py list": f"oleg\t{UUID}\t1.0МБ\tвкл\n",
            "client.py del": "клиент oleg удалён",
            "revoke-client.sh": "отозван: keenetic-home",
            "sub-mirror.py limit": f"{UUID}: устройств по ссылке — 2",
            "sub-mirror.py reset": "привязка снята",
            "sub-mirror.py devices": "{}",
            "device-guard.py unblock": "oleg: снято блокировок — 1",
        }

        def fake_run(host, command, **kw):
            self.calls.append(command)
            for needle, out in self.replies.items():
                if needle in command:
                    return remote.Result(0, out, "")
            return remote.Result(1, "", "не подготовлен ответ")

        self.h.secrets.set("SSH_KEY_PATH", str(TMP / "fake-key"))
        (TMP / "fake-key").write_text("x")
        self.h.state.update(ipv4="203.0.113.11")
        original, botmod.remote.run = botmod.remote.run, fake_run
        self.addCleanup(lambda: setattr(botmod.remote, "run", original))

    def tap(self, data: str) -> str:
        self.h.tg.user_taps(data)
        self.h.pump()
        return self.h.tg.all_visible()

    def ran(self, needle: str) -> bool:
        return any(needle in c for c in self.calls)

    # --- ключи ---------------------------------------------------------------

    def test_удаление_ключа_через_список(self):
        self.tap("vless:del")
        self.assertIn("vless:del:oleg", [d for _, d in self.h.tg.buttons()], "в списке нет кнопки ключа")
        self.assertFalse(self.ran("client.py del"), "удалено без выбора ключа")
        seen = self.tap("vless:del:oleg")
        self.assertTrue(self.ran("client.py del oleg"), "команда удаления не ушла на сервер")
        self.assertIn("Удалён", seen)

    def test_лимит_устройств_два_и_обратно(self):
        self.tap("vless:two:oleg")
        self.assertTrue(self.ran(f"sub-mirror.py limit {UUID} 2"))
        self.tap("vless:one:oleg")
        self.assertTrue(self.ran(f"sub-mirror.py limit {UUID} 1"))

    def test_лимит_несуществующего_ключа(self):
        seen = self.tap("vless:two:nobody")
        self.assertIn("нет", seen)
        self.assertFalse(self.ran("sub-mirror.py limit"))

    def test_снятие_блокировки_сторожа(self):
        seen = self.tap("guard:unblock:oleg")
        self.assertTrue(self.ran("device-guard.py unblock oleg"))
        self.assertIn("Блокировка снята", seen)

    def test_отзыв_конфига_amneziawg(self):
        seen = self.tap("awg:revoke:keenetic-home")
        self.assertTrue(self.ran("revoke-client.sh keenetic-home"))
        self.assertIn("Отозван", seen)

    # --- подделанные кнопки ----------------------------------------------------

    def test_подделанное_имя_в_кнопке_не_доходит_до_сервера(self):
        for data in ("vless:del:oleg;rm -rf /", "vless:del:$(reboot)", "awg:revoke:a b",
                     "awg:send:../../etc/passwd", "guard:unblock:x`id`", "vless:sub:" + "a" * 40,
                     "vless:go:full:oleg&&halt", "vless:two:oleg|cat"):
            self.calls.clear()
            seen = self.tap(data)
            self.assertEqual(self.calls, [], f"{data!r}: команда ушла на сервер")
            self.assertIn("Недопустимое имя", seen)

    def test_чужой_чат_не_управляет(self):
        self.h.tg.user_taps("vless:del:oleg", chat_id="999")
        self.h.pump()
        self.assertFalse(self.ran("client.py del"))

    # --- /admin ---------------------------------------------------------------

    def test_секрет_админки_показывается_один_раз(self):
        self.h.tg.user_says("/admin")
        self.h.pump()
        first = self.h.tg.last_text()
        secret = self.h.secrets.get("ADMIN_TOTP_SECRET")
        self.assertTrue(secret)
        self.assertIn("otpauth://totp/", first)
        self.assertIn(secret[:4], first.replace(" ", ""))

        self.h.tg.user_says("/admin")
        self.h.pump()
        again = self.h.tg.last_text()
        self.assertNotIn(secret[:8], again.replace(" ", ""), "секрет показан повторно")
        self.assertIn("admin:reset", [d for _, d in self.h.tg.buttons()])

    def test_новый_секрет_только_после_подтверждения(self):
        self.h.tg.user_says("/admin")
        self.h.pump()
        old = self.h.secrets.get("ADMIN_TOTP_SECRET")
        self.tap("admin:reset")
        self.assertEqual(self.h.secrets.get("ADMIN_TOTP_SECRET"), old, "секрет сменён без подтверждения")
        self.assertIn("admin:reset:go", [d for _, d in self.h.tg.buttons()])
        self.tap("admin:reset:go")
        new = self.h.secrets.get("ADMIN_TOTP_SECRET")
        self.assertTrue(new)
        self.assertNotEqual(new, old)

    # --- автоматика и сервер ---------------------------------------------------

    def test_пауза_и_режим_автоматики(self):
        paused = self.h.state["paused"]
        self.tap("auto:toggle")
        self.assertEqual(self.h.state["paused"], not paused)
        self.tap("mode:clone")
        self.assertEqual(self.h.state["mode"], "clone")
        self.tap("mode:auto")
        self.assertEqual(self.h.state["mode"], "")

    def test_удаление_сервера_сначала_переспрашивает(self):
        seen = self.tap("srv:ask:delete")
        self.assertIn("БЕЗВОЗВРАТНО", seen)
        self.assertIn("srv:go:delete", [d for _, d in self.h.tg.buttons()])

    # --- уведомления сторожа ---------------------------------------------------

    def test_уведомление_о_втором_устройстве_с_кнопками(self):
        self.h.bot.guard_notify({"kind": "blocked", "user": "oleg", "limit": 1, "owner": ["10.1.1.5"],
                                 "others": ["20.2.2.7"], "minutes": 30})
        text = self.h.tg.last_text()
        self.assertIn("oleg", text)
        self.assertIn("20.2.2.7", text)
        buttons = [d for _, d in self.h.tg.buttons()]
        self.assertIn("guard:unblock:oleg", buttons)
        self.assertIn("vless:two:oleg", buttons)
        self.assertIn("vless:new", buttons)

    def test_режим_notify_не_предлагает_снять_блокировку(self):
        self.h.bot.guard_notify({"kind": "shared", "user": "oleg", "limit": 1, "owner": ["10.1.1.5"],
                                 "others": ["20.2.2.7"]})
        self.assertNotIn("guard:unblock:oleg", [d for _, d in self.h.tg.buttons()])
        self.assertIn("никого не отрезали", self.h.tg.last_text())


if __name__ == "__main__":
    unittest.main()
