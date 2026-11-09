"""Telegram: списки людей идут страницами и листаются в том же сообщении.

Раньше выбор ключа показывал первые 20 имён, а остальных было не достать,
и списки в меню вываливались одним сообщением. Здесь проверяется, что любой
человек достижим, листание правит сообщение, а не шлёт новые, и что кнопки
листания нельзя подделать.
"""
from __future__ import annotations

import unittest

from rotator import bot as botmod, remote
from tests.test_bot_setup import TMP, BotHarness

NAMES = [f"user-{i:02d}" for i in range(1, 26)]            # 25 ключей


class TelegramPagesTest(unittest.TestCase):
    def setUp(self):
        self.h = BotHarness()
        self.keys = list(NAMES)
        self.awg = [f"router-{i:02d}" for i in range(1, 14)]   # 13 конфигов

        def fake_run(host, command, **kw):
            if "client.py list" in command:
                return remote.Result(0, "".join(f"{n}\t11111111-2222-3333-4444-{i:012d}\t0Б\tвкл\n"
                                                 for i, n in enumerate(self.keys)), "")
            if "list-clients.sh" in command:
                return remote.Result(0, "".join(f"{n}\t10.9.1.{i}\t0Б\tне подключался\n"
                                                 for i, n in enumerate(self.awg, 2)), "")
            if "sub-mirror.py devices" in command:
                return remote.Result(0, "{}", "")
            return remote.Result(1, "", "нет ответа")

        self.h.secrets.set("SSH_KEY_PATH", str(TMP / "fake-key"))
        (TMP / "fake-key").write_text("x")
        self.h.state.update(ipv4="203.0.113.11")
        original, botmod.remote.run = botmod.remote.run, fake_run
        self.addCleanup(lambda: setattr(botmod.remote, "run", original))

    def tap(self, data: str) -> None:
        self.h.tg.user_taps(data)
        self.h.pump()

    def keyboard(self) -> list[list[dict]]:
        """Клавиатура, которую пользователь видит сейчас — с учётом правок."""
        return self.h.tg.current_keyboard()

    def names_on_screen(self, prefix: str) -> list[str]:
        return [b["callback_data"].split(":", 2)[2] for row in self.keyboard() for b in row
                if b.get("callback_data", "").startswith(prefix)]

    def nav(self) -> list[str]:
        return [b["text"] for row in self.keyboard() for b in row
                if b.get("callback_data", "").startswith("pg:") or b.get("callback_data") == "noop"]

    # --- выбор ключа ---------------------------------------------------------

    def test_каждый_ключ_достижим(self):
        self.tap("vless:del")
        seen = self.names_on_screen("vless:del:")
        self.assertEqual(len(seen), 10, "на странице не 10 имён")
        self.assertIn("1 / 3", self.nav())
        sent_before = len(self.h.tg.sent)
        for page in (1, 2):
            self.tap(f"pg:vp.del:{page}")
            seen += self.names_on_screen("vless:del:")
        self.assertEqual(sorted(seen), NAMES, "не все ключи можно выбрать")
        self.assertEqual(len(self.h.tg.sent), sent_before, "листание прислало новые сообщения вместо правки")

    def test_кнопки_в_два_столбца(self):
        self.tap("vless:sub")
        widths = [len([b for b in row if b["callback_data"].startswith("vless:sub:")]) for row in self.keyboard()]
        self.assertEqual([w for w in widths if w], [2, 2, 2, 2, 2])

    def test_края_листания(self):
        self.tap("vless:link")
        self.assertNotIn("◀️", self.nav(), "на первой странице есть «назад»")
        self.tap("pg:vp.link:2")
        self.assertNotIn("▶️", self.nav(), "на последней странице есть «вперёд»")
        self.assertEqual(len(self.names_on_screen("vless:link:")), 5)
        self.tap("pg:vp.link:99")                    # список стал короче — прижимаемся к краю
        self.assertEqual(len(self.names_on_screen("vless:link:")), 5)
        self.assertIn("3 / 3", self.nav())

    def test_короткий_список_без_листания(self):
        self.keys = NAMES[:7]
        self.tap("vless:unbind")
        self.assertEqual(len(self.names_on_screen("vless:unbind:")), 7)
        self.assertEqual(self.nav(), [])

    def test_все_виды_выбора_листаются(self):
        for action in ("del", "link", "sub", "file", "unbind", "two", "one"):
            self.tap(f"vless:{action}")
            self.tap(f"pg:vp.{action}:2")
            self.assertEqual(self.names_on_screen(f"vless:{action}:"), NAMES[20:], action)

    # --- меню со списком в тексте -----------------------------------------------

    def test_меню_ключей_не_вываливает_всех(self):
        self.tap("vless:menu")
        text = self.h.tg.last_visible()
        self.assertIn("user-01", text)
        self.assertNotIn("user-11", text, "вторая страница попала в первую")
        self.assertIn("Клиенты · 25", text)
        self.assertIn("стр. 1/3", text)
        self.tap("pg:vm:1")
        text = self.h.tg.last_visible()
        self.assertIn("user-11", text)
        self.assertNotIn("user-01", text)

    def test_устройства_листаются(self):
        self.tap("vless:devices")
        self.assertIn("стр. 1/3", self.h.tg.last_visible())
        self.tap("pg:vd:2")
        text = self.h.tg.last_visible()
        self.assertIn("user-25", text)
        self.assertNotIn("user-01", text)

    def test_amneziawg_листается(self):
        self.tap("awg:menu")
        self.assertIn("Выпущенные конфиги · 13", self.h.tg.last_visible())
        self.tap("awg:revoke")
        self.tap("pg:ap.revoke:1")
        self.assertEqual(self.names_on_screen("awg:revoke:"), self.awg[10:])

    # --- подделки и пустые нажатия -----------------------------------------------

    def test_номер_страницы_не_жмёт_ничего(self):
        before = (len(self.h.tg.sent), len(self.h.tg.edited))
        self.tap("noop")
        self.assertEqual((len(self.h.tg.sent), len(self.h.tg.edited)), before)

    def test_подделанные_кнопки_листания_игнорируются(self):
        before = (len(self.h.tg.sent), len(self.h.tg.edited))
        for data in ("pg:vp.rm:1", "pg:vp.del:abc", "pg:xx:1", "pg:vp.del:1;reboot", "pg:"):
            self.tap(data)
        self.assertEqual((len(self.h.tg.sent), len(self.h.tg.edited)), before)


if __name__ == "__main__":
    unittest.main()
