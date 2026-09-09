"""Сценарии мастера /setup: ровно то, что пользователь делает пальцами в чате."""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

TMP = Path(tempfile.mkdtemp(prefix="rotator-bot-"))
os.environ["ROTATOR_CONFIG"] = str(TMP / "config.toml")
os.environ["ROTATOR_SECRETS"] = str(TMP / "secrets.env")
os.environ["ROTATOR_STATE"] = str(TMP / "state.json")

from rotator import log                                       # noqa: E402
from rotator.bot import Bot                                   # noqa: E402
from rotator.clouddns import Cloudflare                       # noqa: E402
from rotator.config import Config, Secrets                    # noqa: E402
from rotator.engine import Engine                             # noqa: E402
from rotator.state import State                               # noqa: E402
from rotator.upcloud import UpCloud                           # noqa: E402
from tests.fake_api import FakeCloud                          # noqa: E402
from tests.fake_telegram import FakeTelegram                  # noqa: E402

log.setup("CRITICAL")

# Правдоподобные значения: валидатор отсекает короткие заглушки, и это правильно.
GOOD_UC = "ucat_" + "a1b2c3d4e5" * 4
GOOD_CF = "cfTOKEN" + "x9y8z7w6v5" * 4

CONFIG = """
[vpn]
domain = "vpn.example.com"

[detector]
enabled = false

[telegram]
poll_timeout_sec = 0
"""


class BotHarness:
    def __init__(self):
        # Пути выставляем на каждом создании: тестовые модули импортируются
        # вместе и иначе делят один файл состояния.
        os.environ["ROTATOR_CONFIG"] = str(TMP / "config.toml")
        os.environ["ROTATOR_SECRETS"] = str(TMP / "secrets.env")
        os.environ["ROTATOR_STATE"] = str(TMP / "state.json")
        for name in ("config.toml", "secrets.env", "state.json"):
            Path(TMP / name).unlink(missing_ok=True)
        Path(TMP / "config.toml").write_text(CONFIG)

        self.cloud = FakeCloud()
        self.tg = FakeTelegram(admin_id="42")
        self.cloud.telegram = self.tg
        self.server_uuid, self.storage_uuid, self.ip = self.cloud.seed()

        self.cfg = Config()
        self.secrets = Secrets()
        for key, value in {
            "RELAY_URLS": "https://relay.test",
            "RELAY_KEY": "k",
            "TG_BOT_TOKEN": "1:x",
            "TG_ADMIN_ID": "42",
        }.items():
            self.secrets.set(key, value)

        self.state = State()
        # Провайдеры, а не строки — ровно как в боевом __main__.build():
        # /setup меняет токены на лету, и клиенты обязаны их подхватывать.
        self.engine = Engine(
            self.cfg, self.secrets, self.state,
            UpCloud(
                self.cloud,
                lambda: self.secrets.get("UPCLOUD_TOKEN"),
                lambda: self.secrets.get("UPCLOUD_ADMIN_TOKEN"),
            ),
            Cloudflare(self.cloud, lambda: self.secrets.get("CF_TOKEN")),
            lambda t: None,
        )
        self.bot = Bot(self.cloud, self.secrets, self.engine, self.cfg)
        self.engine.notify = self.bot.send

    def pump(self) -> None:
        """Один оборот цикла: разобрать всё, что положено в очередь."""
        stop = threading.Event()
        updates = self.bot.api("getUpdates", {"offset": self.bot.offset}) or []
        for update in updates:
            self.bot.offset = update["update_id"] + 1
            self.bot.handle(update)
        stop.set()



class SetupWizardTest(unittest.TestCase):
    def setUp(self):
        self.h = BotHarness()

    def test_доска_показывает_прогресс_и_кнопку_дальше(self):
        self.h.tg.user_says("/setup")
        self.h.pump()
        self.assertIn("0 из 4", self.h.tg.last_text())
        self.assertIn("wiz:next", [d for _, d in self.h.tg.buttons()])

    def test_дальше_ведёт_к_первому_незакрытому_шагу(self):
        self.h.tg.user_says("/setup")
        self.h.pump()
        self.h.tg.user_taps("wiz:next")
        self.h.pump()
        self.assertEqual(self.h.bot.awaiting, "UPCLOUD_TOKEN")
        self.assertIn("ucat_", self.h.tg.last_text(), "подсказка не объясняет, что именно прислать")

    def test_присланный_токен_сохраняется_и_мастер_идёт_дальше(self):
        """Ровно тот шаг, на котором у пользователя «ничего не происходило»."""
        self.h.tg.user_says("/setup")
        self.h.pump()
        self.h.tg.user_taps("wiz:next")
        self.h.pump()

        before = len(self.h.tg.sent)
        self.h.tg.user_says(GOOD_UC)
        self.h.pump()

        self.assertEqual(self.h.secrets.get("UPCLOUD_TOKEN"), GOOD_UC)
        self.assertGreater(len(self.h.tg.sent), before, "бот промолчал")
        # И сразу предложил выбрать сервер — это следующий шаг.
        self.assertIn("pick:server:0", [d for _, d in self.h.tg.buttons()])

    def test_сервер_выбирается_кнопкой_без_ввода_uuid(self):
        self.h.secrets.set("UPCLOUD_TOKEN", GOOD_UC)
        self.h.tg.user_says("/setup")
        self.h.pump()
        self.h.tg.user_taps("wiz:next")
        self.h.pump()
        self.assertIn("pick:server:0", [d for _, d in self.h.tg.buttons()])

        self.h.tg.user_taps("pick:server:0")
        self.h.pump()
        self.assertEqual(self.h.secrets.get("SERVER_UUID"), self.h.server_uuid,
                         "UUID не подставился из списка")
        self.assertEqual(self.h.bot.awaiting, "CF_TOKEN", "мастер не перешёл к токену Cloudflare")

    def test_зона_и_запись_выбираются_кнопками_а_домен_подставляется(self):
        for key, value in (("UPCLOUD_TOKEN", GOOD_UC), ("SERVER_UUID", self.h.server_uuid),
                           ("CF_TOKEN", GOOD_CF)):
            self.h.secrets.set(key, value)
        self.h.tg.user_says("/setup")
        self.h.pump()
        self.h.tg.user_taps("wiz:next")
        self.h.pump()
        self.assertIn("pick:zone:0", [d for _, d in self.h.tg.buttons()])

        self.h.tg.user_taps("pick:zone:0")
        self.h.pump()
        self.assertEqual(self.h.secrets.get("CF_ZONE_ID"), "zone1")
        self.assertIn("pick:rec:0", [d for _, d in self.h.tg.buttons()], "не предложил выбрать запись")

        self.h.tg.user_taps("pick:rec:0")
        self.h.pump()
        self.assertEqual(self.h.secrets.get("CF_A_RECORD_ID"), "rec-a")
        self.assertEqual(self.h.secrets.get("VPN_DOMAIN"), "vpn.example.com",
                         "домен не подставился из выбранной записи")
        self.assertEqual(self.h.secrets.get("CF_AAAA_RECORD_ID"), "rec-aaaa",
                         "AAAA не подобралась автоматически")

    def test_полный_проход_мастера_ничего_не_печатая_кроме_токенов(self):
        self.h.tg.user_says("/setup")
        self.h.pump()
        self.h.tg.user_taps("wiz:next")
        self.h.pump()
        self.h.tg.user_says(GOOD_UC)               # печатаем токен
        self.h.pump()
        self.h.tg.user_taps("pick:server:0")       # дальше только кнопки
        self.h.pump()
        self.h.tg.user_says(GOOD_CF)               # печатаем второй токен
        self.h.pump()
        self.h.tg.user_taps("pick:zone:0")
        self.h.pump()
        self.h.tg.user_taps("pick:rec:0")
        self.h.pump()

        for key, _ in __import__("rotator.bot", fromlist=["REQUIRED_STEPS"]).REQUIRED_STEPS:
            self.assertTrue(self.h.secrets.get(key), f"{key} не заполнен")
        self.assertIn("🎉", self.h.tg.all_visible(), "мастер не сообщил о завершении")

    def test_токен_подхватывается_без_перезапуска(self):
        """Клиенты обязаны читать токен заново — иначе /setup не даёт эффекта."""
        self.h.secrets.set("UPCLOUD_TOKEN", GOOD_UC)
        self.assertEqual(self.h.engine.uc.token, GOOD_UC)
        self.h.secrets.set("CF_TOKEN", GOOD_CF)
        self.assertEqual(self.h.engine.cf.token, GOOD_CF)

    def test_мастер_переживает_перезапуск(self):
        self.h.tg.user_says("/setup")
        self.h.pump()
        self.h.tg.user_taps("wiz:next")
        self.h.pump()
        self.assertEqual(self.h.bot.awaiting, "UPCLOUD_TOKEN")

        # Новый экземпляр бота поверх того же state — как после systemctl restart.
        from rotator.bot import Bot
        from rotator.state import State
        self.h.engine.state = State()
        fresh = Bot(self.h.cloud, self.h.secrets, self.h.engine, self.h.cfg)
        self.assertEqual(fresh.awaiting, "UPCLOUD_TOKEN", "мастер забыл, чего ждал")

    def test_сообщение_с_токеном_удаляется(self):
        self.h.tg.user_says("/setup")
        self.h.pump()
        self.h.tg.user_taps("wiz:next")
        self.h.pump()
        self.h.tg.user_says(GOOD_UC)
        self.h.pump()
        self.assertTrue(self.h.tg.deleted, "сообщение с токеном не удалено")
        self.assertNotIn(GOOD_UC, self.h.tg.all_visible(), "секрет утёк в ответ")

    def test_справка_открывается_и_влезает_в_лимит(self):
        from rotator import guide
        for page in guide.PAGES:
            self.h.tg.sent.clear()
            self.h.tg.user_says(f"/guide_{page}")
            self.h.pump()
            self.assertTrue(self.h.tg.sent, f"страница {page} не пришла")
            self.assertLessEqual(len(self.h.tg.last_text()), 4000, f"страница {page} длиннее лимита")

    def test_ротация_до_настройки_отправляет_в_мастер(self):
        self.h.tg.user_says("/rotate")
        self.h.pump()
        self.assertIn("Сначала настройка", self.h.tg.last_visible())
        self.assertIn("wiz:board", [d for _, d in self.h.tg.buttons()])

    def test_короткий_мусор_вместо_токена_отвергается(self):
        """Реальный случай: в бота прилетело 6 символов вместо токена."""
        self.h.tg.user_says("/setup")
        self.h.pump()
        self.h.tg.user_taps("wiz:next")
        self.h.pump()

        self.h.tg.user_says("ucat_")           # обрезанное значение из панели
        self.h.pump()

        self.assertEqual(self.h.secrets.get("UPCLOUD_TOKEN"), "", "мусор попал в секреты")
        answer = self.h.tg.last_visible()
        self.assertIn("Не принял", answer, "бот промолчал вместо объяснения")
        self.assertIn("5 симв", answer, "не показал, что именно получил")
        self.assertIn("ucat_", answer, "не объяснил, как выглядит правильный токен")
        self.assertEqual(self.h.bot.awaiting, "UPCLOUD_TOKEN",
                         "после отказа надо остаться на том же шаге, а не терять его")

    def test_расписка_приходит_раньше_любых_проверок(self):
        """Молчания быть не должно: что бы ни случилось дальше, «принял» уже ушло."""
        self.h.tg.user_says("/setup")
        self.h.pump()
        self.h.tg.user_taps("wiz:next")
        self.h.pump()
        self.h.tg.sent.clear()
        self.h.tg.timeline.clear()

        self.h.tg.user_says("что угодно")
        self.h.pump()
        self.assertTrue(self.h.tg.timeline, "бот не ответил вообще ничего")
        self.assertIn("Принял", self.h.tg.timeline[0], "расписка не пришла первой")

    def test_после_отказа_можно_просто_прислать_заново(self):
        self.h.tg.user_says("/setup")
        self.h.pump()
        self.h.tg.user_taps("wiz:next")
        self.h.pump()
        self.h.tg.user_says("ucat_")
        self.h.pump()
        self.h.tg.user_says(GOOD_UC)
        self.h.pump()
        self.assertEqual(self.h.secrets.get("UPCLOUD_TOKEN"), GOOD_UC)

    def test_мусор_с_коротким_значением_тоже_удаляется_из_чата(self):
        """Отвергнутый токен всё равно секрет — он не должен остаться в переписке."""
        self.h.tg.user_says("/setup")
        self.h.pump()
        self.h.tg.user_taps("wiz:next")
        self.h.pump()
        self.h.tg.user_says("ucat_")
        self.h.pump()
        self.assertTrue(self.h.tg.deleted, "отвергнутое значение осталось в чате")

    def test_кривой_uuid_и_кривой_ключ_отвергаются(self):
        from rotator.bot import VALIDATORS
        self.assertTrue(VALIDATORS["SERVER_UUID"]("не-uuid"))
        self.assertFalse(VALIDATORS["SERVER_UUID"]("0074bb45-dabe-4e06-9a32-55edb9b2af16"))
        self.assertTrue(VALIDATORS["SSH_PUBKEY"]("просто текст"))
        self.assertFalse(VALIDATORS["SSH_PUBKEY"]("ssh-ed25519 AAAAC3Nza"))
        self.assertTrue(VALIDATORS["CF_ZONE_ID"]("коротко"))
        self.assertFalse(VALIDATORS["CF_ZONE_ID"]("f5bbcd30d3f695cbd828c8446efb4487"))

    def test_чужой_чат_игнорируется(self):
        self.h.tg.user_says("/setup", chat_id="999")
        self.h.pump()
        self.assertEqual(self.h.tg.sent, [], "бот ответил постороннему чату")


if __name__ == "__main__":
    unittest.main(verbosity=2)
