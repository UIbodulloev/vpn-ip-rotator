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

    def test_в_справке_нет_дублирующихся_определений(self):
        """Дубликат NAME = \"\"\"…\"\"\" тихо затирает первый, и правки уходят в мёртвый код."""
        import re
        from pathlib import Path as _P
        src = _P(__file__).resolve().parents[1].joinpath("rotator/guide.py").read_text()
        names = re.findall(r'^([A-Z_]+) = """', src, re.M)
        duplicates = {n for n in names if names.count(n) > 1}
        self.assertEqual(duplicates, set(), f"определены дважды: {duplicates}")

    def test_в_справке_нет_разнобоя_в_названиях(self):
        """Договорились на двух названиях: Storage Template и Backup."""
        from rotator import guide
        banned = ("образ", "снимок", "снимк", "эталон")
        for page, (_heading, body) in guide.PAGES.items():
            lowered = body.lower()
            found = [w for w in banned if w in lowered]
            self.assertEqual(found, [], f"страница {page}: синонимы {found}")

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

    def test_plan_показывает_шаги_и_ничего_не_делает(self):
        for key, value in (("UPCLOUD_TOKEN", GOOD_UC), ("SERVER_UUID", self.h.server_uuid)):
            self.h.secrets.set(key, value)
        before = dict(self.h.cloud.servers[self.h.server_uuid])

        from rotator.modes import MODE_TITLES
        for mode, human in MODE_TITLES.items():
            self.h.tg.timeline.clear()
            self.h.tg.user_says(f"/plan {mode}")
            self.h.pump()
            card = self.h.tg.all_visible()
            self.assertIn(human, card, f"режим {mode} не назван по-человечески")
            self.assertIn("Что произойдёт", card, f"нет шагов для {mode}")
            self.assertIn("Цена вопроса", card, f"нет цены для {mode}")

        self.assertEqual(self.h.cloud.servers[self.h.server_uuid], before,
                         "/plan изменил состояние сервера")

    def test_plan_без_аргумента_предлагает_выбрать_режим(self):
        self.h.tg.user_says("/plan")
        self.h.pump()
        buttons = [d for _, d in self.h.tg.buttons()]
        for mode in ("plan:clone", "plan:move", "plan:floating"):
            self.assertIn(mode, buttons)

    def test_сообщения_размечены_html_и_не_ломаются(self):
        """Значение с угловой скобкой не должно превращать бота в молчуна."""
        self.h.secrets.set("SERVER_UUID", self.h.server_uuid)
        self.h.cloud.servers[self.h.server_uuid]["hostname"] = "сервер <test> & co"
        self.h.tg.user_says("/status")
        self.h.pump()
        self.assertTrue(self.h.tg.timeline, "бот промолчал")

    def test_единое_меню_ведёт_во_все_разделы(self):
        self.h.secrets.set("SERVER_UUID", self.h.server_uuid)
        self.h.tg.user_says("/menu")
        self.h.pump()
        buttons = [d for _, d in self.h.tg.buttons()]
        for target in ("cmd:status", "cmd:rotate", "srv:menu", "cmd:costs",
                       "cmd:settings", "guide:menu"):
            self.assertIn(target, buttons, f"из меню не попасть в {target}")

    def test_настройки_собирают_всё_в_одном_месте(self):
        self.h.secrets.set("UPCLOUD_TOKEN", GOOD_UC)
        self.h.secrets.set("SERVER_UUID", self.h.server_uuid)
        self.h.tg.user_taps("cmd:settings")
        self.h.pump()
        buttons = [d for _, d in self.h.tg.buttons()]
        for target in ("set:auto", "srv:storage", "wiz:board", "wiz:check", "cmd:diag"):
            self.assertIn(target, buttons, f"в настройках нет {target}")

    def test_ни_одна_кнопка_не_ведёт_в_никуда(self):
        """Обход всех экранов: каждая кнопка должна что-то открывать."""
        self.h.secrets.set("UPCLOUD_TOKEN", GOOD_UC)
        self.h.secrets.set("SERVER_UUID", self.h.server_uuid)
        self.h.secrets.set("CF_TOKEN", GOOD_CF)
        self.h.secrets.set("CF_ZONE_ID", "zone1")
        self.h.secrets.set("CF_A_RECORD_ID", "rec-a")

        seen: set[str] = set()
        queue = ["cmd:menu"]
        # Эти кнопки что-то реально меняют — по ним не ходим.
        destructive = ("srv:go:", "go:", "wiz:unstick", "auto:toggle", "policy:",
                       "costs:prune", "addchat:", "ssh:gen", "mode:", "cmd:rotate")
        while queue:
            data = queue.pop()
            if data in seen:
                continue
            seen.add(data)
            self.h.tg.timeline.clear()
            self.h.tg.sent.clear()
            self.h.tg.user_taps(data)
            self.h.pump()
            self.assertTrue(self.h.tg.timeline, f"кнопка {data} ничего не открыла")
            for _text, target in self.h.tg.buttons():
                if target and not target.startswith(destructive):
                    queue.append(target)
        # Для осмысленности обхода: экранов должно быть много, а не три.
        self.assertGreater(len(seen), 12, f"обошли слишком мало экранов: {sorted(seen)}")

    def test_меню_сервера_показывает_состояние_и_действия(self):
        self.h.secrets.set("UPCLOUD_TOKEN", GOOD_UC)
        self.h.secrets.set("SERVER_UUID", self.h.server_uuid)
        self.h.tg.user_says("/server")
        self.h.pump()
        card = self.h.tg.all_visible()
        self.assertIn("Управление сервером", card)
        self.assertIn("amnezia-test", card)
        buttons = [d for _, d in self.h.tg.buttons()]
        for target in ("srv:ask:stop", "srv:ask:reboot", "srv:ask:template",
                       "srv:new", "srv:docker", "srv:ask:delete"):
            self.assertIn(target, buttons, f"нет действия {target}")

    def test_опасные_действия_требуют_подтверждения(self):
        self.h.secrets.set("SERVER_UUID", self.h.server_uuid)
        before = dict(self.h.cloud.servers[self.h.server_uuid])
        for action in ("stop", "reboot", "delete", "template"):
            self.h.tg.timeline.clear()
            self.h.tg.user_taps(f"srv:ask:{action}")
            self.h.pump()
            card = self.h.tg.all_visible()
            self.assertIn(f"srv:go:{action}", [d for _, d in self.h.tg.buttons()],
                          f"{action}: нет кнопки подтверждения")
            self.assertTrue(len(card) > 60, f"{action}: последствия не объяснены")
        self.assertEqual(self.h.cloud.servers[self.h.server_uuid], before,
                         "экран подтверждения что-то изменил")

    def test_удаление_предупреждает_если_нет_шаблона(self):
        self.h.secrets.set("SERVER_UUID", self.h.server_uuid)
        self.h.tg.user_taps("srv:ask:delete")
        self.h.pump()
        self.assertIn("Шаблонов нет", self.h.tg.all_visible())

    def test_ключ_предлагает_три_способа(self):
        self.h.tg.user_taps("set:SSH_KEY_PATH")
        self.h.pump()
        buttons = [d for _, d in self.h.tg.buttons()]
        for target in ("ssh:gen", "ssh:paste", "ssh:path"):
            self.assertIn(target, buttons, f"нет способа {target}")
        self.assertIn("два ключа", self.h.tg.all_visible(),
                      "не объяснено, зачем ключей может быть два")

    def test_генерация_пары_сохраняет_путь_и_публичный_ключ(self):
        self.h.tg.user_taps("ssh:gen")
        self.h.pump()
        path = self.h.secrets.get("SSH_KEY_PATH")
        self.assertTrue(path and Path(path).is_file(), "приватный ключ не создан")
        self.assertEqual(oct(Path(path).stat().st_mode)[-3:], "600", "права не 0600")
        self.assertTrue(self.h.secrets.get("SSH_PUBKEY").startswith("ssh-"),
                        "публичная часть не выведена")
        card = self.h.tg.all_visible()
        self.assertIn("authorized_keys", card, "не показана команда разрешения ключа")

    def test_приватный_ключ_текстом_принимается_и_стирается_из_чата(self):
        from rotator import sshkeys
        source = Path(TMP / "source-key")
        source.unlink(missing_ok=True)
        Path(str(source) + ".pub").unlink(missing_ok=True)
        _, expected_pub = sshkeys.generate(TMP, name="source-key")
        material = source.read_text()

        self.h.tg.user_taps("ssh:paste")
        self.h.pump()
        self.assertEqual(self.h.bot.awaiting, "SSH_PRIVATE_KEY")

        self.h.tg.user_says(material)
        self.h.pump()

        self.assertEqual(self.h.secrets.get("SSH_PUBKEY"), expected_pub,
                         "публичная часть не совпала с исходной парой")
        self.assertTrue(self.h.tg.deleted, "сообщение с приватным ключом не удалено")
        self.assertNotIn("PRIVATE KEY", self.h.tg.all_visible(), "ключ засветился в ответе")

    def test_публичный_ключ_вместо_приватного_отвергается(self):
        self.h.tg.user_taps("ssh:paste")
        self.h.pump()
        self.h.tg.user_says("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 user@host")
        self.h.pump()
        self.assertEqual(self.h.secrets.get("SSH_KEY_PATH"), "", "мусор принят как ключ")
        self.assertIn("не похоже на приватный ключ", self.h.tg.all_visible())
        self.assertEqual(self.h.bot.awaiting, "SSH_PRIVATE_KEY", "шаг потерян после отказа")

    def test_контейнеры_без_ssh_объясняют_чего_не_хватает(self):
        self.h.secrets.set("SERVER_UUID", self.h.server_uuid)
        self.h.tg.user_taps("srv:docker")
        self.h.pump()
        self.assertIn("SSH-ключ не задан", self.h.tg.all_visible())
        self.assertIn("set:SSH_KEY_PATH", [d for _, d in self.h.tg.buttons()])

    def test_поднять_из_шаблона_без_шаблонов(self):
        self.h.secrets.set("SERVER_UUID", self.h.server_uuid)
        self.h.tg.user_taps("srv:new")
        self.h.pump()
        self.assertIn("Шаблонов нет", self.h.tg.all_visible())
        self.assertIn("srv:ask:template", [d for _, d in self.h.tg.buttons()])

    def test_awg_без_ssh_ключа_предлагает_его_задать(self):
        self.h.tg.user_says("/awg")
        self.h.pump()
        self.assertIn("SSH-ключ", self.h.tg.all_visible())
        self.assertIn("set:SSH_KEY_PATH", [d for _, d in self.h.tg.buttons()])

    def _fake_ssh(self, replies):
        """Подменяет SSH: ключ -> что вернуть. Сами скрипты живут на VPN-сервере."""
        from rotator import bot as botmod, remote

        calls = []

        def fake_run(host, command, **kw):
            calls.append(command)
            for needle, out in replies.items():
                if needle in command:
                    return remote.Result(0, out, "")
            return remote.Result(1, "", "не подготовлен ответ")

        self.h.secrets.set("SSH_KEY_PATH", str(TMP / "fake-key"))
        (TMP / "fake-key").write_text("x")
        self.h.state.update(ipv4="203.0.113.11")
        original, botmod.remote.run = botmod.remote.run, fake_run
        self.addCleanup(lambda: setattr(botmod.remote, "run", original))
        return calls

    def test_awg_показывает_выпущенные_конфиги(self):
        self._fake_ssh({"list-clients.sh": "keenetic-home\t10.9.1.2\t47.9МБ\t12мин назад\n"
                                           "iphone-oleg\t10.9.1.3\t0Б\tне подключался\n"})
        self.h.tg.user_says("/awg")
        self.h.pump()
        card = self.h.tg.all_visible()
        self.assertIn("keenetic-home", card)
        self.assertIn("iphone-oleg", card)
        self.assertIn("47.9МБ", card, "трафик ключа не показан")
        self.assertIn("0Б", card, "неиспользованный ключ не отличить от рабочего")
        self.assertIn("НЕ добавляйте сервер в приложение Amnezia", card,
                      "нет предупреждения про затирание 2.0")
        buttons = [d for _, d in self.h.tg.buttons()]
        for target in ("awg:new", "awg:send", "awg:revoke"):
            self.assertIn(target, buttons)

    def test_awg_понимает_старый_формат_без_трафика(self):
        """Сервер и бот обновляются порознь: три поля вместо четырёх не ломают список."""
        self._fake_ssh({"list-clients.sh": "keenetic-home\t10.9.1.2\t12s назад\n"})
        self.h.tg.user_says("/awg")
        self.h.pump()
        card = self.h.tg.all_visible()
        self.assertIn("keenetic-home", card)
        self.assertIn("12s назад", card)
        self.assertIn("awg:new", [d for _, d in self.h.tg.buttons()])

    def test_выпуск_конфига_присылает_файл(self):
        conf = ("[Interface]\nPrivateKey = test\nAddress = 10.9.1.4/32\n\n"
                "[Peer]\nEndpoint = vpn.example.com:51260\n")
        calls = self._fake_ssh({"add-client.sh": "готово: /opt/awg31/clients/nokia.conf",
                                "cat /opt/awg31/clients/nokia.conf": conf})
        self.h.tg.user_taps("awg:new")
        self.h.pump()
        self.assertEqual(self.h.bot.awaiting, "AWG_CLIENT_NAME")

        self.h.tg.user_says("nokia")
        self.h.pump()
        import time as _t
        for _ in range(50):          # выпуск уходит в отдельный поток
            if self.h.tg.documents:
                break
            _t.sleep(0.02)
        self.assertTrue(self.h.tg.documents, "файл конфига не отправлен")
        doc = self.h.tg.documents[-1]
        self.assertEqual(doc["filename"], "nokia.conf")
        self.assertIn("[Interface]", doc["content"])
        self.assertTrue(any("add-client.sh nokia" in c for c in calls))

    def test_имя_с_опасными_символами_отвергается(self):
        """Имя уходит в команду на сервере — инъекция недопустима."""
        self._fake_ssh({})
        self.h.tg.user_taps("awg:new")
        self.h.pump()
        for bad in ("a; rm -rf /", "$(id)", "../../etc/passwd", "`whoami`"):
            self.h.tg.timeline.clear()
            self.h.bot.awaiting = "AWG_CLIENT_NAME"
            self.h.tg.user_says(bad)
            self.h.pump()
            self.assertIn("Не принял", self.h.tg.all_visible(), f"принято опасное имя: {bad}")

    def _with_upcloud(self):
        self.h.secrets.set("UPCLOUD_TOKEN", GOOD_UC)
        self.h.secrets.set("SERVER_UUID", self.h.server_uuid)

    def test_servers_показывает_только_свой_когда_он_один(self):
        self._with_upcloud()
        self.h.tg.user_says("/servers")
        self.h.pump()
        card = self.h.tg.all_visible()
        self.assertIn(self.h.server_uuid, card)
        self.assertIn("🏠", card, "свой сервер не помечен")
        self.assertNotIn("❓", card, "лишний сервер взялся из ниоткуда")
        self.assertIn("посторонних серверов нет", card)

    def test_servers_находит_забытый_сервер_и_считает_его_цену(self):
        """Сбой ротации может оставить работающий сервер: он тратит деньги и
        может держать копии ключей, а снаружи его не видно."""
        self.h.cloud.servers["dead-beef-0000-1111-222233334444"] = {
            "uuid": "dead-beef-0000-1111-222233334444",
            "state": "started", "zone": "nl-ams1", "plan": "1xCPU-1GB",
            "hostname": "amnezia-clone", "title": "amnezia-clone",
        }
        self.h.cloud.ips["203.0.113.77"] = "dead-beef-0000-1111-222233334444"
        self._with_upcloud()
        self.h.tg.user_says("/servers")
        self.h.pump()
        card = self.h.tg.all_visible()
        self.assertIn("amnezia-clone", card, "забытый сервер не показан")
        self.assertIn("dead-beef-0000-1111-222233334444", card, "нет UUID для поиска в панели")
        self.assertIn("203.0.113.77", card, "не показан адрес — по нему приходят жалобы")
        self.assertIn("❓", card, "забытый сервер не помечен")
        self.assertIn("🏠", card, "свой сервер не помечен")
        # 0.5556 сотых за час * 730 = 4.06 в месяц; важно, что цена вообще есть.
        self.assertIn("4.06", card, "не посчитана цена забытого сервера")
        self.assertIn("удаление необратимо", card, "нет предупреждения перед удалением")

    def test_валюта_берётся_из_account_details(self):
        """В /1.3/account валюты нет — она только в /1.3/account/details/{user}.
        Из-за этого в карточке расходов раньше стоял «?» вместо EUR."""
        self._with_upcloud()
        self.h.tg.user_says("/costs")
        self.h.pump()
        card = self.h.tg.all_visible()
        self.assertIn("EUR", card, "валюта не прочиталась")
        self.assertNotIn("?/мес", card, "валюта снова подставилась заглушкой")

    def test_servers_без_заданного_uuid_не_врёт_про_чужие(self):
        self._with_upcloud()
        self.h.secrets.set("SERVER_UUID", "")
        self.h.tg.user_says("/servers")
        self.h.pump()
        card = self.h.tg.all_visible()
        self.assertIn("SERVER_UUID не задан", card)
        self.assertNotIn("посторонних серверов нет", card,
                         "без своего UUID нельзя утверждать, что чужих нет")

    def test_vless_показывает_клиентов_панели(self):
        self._fake_ssh({"client.py list":
                        "amnezia-1\tuuid-1\t1.2ГБ\tвкл\n"
                        "oleg-iphone\tuuid-2\t340МБ\tвкл\n"})
        self.h.tg.user_says("/vless")
        self.h.pump()
        card = self.h.tg.all_visible()
        self.assertIn("oleg-iphone", card)
        self.assertIn("340МБ", card, "не показан трафик")
        buttons = [d for _, d in self.h.tg.buttons()]
        for target in ("vless:new", "vless:link", "vless:del"):
            self.assertIn(target, buttons)

    LINK = ("vless://11111111-2222-3333-4444-555555555555@vpn.example.com:443"
            "?type=tcp&security=reality&pbk=KEY&sni=www.example.com#oleg")
    CONF = "[Interface]\nPrivateKey = x\nAddress = 172.29.172.5/32\n"

    def _wait(self, condition, tries: int = 100):
        """Выдача идёт в отдельном потоке: ждём, пока он доберётся до конца."""
        import time as _t
        for _ in range(tries):
            if condition():
                return True
            _t.sleep(0.02)
        return False

    def _bundle_ssh(self, drop: tuple[str, ...] = (), **extra):
        replies = {"client.py add": self.LINK,
                   "client.py link": self.LINK,
                   "add-client.sh": "готово: /opt/awg31/clients/oleg.conf",
                   "cat /opt/awg31/clients/oleg.conf": self.CONF}
        replies.update(extra)
        for key in drop:                 # команда свалится: ответа для неё нет
            replies.pop(key, None)
        self.h.secrets.set("SUB_BASE_URL", "https://sub.example.com")
        return self._fake_ssh(replies)

    def test_выдача_человеку_одним_сообщением(self):
        """Админ пересылает одно сообщение, а в нём — все ключи сразу."""
        calls = self._bundle_ssh()
        self.h.tg.user_taps("vless:new")
        self.h.pump()
        self.assertEqual(self.h.bot.awaiting, "VLESS_CLIENT_NAME")

        self.h.tg.user_says("oleg")
        self.h.pump()
        buttons = [d for _, d in self.h.tg.buttons()]
        self.assertIn("vless:go:full:oleg", buttons, "не спросили про белые списки")
        self.assertIn("vless:go:split:oleg", buttons)

        self.h.tg.user_taps("vless:go:full:oleg")
        self.h.pump()
        self.assertTrue(self._wait(lambda: self.h.tg.documents), "комплект не отправлен")

        self.assertTrue(any("client.py add oleg" in c for c in calls), "ключ VLESS не выпущен")
        self.assertTrue(any("add-client.sh oleg full" in c for c in calls),
                        "ключ AmneziaWG не выпущен вместе с VLESS")
        self.assertEqual(len(self.h.tg.documents), 1, "ключи разъехались по разным файлам")
        doc = self.h.tg.documents[-1]
        self.assertEqual(doc["filename"], "oleg.conf")
        self.assertIn("[Interface]", doc["content"])
        caption = doc["caption"]
        self.assertIn("https://sub.example.com/sub/11111111-2222-3333-4444-555555555555",
                      caption, "в сообщении нет подписки для телефона")
        self.assertIn("https://sub.example.com/", caption, "нет ссылки на инструкцию")
        self.assertIn("vless://", caption, "нет простой ссылки vless")
        self.assertIn("AmneziaWG", caption, "не сказано, чем открыть файл")
        self.assertIn("sing-box", caption, "не сказано, какое приложение ставить")

    def test_выдача_с_белыми_списками_передаёт_режим(self):
        calls = self._bundle_ssh()
        self.h.bot.awaiting = "VLESS_CLIENT_NAME"
        self.h.tg.user_says("oleg")
        self.h.pump()
        self.h.tg.user_taps("vless:go:split:oleg")
        self.h.pump()
        self.assertTrue(self._wait(lambda: any("add-client.sh oleg split" in c for c in calls)),
                        "режим белых списков не доехал до сервера")

    def test_сбой_amneziawg_не_отменяет_ключ_для_телефона(self):
        """Выпуск половины комплекта лучше, чем ничего: ключ VLESS уже выдан."""
        calls = self._bundle_ssh(drop=("add-client.sh",))
        self.h.tg.user_taps("vless:go:full:oleg")
        self.h.pump()
        self.assertTrue(self._wait(
            lambda: "sub/11111111-2222-3333-4444-555555555555" in self.h.tg.all_visible()),
            "ключ для телефона не доехал")
        visible = self.h.tg.all_visible()
        self.assertIn("AmneziaWG не выпустился", visible, "сбой не показан администратору")
        self.assertFalse(self.h.tg.documents, "отправлен файл, которого нет")
        self.assertTrue(any("client.py add oleg" in c for c in calls))

    def test_подпись_к_файлу_влезает_в_предел_телеграма(self):
        """У подписи к файлу предел 1024 символа. Длинная ссылка vless уедет
        отдельным сообщением, но обрезанных ключей быть не должно."""
        long_link = ("vless://11111111-2222-3333-4444-555555555555@"
                     "very-long-domain-name-for-this-vpn.example.com:443?" + "x=1&" * 120)
        self._bundle_ssh(**{"client.py add": long_link})
        self.h.tg.user_taps("vless:go:full:oleg")
        self.h.pump()
        self.assertTrue(self._wait(lambda: self.h.tg.documents), "комплект не отправлен")
        caption = self.h.tg.documents[-1]["caption"]
        self.assertLessEqual(len(caption), 1024, "подпись не влезет в Telegram")
        self.assertIn("sub/11111111-2222-3333-4444-555555555555", caption)
        self.assertNotIn("very-long-domain-name", caption, "длинная ссылка не ушла из подписи")
        self.assertTrue(self._wait(
            lambda: "very-long-domain-name-for-this-vpn.example.com" in self.h.tg.all_visible()),
            "длинная ссылка потерялась вместо отдельного сообщения")

    def test_ключ_не_доехавший_до_ядра_виден_и_лечится(self):
        """Клиент есть в панели, но ядро его не знает — снаружи это timeout.

        Именно так сломался первый выданный ключ: панель применяет добавление
        через core API, а следующий перезапуск ядра читает старый config.json.
        """
        calls = self._fake_ssh({"client.py list":
                                "amnezia-1\tuuid-1\t1.2ГБ\tвкл\n"
                                "oleg-iphone\tuuid-2\t0Б\tвкл / НЕ В ЯДРЕ\n",
                                "client.py sync": "ядро знает все ключи: 2"})
        self.h.tg.user_says("/vless")
        self.h.pump()
        card = self.h.tg.all_visible()
        self.assertIn("timeout", card, "не объяснено, что человек увидит timeout")
        buttons = [d for _, d in self.h.tg.buttons()]
        self.assertIn("vless:sync", buttons, "нет кнопки починки")

        self.h.tg.timeline.clear()
        self.h.tg.user_taps("vless:sync")
        self.h.pump()
        import time as _t
        for _ in range(50):
            if any("client.py sync" in c for c in calls):
                break
            _t.sleep(0.02)
        self.assertTrue(any("client.py sync" in c for c in calls), "sync не вызван")

    def test_исправный_ключ_не_помечается_предупреждением(self):
        self._fake_ssh({"client.py list": "oleg\tuuid-1\t0Б\tвкл\n"})
        self.h.tg.user_says("/vless")
        self.h.pump()
        card = self.h.tg.all_visible()
        self.assertNotIn("timeout", card)
        self.assertNotIn("vless:sync", [d for _, d in self.h.tg.buttons()])

    def test_vless_имя_с_инъекцией_отвергается(self):
        self._fake_ssh({})
        self.h.tg.user_taps("vless:new")
        self.h.pump()
        for bad in ("a; id", "$(whoami)", "../x"):
            self.h.tg.timeline.clear()
            self.h.bot.awaiting = "VLESS_CLIENT_NAME"
            self.h.tg.user_says(bad)
            self.h.pump()
            self.assertIn("Не принял", self.h.tg.all_visible(), f"принято: {bad}")

    def test_подписка_без_настроенного_адреса_объясняет_что_нужно(self):
        self._fake_ssh({"client.py list": "oleg\tuuid-1\t0Б\tвкл\n"})
        self.h.tg.user_taps("vless:sub:oleg")
        self.h.pump()
        self.assertIn("не настроен", self.h.tg.all_visible())
        self.assertIn("set:SUB_BASE_URL", [d for _, d in self.h.tg.buttons()])

    def _fake_fetch(self, body, status=200):
        """Подменяет загрузку подписки воркером: сети в тестах нет."""
        import requests

        class Answer:
            status_code = status
            text = body

            def raise_for_status(self):
                if status >= 400:
                    raise requests.HTTPError(f"HTTP {status}")

        original = requests.get
        requests.get = lambda *a, **kw: Answer()
        self.addCleanup(lambda: setattr(requests, "get", original))

    def test_повторная_отправка_не_перевыпускает_ключи(self):
        """«Прислать заново» — то же сообщение. Перевыпуск отключил бы ключ
        на устройстве, которое уже работает."""
        calls = self._bundle_ssh(**{"client.py list":
                                    "oleg\t11111111-2222-3333-4444-555555555555\t0Б\tвкл\n"})
        self.h.tg.user_taps("vless:sub:oleg")
        self.h.pump()
        self.assertTrue(self._wait(lambda: self.h.tg.documents), "комплект не отправлен")
        caption = self.h.tg.documents[-1]["caption"]
        self.assertIn("https://sub.example.com/sub/11111111-2222-3333-4444-555555555555",
                      caption, "в сообщении нет ссылки подписки")
        self.assertIn("https://sub.example.com/", caption, "нет ссылки на инструкцию")
        self.assertIn("Госуслуги", caption, "не сказано про белые списки")
        self.assertFalse(any("client.py add" in c for c in calls), "ключ перевыпущен заново")
        self.assertFalse(any("add-client.sh" in c for c in calls), "конфиг перевыпущен заново")

    def test_подписка_приходит_и_файлом(self):
        """У части мобильных операторов ссылка не открывается — нужен файл."""
        self.h.secrets.set("SUB_BASE_URL", "https://sub.example.com")
        self._fake_fetch('{"outbounds": [{"tag": "proxy"}]}')
        self._fake_ssh({"client.py list":
                        "oleg\t11111111-2222-3333-4444-555555555555\t0Б\tвкл\n"})
        self.h.tg.user_taps("vless:file:oleg")
        self.h.pump()
        self.assertTrue(self._wait(lambda: self.h.tg.documents), "профиль файлом не отправлен")
        doc = self.h.tg.documents[-1]
        self.assertEqual(doc["filename"], "oleg.json")
        self.assertIn("proxy", doc["content"])

    def test_битая_подписка_файлом_не_рассылается(self):
        """Воркер ответил не JSON — лучше честная ошибка, чем мусор человеку."""
        self.h.secrets.set("SUB_BASE_URL", "https://sub.example.com")
        self._fake_fetch("<html>503</html>")
        self._fake_ssh({"client.py list":
                        "oleg\t11111111-2222-3333-4444-555555555555\t0Б\tвкл\n"})
        self.h.tg.user_taps("vless:file:oleg")
        self.h.pump()
        self.assertTrue(self._wait(lambda: "не забрался" in self.h.tg.all_visible()))
        self.assertFalse(self.h.tg.documents, "отправлен файл с мусором вместо конфига")

    def test_адрес_подписок_проверяется(self):
        from rotator.bot import VALIDATORS
        check = VALIDATORS["SUB_BASE_URL"]
        self.assertFalse(check("https://sub.example.com"))
        self.assertFalse(check("https://sub.example.com/"))
        # Зеркало на VPN-сервере живёт на 8443: 443 там занят Xray.
        self.assertFalse(check("https://sub2.example.com:8443"))
        self.assertFalse(check("https://sub2.example.com:8443/"))
        for bad in ("sub.example.com", "http://sub.example.com",
                    "https://sub.example.com/path", "не ссылка"):
            self.assertTrue(check(bad), f"принят мусор: {bad}")

    def test_подписка_ничего_не_качает_на_старте(self):
        """Наборы правил качались через туннель, которого на старте ещё нет.

        Это была главная причина, по которой служба вообще не запускалась:
        «initialize rule-set ... reality verification failed». Списки должны
        лежать в самом конфиге.
        """
        from pathlib import Path as _P
        src = _P(__file__).resolve().parents[1].joinpath("subs/worker.js").read_text()
        for bad in ("rule_set", "download_detour", "raw.githubusercontent.com"):
            self.assertNotIn(bad, src, f"подписка снова зависит от загрузки: {bad}")
        self.assertIn("domain_suffix", src, "в конфиге нет правил по доменам")
        self.assertIn("ip_cidr", src, "в конфиге нет правил по IP-зонам")
        self.assertIn("FALLBACK_DOMAINS", src, "нет запасного списка на случай недоступности источника")

    def test_страница_инструкции_в_воркере_самодостаточна(self):
        """Страница должна открываться там, где половина интернета недоступна."""
        from pathlib import Path as _P
        src = _P(__file__).resolve().parents[1].joinpath("subs/worker.js").read_text()
        page = src[src.index("function instructionPage"):]
        for bad in ("http://", "cdn.", "fonts.googleapis", "<script", "<img"):
            self.assertNotIn(bad, page, f"страница тянет внешнее: {bad}")
        for must in ("sing-box", "Hiddify", "Госуслуги", "буфера обмена",
                     "AmneziaWG", "org.amnezia.awg", "id6478942365"):
            self.assertIn(must, page, f"в инструкции нет {must}")
        # Теперь человеку присылают два ключа, и страница обязана объяснить оба:
        # иначе файл .conf в сообщении выглядит мусором, который он выбросит.
        self.assertIn("Способ 1", page, "нет раздела про телефон")
        self.assertIn("Способ 2", page, "нет раздела про файл AmneziaWG")
        # Рисунки экранов — inline SVG: по сети не грузятся, в тёмной теме живут.
        self.assertGreaterEqual(page.count("<svg"), 4, "шаги без рисунков")
        self.assertIn("var(--accent)", page, "рисунки не переживут тёмную тему")
        # Какое из двух приложений соединится, зависит от версии ядра на
        # сервере. Человек должен прочитать «попробуйте второе», а не гадать.
        self.assertIn("не запускается", page,
                      "страница не говорит, что делать, если приложение не идёт")

    def test_оба_протокола_доступны_из_меню_сервера(self):
        self.h.secrets.set("UPCLOUD_TOKEN", GOOD_UC)
        self.h.secrets.set("SERVER_UUID", self.h.server_uuid)
        self.h.tg.user_says("/server")
        self.h.pump()
        buttons = [d for _, d in self.h.tg.buttons()]
        self.assertIn("awg:menu", buttons, "нет входа в AmneziaWG 3.1")
        self.assertIn("vless:menu", buttons, "нет входа в VLESS Reality")

    def test_кнопка_инструкции_есть_в_главном_меню(self):
        self.h.tg.user_says("/help")
        self.h.pump()
        buttons = [d for _, d in self.h.tg.buttons()]
        self.assertIn("guide:menu", buttons)
        self.assertIn("guide:howto", buttons, "шпаргалка не вынесена на первый экран")

    def test_шпаргалка_покрывает_обе_выдачи_и_запрет(self):
        """Главное, что нужно знать администратору, должно быть на одной странице."""
        from rotator import guide
        howto = guide.PAGES["howto"][1]
        for must in ("/vless", "/awg", "/rotate", "/costs", "/diag", "ssh -L"):
            self.assertIn(must, howto, f"в шпаргалке нет {must}")
        protocols = guide.PAGES["protocols"][1]
        self.assertIn("приложение Amnezia", protocols,
                      "нет предупреждения про затирание 2.0")

    def test_меню_команд_публикуется_и_совпадает_со_справкой(self):
        from rotator.bot import COMMANDS, HELP
        self.h.bot.publish_commands()
        self.assertIn("setMyCommands", self.h.tg.calls, "меню команд не отправлено в Telegram")
        for name, _ in COMMANDS:
            self.assertIn(f"/{name}", HELP, f"{name} есть в меню, но нет в /help")

    def test_simulate_ничего_не_меняет(self):
        before = dict(self.h.state.data)
        self.h.tg.user_says("/simulate")
        self.h.pump()
        answer = self.h.tg.all_visible()
        self.assertIn("Холостой прогон", answer)
        self.assertIn("dry_run", answer, "не сказано, включён ли боевой режим")
        for key in ("ipv4", "history", "last_rotation_ts", "server_uuid"):
            self.assertEqual(self.h.state[key], before[key], f"{key} изменился при холостом прогоне")

    def test_из_неразрешённого_чата_бот_предлагает_его_добавить(self):
        """Реальный случай: в TG_ADMIN_ID вписан ID группы, а человек пишет в личку."""
        self.h.tg.user_says("привет", chat_id="537089165")
        self.h.pump()

        # Постороннему чату бот не отвечает…
        self.assertTrue(all(m["chat_id"] == "42" for m in self.h.tg.sent),
                        "бот ответил в посторонний чат")
        # …но владельца предупреждает, с готовой кнопкой.
        self.assertIn("537089165", self.h.tg.all_visible())
        self.assertIn("addchat:537089165", [d for _, d in self.h.tg.buttons()])

    def test_кнопка_разрешает_чат_и_он_начинает_работать(self):
        self.h.tg.user_says("привет", chat_id="537089165")
        self.h.pump()
        self.h.tg.user_taps("addchat:537089165")
        self.h.pump()

        self.assertIn("537089165", self.h.secrets.get("TG_ADMIN_ID"))
        self.assertIn("537089165", self.h.bot.admins)

        self.h.tg.timeline.clear()
        self.h.tg.user_says("/status", chat_id="537089165")
        self.h.pump()
        self.assertTrue(self.h.tg.timeline, "разрешённый чат всё ещё игнорируется")

    def test_о_неразрешённом_чате_предупреждают_один_раз(self):
        for _ in range(3):
            self.h.tg.user_says("привет", chat_id="537089165")
            self.h.pump()
        offers = [m for m in self.h.tg.sent if "нет в списке разрешённых" in m["text"]]
        self.assertEqual(len(offers), 1, "бот спамит предупреждением на каждое сообщение")

    def test_несколько_чатов_через_запятую(self):
        self.h.secrets.set("TG_ADMIN_ID", "42,537089165")
        from rotator.bot import Bot
        bot = Bot(self.h.cloud, self.h.secrets, self.h.engine, self.h.cfg)
        self.assertEqual(bot.admins, ["42", "537089165"])
        self.assertEqual(bot.admin, "42", "основным должен остаться первый")

    def test_privacy_mode_в_группе_объясняется_при_старте(self):
        """Главная ловушка: в группе бот получает только команды."""
        self.h.secrets.set("TG_ADMIN_ID", "-100500")
        self.h.tg.can_read_all = False
        from rotator.bot import Bot
        bot = Bot(self.h.cloud, self.h.secrets, self.h.engine, self.h.cfg)
        self.h.tg.timeline.clear()
        bot.warn_about_privacy(self.h.tg.request("POST", "/getMe", {}).json()["result"])

        warning = self.h.tg.all_visible()
        self.assertIn("режим приватности", warning)
        self.assertIn("setprivacy", warning)
        self.assertIn("добавьте заново", warning, "не сказано, что бота надо переподключить к группе")

    def test_privacy_mode_не_беспокоит_если_чат_личный(self):
        self.h.tg.can_read_all = False
        self.h.tg.timeline.clear()
        self.h.bot.warn_about_privacy({"can_read_all_group_messages": False})
        self.assertEqual(self.h.tg.timeline, [], "предупреждение про группы в личном чате лишнее")


if __name__ == "__main__":
    unittest.main(verbosity=2)
