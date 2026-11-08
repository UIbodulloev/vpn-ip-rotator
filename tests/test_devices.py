"""Одна ссылка — одно устройство: учёт на зеркале подписок.

Проверяется ровно то, на чём это ломается в жизни: чужое приложение по
пересланной ссылке, переезд владельца из сети в сеть, точный отпечаток
устройства и снятие привязки администратором.
"""
from __future__ import annotations

import importlib.util
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TMP = Path("/tmp/vpn-rotator-tests")


def load_mirror():
    spec = importlib.util.spec_from_file_location("sub_mirror", ROOT / "panel/sub-mirror.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Headers(dict):
    """Заголовки запроса: у http.server это регистронезависимый словарь."""

    def get(self, key, default=None):                # noqa: D102
        for k, v in self.items():
            if k.lower() == key.lower():
                return v
        return default


class DeviceBindingTest(unittest.TestCase):
    def setUp(self):
        TMP.mkdir(parents=True, exist_ok=True)
        self.m = load_mirror()
        self.state = TMP / f"devices-{time.time_ns()}.json"
        self.m.STATE_FILE = self.state
        self.addCleanup(lambda: self.state.unlink(missing_ok=True))
        self.uuid = "11111111-2222-3333-4444-555555555555"

    def age(self, seconds: float, fields=("first", "last", "day")) -> None:
        """Отодвинуть записи в прошлое: иначе весь тест происходит в одну
        секунду. Какие именно поля — важно: сдвинув «last», мы заодно отменим
        правило «две сети подряд», а его как раз и надо проверить."""
        state = self.m.load_state()
        for device in state["links"][self.uuid]["devices"]:
            for key in fields:
                if device.get(key):
                    device[key] -= seconds
            if "last" in fields:
                device["nets"] = {k: t - seconds for k, t in device["nets"].items()}
        self.m.save_state(state)

    def ask(self, app="SFA/1.14.4 (sing-box 1.14.4)", ip="203.0.113.5", hwid=None, limit=1):
        headers = Headers({"User-Agent": app})
        if hwid:
            headers["x-hwid"] = hwid
        return self.m.register(self.uuid, headers, ip, limit)

    # --- приблизительная привязка (sing-box, Hiddify: отпечаток не присылают)

    def test_первое_устройство_встаёт(self):
        allowed, why = self.ask()
        self.assertTrue(allowed, why)

    def test_чужое_приложение_по_пересланной_ссылке_не_встаёт(self):
        self.assertTrue(self.ask()[0])
        allowed, why = self.ask(app="Hiddify/2.5.7", ip="198.51.100.9")
        self.assertFalse(allowed, "ссылка встала на второе устройство")
        self.assertIn("уже", why)

    def test_владелец_переезжает_между_сетями(self):
        """Wi-Fi дома, LTE, Wi-Fi на работе — это одно устройство, не три."""
        self.assertTrue(self.ask()[0])
        self.age(self.m.INSTALL_GRACE + 60)
        for ip in ("203.0.113.5", "10.20.30.40", "172.16.9.9", "100.64.1.1"):
            allowed, why = self.ask(ip=ip)
            self.assertTrue(allowed, f"{ip}: {why}")
            self.age(86400)      # обновления раз в сутки, как и в жизни

    def test_две_сети_за_десять_минут_это_два_устройства(self):
        """Одно приложение обновляется по таймеру раз в сутки. Две сети подряд
        означают, что ссылкой пользуются двое."""
        self.assertTrue(self.ask(ip="203.0.113.5")[0])
        self.age(self.m.INSTALL_GRACE + 60, fields=("first",))
        allowed, why = self.ask(ip="198.51.100.9")
        self.assertFalse(allowed, "двух одновременных не заметили")
        self.assertIn("два устройства", why)

    def test_компания_друзей_упирается_в_число_сетей(self):
        self.assertTrue(self.ask()[0])
        self.age(self.m.INSTALL_GRACE + 60)
        denied = ""
        for i in range(self.m.NET_BUDGET + 3):
            allowed, why = self.ask(ip=f"{10 + i}.0.0.1")
            self.age(86400)
            if not allowed:
                denied = why
                break
        self.assertTrue(denied, "десяток разных сетей сошёл за одно устройство")
        self.assertIn("сетей за месяц", denied)

    def test_жать_обновить_не_запрещено(self):
        """Человек жмёт «обновить» как раз когда у него не работает. Отказ в
        этот момент — худшее, что можно сделать, поэтому по частоте не
        отказываем, только считаем для глаз администратора."""
        for _ in range(12):
            allowed, why = self.ask()
            self.assertTrue(allowed, why)
        device = self.m.load_state()["links"][self.uuid]["devices"][0]
        self.assertEqual(device["today"], 12, "частота не записана")

    def test_установка_со_сменой_сети_не_наказывается(self):
        """Первый час после привязки человек ставит профиль и может выйти из
        дома на середине: смена сети здесь не повод для отказа."""
        self.assertTrue(self.ask(ip="203.0.113.5")[0])
        allowed, why = self.ask(ip="198.51.100.9")
        self.assertTrue(allowed, why)

    # --- точная привязка (Happ, v2RayTun: присылают x-hwid)

    def test_отпечаток_устройства_считается_точно(self):
        self.assertTrue(self.ask(app="Happ/1.0", hwid="device-A")[0])
        allowed, why = self.ask(app="Happ/1.0", hwid="device-B")
        self.assertFalse(allowed, "второе устройство с другим отпечатком пустили")
        self.assertIn("уже", why)

    def test_своё_устройство_узнаётся_в_любой_сети(self):
        """С отпечатком сети уже не важны: это и есть честный счёт устройств."""
        self.assertTrue(self.ask(app="Happ/1.0", hwid="device-A")[0])
        self.age(10 * 86400)
        for i in range(self.m.NET_BUDGET + 5):
            allowed, why = self.ask(app="Happ/1.0", hwid="device-A", ip=f"{10 + i}.0.0.1")
            self.assertTrue(allowed, f"сеть {i}: {why}")

    def test_проверочный_адрес_не_занимает_привязку(self):
        """Им проверяют раздачу установщик и selftest. Если он привяжется,
        вторая проверка получит отказ и будет выглядеть как поломка."""
        for name in "ABC":
            allowed, why = self.m.register(self.m.PROBE_UUID,
                                           Headers({"User-Agent": f"curl/{name}"}),
                                           "203.0.113.1", 1)
            self.assertTrue(allowed, why)
        self.assertNotIn(self.m.PROBE_UUID, self.m.load_state()["links"])

    # --- управление

    def test_снятие_привязки_освобождает_ссылку(self):
        self.assertTrue(self.ask(hwid="device-A")[0])
        self.assertFalse(self.ask(hwid="device-B")[0])
        self.m.reset_link(self.uuid)
        self.assertTrue(self.ask(hwid="device-B")[0], "после сброса ссылка не встала")

    def test_лимит_на_два_устройства(self):
        self.m.set_limit(self.uuid, 2)
        self.assertTrue(self.ask(hwid="device-A", limit=1)[0])
        self.assertTrue(self.ask(hwid="device-B", limit=1)[0], "второе устройство не пустили")
        self.assertFalse(self.ask(hwid="device-C", limit=1)[0], "третье устройство пустили")

    def test_нулевой_лимит_ничего_не_считает(self):
        for name in "ABCDE":
            allowed, why = self.ask(hwid=f"device-{name}", limit=0)
            self.assertTrue(allowed, why)

    def test_отказы_видны_администратору(self):
        self.ask(hwid="device-A")
        self.ask(hwid="device-B")
        link = self.m.load_state()["links"][self.uuid]
        self.assertEqual(link["denied"], 1, "отказ не записан")
        self.assertEqual(len(link["devices"]), 1)

    def test_адреса_людей_не_хранятся(self):
        """На диске лежат хеши сетей, а не адреса: это ключи доступа, рядом с
        которыми список адресов — лишний способ подвести людей."""
        self.ask(ip="203.0.113.77")
        text = self.state.read_text()
        self.assertNotIn("203.0.113", text)
        self.assertNotIn("203.0", text)

    def test_семейство_приложения_узнаётся(self):
        for ua, family in (("SFA/1.14.4 (sing-box)", "sing-box"),
                           ("SFI/1.12.0", "sing-box"),
                           ("Hiddify/2.5.7", "hiddify"),
                           ("v2rayTun/4.1", "v2raytun"),
                           ("Happ/1.0", "happ"),
                           ("", "неизвестное")):
            self.assertEqual(self.m.ua_family(ua), family, ua)


if __name__ == "__main__":
    unittest.main()
