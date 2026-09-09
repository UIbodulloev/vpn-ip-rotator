"""Сквозные тесты ротации против фейкового UpCloud/Cloudflare."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

TMP = Path(tempfile.mkdtemp(prefix="rotator-test-"))
os.environ["ROTATOR_CONFIG"] = str(TMP / "config.toml")
os.environ["ROTATOR_SECRETS"] = str(TMP / "secrets.env")
os.environ["ROTATOR_STATE"] = str(TMP / "state.json")

from rotator import log, modes, probes                        # noqa: E402
from rotator.clouddns import Cloudflare                       # noqa: E402
from rotator.config import Config, Secrets                    # noqa: E402
from rotator.engine import Engine                             # noqa: E402
from rotator.state import State                               # noqa: E402
from rotator.upcloud import UpCloud                           # noqa: E402
from tests.fake_api import FakeCloud                          # noqa: E402

log.setup("CRITICAL")

CONFIG = """
[vpn]
domain = "vpn.example.com"
probe_port = 443
control_port = 22

[detector]
interval_sec = 1
fail_threshold = 2
tcp_timeout_sec = 0.2
sanity_targets = ["127.0.0.1:9"]

[rotation]
cooldown_hours = 0
max_per_day = 99
zone_rotation = ["fi-hel1", "de-fra1"]
wait_stop_sec = 5
wait_start_sec = 5
wait_storage_sec = 5
wait_service_sec = 1
"""


class Harness:
    """Собирает движок поверх фейкового облака."""

    def __init__(self, config_text: str = CONFIG):
        # Пути выставляем на каждом создании: тестовые модули импортируются
        # вместе и иначе делят один файл состояния.
        os.environ["ROTATOR_CONFIG"] = str(TMP / "config.toml")
        os.environ["ROTATOR_SECRETS"] = str(TMP / "secrets.env")
        os.environ["ROTATOR_STATE"] = str(TMP / "state.json")
        for name in ("config.toml", "secrets.env", "state.json"):
            Path(TMP / name).unlink(missing_ok=True)
        Path(TMP / "config.toml").write_text(config_text)

        self.cloud = FakeCloud()
        self.server_uuid, self.storage_uuid, self.ip = self.cloud.seed()

        self.cfg = Config()
        self.secrets = Secrets()
        for key, value in {
            "RELAY_URLS": "https://relay.test",
            "RELAY_KEY": "k",
            "TG_BOT_TOKEN": "1:x",
            "TG_ADMIN_ID": "1",
            "UPCLOUD_TOKEN": "ucat_test",
            "SERVER_UUID": self.server_uuid,
            "CF_TOKEN": "cftoken",
            "CF_ZONE_ID": "zone1",
            "CF_A_RECORD_ID": "rec-a",
            "CF_AAAA_RECORD_ID": "rec-aaaa",
        }.items():
            self.secrets.set(key, value)

        self.state = State()
        self.messages: list[str] = []
        self.engine = Engine(
            self.cfg, self.secrets, self.state,
            UpCloud(self.cloud, "ucat_test"),          # FakeCloud подменяет Relay
            Cloudflare(self.cloud, "cftoken"),
            self.messages.append,
        )

    def dns(self, record: str = "rec-a") -> str:
        return self.cloud.records[record]["content"]


def always_open(host, port, timeout):
    return True


def always_closed(host, port, timeout):
    return False


class ReplaceIpTest(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self._orig = modes.tcp_open
        modes.tcp_open = always_open

    def tearDown(self):
        modes.tcp_open = self._orig

    def test_адрес_меняется_и_старый_освобождается(self):
        old = self.h.ip
        result = self.h.engine.rotate("replace-ip", force=True)

        self.assertNotEqual(result["new_ip"], old)
        self.assertEqual(result["old_ip"], old)
        # Старый адрес больше не принадлежит никому.
        self.assertNotIn(old, self.h.cloud.ips)
        # Новый висит на том же сервере.
        self.assertEqual(self.h.cloud.ips[result["new_ip"]], self.h.server_uuid)
        # Сервер снова запущен.
        self.assertEqual(self.h.cloud.servers[self.h.server_uuid]["state"], "started")
        # DNS переписан.
        self.assertEqual(self.h.dns(), result["new_ip"])
        self.assertIsNone(self.h.state["pending"])

    def test_новый_адрес_заказывается_только_на_остановленном_сервере(self):
        """Фейк повторяет ограничение UpCloud, так что порядок шагов проверяется по-настоящему."""
        self.h.engine.rotate("replace-ip", force=True)
        order = [path for method, path in self.h.cloud.calls if method == "POST"]
        stop_at = next(i for i, p in enumerate(order) if p.endswith("/stop"))
        assign_at = next(i for i, p in enumerate(order) if p == "/1.3/ip_address")
        start_at = next(i for i, p in enumerate(order) if p.endswith("/start"))
        self.assertLess(stop_at, assign_at, "адрес заказан до остановки")
        self.assertLess(assign_at, start_at, "сервер запущен до выдачи адреса")

    def test_старый_адрес_освобождается_после_выдачи_нового(self):
        self.h.engine.rotate("replace-ip", force=True)
        sequence = [f"{m} {p}" for m, p in self.h.cloud.calls if "ip_address" in p]
        self.assertEqual(sequence[0], "POST /1.3/ip_address")
        self.assertTrue(sequence[1].startswith("DELETE"), "старый адрес освобождён раньше выдачи нового")

    def test_если_старый_адрес_не_освобождается_dns_не_трогаем(self):
        old = self.h.ip
        self.h.cloud.fail_on[f"DELETE /1.3/ip_address/{old}"] = 99
        with self.assertRaises(modes.RotationError) as caught:
            self.h.engine.rotate("replace-ip", force=True)
        self.assertIn("не удалось освободить", str(caught.exception))
        # Главное: сервер поднят обратно, а DNS остался на старом адресе.
        self.assertEqual(self.h.cloud.servers[self.h.server_uuid]["state"], "started")
        self.assertEqual(self.h.dns(), old)


class RecreateTest(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self._orig = modes.tcp_open
        modes.tcp_open = always_open

    def tearDown(self):
        modes.tcp_open = self._orig

    def test_пересоздание_в_той_же_зоне(self):
        old_uuid, old_ip = self.h.server_uuid, self.h.ip
        result = self.h.engine.rotate("recreate", force=True)

        self.assertNotEqual(result["new_ip"], old_ip)
        self.assertNotIn(old_uuid, self.h.cloud.servers, "старый сервер не удалён")
        new_uuid = self.h.secrets.get("SERVER_UUID")
        self.assertIn(new_uuid, self.h.cloud.servers)
        self.assertEqual(self.h.cloud.servers[new_uuid]["state"], "started")
        self.assertEqual(self.h.dns(), result["new_ip"])
        # Шаблон остаётся как точка отката.
        self.assertEqual(len(self.h.state["templates"]), 1)
        self.assertIn(self.h.state["templates"][0]["uuid"], self.h.cloud.storages)

    def test_переезд_в_другую_зону(self):
        result = self.h.engine.rotate("recreate", zone="fi-hel1", force=True)
        new_uuid = self.h.secrets.get("SERVER_UUID")
        self.assertEqual(self.h.cloud.servers[new_uuid]["zone"], "fi-hel1")
        self.assertEqual(result["zone"], "fi-hel1")
        # Промежуточный клон подчищен, остаются только шаблоны.
        for storage in self.h.cloud.storages.values():
            self.assertNotIn("rotator-clone", storage["title"])

    def test_сбой_создания_возвращает_старый_сервер_в_работу(self):
        old_uuid, old_ip = self.h.server_uuid, self.h.ip
        self.h.cloud.fail_on["POST /1.3/server"] = 99
        with self.assertRaises(Exception):
            self.h.engine.rotate("recreate", force=True)
        # Ничего не потеряно: сервер жив, работает, DNS не менялся.
        self.assertIn(old_uuid, self.h.cloud.servers)
        self.assertEqual(self.h.cloud.servers[old_uuid]["state"], "started")
        self.assertEqual(self.h.dns(), old_ip)

    def test_прерванная_ротация_доигрывается(self):
        """Обрыв после снятия шаблона: перезапуск должен закончить дело, а не начать заново."""
        self.h.cloud.fail_on["POST /1.3/server"] = 1
        with self.assertRaises(Exception):
            self.h.engine.rotate("recreate", force=True)
        pending = self.h.state["pending"]
        self.assertIsNotNone(pending, "незавершённая ротация не сохранена")
        self.assertTrue(pending["data"].get("template_uuid"), "шаблон не запомнен")

        result = self.h.engine.resume_pending()
        self.assertIsNotNone(result)
        self.assertIsNone(self.h.state["pending"])
        # Шаблон переиспользован, второй раз не снимался.
        templatize_calls = [p for m, p in self.h.cloud.calls if p.endswith("/templatize")]
        self.assertEqual(len(templatize_calls), 1, "шаблон снят повторно вместо переиспользования")


class DryRunTest(unittest.TestCase):
    """Репетиция должна вести себя как настоящая ротация во всём, кроме действий."""

    def setUp(self):
        self.h = Harness(CONFIG.replace("[vpn]", "dry_run = true\n\n[vpn]")
                               .replace("cooldown_hours = 0", "cooldown_hours = 6"))

    def test_ничего_не_трогает_но_включает_предохранители(self):
        old_ip = self.h.ip
        result = self.h.engine.rotate("replace-ip", force=True)

        self.assertTrue(result["dry_run"])
        # Сервер и адрес не тронуты.
        self.assertEqual(self.h.cloud.servers[self.h.server_uuid]["state"], "started")
        self.assertIn(old_ip, self.h.cloud.ips)
        self.assertEqual(self.h.dns(), old_ip, "DNS не должен меняться вхолостую")
        # Но cooldown теперь держит — иначе автоматика слала бы алерт каждую минуту.
        self.assertIn("cooldown", self.h.engine.guard() or "")
        self.assertEqual(self.h.state["fail_streak"], 0, "серия неудач не сброшена")

    def test_попадает_в_историю_с_пометкой(self):
        self.h.engine.rotate("replace-ip", force=True)
        self.assertEqual(self.h.state["history"][0]["to"], "(холостой прогон)")


class VerdictTest(unittest.TestCase):
    """Отличать блок адреса от блока порта — то, ради чего детектор вообще нужен."""

    def setUp(self):
        self.h = Harness()

    def probe_with(self, work, control, state="started", reality=None):
        result = probes.ProbeResult(
            sanity=True, ip="203.0.113.9", work_port=work, control_port=control,
            server_state=state, reality=reality
        )
        result.verdict, result.confident = probes.Prober._verdict(result)
        return result

    def test_оба_порта_закрыты_это_блок_адреса(self):
        result = self.probe_with(False, False)
        self.assertEqual(result.verdict, probes.IP_BLOCKED)
        self.assertIn(result.verdict, probes.ROTATABLE)

    def test_рабочий_закрыт_контрольный_открыт_это_блок_порта(self):
        result = self.probe_with(False, True)
        self.assertEqual(result.verdict, probes.PORT_BLOCKED)
        self.assertNotIn(result.verdict, probes.ROTATABLE, "ротация не должна запускаться")

    def test_порт_открыт_но_сессия_рвётся_это_фингерпринт(self):
        result = self.probe_with(True, True, reality=False)
        self.assertEqual(result.verdict, probes.FINGERPRINT_BLOCKED)
        self.assertNotIn(result.verdict, probes.ROTATABLE)

    def test_сервер_не_запущен_это_не_блокировка(self):
        result = self.probe_with(False, False, state="stopped")
        self.assertEqual(result.verdict, probes.SERVER_DOWN)
        self.assertNotIn(result.verdict, probes.ROTATABLE)

    def test_пустой_адрес_это_не_блокировка(self):
        result = probes.ProbeResult(sanity=True, ip="", work_port=False, control_port=False)
        result.verdict, result.confident = probes.Prober._verdict(result)
        self.assertEqual(result.verdict, probes.UNKNOWN)
        self.assertNotIn(result.verdict, probes.ROTATABLE)

    def test_без_контрольного_порта_уверенности_нет(self):
        result = self.probe_with(False, None)
        self.assertEqual(result.verdict, probes.IP_BLOCKED)
        self.assertFalse(result.confident)


class GuardTest(unittest.TestCase):
    def test_cooldown_и_дневной_лимит_держат_ротацию(self):
        h = Harness(CONFIG.replace("cooldown_hours = 0", "cooldown_hours = 6")
                          .replace("max_per_day = 99", "max_per_day = 1"))
        modes.tcp_open = always_open
        try:
            h.engine.rotate("replace-ip", force=True)
            self.assertIn("cooldown", h.engine.guard() or "")
            with self.assertRaises(modes.RotationError):
                h.engine.rotate("replace-ip")
            # force снимает мягкий предохранитель.
            self.assertIsNone(h.engine.guard(force=True))
        finally:
            modes.tcp_open = probes.tcp_open

    def test_пауза_блокирует_автоматику_но_не_ручной_запуск(self):
        h = Harness()
        h.state["paused"] = True
        self.assertIn("на паузе", h.engine.guard() or "")
        self.assertIsNone(h.engine.guard(force=True))


class EscalationTest(unittest.TestCase):
    """Лестница: сначала адрес, потом зона, потом руки."""

    def setUp(self):
        self.h = Harness()

    def test_первая_блокировка_меняет_адрес(self):
        mode, zone = self.h.engine.choose()
        self.assertEqual(mode, modes.REPLACE_IP)
        self.assertEqual(zone, "")

    def test_быстрый_повтор_переезжает_в_другую_зону(self):
        self.h.state.record_rotation(modes.REPLACE_IP, "1.1.1.1", "2.2.2.2", "nl-ams1", "auto")
        mode, zone = self.h.engine.choose()
        self.assertEqual(mode, modes.RECREATE)
        self.assertEqual(zone, "fi-hel1")

    def test_после_переезда_эскалировать_некуда(self):
        self.h.state.record_rotation(modes.RECREATE, "1.1.1.1", "2.2.2.2", "fi-hel1", "auto")
        mode, _ = self.h.engine.choose()
        self.assertEqual(mode, "", "должен требовать человека, а не жечь адреса дальше")


if __name__ == "__main__":
    unittest.main(verbosity=2)
