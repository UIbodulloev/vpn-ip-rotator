"""Бот пересылает события обоих сторожей с VPN-сервера одним заходом по SSH."""
from __future__ import annotations

import json
import unittest

from rotator import bot as botmod, remote
from tests.test_bot_setup import TMP, BotHarness


class WatchEventsTest(unittest.TestCase):
    def setUp(self):
        self.h = BotHarness()
        self.h.secrets.set("SSH_KEY_PATH", str(TMP / "fake-key"))
        (TMP / "fake-key").write_text("x")
        self.h.state.update(ipv4="203.0.113.11")
        self.reply = remote.Result(0, "", "")
        self.calls: list[str] = []

        def fake_run(host, command, **kw):
            self.calls.append(command)
            return self.reply

        original, botmod.remote.run = botmod.remote.run, fake_run
        self.addCleanup(lambda: setattr(botmod.remote, "run", original))

    def answer(self, guard: list, watch: list) -> None:
        out = json.dumps(guard) + "\n" + botmod.Bot._EVENTS_SPLIT + "\n" + json.dumps(watch)
        self.reply = remote.Result(0, out, "")

    def test_first_run_only_remembers_the_moment(self):
        self.h.bot.guard_report()
        self.assertEqual(self.calls, [])
        self.assertGreater(self.h.state["guard_seen_ts"], 0)
        self.assertGreater(self.h.state["watch_seen_ts"], 0)

    def test_events_of_both_guards_reach_the_owner(self):
        self.h.state.update(guard_seen_ts=100, watch_seen_ts=100)
        self.answer(
            [{"t": 200, "kind": "blocked", "user": "anna", "limit": 1,
              "owner": ["10.1.1.5"], "others": ["20.2.2.7"], "minutes": 30}],
            [{"t": 300, "kind": "restarted", "text": "контейнер 3x-ui был в состоянии exited — перезапущено"},
             {"t": 310, "kind": "tight", "text": "свободной памяти 60 МБ уже 3 мин"}],
        )
        self.h.bot.guard_report()
        self.assertEqual(len(self.calls), 1)               # один заход на оба сторожа
        seen = self.h.tg.all_visible()
        self.assertIn("anna", seen)
        self.assertIn("Починил сам", seen)
        self.assertIn("VPN-серверу тесно", seen)
        self.assertEqual(self.h.state["guard_seen_ts"], 200)
        self.assertEqual(self.h.state["watch_seen_ts"], 310)

    def test_old_server_without_watchdog_still_works(self):
        self.h.state.update(guard_seen_ts=100, watch_seen_ts=100)
        self.reply = remote.Result(0, "[]\n" + botmod.Bot._EVENTS_SPLIT + "\n[]", "")
        self.h.bot.guard_report()
        self.assertEqual(self.h.state["watch_seen_ts"], 100)

    def test_unreachable_server_is_an_error(self):
        self.h.state.update(guard_seen_ts=100, watch_seen_ts=100)
        self.reply = remote.Result(255, "", "ssh: connect to host 203.0.113.11 port 22: Connection timed out")
        with self.assertRaises(remote.RemoteError):
            self.h.bot.guard_report()


if __name__ == "__main__":
    unittest.main()
