"""Движок: цикл детектора, предохранители, лестница эскалации, докат ротации."""

from __future__ import annotations

import threading
import time
from typing import Any, Callable

from . import log, modes, probes
from .clouddns import Cloudflare
from .config import Config, Secrets
from .modes import Ctx, RotationError
from .probes import ProbeResult, Prober
from .state import State
from .upcloud import UpCloud

logger = log.get("engine")

Notify = Callable[[str], None]


class Engine:
    def __init__(
        self,
        cfg: Config,
        secrets: Secrets,
        state: State,
        uc: UpCloud,
        cf: Cloudflare,
        notify: Notify,
    ):
        self.cfg = cfg
        self.secrets = secrets
        self.state = state
        self.uc = uc
        self.cf = cf
        self.notify = notify
        self.lock = threading.Lock()
        self.busy = False
        self.prober = Prober(cfg, self._server_state)
        self._last_alert: tuple[str, float] = ("", 0.0)

    # --- вспомогательное ----------------------------------------------------

    def _server_state(self) -> str:
        uuid = self.secrets.get("SERVER_UUID")
        if not uuid:
            return ""
        return self.uc.server(uuid).get("state", "")

    def ctx(self, progress: Callable[[str], None] | None = None) -> Ctx:
        return Ctx(
            uc=self.uc,
            cf=self.cf,
            state=self.state,
            cfg=self.cfg,
            secrets=self.secrets,
            progress=progress or self.notify,
        )

    def current_ip(self) -> str:
        return self.state["ipv4"]

    def refresh(self) -> dict[str, Any]:
        return modes.collect(self.ctx(lambda _t: None))

    # --- пробы --------------------------------------------------------------

    def probe(self) -> ProbeResult:
        ip = self.current_ip()
        if not ip:
            try:
                ip = self.refresh()["ipv4"]
            except Exception as exc:                          # noqa: BLE001
                logger.warning("не удалось узнать текущий адрес: %s", exc)
        result = self.prober.run(ip)
        self.state.update(
            last_verdict=result.verdict,
            last_probe=result.as_dict(),
            last_probe_ts=result.ts,
        )
        return result

    # --- предохранители -----------------------------------------------------

    def guard(self, *, force: bool = False) -> str | None:
        """Возвращает причину, по которой ротацию запускать нельзя."""
        if self.busy:
            return "ротация уже идёт"
        if self.state["pending"]:
            return "есть незавершённая ротация — сначала докатываю её"
        if force:
            return None
        if self.state["paused"]:
            return "автоматика на паузе (/resume чтобы снять)"
        cooldown = float(self.cfg.get("rotation.cooldown_hours", 6))
        since = self.state.hours_since_last_rotation()
        if since < cooldown:
            return f"не прошёл cooldown: с прошлой ротации {since:.1f} ч из {cooldown:g}"
        limit = int(self.cfg.get("rotation.max_per_day", 2))
        today = self.state.rotations_today()
        if today >= limit:
            return f"исчерпан дневной лимит ({today}/{limit}) — подтвердите вручную через /rotate"
        return None

    # --- выбор режима -------------------------------------------------------

    def choose(self) -> tuple[str, str]:
        """(режим, зона). Пустой режим — эскалировать некуда, нужен человек."""
        configured = self.state["mode"] or self.cfg.get("rotation.mode", "auto")
        if configured != "auto" and configured not in modes.ALL_MODES:
            # Например, сохранённый replace-ip из старой версии.
            logger.warning("режим %r больше не поддерживается — работаю как auto", configured)
            configured = "auto"
        if configured != "auto":
            # Переезду нужна целевая локация, иначе он не стартует.
            return configured, self.next_zone() if configured == modes.MOVE else ""

        history = self.state["history"]
        escalate_after = float(self.cfg.get("rotation.escalate_after_hours", 6))
        since = self.state.hours_since_last_rotation()

        if not history or since >= escalate_after:
            # Обычный случай: копия сервера в той же локации, адрес бесплатный.
            return modes.CLONE, ""

        last = history[0]
        if last.get("mode") == modes.MOVE:
            # Уже переезжали — и снова блок. Дальше гонять адреса бессмысленно.
            return "", ""

        # Адрес умер слишком быстро: дело в подсети, а не в адресе — меняем локацию.
        return modes.MOVE, self.next_zone()

    def next_zone(self) -> str:
        rotation = list(self.cfg.get("rotation.zone_rotation", []) or [])
        current = self.state["zone"]
        for zone in rotation:
            if zone != current:
                return zone
        return ""

    # --- ротация ------------------------------------------------------------

    def rotate(
        self,
        mode: str = "",
        zone: str = "",
        *,
        reason: str = "manual",
        force: bool = False,
        progress: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        # force снимает мягкие предохранители (cooldown, дневной лимит, пауза),
        # но не жёсткие: параллельная и незавершённая ротации остаются запретом.
        blocked = self.guard(force=force)
        if blocked:
            raise RotationError(blocked)

        if not mode:
            mode, auto_zone = self.choose()
            zone = zone or auto_zone
            if not mode:
                raise RotationError(
                    "эскалировать некуда: прошлый переезд в другую зону не помог. "
                    "Дело не в адресе — меняйте порт, dest/SNI Reality или транспорт"
                )

        with self.lock:
            self.busy = True
            try:
                return modes.run(self.ctx(progress), mode, zone=zone, reason=reason)
            finally:
                self.busy = False

    def resume_pending(self, progress: Callable[[str], None] | None = None) -> dict[str, Any] | None:
        """Доиграть ротацию, прерванную рестартом или падением."""
        pending = self.state["pending"]
        if not pending:
            return None
        mode = pending.get("mode", "")
        step = pending.get("step", "?")
        data = pending.get("data", {})

        if mode not in modes.ALL_MODES:
            # Например, оставшаяся от убранного replace-ip. Доигрывать нечего,
            # но сервер после неё мог остаться выключенным.
            self.state.clear_pending()
            self.notify(
                f"⚠️ найдена незавершённая ротация в режиме {mode}, которого больше нет "
                f"(шаг «{step}»). Запись убрана. Проверяю, работает ли сервер…"
            )
            modes._ensure_running(self.ctx(progress), self.secrets.get("SERVER_UUID"))
            return None

        self.notify(f"⚠️ найдена незавершённая ротация {mode} на шаге «{step}» — доигрываю")
        with self.lock:
            self.busy = True
            try:
                return modes.run(
                    self.ctx(progress),
                    mode,
                    zone=data.get("target_zone", ""),
                    reason="resume",
                    resume=data,
                )
            finally:
                self.busy = False

    # --- цикл детектора -----------------------------------------------------

    def detector_loop(self, stop_event: threading.Event) -> None:
        interval = int(self.cfg.get("detector.interval_sec", 60))
        threshold = int(self.cfg.get("detector.fail_threshold", 5))
        logger.info("детектор запущен: интервал %s с, порог %s", interval, threshold)

        while not stop_event.is_set():
            try:
                self._tick(threshold)
            except Exception as exc:                          # noqa: BLE001 — цикл не должен умирать
                logger.exception("сбой в цикле детектора: %s", exc)
            stop_event.wait(interval)

    def _tick(self, threshold: int) -> None:
        if self.busy:
            return
        result = self.probe()

        if result.verdict == probes.OK:
            if self.state["fail_streak"]:
                self.notify(f"✅ связь восстановилась: {result.short()}")
            self.state.update(fail_streak=0)
            return

        if result.verdict == probes.OWN_NET_DOWN:
            logger.info("свой канал недоступен — пропускаю проверку")
            return

        if result.verdict not in probes.ROTATABLE:
            # Блок порта, фингерпринт, лежащий сервер — ротация не поможет.
            self._alert_once(
                f"⚠️ {probes.VERDICT_TEXT[result.verdict]}\n{result.short()}\n"
                f"Ротация НЕ запускается. /rotate — если всё же хотите сменить адрес."
            )
            self.state.update(fail_streak=0)
            return

        streak = self.state["fail_streak"] + 1
        self.state.update(fail_streak=streak)
        logger.warning("вердикт %s, серия %s/%s", result.verdict, streak, threshold)
        if streak < threshold:
            return

        if not result.confident:
            self._alert_once(
                "⚠️ похоже на блокировку адреса, но уверенности нет "
                "(контрольный порт отключён или API молчит). Проверьте и запустите /rotate вручную."
            )
            return

        blocked = self.guard()
        if blocked:
            self._alert_once(f"⚠️ блокировка адреса подтверждена, но ротация не запущена: {blocked}")
            return

        mode, zone = self.choose()
        if not mode:
            self._alert_once(
                "⚠️ блокировка после переезда в другую зону. Смена адреса больше не поможет — "
                "меняйте порт, dest/SNI Reality или транспорт."
            )
            return

        self.notify(
            f"🚨 {probes.VERDICT_TEXT[result.verdict]}\n{result.short()}\n"
            f"Запускаю ротацию: {mode}" + (f" → {zone}" if zone else "")
        )
        try:
            self.rotate(mode, zone, reason=f"auto:{result.verdict}")
        except Exception as exc:                              # noqa: BLE001
            self.notify(f"❌ ротация не удалась: {exc}")

    def _alert_once(self, text: str, repeat_after_sec: int = 3600) -> None:
        """Один и тот же алерт не чаще раза в час."""
        now = time.time()
        last_text, last_ts = self._last_alert
        if text == last_text and now - last_ts < repeat_after_sec:
            return
        self._last_alert = (text, now)
        self.notify(text)
