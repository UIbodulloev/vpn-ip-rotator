"""Три режима смены адреса: replace-ip, recreate, floating.

Каждый шаг фиксируется в state перед выполнением, поэтому упавшую посреди дела
ротацию можно доиграть, а не начинать заново с остановленным или удалённым сервером.
"""

from __future__ import annotations

import shlex
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Callable

from . import log, upcloud
from .clouddns import Cloudflare
from .config import Config, Secrets, domain_of
from .probes import tcp_open
from .state import State
from .upcloud import UpCloud, UpCloudError

logger = log.get("modes")

REPLACE_IP = "replace-ip"
RECREATE = "recreate"
FLOATING = "floating"
ALL_MODES = (REPLACE_IP, RECREATE, FLOATING)

NETPLAN_FILE = "/etc/netplan/99-floating.yaml"


class RotationError(RuntimeError):
    pass


@dataclass
class Ctx:
    uc: UpCloud
    cf: Cloudflare
    state: State
    cfg: Config
    secrets: Secrets
    progress: Callable[[str], None]

    def say(self, text: str) -> None:
        logger.info(text)
        try:
            self.progress(text)
        except Exception:                                    # noqa: BLE001 — уведомление не должно ронять ротацию
            logger.debug("не удалось отправить прогресс", exc_info=True)


# --- общие шаги -------------------------------------------------------------


def collect(ctx: Ctx) -> dict[str, Any]:
    """Снимок сервера в state: без него нечего восстанавливать после сбоя."""
    uuid = ctx.secrets.get("SERVER_UUID")
    if not uuid:
        raise RotationError("SERVER_UUID не задан — пройдите /setup")
    info = upcloud.summarize(ctx.uc.server(uuid))
    ctx.state.update(
        server_uuid=info["uuid"] or uuid,
        storage_uuid=info["storage_uuid"],
        hostname=info["hostname"],
        plan=info["plan"],
        zone=info["zone"],
        ipv4=info["ipv4"],
        ipv6=info["ipv6"],
        eth0_mac=info["mac"],
    )
    return info


def update_dns(ctx: Ctx, ipv4: str, ipv6: str = "") -> list[str]:
    """Обновляет A и, если настроено, AAAA. Возвращает человекочитаемый отчёт."""
    zone_id = ctx.secrets.get("CF_ZONE_ID")
    domain = domain_of(ctx.cfg, ctx.secrets)
    ttl = int(ctx.cfg.get("rotation.dns_ttl", 60))
    done: list[str] = []

    a_record = ctx.secrets.get("CF_A_RECORD_ID")
    if ipv4 and zone_id and a_record:
        ctx.cf.update_record(zone_id, a_record, rtype="A", name=domain, content=ipv4, ttl=ttl)
        done.append(f"A → {ipv4}")

    aaaa_record = ctx.secrets.get("CF_AAAA_RECORD_ID")
    if ipv6 and zone_id and aaaa_record and ctx.cfg.get("vpn.update_aaaa", True):
        ctx.cf.update_record(zone_id, aaaa_record, rtype="AAAA", name=domain, content=ipv6, ttl=ttl)
        done.append(f"AAAA → {ipv6}")

    if not done:
        raise RotationError("DNS не обновлён: не заданы CF_ZONE_ID/CF_A_RECORD_ID")
    return done


def wait_service(ctx: Ctx, ip: str) -> bool:
    """Ждём, пока на новом адресе поднимется рабочий порт."""
    port = int(ctx.cfg.get("vpn.probe_port", 443))
    deadline = time.monotonic() + int(ctx.cfg.get("rotation.wait_service_sec", 240))
    while time.monotonic() < deadline:
        if tcp_open(ip, port, 5.0):
            return True
        time.sleep(5)
    return False


def _stop_and_wait(ctx: Ctx, uuid: str) -> None:
    timeout = int(ctx.cfg.get("rotation.wait_stop_sec", 240))
    server = ctx.uc.server(uuid)
    if server.get("state") == "stopped":
        ctx.say("сервер уже остановлен")
        return
    ctx.say("останавливаю сервер (soft)…")
    ctx.uc.stop_server(uuid, "soft", 60)
    try:
        ctx.uc.wait_server_state(uuid, "stopped", timeout)
    except TimeoutError:
        ctx.say("soft-стоп не уложился в таймаут — принудительная остановка")
        ctx.uc.stop_server(uuid, "hard")
        ctx.uc.wait_server_state(uuid, "stopped", 120)
    ctx.say("сервер остановлен")


def _start_and_wait(ctx: Ctx, uuid: str) -> dict[str, Any]:
    ctx.say("запускаю сервер…")
    ctx.uc.start_server(uuid)
    server = ctx.uc.wait_server_state(uuid, "started", int(ctx.cfg.get("rotation.wait_start_sec", 300)))
    ctx.say("сервер запущен")
    return server


def _finish(ctx: Ctx, mode: str, old_ip: str, new_ip: str, zone: str, reason: str, dns: list[str]) -> dict[str, Any]:
    ctx.state.record_rotation(mode, old_ip, new_ip, zone, reason)
    ctx.state.clear_pending()
    ctx.state.update(fail_streak=0)
    alive = wait_service(ctx, new_ip)
    ctx.say(
        f"готово: {old_ip or '—'} → {new_ip}, {', '.join(dns)}, "
        + ("рабочий порт отвечает" if alive else "рабочий порт пока молчит — проверьте вручную")
    )
    return {"mode": mode, "old_ip": old_ip, "new_ip": new_ip, "zone": zone, "service_up": alive}


# --- режим 1: replace-ip ----------------------------------------------------


def replace_ip(ctx: Ctx, reason: str = "manual", resume: dict[str, Any] | None = None) -> dict[str, Any]:
    """Стоп → новый IPv4 на MAC eth0 → освободить старый → старт. ~2-3 минуты, бесплатно."""
    data: dict[str, Any] = dict(resume or {})
    uuid = ctx.secrets.get("SERVER_UUID")

    if not data.get("old_ip"):
        info = collect(ctx)
        if not info["mac"]:
            raise RotationError("не удалось определить MAC публичного интерфейса")
        data.update(old_ip=info["ipv4"], mac=info["mac"], zone=info["zone"])
        ctx.state.set_pending(REPLACE_IP, "collected", **data)

    ctx.say(f"режим replace-ip, текущий адрес {data['old_ip']}")

    if not data.get("stopped"):
        ctx.state.set_pending(REPLACE_IP, "stopping", **data)
        _stop_and_wait(ctx, uuid)
        data["stopped"] = True
        ctx.state.set_pending(REPLACE_IP, "stopped", **data)

    if not data.get("new_ip"):
        ctx.state.set_pending(REPLACE_IP, "assigning", **data)
        ctx.say("заказываю новый IPv4 на существующий интерфейс…")
        # MAC указывается намеренно: адрес садится на eth0, а не создаёт новый
        # интерфейс — иначе на сервере пришлось бы править netplan.
        assigned = ctx.uc.assign_ip(server_uuid=uuid, mac=data["mac"], family="IPv4")
        data["new_ip"] = assigned.get("address", "")
        if not data["new_ip"]:
            raise RotationError(f"UpCloud не вернул адрес: {assigned}")
        ctx.state.set_pending(REPLACE_IP, "assigned", **data)
        ctx.say(f"выдан {data['new_ip']}")

    if not data.get("released"):
        # Строго после выдачи нового: интерфейс не должен остаться без адресов.
        ctx.state.set_pending(REPLACE_IP, "releasing", **data)
        for attempt in range(3):
            try:
                ctx.uc.release_ip(data["old_ip"])
                data["released"] = True
                break
            except UpCloudError as exc:
                logger.warning("попытка %s освободить %s: %s", attempt + 1, data["old_ip"], exc)
                time.sleep(5)
        ctx.state.set_pending(REPLACE_IP, "released", **data)

    if not data.get("released"):
        # Старый адрес остался — DHCP может выдать при старте именно его.
        # Поднимаем сервер, но DNS не трогаем и зовём человека.
        _start_and_wait(ctx, uuid)
        ctx.state.clear_pending()
        raise RotationError(
            f"не удалось освободить {data['old_ip']}. Сервер запущен со старым адресом, "
            "DNS не менялся — разберитесь в панели UpCloud вручную"
        )

    ctx.say(f"старый {data['old_ip']} освобождён")
    server = _start_and_wait(ctx, uuid)
    info = upcloud.summarize(server)
    actual_ip = info["ipv4"] or data["new_ip"]
    ctx.state.update(ipv4=actual_ip, ipv6=info["ipv6"], eth0_mac=info["mac"])

    dns = update_dns(ctx, actual_ip, info["ipv6"])
    return _finish(ctx, REPLACE_IP, data["old_ip"], actual_ip, info["zone"], reason, dns)


# --- режим 2: recreate ------------------------------------------------------


def recreate(
    ctx: Ctx,
    zone: str = "",
    reason: str = "manual",
    resume: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Шаблон диска → новый сервер (в той же или другой зоне) → удалить старый.

    Новый сервер создаётся ДО удаления старого: если что-то сорвётся, старый
    просто запускается обратно, а не остаётся удалённым.
    """
    data: dict[str, Any] = dict(resume or {})
    old_uuid = data.get("old_uuid") or ctx.secrets.get("SERVER_UUID")

    if not data.get("collected"):
        info = collect(ctx)
        data.update(
            collected=True,
            old_uuid=info["uuid"] or old_uuid,
            old_ip=info["ipv4"],
            old_ipv6=info["ipv6"],
            src_zone=info["zone"],
            plan=info["plan"],
            hostname=info["hostname"],
            title=info["title"] or info["hostname"],
            storage_uuid=info["storage_uuid"],
            storage_size=info["storage_size"],
            storage_tier=info["storage_tier"] or "standard",
        )
        old_uuid = data["old_uuid"]
        ctx.state.set_pending(RECREATE, "collected", **data)

    target_zone = zone or data.get("target_zone") or data["src_zone"]
    data["target_zone"] = target_zone
    same_zone = target_zone == data["src_zone"]
    ctx.say(
        f"режим recreate, {data['old_ip']} в {data['src_zone']} → новый сервер в {target_zone}"
        + ("" if same_zone else " (кросс-зонный клон, это долго)")
    )

    try:
        if not data.get("stopped"):
            ctx.state.set_pending(RECREATE, "stopping", **data)
            _stop_and_wait(ctx, old_uuid)
            data["stopped"] = True
            ctx.state.set_pending(RECREATE, "stopped", **data)

        if not data.get("template_uuid"):
            ctx.state.set_pending(RECREATE, "templatizing", **data)
            ctx.say("снимаю шаблон системного диска (ключи, клиенты, swap — всё внутри)…")
            stamp = time.strftime("%Y%m%d-%H%M%S")
            template = ctx.uc.templatize(data["storage_uuid"], f"rotator-{data['hostname']}-{stamp}")
            data["template_uuid"] = template.get("uuid", "")
            if not data["template_uuid"]:
                raise RotationError(f"templatize не вернул uuid: {template}")
            ctx.state.set_pending(RECREATE, "templatizing", **data)
            ctx.uc.wait_storage_online(
                data["template_uuid"],
                int(ctx.cfg.get("rotation.wait_storage_sec", 3600)),
                on_tick=lambda st, left: ctx.say(f"шаблон готовится… ({st}, осталось ≤{left} с)"),
            )
            ctx.state.add_template(data["template_uuid"], data["src_zone"])
            ctx.say("шаблон готов")

        # Кросс-зонный переезд: клонируем шаблон в целевую зону и делаем шаблон уже там.
        if not same_zone and not data.get("zone_template_uuid"):
            ctx.state.set_pending(RECREATE, "cloning", **data)
            ctx.say(f"копирую диск в {target_zone} — самый долгий шаг…")
            clone = ctx.uc.clone_storage(
                data["template_uuid"], target_zone, f"rotator-clone-{target_zone}-{int(time.time())}"
            )
            data["clone_uuid"] = clone.get("uuid", "")
            ctx.state.set_pending(RECREATE, "cloning", **data)
            ctx.uc.wait_storage_online(
                data["clone_uuid"],
                int(ctx.cfg.get("rotation.wait_storage_sec", 3600)),
                on_tick=lambda st, left: ctx.say(f"копирование… ({st}, осталось ≤{left} с)"),
            )
            zone_template = ctx.uc.templatize(data["clone_uuid"], f"rotator-{target_zone}-{int(time.time())}")
            data["zone_template_uuid"] = zone_template.get("uuid", "")
            ctx.state.set_pending(RECREATE, "cloning", **data)
            ctx.uc.wait_storage_online(
                data["zone_template_uuid"], int(ctx.cfg.get("rotation.wait_storage_sec", 3600))
            )
            ctx.state.add_template(data["zone_template_uuid"], target_zone)
            ctx.say(f"диск в {target_zone} готов")

        source_template = data.get("zone_template_uuid") or data["template_uuid"]

        if not data.get("new_uuid"):
            ctx.state.set_pending(RECREATE, "creating", **data)
            ctx.say("создаю новый сервер из шаблона…")
            created = ctx.uc.create_server(_server_spec(ctx, data, source_template, target_zone))
            data["new_uuid"] = created.get("uuid", "")
            if not data["new_uuid"]:
                raise RotationError(f"create_server не вернул uuid: {created}")
            ctx.state.set_pending(RECREATE, "created", **data)

        server = ctx.uc.wait_server_state(
            data["new_uuid"],
            "started",
            int(ctx.cfg.get("rotation.wait_start_sec", 300)),
            on_tick=lambda st, left: ctx.say(f"новый сервер поднимается… ({st})"),
        )
        info = upcloud.summarize(server)
        data["new_ip"] = info["ipv4"]
        data["new_ipv6"] = info["ipv6"]
        ctx.state.set_pending(RECREATE, "started", **data)
        ctx.say(f"новый сервер {info['uuid'][:8]}… поднялся на {info['ipv4']}")

        _grant_permission(ctx, data["new_uuid"])

        ctx.secrets.set("SERVER_UUID", data["new_uuid"])
        ctx.state.update(
            server_uuid=info["uuid"],
            storage_uuid=info["storage_uuid"],
            hostname=info["hostname"],
            plan=info["plan"],
            zone=info["zone"],
            ipv4=info["ipv4"],
            ipv6=info["ipv6"],
            eth0_mac=info["mac"],
        )

    except Exception as exc:
        # До обновления DNS всё обратимо: возвращаем старый сервер в строй.
        ctx.say(f"сбой: {exc}. Пробую вернуть старый сервер в работу…")
        try:
            _start_and_wait(ctx, old_uuid)
            ctx.say(f"старый сервер снова работает на {data.get('old_ip')}, DNS не менялся")
        except Exception as recovery_exc:                    # noqa: BLE001
            ctx.say(f"вернуть старый сервер не удалось: {recovery_exc}. Нужны руки в панели UpCloud")
        raise

    dns = update_dns(ctx, data["new_ip"], data.get("new_ipv6", ""))

    # Точка невозврата пройдена — старый сервер больше не нужен.
    ctx.state.set_pending(RECREATE, "deleting-old", **data)
    try:
        ctx.uc.delete_server(old_uuid, storages=True, backups="delete")
        ctx.say(f"старый сервер удалён, адрес {data['old_ip']} освобождён")
    except UpCloudError as exc:
        ctx.say(f"старый сервер удалить не удалось ({exc}) — удалите вручную, он тарифицируется")

    _prune_templates(ctx, keep=int(ctx.cfg.get("rotation.keep_templates", 1)), extra=[data.get("clone_uuid", "")])
    return _finish(ctx, RECREATE, data["old_ip"], data["new_ip"], target_zone, reason, dns)


def _server_spec(ctx: Ctx, data: dict[str, Any], template_uuid: str, zone: str) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "zone": zone,
        "title": data.get("title") or data["hostname"],
        "hostname": data["hostname"],
        "plan": data["plan"],
        "storage_devices": {
            "storage_device": [
                {
                    "action": "clone",
                    "storage": template_uuid,
                    "title": f"{data['hostname']}-osdisk",
                    "size": int(data["storage_size"]) or 10,
                    # Кастомный шаблон разворачивается только на тот же тир хранилища.
                    "tier": data.get("storage_tier") or "standard",
                }
            ]
        },
        "networking": {
            "interfaces": {
                "interface": [
                    {"type": "public", "ip_addresses": {"ip_address": [{"family": "IPv4"}]}},
                    {"type": "utility", "ip_addresses": {"ip_address": [{"family": "IPv4"}]}},
                    {"type": "public", "ip_addresses": {"ip_address": [{"family": "IPv6"}]}},
                ]
            }
        },
    }
    pubkey = ctx.secrets.get("SSH_PUBKEY")
    if pubkey:
        spec["login_user"] = {"username": "root", "ssh_keys": {"ssh_key": [pubkey]}}
    return spec


def _grant_permission(ctx: Ctx, new_uuid: str) -> None:
    """Субаккаунт не видит только что созданный сервер, пока ему не выдали права."""
    subaccount = ctx.secrets.get("UPCLOUD_SUBACCOUNT")
    if not subaccount:
        return
    if not ctx.secrets.get("UPCLOUD_ADMIN_TOKEN"):
        ctx.say(
            "⚠️ UPCLOUD_ADMIN_TOKEN не задан: субаккаунт не получит права на новый сервер. "
            "Выдайте их в панели, иначе следующая ротация не пройдёт"
        )
        return
    try:
        ctx.uc.grant_server_permission(subaccount, new_uuid)
        ctx.say(f"права субаккаунта {subaccount} на новый сервер выданы")
    except UpCloudError as exc:
        ctx.say(f"⚠️ не удалось выдать права субаккаунту: {exc}")


def _prune_templates(ctx: Ctx, keep: int, extra: list[str]) -> None:
    """Оставляем последний шаблон как точку отката, промежуточные клоны удаляем."""
    for uuid in [u for u in extra if u]:
        try:
            ctx.uc.delete_storage(uuid)
            ctx.state.drop_template(uuid)
        except UpCloudError as exc:
            logger.warning("промежуточный диск %s не удалён: %s", uuid, exc)

    # keep=0 — удалить все шаблоны: точки отката не будет, зато не тарифицируется.
    templates = ctx.state["templates"]
    for entry in templates[max(keep, 0):]:
        try:
            ctx.uc.delete_storage(entry["uuid"])
            ctx.state.drop_template(entry["uuid"])
            logger.info("удалён устаревший шаблон %s", entry["uuid"])
        except UpCloudError as exc:
            logger.warning("шаблон %s не удалён: %s", entry["uuid"], exc)


# --- режим 3: floating ------------------------------------------------------


def floating(ctx: Ctx, reason: str = "manual", resume: dict[str, Any] | None = None) -> dict[str, Any]:
    """Плавающий адрес на живом сервере: нулевой даунтайм, но нужен SSH и ~$3.5/мес."""
    data: dict[str, Any] = dict(resume or {})
    uuid = ctx.secrets.get("SERVER_UUID")
    key_path = ctx.secrets.get("SSH_KEY_PATH")
    if not key_path:
        raise RotationError("режиму floating нужен SSH_KEY_PATH — задайте его в /setup")

    if not data.get("collected"):
        info = collect(ctx)
        data.update(collected=True, mac=info["mac"], primary_ip=info["ipv4"], ipv6=info["ipv6"], zone=info["zone"])
        ctx.state.set_pending(FLOATING, "collected", **data)

    previous = ctx.state.data.get("floating_ip", "")
    data.setdefault("old_ip", previous or data["primary_ip"])

    # SSH идёт по любому ещё живому адресу: рабочий порт может быть заблокирован,
    # а 22-й при этом открыт — ровно этот случай различает детектор.
    ssh_host = _pick_ssh_host(ctx, [previous, data["primary_ip"], data.get("ipv6", "")])
    if not ssh_host:
        raise RotationError(
            "ни один адрес сервера не отвечает по SSH — floating тут не сработает, "
            "используйте replace-ip или recreate"
        )
    data["ssh_host"] = ssh_host

    if not data.get("new_ip"):
        ctx.state.set_pending(FLOATING, "assigning", **data)
        ctx.say("заказываю плавающий адрес (сервер продолжает работать)…")
        assigned = ctx.uc.assign_ip(
            mac=data["mac"], family="IPv4", floating=True, release_policy="release"
        )
        data["new_ip"] = assigned.get("address", "")
        if not data["new_ip"]:
            raise RotationError(f"UpCloud не вернул плавающий адрес: {assigned}")
        ctx.state.set_pending(FLOATING, "assigned", **data)
        ctx.say(f"выдан {data['new_ip']}")

    if not data.get("configured"):
        ctx.state.set_pending(FLOATING, "configuring", **data)
        ctx.say(f"поднимаю адрес на интерфейсе через SSH ({ssh_host})…")
        _apply_netplan(ctx, ssh_host, key_path, data["new_ip"])
        data["configured"] = True
        ctx.state.set_pending(FLOATING, "configured", **data)

    ctx.state.data["floating_ip"] = data["new_ip"]
    ctx.state.save()

    dns = update_dns(ctx, data["new_ip"], data.get("ipv6", ""))

    # Освобождаем только предыдущий плавающий адрес: основной DHCP-адрес сервера
    # трогать нельзя, пока сервер работает.
    if previous and previous != data["new_ip"]:
        try:
            ctx.uc.release_ip(previous)
            ctx.say(f"предыдущий плавающий {previous} освобождён (тарификация прекращена)")
        except UpCloudError as exc:
            ctx.say(f"⚠️ {previous} не освобождён ({exc}) — он продолжает тарифицироваться")

    return _finish(ctx, FLOATING, data["old_ip"], data["new_ip"], data["zone"], reason, dns)


def _pick_ssh_host(ctx: Ctx, candidates: list[str]) -> str:
    port = int(ctx.cfg.get("vpn.control_port", 22)) or 22
    for host in candidates:
        if host and tcp_open(host, port, 5.0):
            return host
    return ""


def _apply_netplan(ctx: Ctx, host: str, key_path: str, ip: str) -> None:
    netplan = (
        "network:\n"
        "  version: 2\n"
        "  renderer: networkd\n"
        "  ethernets:\n"
        "    eth0:\n"
        "      addresses:\n"
        f"        - {ip}/32\n"
    )
    remote = (
        f"umask 077 && cat > {NETPLAN_FILE} <<'NPEOF'\n{netplan}NPEOF\n"
        f"netplan apply && ip -4 addr show dev eth0 | grep -q {shlex.quote(ip)}"
    )
    port = int(ctx.cfg.get("vpn.control_port", 22)) or 22
    cmd = [
        "ssh",
        "-i", key_path,
        "-p", str(port),
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=10",
        "-o", "BatchMode=yes",
        f"root@{host}",
        remote,
    ]
    completed = subprocess.run(cmd, capture_output=True, timeout=90, check=False)
    if completed.returncode != 0:
        raise RotationError(
            f"netplan на сервере не применился (код {completed.returncode}): "
            f"{completed.stderr.decode(errors='replace')[:300]}"
        )


# --- диспетчер --------------------------------------------------------------

RUNNERS: dict[str, Callable[..., dict[str, Any]]] = {
    REPLACE_IP: replace_ip,
    RECREATE: recreate,
    FLOATING: floating,
}


def run(ctx: Ctx, mode: str, *, zone: str = "", reason: str = "manual", resume: dict[str, Any] | None = None):
    if mode not in RUNNERS:
        raise RotationError(f"неизвестный режим {mode!r}, доступны: {', '.join(ALL_MODES)}")
    if ctx.cfg.get("dry_run"):
        # Репетиция должна вести себя как настоящая ротация во всём, кроме
        # действий: иначе cooldown и дневной лимит не применяются, серия неудач
        # не сбрасывается, и автоматика присылает «запускаю ротацию» каждую минуту.
        current = ctx.state["ipv4"]
        ctx.say(
            f"dry_run: ротация {mode}"
            + (f" → {zone}" if zone else "")
            + f" НЕ выполняется. В боевом режиме адрес {current or '—'} сменился бы сейчас."
        )
        ctx.state.record_rotation(mode, current, "(холостой прогон)", zone or ctx.state["zone"], reason)
        ctx.state.update(fail_streak=0)
        return {"mode": mode, "dry_run": True, "old_ip": current, "new_ip": "(холостой прогон)"}
    if mode == RECREATE:
        return recreate(ctx, zone=zone, reason=reason, resume=resume)
    return RUNNERS[mode](ctx, reason=reason, resume=resume)
