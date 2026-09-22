"""Расчёт расходов по прайсу аккаунта UpCloud.

Цены из GET /1.3/price приходят в СОТЫХ долях валюты за час: например
server_plan_1xCPU-2GB = 2.2321 означает 2.2321 цента в час, то есть ≈16.3 в месяц.
Проверено сверкой трёх позиций с публичным прайсом UpCloud.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

HOURS_PER_MONTH = 730          # среднее: 365 * 24 / 12
CENTS = 100.0


def monthly(price_per_hour_cents: float, units: float = 1.0) -> float:
    return price_per_hour_cents * units * HOURS_PER_MONTH / CENTS


@dataclass
class Line:
    what: str
    detail: str
    per_month: float
    always: bool = True        # False — платится только во время операции


@dataclass
class Estimate:
    currency: str = "?"
    lines: list[Line] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)

    @property
    def standing(self) -> float:
        return sum(line.per_month for line in self.lines if line.always)

    @property
    def transient(self) -> float:
        return sum(line.per_month for line in self.lines if not line.always)


def zone_prices(prices: list[dict[str, Any]], zone: str) -> dict[str, Any]:
    for entry in prices:
        if entry.get("name") == zone:
            return entry
    return prices[0] if prices else {}


def _price(zone: dict[str, Any], key: str) -> tuple[float, float] | None:
    entry = zone.get(key)
    if not isinstance(entry, dict) or "price" not in entry:
        return None
    return float(entry["price"]), float(entry.get("amount") or 1)


def _plan_price(zone: dict[str, Any], plan: str) -> tuple[float, float] | None:
    """План может называться по-разному в прайсе — ищем без учёта регистра."""
    direct = _price(zone, f"server_plan_{plan}")
    if direct:
        return direct
    wanted = f"server_plan_{plan}".lower()
    for key in zone:
        if key.lower() == wanted:
            return _price(zone, key)
    return None


def _storage_price(zone: dict[str, Any], tier: str) -> tuple[float, float] | None:
    for key in (f"storage_{tier}", "storage_maxiops", "storage_standard", "storage_hdd"):
        found = _price(zone, key)
        if found:
            return found
    return None


def estimate(
    *,
    prices: list[dict[str, Any]],
    currency: str,
    server: dict[str, Any],
    storages: list[dict[str, Any]],
    ip_addresses: list[dict[str, Any]],
    template_uuids: set[str],
) -> Estimate:
    """Разбивка: что платится всегда, а что — только во время ротации."""
    out = Estimate(currency=currency)
    zone = zone_prices(prices, server.get("zone", ""))
    if not zone:
        out.unknown.append("прайс аккаунта не прочитался")
        return out

    plan = server.get("plan", "")
    plan_price = _plan_price(zone, plan)
    if plan_price:
        price, units = plan_price
        out.lines.append(Line("Сервер", f"{plan}, {server.get('zone')}", monthly(price, 1 / units)))
    else:
        out.unknown.append(f"цена плана {plan} не найдена в прайсе")

    # Диск сервера входит в план. Отдельно тарифицируются шаблоны и отцепленные
    # диски — то есть всё, что не привязано к серверу.
    server_disks = {
        device.get("storage")
        for device in (server.get("storage_devices") or {}).get("storage_device", [])
    }
    extra = [s for s in storages if s.get("uuid") not in server_disks and s.get("type") != "backup"]
    for storage in extra:
        size = float(storage.get("size") or 0)
        tier = storage.get("tier") or "standard"
        found = _storage_price(zone, tier)
        if not found:
            out.unknown.append(f"цена хранилища {tier} не найдена")
            continue
        price, units = found
        is_template = storage.get("uuid") in template_uuids or storage.get("type") == "template"
        out.lines.append(Line(
            "Шаблон диска" if is_template else "Отдельный диск",
            f"{storage.get('title', '')[:28]} · {size:g} ГБ, {tier}",
            monthly(price, size / units),
        ))

    # Первый публичный IPv4 входит в план, остальные — платные.
    public_v4 = [ip for ip in ip_addresses
                 if ip.get("access") == "public" and ip.get("family") == "IPv4"]
    billable = [ip for ip in public_v4 if ip.get("floating") == "yes"] or public_v4[1:]
    found = _price(zone, "ipv4_address")
    if billable and found:
        price, units = found
        for ip in billable:
            kind = "плавающий" if ip.get("floating") == "yes" else "дополнительный"
            out.lines.append(Line("Адрес IPv4", f"{ip.get('address')} · {kind}",
                                  monthly(price, 1 / units)))

    # Во время ротации недолго живёт второй сервер — считаем как разовую добавку.
    if plan_price:
        price, units = plan_price
        out.lines.append(Line(
            "Второй сервер при ротации",
            "только пока идёт операция, 10–40 минут",
            monthly(price, 1 / units), always=False,
        ))
    return out
