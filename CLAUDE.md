# vpn-ip-rotator — как здесь работать

Личный VPN для нескольких человек и Telegram-бот, который им управляет.
Этот файл читает Claude CLI на VPN-сервере. Здесь всё, что нужно, чтобы
менять систему самостоятельно и не просить владельца запускать команды.

## Где что живёт

| Что | Где | Как управлять |
|---|---|---|
| Рабочая копия репозитория | VPN-сервер, `/root/vpn-ip-rotator` | git; источник правды — GitHub `UIbodulloev/vpn-ip-rotator`, ветка `main` |
| VLESS Reality :443/TCP | VPN-сервер, ядро xray в контейнере `3x-ui` | `panel/client.py`, панель на 127.0.0.1:2053 |
| Hysteria2 :39443/UDP | VPN-сервер, `hysteria-server.service` (официальный сервер) | `/etc/hysteria/config.yaml`, ставится `panel/hysteria-official.sh` |
| Сторож «1 ключ = 1 устройство» | VPN-сервер, `device-guard.service` | `panel/device-guard.py status / events / unblock <имя>` |
| Сторож здоровья | VPN-сервер, `vpn-watchdog.timer` раз в минуту | `panel/watchdog.py status / events` |
| Зеркало подписок :8443 | VPN-сервер, `sub-mirror.service` (sub.mos8.online) | `panel/sub-mirror.py devices / reset / limit` |
| AmneziaWG | VPN-сервер, контейнеры `amnezia-awg2`, `awg31` | `awg31/*.sh` |
| Генератор подписок | Cloudflare Worker, origin.mos8.online | `subs/worker.js`, выкатка `vpnctl worker` |
| Telegram-бот | сервер medbot (91.218.115.82), `vpn-rotator.service`, код в `/opt/vpn-rotator` | только через `vpnctl bot-*` |
| Статистика | medbot, `/var/lib/vpn-rotator/stats.db` (SQLite, почасово: адрес × протокол × клиент) | `rotator/stats.py`; снимок с VPN-сервера — `panel/stats-snapshot.py` раз в 5 мин |
| Веб-админка | https://admin.mos8.online → nginx на medbot → бот на 127.0.0.1:8787 | `rotator/admin.py`; вход — TOTP, секрет выпускает `/admin` в боте |

Скрипты панели работают из `/opt/panel` — это копии `panel/` из репозитория.

## Главный инструмент: vpnctl

```
vpnctl status        здоровье всего: службы, память, сторож, подписка, бот
vpnctl ship          push → panel → worker (если менялся subs/) → бот (если менялся rotator/)
vpnctl panel         panel/ → /opt/panel, перезапуск сторожа/зеркала при их изменении
vpnctl worker        выкатить subs/worker.js на Cloudflare и проверить подписку
vpnctl bot-test      тесты бота на medbot на коммите из GitHub
vpnctl bot-deploy    выкатить бота на medbot (тесты → копия → перезапуск → откат при сбое)
vpnctl bot-rollback  вернуть предыдущую версию бота
vpnctl bot-logs [N]  журнал бота
```

## Порядок любой правки

1. `cd /root/vpn-ip-rotator && git pull --ff-only`
2. Правка. Для бота и сторожа — тест в `tests/` (сторож: `tests/test_guard.py`,
   работает без сети; запуск здесь: `python3 -m unittest tests.test_guard`).
3. `git commit` (сообщение по-русски, как в истории) → `vpnctl ship`.
4. `vpnctl status` — убедиться, что всё зелёное.

На medbot нет доступа к консоли — и не нужен: ключ VPN-сервера там пускает
только в `ops/vpn-rotator-ops` (status, logs, test, deploy, rollback, restart).
Выкатывается только то, что уже лежит в origin/main, и только после тестов.

## Как устроена подписка (коротко)

- Телефон (sing-box) качает `https://sub.mos8.online:8443/sub/<UUID>`. Зеркало
  привязывает ссылку к устройству и отдаёт копию ответа воркера (кэш 1 час).
- Воркер собирает конфиг sing-box: группа `auto` (urltest, Hysteria2 первым,
  tolerance 1000 мс — держится за Hysteria2, пока он отвечает; умер —
  уходит на VLESS), селектор `proxy` для ручного выбора, российское
  напрямую, заблокированное в РФ (даже в .ru) — через VPN, QUIC — отказ с `no_drop`.
- Заблокированное: курируемые списки itdoginfo (Russia/inside) и antifilter
  community, из них берутся только домены, попадающие под «российское».
- `https://origin.mos8.online/health` — состояние списков (live или fallback).
- Списки российского: зоны .ru/.su/.рф и др. зашиты в `RU_TLDS`; домены и
  IP-сети — с russia.iplist.opencck.org (кэш Cloudflare сутки), при сбое —
  `FALLBACK_DOMAINS`. Android-приложения банков и госсервисов — `BYPASS_APPS`
  (идут мимо VPN целиком). Новый банк — добавить пакет туда и `vpnctl ship`.
- Параметры Reality и Hysteria2 воркер получает при выкатке из
  `/opt/panel/reality-params.env` и `/opt/panel/hysteria2.env`.

## Сторож устройств

Видит живые подключения VLESS (API ядра) и Hysteria2 (API статистики). Два
живых подключения ключа из разных /24 дольше ~1,5 мин → пришедший позже
отрезается на 30 мин; бот присылает владельцу событие. Лимит на ключ — из
`/var/lib/sub-mirror/devices.json` (кнопки бота «Разрешить два устройства»).
Режим — `/opt/panel/device-guard.env` (`MODE=enforce` или `notify`).
Hysteria2 проверяет каждый вход через сторож: если служба лежит, новые
подключения Hysteria2 не пускаются — чинить первым делом.
Откат Hysteria2 на sing-box: `/opt/panel/hysteria-official.sh rollback`.

## Сторож здоровья

`panel/watchdog.py` раз в минуту: упавшие службы и контейнеры поднимает,
неотвечающие (ядро VLESS, Hysteria2, сторож, зеркало) перезапускает со
второго провала, следит за памятью, свопом, диском, нагрузкой и OOM, раз в
5 минут проверяет бота на medbot (лёг — перезапускает), раз в 6 часов —
`https://origin.mos8.online/health` (не перешёл ли генератор на запасные
списки). События — в `/var/lib/vpn-watchdog/events.jsonl`, бот забирает их
раз в минуту вместе с событиями сторожа устройств и пишет владельцу. Если
VPN-сервер не отвечает по SSH 3 минуты, бот пишет об этом сам.

Тарифа больше 843 МБ не будет — это решение владельца. Не предлагай его;
если тесно, ищи, что съело память.

## Нельзя

- Печатать в ответах содержимое секретов: `/root/.config/vpn/cf-deploy-token`,
  `/opt/panel/*.env`, `/opt/panel/credentials`, `/etc/hysteria/config.yaml`,
  UUID и пароли из базы панели.
- Перезапускать `3x-ui`/xray и `hysteria-server` без причины — это рвёт
  сессии всем. Выдача ключей их перезапуска не требует.
- Менять `/opt/panel` руками в обход репозитория — следующий `vpnctl panel`
  вернёт файлы из git.
- Держать тяжёлые процессы: у сервера 843 МБ памяти. Не запускать сборки,
  браузеры, большие загрузки; закончил — выходи.
- Пушить мимо `main` или переписывать историю (`--force`).

## Если токена Cloudflare нет

`vpnctl worker` скажет об этом. Владелец кладёт токен один раз (права:
Workers Scripts Edit, Workers Routes Edit, DNS Edit, Zone Read):

```
install -d -m 700 /root/.config/vpn && read -rsp 'Токен: ' t && printf '%s' "$t" > /root/.config/vpn/cf-deploy-token && chmod 600 /root/.config/vpn/cf-deploy-token; echo
```
