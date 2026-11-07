# Панель 3X-UI на VPN-сервере

`client.py` живёт на VPN-сервере в `/opt/panel/client.py` и управляет клиентами
VLESS+Reality. Бот вызывает его по SSH (`rotator/bot.py`, `PANEL_SCRIPT`) —
панель слушает только `127.0.0.1`, наружу её порт не открыт.

```
client.py list          # клиенты, трафик, состояние
client.py add <имя>     # создать и выдать ссылку vless://
client.py link <имя>    # ссылка существующего клиента
client.py del <имя>     # удалить
client.py sync          # заставить ядро перечитать клиентов из базы
```

## Зачем `sync` и метка «НЕ В ЯДРЕ»

3X-UI 3.11 применяет добавление клиента **через core API, не перезаписывая
`/app/bin/config.json`**. Пока ядро не перезапускалось, клиент работает. Но
любой следующий перезапуск ядра (например, удаление другого клиента — панель
пишет в лог `hot apply: clients left the config, restarting`) читает файл, где
нового клиента нет. Результат: ключ выдан, в панели виден, в базе `enable=1`,
а на телефоне **timeout**.

Поэтому `add` и `del` после правки вызывают `restartXrayService` и ждут, пока
UUID действительно появится (или исчезнет) в живом конфиге. `list` сверяет базу
с ядром и помечает расхождение как `НЕ В ЯДРЕ` — этот же случай виден в боте.

Проверить вручную:

```sh
docker exec 3x-ui cat /app/bin/config.json \
  | python3 -c 'import sys,json; [print(c.get("email"), c.get("id")) for i in json.load(sys.stdin)["inbounds"] for c in (i.get("settings") or {}).get("clients") or []]'
```

## Остальные файлы в `/opt/panel`

| Файл | Что | Права |
|---|---|---|
| `credentials` | логин панели и `PANEL_API_TOKEN` | 0600 |
| `reality-params.env` | host, порт, pbk, sid, sni для генератора ссылок | 0600 |
| `backup/amnezia-xray-server.json` | конфиг Amnezia до переноса на 443 | — |

Приватного ключа Reality в `reality-params.env` нет намеренно: генератору
ссылок и Worker'у он не нужен.
