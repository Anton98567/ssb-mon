# ssb-mon

Мониторинг пользователей **Secret-Sing-Box** (SSB) для sing-box. Чисто SSH-версия: без веб-панелей и внешних сервисов — только clash-api на localhost, SQLite и команда `ssb-mon` в терминале.

**Репозиторий:** https://github.com/Anton98567/ssb-mon

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/Anton98567/ssb-mon/main/install.sh)"
```

## Возможности

- **Кто сейчас онлайн** — IP клиентов, число активных соединений, трафик up/down, время начала
- **История входов** — кто из пользователей (`admin10lgqj54w7ab` и др.) и когда подключался
- **Память** — sing-box (clash-api + RSS процесса), снимки каждые 10 сек, мин/макс за сутки
- **История** — почасовые снапшоты памяти в SQLite
- Всё локально: API слушает `127.0.0.1`, наружу ничего не открывается

## Требования

- Ubuntu (проверено на 24.04), root
- Установленный **Secret-Sing-Box** (sing-box со всеми пользователями)
- `python3` (стандартная библиотека, ничего ставить не надо)

## Установка

### Одна команда (после установки SSB)

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/Anton98567/ssb-mon/main/install.sh)"
```

Скажет всё сама: включит clash-api, поднимет лог, поставит демон — останется зайти по SSH и смотреть `ssb-mon online`.

### Вручную (через копию проекта)

```bash
# скопировать проект на сервер (например так):
scp -r ssb-mon root@SERVER:/root/

ssh root@SERVER
cd /root/ssb-mon
bash install.sh
```

Скрипт делает:

1. **Бэкап** `/etc/sing-box/config.json` → `config.json.bak.ssb-mon`
2. Включает в конфиг `experimental.clash_api` (`127.0.0.1:9090` + случайный секрет) и поднимает `log.level` до `info` (имя пользователя берётся из лога — в clash-api этой версии sing-box поля `user` нет)
3. Проверяет конфиг (`sing-box check`) и перезапускает sing-box
4. Ставит `/usr/local/bin/ssb-mon`
5. Создаёт и включает systemd-сервис `ssb-mon` (авторестарт + автозапуск)

Параметры можно переопределить при установке:

```bash
SSB_MON_PORT=9090 SECRET=mysupersecret SSB_MON_INTERVAL=10 bash install.sh
```

По умолчанию секрет генерируется случайно. Он хранится в `/etc/ssb-mon/env` (этот файл читают и CLI, и демон через `EnvironmentFile`).

## Использование

| Команда | Что показывает |
|---|---|
| `ssb-mon online` | активные подключения: IP, число соединений, up/down, начало |
| `ssb-mon traffic` | суммарный трафик активных соединений |
| `ssb-mon mem` | память sing-box (API + RSS), последний снапшот, мин/макс за 24ч |
| `ssb-mon sessions` | последние 25 событий входа по пользователям |
| `ssb-mon users` | сводка: количество входов, первый/последний вход |
| `ssb-mon history` | почасовые снапшоты памяти за последние 12 часов |

Все команды читают текущее состояние API и базу `/var/lib/ssb-mon/state.db` — можно запускать от любого пользователя через `sudo`:

```bash
sudo ssb-mon online
```

## Как это работает

```
sing-box ──► clash-api (127.0.0.1:9090, Bearer-секрет)
  │                 │
  └── box.log (INFO)└──► ssb-mon daemon (systemd, каждые 10с)
                              │
                        SQLite /var/lib/ssb-mon/state.db
                              │
                        ssb-mon <команда> (CLI по SSH)
```

- **Daemon** (`ssb-mon daemon`): опрашивает `/connections` и `/memory` каждые `SSB_MON_INTERVAL` секунд, пишет снапшоты в таблицу `snapshots`; хвостовой чтением `box.log` фиксирует события входа — таблица `users_log`.
- **`/memory` и `/traffic`** — стрим-эндпоинты (HTTP-ответ не закрывается, кадры идут подряд). Клиент читает ровно один JSON-объект и рвёт соединение.
- **Имя пользователя** определяется по логу `[user] inbound connection to host:port` — в Clash API sing-box v1.13+ метаданные пользователя не отдаются (проверено по исходникам).

## Инфраструктура

| Что | Где |
|---|---|
| Исполняемый файл | `/usr/local/bin/ssb-mon` |
| База данных | `/var/lib/ssb-mon/state.db` (WAL) |
| Конфигурация | `/etc/ssb-mon/env` (секрет, порт, интервал) |
| Юнит | `/etc/systemd/system/ssb-mon.service` |
| Бэкап конфига | `/etc/sing-box/config.json.bak.ssb-mon` |
| Лог sing-box | `/var/lib/sing-box/box.log` |

```bash
systemctl status ssb-mon      # состояние демона
journalctl -u ssb-mon -f      # логи демона
sqlite3 /var/lib/ssb-mon/state.db ".tables"   # при наличии sqlite3
```

## Переменные окружения

| Переменная | По умолчанию | Описание |
|---|---|---|
| `SSB_MON_API` | `http://127.0.0.1:9090` | адрес clash-api |
| `SSB_MON_SECRET` | (задаёт install.sh) | Bearer-секрет |
| `SSB_MON_INTERVAL` | `10` | период опроса, сек |
| `SSB_MON_DB` | `/var/lib/ssb-mon/state.db` | путь к SQLite |
| `SSB_MON_LOG` | `/var/lib/sing-box/box.log` | путь к логу sing-box |

## Удаление

```bash
systemctl disable --now ssb-mon
rm /etc/systemd/system/ssb-mon.service
rm -rf /etc/ssb-mon
rm /usr/local/bin/ssb-mon
rm -rf /var/lib/ssb-mon
# вернуть конфиг sing-box:
mv /etc/sing-box/config.json.bak.ssb-mon /etc/sing-box/config.json
systemctl restart sing-box
```

## Примечания

- Лог `box.log` теперь на уровне `info` — имени юзеров требуют этого; при желании после настройки можно вернуть уровень ниже, но тогда исчезнут события входа.
- Секреты (`clash_api.secret`) хранятся в `/etc/ssb-mon/env` с правами только для чтения у root.
- Данные доступны только по SSH (root), никакого HTTP наружу.
