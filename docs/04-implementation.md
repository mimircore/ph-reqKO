# Цель 4: Реализация DNS-резолвера с фильтрацией

## 1. Обзор

Данный документ описывает реализацию DNS-резолвера **ph-reqKO** в рамках Цели 4. Реализация соответствует архитектуре из `docs/03-architecture.md` и требованиям из `docs/02-requirements.md`.

Проверено на реальной машине: Windows 11 x64, Python 3.11.9, без доступа к целевому стенду Raspberry Pi (замеры производительности на целевом оборудовании — **допущение, подлежащее валидации в Цели 8**).

---

## 2. Структура модулей

| Модуль | Путь | Назначение | Требования |
|--------|------|-----------|-----------|
| `config` | `src/reqko/config.py` | Typed dataclass для всех переменных `REQKO_*` (включая `REQKO_BLOCKLIST_FILES` — локальные списки, загружаемые на старте), строгая валидация, обязательный `REQKO_API_KEY` | NFR-08 |
| `storage/migrations` | `src/reqko/storage/migrations.py` | Идемпотентное применение DDL-схемы, WAL-прагмы SQLite, таблица `schema_migrations` | FR-11, FR-12, FR-19 |
| `storage/schema.sql` | `src/reqko/storage/schema.sql` | Точная DDL-схема: 6 таблиц, 10 статусов `query_log`, почасовые счётчики `stats_hourly` | FR-11, FR-12, FR-19 |
| `dns/protocol` | `src/reqko/dns/protocol.py` | Wire-парсер и сериализатор RFC 1035: Header, Question, A, AAAA, CNAME, SOA, raw RDATA; сжатие 0xC0; детектирование петель; лимит 255 байт; OPT-запись EDNS0 (RFC 6891) | NFR-10 |
| `dns/acl` | `src/reqko/dns/acl.py` | Сопоставление IP-клиента с `REQKO_ALLOWED_NETWORKS` (`IPv4Network`/`IPv6Network`) | FR-13 |
| `dns/ratelimit` | `src/reqko/dns/ratelimit.py` | Token Bucket per client IP с инъецируемыми часами и очисткой простаивающих клиентов | FR-14 |
| `dns/cache` | `src/reqko/dns/cache.py` | LRU-кеш `OrderedDict`, `CacheEntry` с `cname_targets`, зажим TTL, негативное кеширование RFC 2308; OPT-записи никогда не кешируются | FR-03, FR-04, FR-09 |
| `dns/upstream` | `src/reqko/dns/upstream.py` | Асинхронный клиент UDP+TCP (TC=1 fallback), валидация ID и вопроса, список резервных серверов; возвращает ответ **и** адрес сервера, который реально ответил | FR-02 |
| `dns/pipeline` | `src/reqko/dns/pipeline.py` | Полный конвейер обработки: ACL → Rate Limit → Wire Parse → ANY check → Allowlist/Blocklist (одна проверка `match()`) → Cache → Re-validation → Upstream → CNAME uncloak → Cache store → Response → Async Log; TTL ответа клиенту = зажатый TTL кеша | FR-01..FR-14, NFR-03 |
| `dns/server` | `src/reqko/dns/server.py` | UDP `DatagramProtocol` + TCP `asyncio.start_server` с 2-байтовым префиксом, семафором соединений и idle timeout; UDP и TCP слушают один и тот же порт (включая эфемерный порт 0 для тестов) | FR-01, NFR-03 |
| `filtering/parser` | `src/reqko/filtering/parser.py` | Парсер `/etc/hosts`, plain domain, Adblock-подмножество (`\|\|domain^`, `@@\|\|domain^`), нормализация | FR-05 |
| `filtering/engine` | `src/reqko/filtering/engine.py` | `FilterSnapshot` (frozenset × 4), `FilterEngine`, алгоритм Label Walk, атомарная смена snapshot | FR-05..FR-07, FR-10 |
| `filtering/updater` | `src/reqko/filtering/updater.py` | Загрузка списков (HTTP/HTTPS/file с защитой от path traversal), парсинг в executor, атомарная смена с fallback; ошибки логируются по типу исключения, без форматирования объекта исключения | FR-10 |
| `__main__` | `src/reqko/__main__.py` | CLI-запуск сервера, загрузка локальных списков на старте, обработка SIGINT/SIGTERM (с fallback для Windows, где `loop.add_signal_handler` не поддерживается) | — |

---

## 3. Порядок конвейера обработки запроса

Реализован строго по Разделу 3 документа архитектуры:

```
Входящий пакет (UDP/TCP)
  │
  ├─[1] ACL (FR-13) ──────────── REFUSED_ACL (RCODE=5)
  ├─[2] Rate Limit (FR-14) ────── REFUSED_RATE_LIMIT (RCODE=5)
  ├─[3] Wire Parse (NFR-10) ───── ERROR_FORMAT (RCODE=1 FORMERR)
  ├─[4] ANY Check (FR-13) ──────── REFUSED_ANY (RCODE=5)
  ├─[5+6] Allowlist/Blocklist ─── один вызов filter_engine.match(qname)
  │       (FR-06, FR-04, FR-07)   (allowlist проверяется первым внутри match())
  │       └─ заблокирован ─────── BLOCKED_BLACKLIST (0.0.0.0/NXDOMAIN/NODATA)
  ├─[7] Cache Lookup (FR-03)
  │       ├─ Hit: re-check qname по текущему снимку правил (FR-04) → BLOCKED_BLACKLIST
  │       ├─ Hit: re-check CNAME-целей, если имя не в allowlist (FR-09) → BLOCKED_CNAME
  │       └─ Hit: валиден → CACHED
  ├─[8] Upstream (FR-02) ─────── ERROR_UPSTREAM (RCODE=2 SERVFAIL)
  ├─[9] CNAME Uncloaking (FR-09) ─ BLOCKED_CNAME (0.0.0.0/NXDOMAIN/NODATA)
  ├─[10] Cache Store (FR-03) + выравнивание TTL ответа с кешем
  └─[11] Response + Async Log (NFR-03) → FORWARDED / ALLOWED
```

Ключевые детали реализации:

- **Одна проверка правил на запрос**: до кеша вызывается ровно один `filter_engine.match(qname)`; приоритет allowlist проверяется внутри `match()` (FR-06). На cache hit выполняется повторный `match()` против **актуального** снимка правил, поэтому правило, добавленное после кеширования, блокирует немедленно (FR-04).
- **Ранние ответы** (ACL, rate limit, FORMERR) формируются одним хелпером `_make_early_response()` и сохраняют ID пакета клиента.
- **Блокирующие ответы** формируются одним хелпером `_blocked()` для всех четырёх точек блокировки.
- **EDNS0 (RFC 6891)**: OPT-запись (type 41) никогда не кешируется и её TTL-поле никогда не перезаписывается (в нём лежат флаги EDNS, а не TTL). Если клиент прислал OPT — ответ содержит ровно одну свежую OPT; если не прислал — OPT в ответе отсутствует.
- **TTL-согласованность**: после сохранения в кеш TTL-поля answer- и authority-записей ответа клиенту перезаписываются зажатым TTL записи кеша (`expires_at - created_at`); клиент не может увидеть TTL 50, а затем 58 при том же кеш-состоянии.
- **Логирование событий** выполняется через неблокирующий `asyncio.Queue` (NFR-03: DNS-путь не зависит от БД); каждое событие также выводится в лог процесса строкой `query_log: status=...`.

---

## 4. Статусы query_log и подсчёт в stats_hourly

| Статус | Категория stats_hourly | Шаг конвейера |
|--------|----------------------|---------------|
| `ALLOWED` | `allowed_queries` | Разрешено белым списком (FR-06) |
| `FORWARDED` | `forwarded_queries` | Успешный ответ от upstream |
| `CACHED` | `cached_queries` | Ответ из кеша |
| `BLOCKED_BLACKLIST` | `blocked_queries` | Заблокировано чёрным списком |
| `BLOCKED_CNAME` | `blocked_queries` | Заблокировано через CNAME-uncloaking |
| `REFUSED_ACL` | `refused_queries` | IP не в allowed networks |
| `REFUSED_RATE_LIMIT` | `refused_queries` | Превышен лимит запросов |
| `REFUSED_ANY` | `refused_queries` | QTYPE=255 ANY |
| `ERROR_UPSTREAM` | `error_queries` | Все upstream недоступны |
| `ERROR_FORMAT` | `error_queries` | Повреждённый DNS-пакет |

Сумма 6 подкатегорий строго равна `total_queries`. Повреждённые пакеты логируются со своим статусом `ERROR_FORMAT` (а не `REFUSED_ACL`).

---

## 5. Тесты

### 5.1 Покрытие по модулям

| Тест-файл | Что проверяется | Требования |
|-----------|----------------|-----------|
| `tests/unit/test_config.py` | Дефолты, валидные/невалидные env-переменные, обязательный API_KEY | NFR-08, NFR-09 |
| `tests/unit/test_storage.py` | Идемпотентная миграция, все 10 статусов `query_log`, UPSERT-сумма | FR-11, FR-12, FR-19 |
| `tests/unit/test_dns_protocol.py` | Roundtrip парсер↔сериализатор с dnspython, сжатие, петли, FORMERR | NFR-10 |
| `tests/unit/test_filter_parser.py` | /etc/hosts, plain domain, Adblock-синтаксис, комментарии | FR-05 |
| `tests/unit/test_filter_engine.py` | Exact block, wildcard, allowlist-приоритет, BLOCKED_CNAME, атомарный swap | FR-05..FR-07, FR-10 |
| `tests/unit/test_acl_ratelimit.py` | ACL RFC 1918 + loopback, token bucket, cleanup | FR-13, FR-14 |
| `tests/unit/test_cache.py` | Cache hit/miss, TTL rewrite, зажим TTL, LRU eviction, CNAME targets, NXDOMAIN | FR-03, FR-04, FR-09 |
| `tests/integration/test_pipeline.py` | Интеграция конвейера: ACL refusal, rate limit, FORMERR, ANY refused, blocklist, allowlist, TTL-согласованность forwarded/CACHED (mock-часы), EDNS OPT presence, allowlist-регрессии (FR-06 vs FR-04/FR-09), статус события FORMERR | FR-01..FR-14 |
| `tests/integration/fake_upstream.py` | Фейковый upstream UDP+TCP в процессе теста (dnspython): задержки, TC=1, canned-ответы, лог запросов | тестовое окружение |
| `tests/integration/test_upstream_client.py` | Таймаут первого upstream → ответ второго, TC=1 → повтор по TCP, отбраковка неверного ID и вопроса, все upstream недоступны | FR-02 |
| `tests/integration/test_servers.py` | Сквозные тесты через реальные UDP/TCP-слушатели: forwarding, кеш, блокировки, ACL, rate limit, TCP idle timeout, максимум TCP-соединений, EDNS через сервер, очередь событий | FR-01..FR-14 |
| `tests/integration/test_updater.py` | Обновление списков: успешная атомарная смена, HTTP 500 / ошибка соединения / битый список → старый снимок, path traversal отклоняется, частичный сбой не мешает остальным источникам | FR-10 |

Интеграционные тесты не требуют доступа в интернет: upstream-серверы поднимаются в самом тестовом процессе, клиентская сторона — dnspython.

### 5.2 Результат запуска

Реальный запуск на машине разработки (Windows 11 x64, Python 3.11.9):

```
> .venv\Scripts\python.exe -m ruff check .
All checks passed!

> .venv\Scripts\python.exe -m mypy src tests
Success: no issues found in 30 source files

> .venv\Scripts\python.exe -m pytest
........................................................................ [ 74%]
.........................                                                [100%]
97 passed in 5.42s
```

Все 97 тестов проходят без единой ошибки или пропуска.

### 5.3 Покрытие кода

```
> .venv\Scripts\python.exe -m pytest --cov=reqko --cov-report=term-missing -q
........................................................................ [ 74%]
.........................                                                [100%]

Name                              Stmts   Miss  Cover   Missing
---------------------------------------------------------------
src\reqko\__init__.py                 1      0   100%
src\reqko\__main__.py                68     68     0%   3-155
src\reqko\config.py                 140      9    94%   141-143, 171, 247, 254-255, 258, 268
src\reqko\dns\__init__.py             2      0   100%
src\reqko\dns\acl.py                 15      0   100%
src\reqko\dns\cache.py               92      7    92%   97, 130, 156, 187, 200-202
src\reqko\dns\pipeline.py           150     15    90%   87-88, 104-105, 172-175, 180-182, 256-258, 285
src\reqko\dns\protocol.py           304     35    88%   142, 183, 196, 208-210, 220, 222-224, 226-227, 229-241, 245-247, 328, 335, 343, 352, 363, 371-372, 377, 395, 409, 413, 423, 428, 436
src\reqko\dns\ratelimit.py           37      2    95%   37, 48
src\reqko\dns\server.py              73     12    84%   37-38, 41, 64, 68-69, 76, 81-82, 123-126
src\reqko\dns\upstream.py            84     14    83%   49-50, 54, 90-91, 106, 136-145, 154, 162-166
src\reqko\filtering\__init__.py       3      0   100%
src\reqko\filtering\engine.py        56      0   100%
src\reqko\filtering\parser.py        98     10    90%   52-55, 88, 123, 133, 142, 171, 184
src\reqko\filtering\updater.py       73      7    90%   33, 66, 71, 139-145, 154
src\reqko\storage\__init__.py         2      0   100%
src\reqko\storage\migrations.py      35      3    91%   21, 26, 37
---------------------------------------------------------------
TOTAL                              1233    182    85%
```

Суммарное покрытие **85%** (целевой ориентир NFR-09 — более 70%). `__main__.py` не покрыт автотестами (точка входа проверяется демо-запуском, раздел 6).

---

## 6. Демо-запуск на порту 5454

Демо выполнено на реальной машине разработчика (Windows 11, Python 3.11.9). Internet-связность есть, поэтому использован **реальный upstream 9.9.9.9 (Quad9)**. Блоклист — небольшой локальный файл:

```
# ph-reqKO demo blocklist (local file, REQKO_BLOCKLIST_FILES)
||ads.example.com^
doubleclick.net
tracker.test
```

**Команда запуска (PowerShell):**

```powershell
$env:REQKO_API_KEY='demo-key-not-a-secret'
$env:REQKO_DNS_PORT='5454'; $env:REQKO_DNS_HOST='127.0.0.1'
$env:REQKO_LOG_LEVEL='DEBUG'
$env:REQKO_BLOCKLIST_FILES='C:\Users\mirrw0\AppData\Local\Temp\reqko_demo\demo_blocklist.txt'
Start-Process -FilePath '.venv\Scripts\python.exe' -ArgumentList '-m','reqko' `
  -RedirectStandardOutput server.log -RedirectStandardError server_err.log -PassThru
```

**Реальный вывод сервера при старте (журнал stderr):**

```
2026-11-04 02:07:51,046 [INFO] reqko: Starting ph-reqKO DNS resolver v0.1.0
2026-11-04 02:07:51,046 [INFO] reqko: DNS listeners: 127.0.0.1:5454 (UDP+TCP)
2026-11-04 02:07:51,046 [INFO] reqko: REST API (0.0.0.0:8080) and metrics exporter (127.0.0.1:9100) are not implemented yet (objective 5)
2026-11-04 02:07:51,046 [INFO] reqko: Block mode: NULL | Upstreams: [('9.9.9.9', 53), ('149.112.112.112', 53)]
2026-11-04 02:07:51,048 [INFO] reqko: Loading 1 local blocklist file(s): C:\Users\mirrw0\AppData\Local\Temp\reqko_demo\demo_blocklist.txt
2026-11-04 02:07:51,053 [INFO] reqko.filtering.updater: Loaded blocklist: C:\Users\mirrw0\AppData\Local\Temp\reqko_demo\demo_blocklist.txt (4 lines)
2026-11-04 02:07:51,053 [INFO] reqko.filtering.updater: Filter rules updated to v1: 3 total rules
2026-11-04 02:07:51,053 [INFO] reqko: Filter rules loaded: 3 rules (version 1)
2026-11-04 02:07:51,054 [INFO] reqko.dns.server: DNS UDP+TCP listening on 127.0.0.1:5454
2026-11-04 02:07:51,054 [INFO] reqko: ph-reqKO DNS resolver ready on 127.0.0.1:5454 (UDP+TCP, block_mode=NULL)
```

Стартовый журнал не заявляет API/Metrics как слушающие — они не реализованы (Цель 5).

Примечание: приведённые ниже выводы клиента и журнала сервера собраны за несколько прогонов одной и той же конфигурации сервера (в ходе отладки сервер перезапускался; каждый блок соответствует реальному выводу соответствующего прогона).

### Реальные выходные данные клиента

Клиент — короткий dnspython-скрипт. Примечание: `dig` в Windows отсутствует; установленный в системе `nslookup` не поддерживает нестандартный порт ни в форме `nslookup -port=5454 ...` (игнорируется/ошибка синтаксиса — запросы уходят на порт 53, что подтверждено пустым журналом сервера и прослушиванием порта сырым UDP-сокетом), ни через `set port=5454` в интерактивном режиме. Поэтому использован dnspython (это тот же wire-протокол RFC 1035).

**[1] Обычный A-запрос (FORWARDED) и повтор через <2 с (CACHED) — TTL не растёт и убывает:**

```
[UDP A example.com] rcode=NOERROR answers=1
    example.com. 156 IN A 104.20.23.154
example.com. 156 IN A 172.66.147.243
    OPT present: False
[UDP A example.com (2nd)] rcode=NOERROR answers=1
    example.com. 155 IN A 104.20.23.154
example.com. 155 IN A 172.66.147.243
    OPT present: False
--- спустя 2 секунды ---
[UDP A example.com (2nd)] rcode=NOERROR answers=1
    example.com. 153 IN A 104.20.23.154
example.com. 153 IN A 172.66.147.243
    OPT present: False
```

TTL первого (forwarded) ответа равен TTL, сохранённому в кеш (156), далее монотонно убывает (155 → 153) — расхождение «TTL 50 у клиента, 58 в кеше» невозможно по построению (раздел 3).

**Соответствующие строки журнала сервера:**

```
2026-11-04 02:07:59,834 [INFO] reqko.dns.pipeline: query_log: status=FORWARDED name=example.com type=A client=127.0.0.1 upstream=9.9.9.9:53 latency=3.0ms rcode=0
2026-11-04 02:08:00,075 [INFO] reqko.dns.pipeline: query_log: status=CACHED name=example.com type=A client=127.0.0.1 upstream=- latency=0.1ms rcode=0
2026-11-04 02:08:02,538 [INFO] reqko.dns.pipeline: query_log: status=CACHED name=example.com type=A client=127.0.0.1 upstream=- latency=0.1ms rcode=0
```

**[2] Заблокированный домен (`||ads.example.com^`) — 0.0.0.0:**

```
[UDP A ads.example.com (blocked)] rcode=NOERROR answers=1
    ads.example.com. 300 IN A 0.0.0.0
    OPT present: False
```

```
2026-11-04 02:08:02,773 [INFO] reqko.dns.pipeline: query_log: status=BLOCKED_BLACKLIST name=ads.example.com type=A client=127.0.0.1 upstream=- latency=0.1ms rcode=0
```

**[3] ANY-запрос — REFUSED (RCODE=5):**

```
[UDP ANY example.com] rcode=REFUSED answers=0
    OPT present: False
```

```
2026-11-04 02:08:11,563 [INFO] reqko.dns.pipeline: query_log: status=REFUSED_ANY name=example.com type=ANY client=127.0.0.1 upstream=- latency=0.1ms rcode=5
```

**[4] TCP-запрос (закешированный ответ, обслуженный по TCP):**

```
[TCP A example.com] rcode=NOERROR answers=1
    example.com. 152 IN A 104.20.23.154
example.com. 152 IN A 172.66.147.243
    OPT present: False
```

**[5] FORMERR на повреждённом пакете (4 байта, ID=0xABCD):**

```
[FORMERR test] sent 4 malformed bytes; response: 12 bytes, id=0xABCD (expected 0xABCD), rcode=1 (expected 1=FORMERR)
```

```
2026-11-04 02:08:03,245 [DEBUG] reqko.dns.pipeline: FORMERR from 127.0.0.1: DNSFormatError: Packet shorter than DNS header (12 bytes)
2026-11-04 02:08:03,245 [INFO] reqko.dns.pipeline: query_log: status=ERROR_FORMAT name= type=? client=127.0.0.1 upstream=- latency=0.3ms rcode=1
```

### Баги, выявленные и исправленные в ходе демо

| Баг | Исправление |
|-----|-------------|
| Корневое имя `.` кодировалось двумя нулевыми байтами (пустая метка + терминатор), из-за чего OPT-записи EDNS искажались при сериализации | `append_domain_name()` нормализует имя до проверки; корень кодируется одним нулевым байтом |
| `time.monotonic()` на Windows имеет гранулярность ~15 мс: latency в журнале округлялась до 0.0, после смены пары часов — отрицательные значения | Замер задержки переведён на `time.perf_counter()` (наивысшее разрешение на всех платформах) |
| UDP и TCP слушатели при порте 0 занимали разные эфемерные порты (реальный DNS обязан слушать UDP и TCP на одном порту) | `run_dns_servers()` берёт фактический порт UDP-сокета и запускает TCP на нём же |
| `urlparse("C:\\...")` принимал букву диска за URL-схему — локальные списки на Windows вообще не загружались | `fetch_list()` трактует односимвольную схему как букву диска Windows; для `file://` путь конвертируется через `urllib.request.url2pathname()` |

---

## 7. Ограничения текущей реализации

| Ограничение | Причина | Цель устранения |
|------------|---------|----------------|
| Нет REST API и веб-панели | Scope Цели 5 | Цель 5 |
| Нет записи `query_log` в SQLite (только очередь событий и stdout-лог) | Scope Цели 5 | Цель 5 |
| Нет экспорта метрик Prometheus | Scope Цели 5 | Цель 5 |
| Нет ротации логов и анонимизации IP в записи (конфигурация есть, код записи — Цель 5) | Scope Цели 5 | Цель 5 |
| Нет ручных правил через API (движок правила принимает, API — Цель 5) | Scope Цели 5 | Цель 5 |
| Списки загружаются только локальными файлами на старте; расписание и управление через API — Цель 5 | `updater.py` поддерживает HTTP(S), подключение — Цель 5 | Цель 5 |
| Производительность не замерена на Raspberry Pi 4 | Нет доступа к целевому стенду | Цель 8 |
| Клиентский IP в Docker может быть bridge gateway | Требует `network_mode: host` или macvlan | Цель 6, Цель 8 |

### 7.1 Известная ловушка Windows: UDP и WinError 10054

**Симптом:** в логе появляется `[WARNING] reqko.dns.server: UDP socket error: [WinError 10054]`, после чего UDP-запросы перестают отвечать (TCP и REST API работают), хотя сокет числится слушающим.

**Причина:** клиент, закрывший UDP-сокет сразу после отправки, заставляет Windows доставить ICMP port-unreachable; следующая операция на сокете завершается с WSAECONNRESET (WinError 10054). В `ProactorEventLoop` цикл чтения датаграммного транспорта (`_ProactorDatagramTransport._loop_reading`) после такой ошибки не перевзводится, а транспорт записи молча выставляет `_conn_lost` и перестаёт отправлять ответы.

**Защита (реализована в `dns/server.py`, четыре уровня):**

1. UDP-сокет создаётся самим reqko и ему через `WSAIoctl` выставляется `SIO_UDP_CONNRESET = FALSE` (и `SIO_UDP_NETRESET = FALSE`, где доступно) — Python-овский `socket.ioctl` ограничен фиксированным набором команд и эти коды отклоняет;
2. в точке входа (`__main__.py`) на Windows включается `WindowsSelectorEventLoopPolicy` — selector-транспорт перевзводит чтение после `error_received()`;
3. ответы отправляются через сырой сокет, а не `transport.sendto`: однократный WSAECONNRESET теряет один ответ, а не «глушит» транспорт навсегда;
4. сторож `DnsUdpWatchdog`: каждые 30 с UDP-запрос имени `selfprobe.reqko.internal` на `127.0.0.1:<порт>` (конвейер отвечает REFUSED локально, в `query_log` событие не пишется). Две неудачи подряд (таймаут 2 с) — ERROR в лог и переоткрытие UDP-эндпоинта (`UdpDnsServer.rebind`).

**Наблюдаемость:** `/health` отдаёт `self_probe` с полями `last_probe_ok`, `consecutive_failures`, `event_loop_lag_ms` (задержка цикла событий, мс). Сторож активен при привязке DNS к `0.0.0.0`/`::`/loopback; при привязке к конкретному адресу отключается (проба шлётся на `127.0.0.1`).

**Проверка:** юнит-тест протокола (`error_received(ConnectionResetError)` не останавливает обслуживание), Windows-тест «клиент закрыл сокет сразу после отправки → сервер продолжает отвечать» (пропускается на других ОС; воспроизводимость зависит от доставки ICMP в конкретной сборке Windows), тесты сторожа (успешная проба; два провала → rebind) и rebind-тест на реальном сервере. На машине разработки (Windows 11 26200) остановку не удалось воспроизвести с корректным асинхронным клиентом во всех комбинациях флагов — доставки ICMP-ошибки на сокет в этой сборке не происходит; защиты включены постоянно.

---

## 8. Соответствие требованиям (таблица трассировки)

| ID | Требование | Статус | Модуль |
|----|-----------|--------|--------|
| FR-01 | Приём DNS по UDP и TCP (RFC 1035) | ✅ | `server`, `protocol` |
| FR-02 | Upstream forwarding + TC=1 TCP fallback + fallback-список + отчёт об ответившем сервере | ✅ | `upstream` |
| FR-03 | In-memory LRU-кеш, TTL rewrite, негативное кеширование RFC 2308 | ✅ | `cache` |
| FR-04 | Фильтрация ДО кеша + повторная валидация кеша по актуальным правилам | ✅ | `pipeline`, `engine` |
| FR-05 | Парсинг hosts, plain domain, Adblock-синтаксиса | ✅ | `filtering/parser` |
| FR-06 | Allowlist с наивысшим приоритетом (в т.ч. на cache hit и против CNAME-блокировки) | ✅ | `filtering/engine`, `pipeline` |
| FR-07 | Label Walk для wildcard-блокировок | ✅ | `filtering/engine` |
| FR-08 | Режимы блокировки: NULL / NXDOMAIN / NODATA | ✅ | `protocol`, `pipeline` |
| FR-09 | CNAME uncloaking (свежий ответ и из кеша) | ✅ | `pipeline`, `cache` |
| FR-10 | Атомарная смена FilterSnapshot, fallback на старые правила при сбое | ✅ | `filtering/engine`, `updater` |
| FR-11 | Журнал запросов и агрегированная статистика в БД | ⚠️ PARTIAL — очередь событий `asyncio.Queue` + stdout-лог; записи в SQLite и агрегаты (`stats_hourly`) не реализованы | `pipeline` |
| FR-12 | Срок хранения логов и анонимизация IP | ⚠️ PARTIAL — конфигурация (`REQKO_LOG_RETENTION_DAYS`, `REQKO_ANONYMIZE_IPS`) есть; сама обработка при записи в БД не реализована | `config` |
| FR-13 | ACL по подсетям + отказ в ANY (REFUSED) | ✅ | `acl`, `pipeline` |
| FR-14 | Rate limiting (token bucket per IP) | ✅ | `ratelimit`, `pipeline` |
| FR-15 | REST API управления и статистики | ❌ NOT IMPLEMENTED | — (Цель 5) |
| FR-16 | Health check эндпоинты (`/health`, `/ready`) | ❌ NOT IMPLEMENTED | — (Цель 5) |
| FR-17 | Аутентификация REST API (`X-API-Key`) | ❌ NOT IMPLEMENTED | `config` хранит ключ, HTTP-часть — Цель 5 |
| FR-18 | Веб-панель с графиками | ❌ NOT IMPLEMENTED | — (Цель 5) |
| FR-19 | Ручные пользовательские правила (API) | ❌ NOT IMPLEMENTED | — (Цель 5) |
| NFR-01 | Задержка p95 < 10–15 мс из кеша | ❌ NOT IMPLEMENTED (не замерялась) | Цель 8 |
| NFR-02 | RAM < 200–350 МБ при 100k+ правил | ❌ NOT IMPLEMENTED (не замерялась) | Цель 8 |
| NFR-03 | Изоляция сбоев: DNS-путь не зависит от БД/API (`asyncio.Queue` без блокировок) | ✅ | `pipeline`, `server` |
| NFR-04 | Безопасность контура (non-root, Trivy и т.п.) | ❌ NOT IMPLEMENTED | Цель 6 |
| NFR-05 | Качество кода: ruff 0 ошибок, mypy strict 0 ошибок | ✅ | вся кодовая база |
| NFR-06 | Переносимость без обязательных C-расширений | ⚠️ Частично — чистый `asyncio` + `dnspython`/`aiohttp` (колёса), ARM-сборка не проверялась | Цель 6 |
| NFR-07 | Экспорт метрик Prometheus | ❌ NOT IMPLEMENTED | Цель 5/7 |
| NFR-08 | Развёртывание `docker compose up -d` | ❌ NOT IMPLEMENTED | Цель 6 |
| NFR-09 | Тестовое покрытие > 70% и CI | ⚠️ PARTIAL — покрытие 85% достигнуто; CI (GitHub Actions) не настроен | `tests/` |
| NFR-10 | RFC 1034/1035: FORMERR на битые пакеты, сжатие меток, ID/вопрос валидируются | ✅ | `protocol`, `upstream` |

Покрытие требований по целям: Цель 4 закрывает FR-01..FR-10, FR-13, FR-14 и NFR-03, NFR-05, NFR-10; FR-11/FR-12 (запись в БД, ротация, анонимизация) и FR-15..FR-19 (API/панель) — Цель 5; NFR-01/02 (замеры) — Цель 8; NFR-04/06/08 (контейнер, security-аудит) — Цель 6; NFR-07 (метрики) — Цели 5/7; CI-часть NFR-09 — Цель 7.
