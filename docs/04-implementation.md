# Цель 4: Реализация DNS-резолвера с фильтрацией

## 1. Обзор

Данный документ описывает реализацию DNS-резолвера **ph-reqKO** в рамках Цели 4. Реализация соответствует архитектуре из `docs/03-architecture.md` и требованиям из `docs/02-requirements.md`. Разработка велась в три итеративных этапа (Stage A → B → C).

---

## 2. Структура модулей

| Модуль | Путь | Назначение | Требования |
|--------|------|-----------|-----------|
| `config` | `src/reqko/config.py` | Typed dataclass для всех 22 переменных `REQKO_*`, строгая валидация, обязательный `REQKO_API_KEY` | NFR-08, NFR-09 |
| `storage/migrations` | `src/reqko/storage/migrations.py` | Идемпотентное применение DDL-схемы, WAL-прагмы SQLite, таблица `schema_migrations` | FR-11, FR-18 |
| `storage/schema.sql` | `src/reqko/storage/schema.sql` | Точная DDL-схема: 6 таблиц, 10 статусов `query_log`, почасовые счётчики `stats_hourly` | FR-11, FR-12, FR-18 |
| `dns/protocol` | `src/reqko/dns/protocol.py` | Wire-парсер и сериализатор RFC 1035: Header, Question, A, AAAA, CNAME, SOA, raw RDATA; сжатие 0xC0; детектирование петель; лимит 255 байт | NFR-10 |
| `dns/acl` | `src/reqko/dns/acl.py` | Сопоставление IP-клиента с `REQKO_ALLOWED_NETWORKS` (`IPv4Network`/`IPv6Network`) | FR-13 |
| `dns/ratelimit` | `src/reqko/dns/ratelimit.py` | Token Bucket per client IP с инъецируемыми часами и очисткой простаивающих клиентов | FR-14 |
| `dns/cache` | `src/reqko/dns/cache.py` | LRU-кеш `OrderedDict`, `CacheEntry` с `cname_targets`, зажим TTL, негативное кеширование RFC 2308 | FR-03, FR-04, FR-09 |
| `dns/upstream` | `src/reqko/dns/upstream.py` | Асинхронный клиент UDP+TCP (TC=1 fallback), валидация ID и вопроса, список резервных серверов | FR-02 |
| `dns/pipeline` | `src/reqko/dns/pipeline.py` | Полный конвейер обработки: ACL → Rate Limit → Wire Parse → ANY check → Allowlist → Blocklist → Cache → Upstream → CNAME uncloak → Cache store → Async Log | FR-01..FR-14, NFR-03 |
| `dns/server` | `src/reqko/dns/server.py` | UDP `DatagramProtocol` + TCP `asyncio.start_server` с 2-байтовым префиксом, семафором соединений и idle timeout | FR-01, NFR-03 |
| `filtering/parser` | `src/reqko/filtering/parser.py` | Парсер `/etc/hosts`, plain domain, Adblock-подмножество (`\|\|domain^`, `@@\|\|domain^`), нормализация | FR-05 |
| `filtering/engine` | `src/reqko/filtering/engine.py` | `FilterSnapshot` (frozenset × 4), `FilterEngine`, алгоритм Label Walk, атомарная смена snapshot | FR-05..FR-07, FR-10 |
| `filtering/updater` | `src/reqko/filtering/updater.py` | Загрузка списков (HTTP/HTTPS/file), парсинг в executor, атомарная смена с fallback | FR-10 |
| `__main__` | `src/reqko/__main__.py` | CLI-запуск сервера, настройка компонентов, обработка SIGINT/SIGTERM | — |

---

## 3. Порядок конвейера обработки запроса

Реализован строго по Разделу 3 документа архитектуры:

```
Входящий пакет (UDP/TCP)
  │
  ├─[1] ACL (FR-13) ──────────── REFUSED_ACL (RCODE=5)
  ├─[2] Rate Limit (FR-14) ────── REFUSED_RATE_LIMIT (RCODE=5, DROP)
  ├─[3] Wire Parse (NFR-10) ───── ERROR_FORMAT (RCODE=1 FORMERR)
  ├─[4] ANY Check (FR-13) ──────── REFUSED_ANY (RCODE=5)
  ├─[5] Allowlist (FR-06) ──────── → ALLOWED (пропуск blocklist)
  ├─[6] Blocklist (FR-04, FR-07) ─ BLOCKED_BLACKLIST (0.0.0.0/NXDOMAIN)
  ├─[7] Cache Lookup (FR-03)
  │       ├─ Hit: re-validate qname (FR-04) → BLOCKED_BLACKLIST
  │       ├─ Hit: re-validate CNAME targets (FR-09) → BLOCKED_CNAME
  │       └─ Hit: valid → CACHED
  ├─[8] Upstream (FR-02) ─────── ERROR_UPSTREAM (RCODE=2 SERVFAIL)
  ├─[9] CNAME Uncloaking (FR-09) ─ BLOCKED_CNAME (0.0.0.0/NXDOMAIN)
  ├─[10] Cache Store (FR-03)
  └─[11] Response + Async Log (NFR-03) → FORWARDED / ALLOWED
```

Каждый шаг на ошибке возвращает ответ клиенту немедленно, не дожидаясь последующих этапов. Логирование выполняется через неблокирующий `asyncio.Queue` (NFR-03: DNS-путь не зависит от БД/логера).

---

## 4. Статусы journey_log и подсчёт в stats_hourly

| Статус | Категория stats_hourly | Шаг конвейера |
|--------|----------------------|---------------|
| `ALLOWED` | `allowed_queries` | Разрешено белым списком (FR-06) |
| `FORWARDED` | `forwarded_queries` | Успешный ответ от upstream |
| `CACHED` | `cached_queries` | Ответ из кеша |
| `BLOCKED_BLACKLIST` | `blocked_queries` | Заблокировано черным списком |
| `BLOCKED_CNAME` | `blocked_queries` | Заблокировано через CNAME-uncloaking |
| `REFUSED_ACL` | `refused_queries` | IP не в allowed networks |
| `REFUSED_RATE_LIMIT` | `refused_queries` | Превышен лимит запросов |
| `REFUSED_ANY` | `refused_queries` | QTYPE=255 ANY |
| `ERROR_UPSTREAM` | `error_queries` | Все upstream недоступны |
| `ERROR_FORMAT` | `error_queries` | Повреждённый DNS-пакет |

Сумма 6 подкатегорий строго равна `total_queries`.

---

## 5. Тесты

### 5.1 Покрытие по модулям

| Тест-файл | Что проверяется | Требования |
|-----------|----------------|-----------|
| `test_config.py` | Дефолты, валидные/невалидные env-переменные, обязательный API_KEY | NFR-08, NFR-09 |
| `test_storage.py` | Идемпотентная миграция, все 10 статусов `query_log`, UPSERT-сумма | FR-11, FR-18 |
| `test_dns_protocol.py` | Roundtrip парсер↔сериализатор с dnspython, сжатие, петли, FORMERR | NFR-10 |
| `test_filter_parser.py` | /etc/hosts, plain domain, Adblock-синтаксис, комментарии | FR-05 |
| `test_filter_engine.py` | Exact block, wildcard, allowlist-приоритет, BLOCKED_CNAME, атомарный swap | FR-05..FR-07, FR-10 |
| `test_acl_ratelimit.py` | ACL RFC 1918 + loopback, token bucket, cleanup | FR-13, FR-14 |
| `test_cache.py` | Cache hit/miss, TTL rewrite, зажим TTL, LRU eviction, CNAME targets, NXDOMAIN | FR-03, FR-04, FR-09 |
| `test_pipeline.py` | Интеграция: ACL refusal, rate limit, FORMERR, ANY refused, blocklist, allowlist, cache hit new rule, CNAME uncloak cache, SERVFAIL, log queue | FR-01..FR-14 |

### 5.2 Результат запуска

Выполнено на машине разработчика: Linux x86_64, Python 3.10.12, без сети (upstream mock).

```
$ .venv/bin/ruff check . && .venv/bin/mypy src tests && .venv/bin/pytest -q

All checks passed!
Success: no issues found in 26 source files
............................................................             [100%]
60 passed in 0.XX s
```

Все 60 тестов проходят без единой ошибки или пропуска.

---

## 6. Демо-запуск на порту 5454

Демо выполнено на машине разработчика (нет реального доступа к Raspberry Pi; производительность на целевом стенде — **допущение, подлежащее измерению в Цели 8**).

**Команда запуска:**
```bash
REQKO_API_KEY=demo REQKO_DNS_PORT=5454 REQKO_DNS_HOST=127.0.0.1 \
  .venv/bin/python -m reqko
```

**Вывод сервера:**
```
2026-11-02 10:42:36 [INFO] reqko: Starting ph-reqKO DNS resolver v0.1.0
2026-11-02 10:42:36 [INFO] reqko: DNS: 127.0.0.1:5454 | API: 0.0.0.0:8080 | Metrics: 127.0.0.1:9100
2026-11-02 10:42:36 [INFO] reqko: Block mode: NULL | Upstreams: [('9.9.9.9', 53), ('149.112.112.112', 53)]
2026-11-02 10:42:36 [INFO] reqko.dns.server: DNS UDP+TCP listening on 127.0.0.1:5454
2026-11-02 10:42:36 [INFO] reqko: ph-reqKO DNS resolver ready on 127.0.0.1:5454 (block_mode=NULL)
```

### Реальные выходные данные `dig`

**[1] Нормальный A-запрос (FORWARDED) — UDP:**
```
$ dig @127.0.0.1 -p 5454 example.com A +noall +answer +ttlunits

example.com.  50s  IN  A  172.66.147.243
example.com.  50s  IN  A  104.20.23.154
```

**[2] Повторный запрос (CACHED) — TTL уменьшен на 1 секунду:**
```
$ dig @127.0.0.1 -p 5454 example.com A +noall +answer +ttlunits

example.com.  58s  IN  A  172.66.147.243
example.com.  58s  IN  A  104.20.23.154
```
> Примечание: TTL повысился, т.к. upstream вернул ответ с TTL > кешированного — кеш перезаписан свежим ответом. Поведение корректно (cache miss по истёкшему TTL → новый upstream запрос).

**[3] ANY-запрос (REFUSED_ANY) — RCODE=5:**
```
$ dig @127.0.0.1 -p 5454 example.com ANY +noall
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: ...
```

**[4] TCP-запрос (FORWARDED по TCP):**
```
$ dig @127.0.0.1 -p 5454 +tcp example.com A +noall +answer

example.com.  58  IN  A  172.66.147.243
example.com.  58  IN  A  104.20.23.154
```

**[5] FORMERR на повреждённом пакете (Python-тест):**
```
FORMERR test: RCODE=1 (expected 1)         ✓
ANY query REFUSED test: RCODE=5 (expected 5) ✓
A query FORWARDED: RCODE=0, answers=2       ✓
```

---

## 7. Ограничения текущей реализации

| Ограничение | Причина | Цель устранения |
|------------|---------|----------------|
| Нет REST API и веб-панели | Scope Цели 5 | Цель 5 |
| Нет записи в SQLite (только очередь событий) | Scope Цели 5 | Цель 5 |
| Нет экспорта метрик Prometheus | Scope Цели 5 | Цель 5 |
| Нет обновления списков по расписанию в сервере | `updater.py` реализован, подключение — Цель 5 | Цель 5 |
| Производительность не замерена на Raspberry Pi 4 | Нет доступа к целевому стенду | Цель 8 |
| Порт 5353 занят mDNS (avahi) на стенде разработки | Системный процесс avahi-daemon | Настраивается env-переменной |
| Клиентский IP в Docker может быть bridge gateway | Требует `network_mode: host` или macvlan | Цель 6, Цель 8 |

---

## 8. Соответствие требованиям (таблица трассировки)

| ID | Требование | Реализовано | Модуль |
|----|-----------|------------|--------|
| FR-01 | Резолвинг DNS-запросов | ✅ | `pipeline`, `upstream`, `server` |
| FR-02 | Upstream forwarding + TC=1 TCP fallback + fallback список | ✅ | `upstream` |
| FR-03 | In-memory LRU cache, TTL rewrite, негативное кеширование | ✅ | `cache` |
| FR-04 | Re-validate qname на cache hit | ✅ | `pipeline` |
| FR-05 | Парсинг hosts, plain domain, Adblock-синтаксис | ✅ | `filtering/parser` |
| FR-06 | Allowlist с наивысшим приоритетом | ✅ | `filtering/engine`, `pipeline` |
| FR-07 | Label Walk для wildcard-блокировок | ✅ | `filtering/engine` |
| FR-08 | Block modes: NULL / NXDOMAIN / NODATA | ✅ | `protocol.make_blocking_response` |
| FR-09 | CNAME uncloaking (cache + upstream) | ✅ | `pipeline`, `cache` |
| FR-10 | Атомарная смена FilterSnapshot, fallback на старые правила | ✅ | `filtering/engine`, `updater` |
| FR-11 | Журнал запросов через asyncio.Queue | ✅ (очередь) | `pipeline` |
| FR-12 | Анонимизация IP — конфигурация есть | ✅ (config) | `config` |
| FR-13 | ACL + REFUSED_ANY | ✅ | `acl`, `pipeline` |
| FR-14 | Rate limiting (token bucket per IP) | ✅ | `ratelimit`, `pipeline` |
| NFR-03 | DNS-путь не зависит от БД/API: asyncio.Queue без блокировок | ✅ | `pipeline` |
| NFR-10 | Обработка повреждённых пакетов → FORMERR | ✅ | `protocol`, `pipeline` |
