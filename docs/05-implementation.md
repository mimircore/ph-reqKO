# Цель 5: Сбор статистики и REST API

## 1. Обзор

Данный документ описывает реализацию подсистемы хранения статистики запросов (FR-11, FR-12) и REST API управления (FR-15..FR-17, FR-19) в рамках Цели 5. Реализация опирается на резолвер Цели 4 (`docs/04-implementation.md`): конвейер DNS уже публикует события запросов в `asyncio.Queue`, REST API не имеет доступа к горячему пути DNS.

Проверено на реальной машине: Windows 11 x64, Python 3.11.9, upstream 9.9.9.9 (Quad9). Работа ведётся в ветке `obj-5-stats-api`.

---

## 2. Структура модулей

| Модуль | Путь | Назначение | Требования |
|--------|------|-----------|-----------|
| `storage/writer` | `src/reqko/storage/writer.py` | Асинхронный потребитель очереди событий: пакетная вставка в `query_log` + UPSERT `stats_hourly` в одной транзакции; flush по N событий или T секунд; drain при остановке; анонимизация IP | FR-11, FR-12, NFR-03 |
| `storage/retention` | `src/reqko/storage/retention.py` | Ротация: удаление `query_log` старше `REQKO_LOG_RETENTION_DAYS`; запуск на старте и затем раз в час | FR-12 |
| `storage/settings` | `src/reqko/storage/settings.py` | Ключ/значение в `system_settings` (хеш админ-токена, время последнего обновления списков) | FR-17 |
| `storage/migrations` | `src/reqko/storage/migrations.py` | Миграция v2: колонки `latency_sum`, `latency_samples` в `stats_hourly` (схема v1 обновляется на месте, данные сохраняются) | FR-11 |
| `filtering/rules` | `src/reqko/filtering/rules.py` | `RuleManager`: пользовательские правила в таблице `custom_rules`, слияние с базовым снимком и атомарная подмена `FilterSnapshot` без перезапуска | FR-19, FR-10 |
| `api/app` | `src/reqko/api/app.py` | Фабрика aiohttp-приложения: middleware (заголовки безопасности, RFC 7807 ошибки, Bearer-аутентификация), `ApiState` | FR-15..FR-17 |
| `api/auth` | `src/reqko/api/auth.py` | SHA-256 хеширование токенов, сравнение `hmac.compare_digest`, скоупы read/admin, per-IP лимит неудачных аутентификаций | FR-17 |
| `api/routes` | `src/reqko/api/routes.py` | Обработчики: `/health`, `/ready`, статистика, журнал запросов, правила, обновление списков | FR-15, FR-16, FR-19 |
| `dns/upstream` | `src/reqko/dns/upstream.py` | + `probe_upstream()`: лёгкий UDP-зонд (запрос NS корня) для `/health` | FR-16 |
| `config` | `src/reqko/config.py` | Новые переменные: `REQKO_API_HOST/PORT`, `REQKO_ADMIN_TOKEN`, `REQKO_READ_TOKEN`, `REQKO_LOG_CLIENT_IP`, `REQKO_LOG_BATCH_SIZE`, `REQKO_LOG_FLUSH_INTERVAL`, `REQKO_AUTH_FAILURE_LIMIT/WINDOW`, `REQKO_BLOCKLIST_URLS`, `REQKO_LOG_RETENTION_DAYS` (по умолчанию 7) | NFR-08 |
| `__main__` | `src/reqko/__main__.py` | Запуск DNS-серверов и REST API в одном event loop; bootstrap токена; writer, retention; корректная остановка с финальным flush | FR-15..FR-17 |

---

## 3. Поток статистики

```
DNS-конвейер (pipeline)                    Фоновые задачи                    SQLite (WAL)
──────────────────────                    ─────────────────────────────     ─────────────
process_query() ──put_nowait──▶ asyncio.Queue(maxsize=10000) ──▶ QueryLogWriter.run()
        │                                        │                        │
        └─ очередь полна: событие                │ пакет: ≥ N событий     │ BEGIN
           отброшено, drop_counter += 1          │ или T секунд           │ ├ executemany INSERT query_log
                                                 ▼                        │ ├ UPSERT stats_hourly (+latency_sum/samples)
                                        анонимизация IP (FR-12)          │ └ COMMIT (в executor, вне event loop)
                                                                          ▼
                                        RetentionJob: DELETE ... WHERE timestamp < now - REQKO_LOG_RETENTION_DAYS дней (старт + каждый час)
```

Ключевые решения:

- **NFR-03 (изоляция горячего пути)**: запись в SQLite выполняется в `run_in_executor`; DNS-конвейер только кладёт событие в очередь `put_nowait`. Переполнение очереди не блокирует резолвинг — событие отбрасывается, счётчик `dropped_events` доступен в `/health`.
- **Одна транзакция**: строки `query_log` и UPSERT `stats_hourly` коммитятся вместе. Категории статусов — по разделу 7.3 архитектуры; в v2 схемы добавлены `latency_sum`/`latency_samples`, поэтому средняя задержка считается инкрементально (без полного сканирования журнала).
- **Приватность (FR-12)**: `REQKO_LOG_CLIENT_IP = full | anonymized | off`. `anonymized` маскирует последний октет IPv4 (`192.168.1.45` → `192.168.1.0`) и последние 80 бит IPv6 (сохраняется префикс /48). Legacy-переменная `REQKO_ANONYMIZE_IPS=true` эквивалентна `anonymized`. Значение `off` записывает пустую строку.
- **Flush при остановке**: `writer.stop()` + завершение задачи осушают очередь и выполняют финальную вставку — ни одно принятое событие не теряется при штатной остановке.
- **Retention**: `DELETE FROM query_log WHERE timestamp < datetime('now', '-' || ? || ' days')` — параметризованный запрос; агрегаты `stats_hourly` сохраняются, поэтому графики остаются полными после удаления детальных строк.

---

## 4. REST API

Базовый префикс `/api/v1`; ошибки — RFC 7807 (`application/problem+json`); все параметры SQL — только связанные (`?`). API по умолчанию слушает `127.0.0.1:8080` (`REQKO_API_HOST` / `REQKO_API_PORT`).

### 4.1 Таблица эндпоинтов

| Метод | Путь | Аутентификация | Назначение (FR) | Коды |
|---|---|:---:|---|:---:|
| `GET` | `/health` | нет (публичный) | Живость: статус, uptime, БД, upstream, списки, очередь (FR-16) | 200, 503 |
| `GET` | `/ready` | нет (публичный) | Готовность: правила загружены в память (FR-16) | 200, 503 |
| `GET` | `/api/v1/stats/summary?from=&to=` | Bearer (read) | Итоги, % блокировок, % кеша, средняя задержка (FR-15) | 200, 400 |
| `GET` | `/api/v1/stats/timeseries?bucket=hour\|day` | Bearer (read) | Временные ряды из `stats_hourly` (FR-15) | 200, 400 |
| `GET` | `/api/v1/stats/top-domains?status=&limit=` | Bearer (read) | Топ доменов: blocked / allowed / all (FR-15) | 200, 400 |
| `GET` | `/api/v1/stats/top-clients?limit=` | Bearer (read) | Топ клиентов (FR-11) | 200, 400 |
| `GET` | `/api/v1/queries?limit=&offset=&status=&client=&domain=` | Bearer (read) | Журнал запросов, `limit` ≤ 500 (FR-11) | 200, 400 |
| `GET` | `/api/v1/allowlist` | Bearer (read) | Список пользовательских исключений (FR-19) | 200 |
| `POST` | `/api/v1/allowlist` | Bearer (admin) | Добавить домен в белый список (FR-19) | 201, 400 |
| `DELETE` | `/api/v1/allowlist/{domain}` | Bearer (admin) | Удалить исключение (FR-19) | 200, 404 |
| `GET` | `/api/v1/blocklist/custom` | Bearer (read) | Список пользовательских блокировок (FR-19) | 200 |
| `POST` | `/api/v1/blocklist/custom` | Bearer (admin) | Добавить блокировку (FR-19) | 201, 400 |
| `DELETE` | `/api/v1/blocklist/custom/{domain}` | Bearer (admin) | Удалить блокировку (FR-19) | 200, 404 |
| `POST` | `/api/v1/blocklists/update` | Bearer (admin) | Фоновое обновление списков (FR-10, FR-15) | 202, 400, 409 |

Пагинация: `limit` от 1 до 500 (`top-*` до 100), `offset` ≥ 0. `from`/`to` — ISO 8601 (дата трактуется как полный день для `to`). Домены валидируются `normalize_domain` (нижний регистр, без замыкающей точки).

### 4.2 Аутентификация (FR-17)

- Схема: `Authorization: Bearer <token>`. Хранится **только SHA-256 хеш**; сравнение — `hmac.compare_digest`.
- Скоупы: `admin` — все методы; `read` — только GET. `/health` и `/ready` публичны.
- Bootstrap: токен из `REQKO_ADMIN_TOKEN` (хешируется на старте) либо генерируется **один раз** при первом старте (`secrets.token_urlsafe(32)`), выводится в stdout однократно, в БД сохраняется только хеш (таблица `system_settings`). Дополнительный read-only токен — `REQKO_READ_TOKEN`.
- Rate limit неудачных аутентификаций: 10 неудач за 60 с на IP → `429` (`REQKO_AUTH_FAILURE_LIMIT` / `REQKO_AUTH_FAILURE_WINDOW`).
- Заголовки безопасности на всех ответах: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`.

---

## 5. Тесты

### 5.1 Покрытие по модулям

| Тест-файл | Что проверяется | Требования |
|-----------|----------------|-----------|
| `tests/unit/test_storage_writer.py` | Батчи по размеру и по времени, flush при остановке (без потерь), UPSERT `stats_hourly` (все категории + latency), drop-when-full через реальный pipeline, анонимизация IPv4/IPv6/off, retention (старые строки удаляются, свежие остаются), остановка retention | FR-11, FR-12, NFR-03 |
| `tests/unit/test_storage_settings.py` | Ключ/значение: отсутствующий ключ, roundtrip, перезапись, контроль типов | FR-17 |
| `tests/unit/test_storage.py` | + миграция v1→v2 на живой БД: колонки добавляются, данные и счётчики сохраняются, UPSERT работает | FR-11 |
| `tests/unit/test_auth.py` | SHA-256 хеш, скоупы (admin/read/нет), read-токен не получает admin, limiter: блокировка после N, окно, per-IP | FR-17 |
| `tests/unit/test_config.py` | + новые переменные, legacy-алиасы (`REQKO_API_KEY`, `REQKO_HTTP_*`), `REQKO_ANONYMIZE_IPS` → `anonymized`, валидация | NFR-08 |
| `tests/integration/test_api.py` | Все эндпоинты: health/ready (публичные, 503), 401/403/429, скоупы, пагинация и её пределы, фильтры, SQL-инъекция как связанный параметр (таблица цела), невалидный ввод → 400 problem+json, CRUD правил с нормализацией, `/ready` после загрузки правил, обновление списков 202/409/400, интеграция: allowlist меняет следующий DNS-ответ | FR-15..FR-19 |

### 5.2 Результат запуска

Реальный запуск на машине разработки (Windows 11 x64, Python 3.11.9):

```
> .venv\Scripts\python.exe -m ruff check .
All checks passed!

> .venv\Scripts\python.exe -m mypy src tests
Success: no issues found in 42 source files

> .venv\Scripts\python.exe -m pytest
........................................................................ [ 48%]
........................................................................ [ 97%]
....                                                                     [100%]
148 passed in 7.24s
```

### 5.3 Покрытие кода

```
> .venv\Scripts\python.exe -m pytest --cov=reqko --cov-report=term-missing -q
........................................................................ [ 48%]
........................................................................ [ 97%]
....                                                                     [100%]

Name                              Stmts   Miss  Cover   Missing
---------------------------------------------------------------
src\reqko\__init__.py                 1      0   100%
src\reqko\__main__.py               126    126     0%   3-272
src\reqko\api\__init__.py             0      0   100%
src\reqko\api\app.py                 94      0   100%
src\reqko\api\auth.py                47      0   100%
src\reqko\api\routes.py             286      9    97%   99-100, 116, 118, 137-138, 467, 484, 505
src\reqko\config.py                 170     10    94%   162-164, 192, 313, 319, 326-327, 330, 340
src\reqko\dns\__init__.py             2      0   100%
src\reqko\dns\acl.py                 15      0   100%
src\reqko\dns\cache.py               92      7    92%   97, 130, 156, 187, 200-202
src\reqko\dns\pipeline.py           150     11    93%   87-88, 104-105, 180-182, 256-258, 285
src\reqko\dns\protocol.py           304     35    88%   142, 183, 196, 208-210, 220, 222-224, 226-227, 229-241, 245-247, 328, 335, 343, 352, 363, 371-372, 377, 395, 409, 413, 423, 428, 436
src\reqko\dns\ratelimit.py           37      2    95%   37, 48
src\reqko\dns\server.py              73     12    84%   37-38, 41, 64, 68-69, 76, 81-82, 123-126
src\reqko\dns\upstream.py            97     14    86%   58, 94-95, 110, 140-149, 158, 166-170, 196, 205
src\reqko\filtering\__init__.py       3      0   100%
src\reqko\filtering\engine.py        56      0   100%
src\reqko\filtering\parser.py        98     10    90%   52-55, 88, 123, 133, 142, 171, 184
src\reqko\filtering\rules.py         70      1    99%   136
src\reqko\filtering\updater.py       73      6    92%   33, 66, 71, 139-145
src\reqko\storage\__init__.py         2      0   100%
src\reqko\storage\migrations.py      45      3    93%   39, 44, 55
src\reqko\storage\retention.py       34      2    94%   55-56
src\reqko\storage\settings.py         9      0   100%
src\reqko\storage\writer.py         107      6    94%   189, 192-193, 217-219
---------------------------------------------------------------
TOTAL                              1991    254    87%
```

Покрытие нового кода Цели 5: `api/app` 100%, `api/auth` 100%, `api/routes` 97%, `filtering/rules` 99%, `storage/writer` 94%, `storage/retention` 94%, `storage/settings` 100% — все выше порога 85%. `__main__.py` не покрыт автотестами (точка входа проверяется демо-запуском, раздел 6).

---

## 6. Демо-запуск

Демо выполнено на реальной машине (Windows 11, Python 3.11.9, upstream 9.9.9.9). DNS — порт 5454, API — 127.0.0.1:8080. Блоклист — локальный файл (`||ads.example.com^`, `doubleclick.net`, `tracker.test`); БД — временный файл; `REQKO_ADMIN_TOKEN` / `REQKO_READ_TOKEN` заданы явно.

**Реальный журнал старта:**

```
2026-11-04 18:19:07,789 [INFO] reqko: Starting ph-reqKO DNS resolver + REST API v0.1.0
2026-11-04 18:19:07,790 [INFO] reqko: DNS listeners: 127.0.0.1:5454 (UDP+TCP) | REST API: 127.0.0.1:8080
2026-11-04 18:19:07,807 [INFO] reqko.storage.migrations: Recorded schema migration version 2
2026-11-04 18:19:07,831 [INFO] reqko.filtering.updater: Loaded blocklist: C:\Users\mirrw0\AppData\Local\Temp\reqko_demo\demo_blocklist.txt (4 lines)
2026-11-04 18:19:07,832 [INFO] reqko.filtering.rules: Filter rules v2: 3 rules (3 base + 0 custom)
2026-11-04 18:19:07,833 [INFO] reqko.dns.server: DNS UDP+TCP listening on 127.0.0.1:5454
2026-11-04 18:19:07,833 [INFO] reqko: ph-reqKO DNS resolver ready on 127.0.0.1:5454 (UDP+TCP, block_mode=NULL)
2026-11-04 18:19:07,836 [INFO] reqko: REST API listening on 127.0.0.1:8080 (auth: Bearer token; /health is public)
2026-11-04 18:19:07,837 [INFO] reqko: Metrics exporter (127.0.0.1:9100) is not implemented yet (objective 7)
```

**22 DNS-запроса (dnspython):** `example.com` ×5 (FORWARDED → CACHED), `ads.example.com` ×4 и `sub.ads.example.com` ×3 (BLOCKED, 0.0.0.0), `doubleclick.net` ×3 (BLOCKED), `wikipedia.org` ×2, `example.com ANY` ×2 (REFUSED), `newdomain.test` ×2 и `definitely-not-real-xyz.test` (NXDOMAIN от upstream, негативно закеширован). Итог: 22 события, все попали в БД.

**`GET /health` (публичный):**

```json
{"status": "ok", "uptime_seconds": 18.641, "database": {"reachable": true}, "upstream": {"reachable": true}, "blocklist": {"domains": 3, "version": 2, "last_update": "2026-11-04 16:19:07"}, "queue": {"depth": 0, "dropped_events": 0}}
```

**`GET /api/v1/stats/summary` (Bearer admin):**

```json
{"from": null, "to": null, "total_queries": 22, "blocked_queries": 10, "blocked_percentage": 45.45, "cached_queries": 6, "cache_hit_percentage": 27.27, "forwarded_queries": 4, "allowed_queries": 0, "refused_queries": 2, "error_queries": 0, "avg_latency_ms": 0.659}
```

**`GET /api/v1/stats/top-domains?status=blocked`:**

```json
{"status": "blocked", "domains": [{"question_name": "ads.example.com", "hits": 4}, {"question_name": "doubleclick.net", "hits": 3}, {"question_name": "sub.ads.example.com", "hits": 3}]}
```

**`GET /api/v1/queries?limit=5` (новые записи первыми; показан фрагмент):**

```json
{"total": 22, "limit": 5, "offset": 0, "queries": [{"id": 22, "timestamp": "2026-11-04 16:19:18", "client_ip": "127.0.0.1", "question_name": "definitely-not-real-xyz.test", "question_type": "A", "status": "FORWARDED", "matched_rule": null, "upstream": "9.9.9.9:53", "latency_ms": 3.1096001621335745, "response_code": 3}, "...ещё 4 записи..."]}
```

**Без токена → 401 (RFC 7807 + заголовки безопасности):**

```
HTTP/1.1 401 Unauthorized
Content-Type: application/problem+json; charset=utf-8
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Cache-Control: no-store
...

{"type": "about:blank", "title": "Unauthorized", "status": 401, "detail": "Provide the API token as 'Authorization: Bearer <token>'."}
```

**POST с read-токеном → 403 (скоуп admin требуется):**

```
HTTP/1.1 403 Forbidden
Content-Type: application/problem+json; charset=utf-8
...

{"type": "about:blank", "title": "Forbidden", "status": 403, "detail": "This endpoint requires a token with the admin scope."}
```

**Allowlist меняет следующий DNS-ответ (FR-19):**

```
DELETE /api/v1/allowlist/... → {"status": "deleted", ...}
DNS doubleclick.net ДО:    NOERROR ['doubleclick.net. 300 IN A 0.0.0.0']
POST /api/v1/allowlist {"domain": "doubleclick.net"} → 201 {"status": "created", "rule": {"type": "whitelist", "domain": "doubleclick.net"}}
DNS doubleclick.net ПОСЛЕ: NOERROR ['doubleclick.net. 291 IN A 172.253.62.102
                                     doubleclick.net. 291 IN A 172.253.62.139, ...']
DELETE правила → снова 0.0.0.0
```

Примечание: для `ads.example.com` после исключения из блокировки upstream Quad9 возвращает NOERROR без записей (NODATA — у домена нет A-записей); резолвер корректно отдаёт пустой авторитетный ответ и негативно кеширует его. Для наглядности в демо использован `doubleclick.net`, у которого есть реальные A-записи.

---

## 7. Ограничения текущей реализации

| Ограничение | Причина | Цель устранения |
|------------|---------|----------------|
| Нет веб-панели с графиками (FR-18) — API готов отдавать данные | Scope панели не входит в задачу Цели 5 | Цель 5/6 |
| Нет экспорта метрик Prometheus | Scope Цели 7 | Цель 7 |
| Токены не управляются через API (создание/ротация read-токенов — только env) | Минимальный скоуп аутентификации | Цель 6/7 |
| `/stats/summary` считает по `query_log`, а не по `stats_hourly` (после ротации итоги за удалённый период исчезают) | Точность важнее скорости на текущих объёмах; `timeseries` уже строится по агрегатам | Цель 7 |
| Ретеншн не удаляет строки `stats_hourly` (агрегаты копятся бессрочно) | Соответствует архитектуре: графики остаются полными | Цель 7 |
| Метаданные списков (`blocklist_sources`) не заполняются — статус обновления в `system_settings` | Таблица зарезервирована для управления списками через API | Цель 6/7 |
| `__main__.py` не покрыт юнит-тестами | Точка входа проверяется демо-запуском | Цель 8 |

---

## 8. Соответствие требованиям (таблица трассировки)

| ID | Требование | Статус | Модуль |
|----|-----------|--------|--------|
| FR-01..FR-10 | Резолвер, фильтрация, кеш, обновление списков | ✅ (Цель 4) | `dns/*`, `filtering/*` |
| FR-11 | Журнал запросов и агрегированная статистика в БД | ✅ | `storage/writer`, `api/routes` |
| FR-12 | Срок хранения логов (ротация) и анонимизация IP | ✅ | `storage/retention`, `storage/writer`, `config` |
| FR-13 | ACL + отказ в ANY | ✅ (Цель 4) | `dns/acl`, `dns/pipeline` |
| FR-14 | Rate limiting DNS-клиентов | ✅ (Цель 4) | `dns/ratelimit` |
| FR-15 | REST API управления и статистики | ✅ (без управления списками-источниками CRUD; refresh и custom rules реализованы) | `api/routes` |
| FR-16 | Health/Ready эндпоинты | ✅ (`/health`, `/ready`, публичные, 200/503) | `api/routes` |
| FR-17 | Аутентификация REST API (X-API-Key/Bearer) | ✅ (Bearer + SHA-256; генерация при первом старте вместо отказа запуска — допустимая альтернатива из FR-17) | `api/auth`, `api/app`, `__main__` |
| FR-18 | Веб-панель с графиками | ❌ NOT IMPLEMENTED | — |
| FR-19 | Ручные пользовательские правила | ✅ (API; применение без перезапуска) | `filtering/rules`, `api/routes` |
| NFR-01/02 | Задержка p95, RAM | ❌ NOT IMPLEMENTED (не замерялись) | Цель 8 |
| NFR-03 | Изоляция сбоев: очередь с отбрасыванием, БД вне горячего пути | ✅ | `storage/writer`, `dns/pipeline` |
| NFR-04 | Безопасность контура (non-root, Trivy) | ❌ NOT IMPLEMENTED | Цель 6 |
| NFR-05 | Качество кода: ruff 0, mypy strict 0 | ✅ | вся кодовая база |
| NFR-06 | Переносимость (Windows/Linux, без обязательных C-расширений) | ⚠️ Частично: Windows проверена, ARM/Docker — нет | Цель 6 |
| NFR-07 | Метрики Prometheus | ❌ NOT IMPLEMENTED | Цель 7 |
| NFR-08 | Развёртывание docker compose | ❌ NOT IMPLEMENTED | Цель 6 |
| NFR-09 | Покрытие > 70% и CI | ⚠️ PARTIAL — 87% покрытие; CI не настроен | `tests/` |
| NFR-10 | RFC 1034/1035 | ✅ (Цель 4) | `dns/protocol` |
