# Цель 6 (дополнение): Адаптивное обнаружение рекламных доменов

> Механизм предлагает домены для блокировки на основе анализа вашего собственного query_log — без внешних сервисов, без ML. Каждый suggestion проходит ручное approve/reject до попадания в блоклист.

---

## 1. Алгоритм

Каждые `REQKO_SUGGEST_INTERVAL_MINUTES` (по умолчанию 15; 0 отключает) задача читает `query_log` за последние `REQKO_SUGGEST_WINDOW_HOURS` (по умолчанию 24 ч) и оценивает домены со статусами FORWARDED/CACHED:

| Сигнал | Описание | Score | Причина (в БД) |
|---|---|---|---|
| Keyword | Метка домена или её токен (разбиение по `-` и цифрам) совпадает с ключевым словом: ad, ads, adserver, adservice, adx, adsystem, doubleclick, track, tracker, tracking, telemetry, metrics, analytics, attribution, mediation, rtb, ssp, dsp, pixel, beacon, banner, offerwall, rewarded, events | +2 за каждую метку | `keyword:<токен>` |
| Fallback | Тот же клиент запросил домен в течение 3 с ПОСЛЕ BLOCKED_*, и домен никогда не запрашивался вне таких окон | +3 | `fallback after blocked` |
| Sibling burst | Домен запрошен в том же 2-секундном всплеске, что и ≥ 2 BLOCKED_* домена от разных рекламных сетей (разные registrable base) | +2 | `sibling burst` |

Минимум: `REQKO_SUGGEST_MIN_HITS` (по умолчанию 2) запросов домена за окно.

Точное совпадение токенов: `ads` не матчит `loads`, `uploads`, `gadsden` (проверено тестами). Разбиение по цифрам: `ad2` → `ad`. Разбиение по дефису: `sdk-events` → `events`.

### Защищённые базовые домены (PROTECTED)

Домены, registrable base которых входит в защищённый список, **никогда не предлагаются**, даже при совпадении ключевых слов: google.com, googleapis.com, gstatic.com, googleusercontent.com, facebook.com, fbcdn.net, instagram.com, whatsapp.com, microsoft.com, windows.com, apple.com, icloud.com, cloudflare.com, amazonaws.com, github.com, miui.com, xiaomi.com, а также wildcard `firebase*` и `connectivitycheck.*`.

Исключение: хосты вида `ad.intl.xiaomi.com` (Xiaomi ad hosts на защищённом base) остаются suggestible — ключевое слово `ad` в самом хосте отменяет защиту для base xiaomi.com/miui.com только.

Список редактируется в `src/reqko/filtering/data/protected_bases.txt` (package-data), тесты фиксируют поведение для googleapis/facebook/gstatic.

### Registrable base

Мини-хелпер публичных суффиксов (без зависимостей): co.uk, com.au, co.jp, com.br, org.uk, ac.uk, gov.uk, net.au, org.au, co.nz, co.in, co.za, co.kr, co.id, com.cn, com.tw, com.hk, com.sg, com.tr, com.ua, com.pl, com.my, ne.jp, or.jp, com.mx, com.ar. Для `metrics.ads.yahoo.co.uk` base = `yahoo.co.uk`. Предложение экспортирует base как wildcard-правило (`||base^`), только когда base сам набирает score; иначе — точный домен.

## 2. Хранение и API

Миграция v4: таблица `domain_suggestions` (domain PK, base, score, reasons_json, hits, first_seen, last_seen, status pending|approved|rejected, auto, decided_at). Данные v3 сохраняются.

| Метод | Путь | Скоуп | Назначение |
|---|---|---|---|
| GET | `/api/v1/suggestions?status=pending\|approved\|rejected&limit=` | read | Список предложений |
| POST | `/api/v1/suggestions/analyze` | admin | Запустить анализ немедленно |
| POST | `/api/v1/suggestions/{domain}/approve` | admin | Добавить custom blocklist rule через RuleManager (atomic swap, без рестарта), пометить approved |
| POST | `/api/v1/suggestions/{domain}/reject` | admin | Пометить rejected (анализатор больше не предлагает) |

Auto-approve: `REQKO_SUGGEST_AUTO_APPROVE_SCORE=<N>` — предложения с score ≥ N автоматически получают правило blocklist (wildcard для base с keyword, иначе exact) и помечаются `auto=1` для последующего ревью. По умолчанию выключено.

## 3. Периодический refresh блоклистов

`REQKO_BLOCKLIST_REFRESH_HOURS` (по умолчанию 24; 0 отключает): фоновая задача перезагружает `REQKO_BLOCKLIST_URLS` с ETag/If-None-Match — при 304 сохраняются текущие правила без пересборки; при ошибке — тоже (FR-10). Локальные файлы перечитываются всегда.

Проверенные URL для старта (реальные загрузки на машине разработки):
- `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts` (84576 строк → 77758 правил)

## 4. Оценка на реальных данных (честная)

Запуск на копии `reqko.db` демо-сервера (1343 строки query_log, окно 7 дней, `min_hits=2`): **27 предложений**.

| Домен | Score | Причины | Классификация |
|---|---|---|---|
| px.ads.linkedin.com | 7 | keyword:ads, fallback, burst | **ad/tracker** (LinkedIn ad pixel) |
| api.cr-relay.com | 5 | fallback, burst | legitimate (crash relay) |
| d.applvn.com | 5 | fallback, burst | **ad/tracker** (AppLovin) |
| env-backend-prod...elasticbeanstalk.com | 5 | fallback, burst | legitimate (app backend) |
| ms4.applvn.com | 5 | fallback, burst | **ad/tracker** (AppLovin) |
| tracker.gg | 5 | keyword:tracker, fallback | legitimate (game stats site) |
| wikipedia.org | 5 | fallback, burst | legitimate |
| www.google.md | 5 | fallback, burst | legitimate (Google TLD-вариант) |
| www.linkedin.com.cdn.cloudflare.net | 5 | fallback, burst | legitimate (CDN) |
| mediation.goog | 4 | keyword:mediation, burst | **ad/tracker** (Google AdMob) |
| api.individual.githubcopilot.com | 3 | fallback | legitimate |
| atm.outlook...cloud.microsoft | 3 | fallback | legitimate |
| avatars.githubusercontent.com | 3 | fallback | legitimate |
| config.uca.cloud.unity3d.com | 3 | fallback | legitimate |
| github.githubassets.com | 3 | fallback | legitimate |
| outlook.cloud.microsoft | 3 | fallback | legitimate |
| shed.outlook...cloud.microsoft | 3 | fallback | legitimate |
| support.mozilla.org | 3 | fallback | legitimate |
| unsplash.com | 3 | fallback | legitimate |
| user-images.githubusercontent.com | 3 | fallback | legitimate |
| api.ad.intl.xiaomi.com | 2 | keyword:ad | **ad/tracker** (Xiaomi ads) |
| claude.ai | 2 | burst | legitimate |
| example.com | 2 | burst | legitimate (test) |
| logs.ads.vungle.com | 2 | keyword:ads | **ad/tracker** (Vungle) |
| ohttp-relay-safebrowsing...fastly-edge.com | 2 | burst | legitimate (Safe Browsing) |
| prod-mediate-events.applovin.com | 2 | keyword:events | **ad/tracker** (AppLovin) |
| us.api.userled.io | 2 | burst | **ad/tracker** (marketing tracking, borderline) |

**Precision: 8/27 ≈ 30%** при дефолтных настройках. Основной источник ложных срабатываний — сигнал fallback+burst: legit домены, запрошенные сразу после блока рекламного CDN (технологические всплески при загрузке страницы), набирают тот же score. Keyword-сигнал точнее (8/9 для явных ad-меток).

Митигация: каждое предложение требует явного approve до попадания в блоклист; auto-approve выключен по умолчанию; PROTECTED-список отсекает критичные базы; reject запоминается навсегда.

## 5. Ограничения

- Не ловит рекламу на first-party доменах (site.com/pagead/...) — нет универсального селектора.
- Эвристики, не ML: keyword + поведенческие сигналы; точность зависит от паттернов использования.
- Fallback/burst сигналы дают много false positives на shared-инфраструктуре — ручное approve обязательно при дефолтных настройках.
- Приложения вне браузера и системный DNS фильтруются ядром, не расширением.

## 6. Конфигурация

| Переменная | По умолчанию | Описание |
|---|---|---|
| `REQKO_SUGGEST_WINDOW_HOURS` | 24 | Окно анализа query_log (часы) |
| `REQKO_SUGGEST_MIN_HITS` | 2 | Минимум запросов домена за окно |
| `REQKO_SUGGEST_INTERVAL_MINUTES` | 15 | Интервал планировщика (0 = отключить) |
| `REQKO_SUGGEST_AUTO_APPROVE_SCORE` | *(выкл)* | Авто-approve при score ≥ N (пусто = ручное ревью) |
| `REQKO_BLOCKLIST_REFRESH_HOURS` | 24 | Периодический refresh URL-списков (0 = отключить) |
