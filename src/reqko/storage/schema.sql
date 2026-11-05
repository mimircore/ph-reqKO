-- Schema definition for reqko (ph-reqKO)
-- Based on docs/03-architecture.md section 7.2

PRAGMA foreign_keys = ON;

-- 1. Таблица версий схемы и истории миграций
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    description TEXT NOT NULL
);

-- 2. Таблица подключённых источников списков блокировок (FR-15)
CREATE TABLE IF NOT EXISTS blocklist_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    url TEXT NOT NULL UNIQUE,
    format TEXT NOT NULL CHECK(format IN ('hosts', 'plain', 'abp')),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    last_updated_at TIMESTAMP,
    last_status TEXT CHECK(last_status IN ('success', 'error', 'pending')),
    error_message TEXT,
    rules_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 3. Таблица пользовательских исключений и блокировок (FR-19)
CREATE TABLE IF NOT EXISTS custom_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_type TEXT NOT NULL CHECK(rule_type IN ('whitelist', 'blacklist')),
    syntax_type TEXT NOT NULL CHECK(syntax_type IN ('exact', 'wildcard')),
    domain TEXT NOT NULL,
    comment TEXT,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(rule_type, domain)
);

-- 4. Детальный журнал обработанных запросов (FR-11, FR-12)
CREATE TABLE IF NOT EXISTS query_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    client_ip TEXT NOT NULL,
    question_name TEXT NOT NULL,
    question_type TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN (
        'ALLOWED',
        'FORWARDED',
        'BLOCKED',
        'BLOCKED_BLACKLIST',
        'BLOCKED_CNAME',
        'CACHED',
        'REFUSED_ACL',
        'REFUSED_RATE_LIMIT',
        'REFUSED_ANY',
        'ERROR_UPSTREAM',
        'ERROR_FORMAT'
    )),
    matched_rule TEXT,
    upstream TEXT,
    latency_ms REAL NOT NULL,
    response_code INTEGER NOT NULL,
    -- v3: event origin (dns query vs aggregated browser-extension report)
    source TEXT NOT NULL DEFAULT 'dns' CHECK(source IN ('dns', 'browser')),
    -- v3: aggregated occurrence count (browser reports batch counts)
    occurrences INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_query_log_timestamp ON query_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_query_log_client_ip ON query_log(client_ip);
CREATE INDEX IF NOT EXISTS idx_query_log_question_name ON query_log(question_name);
CREATE INDEX IF NOT EXISTS idx_query_log_status ON query_log(status);

-- 5. Почасовая агрегированная статистика для быстрых графиков (FR-11, FR-18)
-- Сумма подкатегорий строго равна total_queries
CREATE TABLE IF NOT EXISTS stats_hourly (
    bucket_timestamp TIMESTAMP NOT NULL PRIMARY KEY,
    total_queries INTEGER NOT NULL DEFAULT 0,
    blocked_queries INTEGER NOT NULL DEFAULT 0,
    cached_queries INTEGER NOT NULL DEFAULT 0,
    forwarded_queries INTEGER NOT NULL DEFAULT 0,
    allowed_queries INTEGER NOT NULL DEFAULT 0,
    refused_queries INTEGER NOT NULL DEFAULT 0,
    error_queries INTEGER NOT NULL DEFAULT 0,
    latency_sum REAL NOT NULL DEFAULT 0,
    latency_samples INTEGER NOT NULL DEFAULT 0
);

-- 6. Таблица параметров и настроек
CREATE TABLE IF NOT EXISTS system_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
