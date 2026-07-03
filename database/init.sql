CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS incident_baskets (
    basket_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_name       TEXT NOT NULL,
    user_name       TEXT,
    source_ip       TEXT,
    status          TEXT DEFAULT 'open',
    confidence_score INT DEFAULT 0,
    matched_stages  JSONB DEFAULT '[]',
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS basket_events (
    event_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    basket_id       UUID REFERENCES incident_baskets(basket_id) ON DELETE CASCADE,
    event_type      TEXT,
    raw_event       JSONB,
    mitre_technique TEXT,
    event_time      TIMESTAMP WITH TIME ZONE,
    ingestion_time  TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS enrichment_cache (
    indicator       TEXT NOT NULL,
    indicator_type  TEXT NOT NULL,
    source          TEXT NOT NULL,
    verdict         JSONB,
    checked_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (indicator, source)
);

CREATE TABLE IF NOT EXISTS alert_suppression (
    id              SERIAL PRIMARY KEY,
    host_name       TEXT,
    user_name       TEXT,
    rule_id         TEXT,
    suppressed_by   TEXT DEFAULT 'analyst',
    suppressed_at   TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at      TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS login_baseline (
    user_name           TEXT NOT NULL,
    source_ip           TEXT NOT NULL,
    source_country      TEXT,
    typical_hour_start  INT DEFAULT 0,
    typical_hour_end    INT DEFAULT 23,
    first_seen          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen           TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    seen_count          INT DEFAULT 1,
    PRIMARY KEY (user_name, source_ip)
);

-- Index for common queries
CREATE INDEX IF NOT EXISTS idx_baskets_open_host ON incident_baskets(host_name) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS idx_basket_events_basket ON basket_events(basket_id);
CREATE INDEX IF NOT EXISTS idx_suppression_lookup ON alert_suppression(host_name, user_name, rule_id);
