CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS incident_baskets (
    basket_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_name       TEXT NOT NULL,
    user_name       TEXT,
    source_ip       TEXT,
    status          TEXT DEFAULT 'open',
    confidence_score INT DEFAULT 0,
    matched_stages  JSONB DEFAULT '[]',
    assigned_to     TEXT,
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

-- Phase 6: Audit log for SOC2/HIPAA/PCI evidence trail
CREATE TABLE IF NOT EXISTS audit_log (
    id          SERIAL PRIMARY KEY,
    event_type  TEXT NOT NULL,          -- alert_fired | response_action:* | suppression_created | playbook_fired
    basket_id   UUID,
    rule_id     TEXT,
    tier        TEXT,
    actor       TEXT DEFAULT 'system',  -- analyst name, 'engine', 'thehive_webhook', 'playbook:<id>'
    detail      JSONB DEFAULT '{}',
    created_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_basket ON audit_log(basket_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at DESC);

-- Phase 8: Saved Searches
CREATE TABLE IF NOT EXISTS saved_searches (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    query TEXT NOT NULL,
    created_by TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Phase 9: Cases (Escalation)
CREATE TABLE IF NOT EXISTS cases (
    id SERIAL PRIMARY KEY,
    basket_id UUID REFERENCES incident_baskets(basket_id),
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    assignee TEXT,
    summary TEXT,
    technical_details TEXT,
    status TEXT DEFAULT 'open',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
