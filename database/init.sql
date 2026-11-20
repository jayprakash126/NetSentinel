-- ==========================================
-- NetSentinel Database Schema
-- PostgreSQL 16
-- ==========================================

-- 1. Network Events
CREATE TABLE IF NOT EXISTS network_events (
    id BIGSERIAL PRIMARY KEY,

    event_type VARCHAR(50) NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL,

    source_ip INET,
    destination_ip INET,

    source_port INTEGER,
    destination_port INTEGER,

    protocol VARCHAR(20),
    application_protocol VARCHAR(50),

    raw_event JSONB NOT NULL,

    event_hash VARCHAR(64),

    created_at TIMESTAMPTZ DEFAULT NOW(),

    CONSTRAINT valid_source_port
        CHECK (
            source_port IS NULL
            OR source_port BETWEEN 0 AND 65535
        ),

    CONSTRAINT valid_destination_port
        CHECK (
            destination_port IS NULL
            OR destination_port BETWEEN 0 AND 65535
        )
);

-- 2. Security Alerts
CREATE TABLE IF NOT EXISTS alerts (
    id BIGSERIAL PRIMARY KEY,

    network_event_id BIGINT
        REFERENCES network_events(id)
        ON DELETE SET NULL,

    source_ip INET,
    destination_ip INET,

    attack_type VARCHAR(100) NOT NULL,
    signature VARCHAR(255),

    severity SMALLINT NOT NULL DEFAULT 3
        CHECK (severity BETWEEN 1 AND 4),

    description TEXT,

    detection_method VARCHAR(50),

    deduplication_key VARCHAR(64),

    status VARCHAR(20) NOT NULL DEFAULT 'new'
        CHECK (
            status IN (
                'new',
                'acknowledged',
                'resolved'
            )
        ),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. Custom Detection Rules
CREATE TABLE IF NOT EXISTS detection_rules (
    id BIGSERIAL PRIMARY KEY,

    rule_name VARCHAR(150) NOT NULL UNIQUE,
    description TEXT,

    attack_type VARCHAR(100) NOT NULL,

    detection_method VARCHAR(50) NOT NULL,

    threshold INTEGER,
    time_window_seconds INTEGER,

    severity SMALLINT NOT NULL DEFAULT 3
        CHECK (severity BETWEEN 1 AND 4),

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ==========================================
-- Compatibility additions for existing DBs
-- ==========================================

ALTER TABLE network_events
ADD COLUMN IF NOT EXISTS event_hash VARCHAR(64);

ALTER TABLE alerts
ADD COLUMN IF NOT EXISTS deduplication_key VARCHAR(64);

-- ==========================================
-- Indexes for faster queries
-- ==========================================

CREATE INDEX IF NOT EXISTS idx_events_timestamp
ON network_events(event_timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_events_source_ip
ON network_events(source_ip);

CREATE INDEX IF NOT EXISTS idx_events_destination_ip
ON network_events(destination_ip);

CREATE UNIQUE INDEX IF NOT EXISTS idx_network_events_event_hash
ON network_events(event_hash)
WHERE event_hash IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
ON alerts(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_alerts_severity
ON alerts(severity);

CREATE INDEX IF NOT EXISTS idx_alerts_status
ON alerts(status);

CREATE INDEX IF NOT EXISTS idx_alerts_source_ip
ON alerts(source_ip);

CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_deduplication_key
ON alerts(deduplication_key)
WHERE deduplication_key IS NOT NULL;

-- ==========================================
-- Initial Custom Detection Rules
-- ==========================================

INSERT INTO detection_rules (
    rule_name,
    description,
    attack_type,
    detection_method,
    threshold,
    time_window_seconds,
    severity
)
VALUES
(
    'Port Scan Detection',
    'Detects repeated connections to multiple ports on a destination.',
    'Port Scan',
    'behavioral',
    10,
    60,
    2
),
(
    'High Connection Rate',
    'Detects unusually high connection activity from a source IP.',
    'Suspicious Traffic',
    'behavioral',
    100,
    60,
    2
)
ON CONFLICT (rule_name) DO NOTHING;