-- ==========================================
-- NetSentinel Migration
-- Date: 2026-11-19
-- Purpose:
-- 1. Ensure network event deduplication
-- 2. Ensure behavioral alert deduplication
-- ==========================================

BEGIN;

ALTER TABLE network_events
ADD COLUMN IF NOT EXISTS event_hash VARCHAR(64);

CREATE UNIQUE INDEX IF NOT EXISTS idx_network_events_event_hash
ON network_events(event_hash)
WHERE event_hash IS NOT NULL;

ALTER TABLE alerts
ADD COLUMN IF NOT EXISTS deduplication_key VARCHAR(64);

CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_deduplication_key
ON alerts(deduplication_key)
WHERE deduplication_key IS NOT NULL;

COMMIT;