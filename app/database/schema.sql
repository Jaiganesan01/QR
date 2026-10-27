-- QShield SQLite Database Schema
-- Privacy-by-Design Scan History Table
-- STORES ONLY NON-SENSITIVE SCAN METADATA:
-- DO NOT store raw decoded payloads, full query strings, raw image binaries, or user identifiers.

CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type TEXT NOT NULL CHECK(scan_type IN ('upload', 'manual', 'unknown')),
    payload_type TEXT NOT NULL,
    target_domain TEXT,
    risk_score INTEGER,
    risk_level TEXT,
    indicator_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL CHECK(status IN ('completed', 'failed', 'inconclusive')),
    detection_method TEXT DEFAULT 'heuristic_rules',
    threat_intel_status TEXT DEFAULT 'not_requested',
    indicators_summary TEXT DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scan_history_created_at ON scan_history(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_history_payload_type ON scan_history(payload_type);
CREATE INDEX IF NOT EXISTS idx_scan_history_risk_level ON scan_history(risk_level);
CREATE INDEX IF NOT EXISTS idx_scan_history_status ON scan_history(status);
