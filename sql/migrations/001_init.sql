-- Initial database schema
-- Semua kolom enum menggunakan VARCHAR agar kompatibel dengan native_enum=False

CREATE TABLE IF NOT EXISTS targets (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) UNIQUE NOT NULL,
    scope_pattern VARCHAR(255),
    status VARCHAR(20) DEFAULT 'active',
    scan_mode VARCHAR(20) DEFAULT 'safe',
    created_by_chat_id BIGINT,   -- 🔥 ubah dari INTEGER ke BIGINT
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_recon_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scans (
    id SERIAL PRIMARY KEY,
    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    scan_type VARCHAR(50) DEFAULT 'full',
    status VARCHAR(20) DEFAULT 'pending',
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration_seconds INTEGER,
    error_message TEXT,
    extra_metadata TEXT   -- 🔥 ganti nama dari metadata
);

CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    finding_type VARCHAR(50),
    finding_data JSONB,
    severity VARCHAR(20) DEFAULT 'info',
    is_new BOOLEAN DEFAULT TRUE,
    dedup_hash VARCHAR(64),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_targets_domain ON targets(domain);
CREATE INDEX idx_targets_status ON targets(status);
CREATE INDEX idx_scans_target_id ON scans(target_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_findings_target_id ON findings(target_id);
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_dedup_hash ON findings(dedup_hash);
CREATE INDEX idx_findings_is_new ON findings(is_new) WHERE is_new = TRUE;

