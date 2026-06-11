-- Additional indexes for performance

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_created_at ON findings(created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_scans_completed_at ON scans(completed_at DESC);