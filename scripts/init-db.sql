-- libreleak database schema
-- Stores scan reports for research and aggregation

-- Scan metadata table
CREATE TABLE IF NOT EXISTS scans (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR(64) UNIQUE NOT NULL,
    scanner_version VARCHAR(20) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    target_path TEXT,
    target_type VARCHAR(20), -- 'directory', 'git_url', 'file'
    git_remote TEXT,
    git_branch VARCHAR(255),
    git_commit VARCHAR(40),
    scan_duration_ms INTEGER,
    total_findings INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Findings table
CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR(64) NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    rule_id VARCHAR(100) NOT NULL,
    rule_name VARCHAR(255) NOT NULL,
    file_path TEXT NOT NULL,
    line_number INTEGER NOT NULL,
    column_number INTEGER NOT NULL,
    secret_preview TEXT, -- Redacted secret preview
    context JSONB, -- Context lines as JSON array
    verification_status VARCHAR(20) DEFAULT 'pending', -- pending, active, inactive, invalid
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_rule_id ON findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_findings_verification ON findings(verification_status);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
CREATE INDEX IF NOT EXISTS idx_scans_git_remote ON scans(git_remote);

-- View for summary statistics
CREATE OR REPLACE VIEW scan_summary AS
SELECT
    s.scan_id,
    s.timestamp,
    s.target_path,
    s.git_remote,
    s.git_branch,
    s.total_findings,
    COUNT(DISTINCT f.rule_id) as unique_rules_triggered,
    COUNT(CASE WHEN f.verification_status = 'active' THEN 1 END) as verified_active,
    COUNT(CASE WHEN f.verification_status = 'inactive' THEN 1 END) as verified_inactive,
    COUNT(CASE WHEN f.verification_status = 'pending' THEN 1 END) as pending_verification
FROM scans s
LEFT JOIN findings f ON s.scan_id = f.scan_id
GROUP BY s.scan_id, s.timestamp, s.target_path, s.git_remote, s.git_branch, s.total_findings;

-- View for findings by repository (for trend analysis)
CREATE OR REPLACE VIEW findings_by_repo AS
SELECT
    COALESCE(s.git_remote, s.target_path) as repository,
    f.rule_id,
    f.rule_name,
    COUNT(*) as occurrence_count,
    MAX(s.timestamp) as last_seen,
    MIN(s.timestamp) as first_seen
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
GROUP BY COALESCE(s.git_remote, s.target_path), f.rule_id, f.rule_name;

-- View for bug bounty candidates (high-severity active secrets)
CREATE OR REPLACE VIEW bounty_candidates AS
SELECT
    f.id,
    s.git_remote as repository,
    f.rule_id,
    f.rule_name,
    f.file_path,
    f.line_number,
    f.secret_preview,
    f.verification_status,
    f.verified_at,
    s.timestamp as scan_timestamp
FROM findings f
JOIN scans s ON f.scan_id = s.scan_id
WHERE f.verification_status = 'active'
  AND (f.rule_id LIKE '%api-key%'
       OR f.rule_id LIKE '%private-key%'
       OR f.rule_id LIKE '%aws%'
       OR f.rule_id LIKE '%database%')
ORDER BY s.timestamp DESC;

-- Statistics view for security reports
CREATE OR REPLACE VIEW security_stats AS
SELECT
    DATE_TRUNC('day', s.timestamp) as scan_date,
    COUNT(DISTINCT s.scan_id) as total_scans,
    SUM(s.total_findings) as total_findings,
    COUNT(DISTINCT f.rule_id) as unique_rules,
    COUNT(DISTINCT COALESCE(s.git_remote, s.target_path)) as unique_repos
FROM scans s
LEFT JOIN findings f ON s.scan_id = f.scan_id
GROUP BY DATE_TRUNC('day', s.timestamp)
ORDER BY scan_date DESC;
