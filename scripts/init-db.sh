#!/bin/bash
# libreleak database initialization
# Creates SQLite database for persistent repo tracking

set -e

DB_PATH="${LIBRELEAK_DB:-$HOME/.libreleak/libreleak.db}"
DB_DIR=$(dirname "$DB_PATH")

# Create directory if needed
mkdir -p "$DB_DIR"

echo "[init-db] Initializing database at $DB_PATH"

sqlite3 "$DB_PATH" << 'EOF'
-- Enable foreign keys
PRAGMA foreign_keys = ON;

-- Repositories table - all discovered repos
CREATE TABLE IF NOT EXISTS repos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT UNIQUE NOT NULL,
    platform TEXT NOT NULL,  -- github, gitlab, codeberg, etc.
    owner TEXT,              -- org or user
    name TEXT,               -- repo name
    source TEXT NOT NULL,    -- how discovered: events_api, search_api, trending, manual
    priority INTEGER DEFAULT 5,  -- 1-10, higher = scan first
    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_scanned_at DATETIME,
    scan_count INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    status TEXT DEFAULT 'pending',  -- pending, scanning, scanned, error, skipped
    error_message TEXT,
    metadata TEXT  -- JSON blob for extra data
);

-- Findings table - all detected secrets
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id INTEGER NOT NULL,
    scan_id INTEGER,
    rule_id TEXT NOT NULL,       -- e.g., openai-api-key
    rule_name TEXT,              -- e.g., OpenAI API Key
    file_path TEXT NOT NULL,
    line_number INTEGER,
    secret_preview TEXT,         -- redacted preview (sk-...1234)
    secret_hash TEXT,            -- SHA256 hash for deduplication
    context TEXT,                -- surrounding lines
    found_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    verified BOOLEAN DEFAULT FALSE,
    verification_status TEXT,    -- active, inactive, unknown, error
    verification_message TEXT,
    reported BOOLEAN DEFAULT FALSE,
    reported_at DATETIME,
    reported_to TEXT,            -- e.g., openai_bugcrowd
    bounty_amount REAL,
    notes TEXT,
    FOREIGN KEY (repo_id) REFERENCES repos(id) ON DELETE CASCADE
);

-- Scans table - scan history
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id INTEGER NOT NULL,
    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    duration_ms INTEGER,
    status TEXT DEFAULT 'running',  -- running, completed, failed, timeout
    findings_count INTEGER DEFAULT 0,
    error_message TEXT,
    scanner_version TEXT,
    FOREIGN KEY (repo_id) REFERENCES repos(id) ON DELETE CASCADE
);

-- Feed sources - track what feeds we've fetched
CREATE TABLE IF NOT EXISTS feed_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,   -- e.g., github_events, github_search_rust
    last_fetched_at DATETIME,
    last_cursor TEXT,            -- pagination cursor, etag, etc.
    repos_fetched INTEGER DEFAULT 0,
    metadata TEXT
);

-- Bug bounty programs
CREATE TABLE IF NOT EXISTS bounty_programs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    platform TEXT,               -- bugcrowd, hackerone, direct
    url TEXT,
    key_types TEXT,              -- comma-separated: openai-api-key,anthropic-api-key
    min_payout REAL,
    max_payout REAL,
    active BOOLEAN DEFAULT TRUE,
    notes TEXT
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_repos_status ON repos(status);
CREATE INDEX IF NOT EXISTS idx_repos_platform ON repos(platform);
CREATE INDEX IF NOT EXISTS idx_repos_last_scanned ON repos(last_scanned_at);
CREATE INDEX IF NOT EXISTS idx_repos_priority ON repos(priority DESC);
CREATE INDEX IF NOT EXISTS idx_findings_repo ON findings(repo_id);
CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_findings_verified ON findings(verified);
CREATE INDEX IF NOT EXISTS idx_findings_reported ON findings(reported);
CREATE INDEX IF NOT EXISTS idx_scans_repo ON scans(repo_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_unique ON findings(repo_id, rule_id, file_path, line_number, secret_hash);

-- Insert default bounty programs
INSERT OR IGNORE INTO bounty_programs (name, platform, url, key_types, min_payout, max_payout, notes) VALUES
    ('OpenAI', 'bugcrowd', 'https://bugcrowd.com/openai', 'openai-api-key,openai-project-key', 200, 100000, 'Best program for leaked API keys'),
    ('Anthropic', 'direct', 'https://www.anthropic.com/responsible-disclosure', 'anthropic-api-key', NULL, NULL, 'Contact security team'),
    ('Stripe', 'hackerone', 'https://hackerone.com/stripe', 'stripe-secret-key,stripe-restricted-key', 500, 10000, 'Live keys only'),
    ('GitHub', 'hackerone', 'https://hackerone.com/github', 'github-pat,github-oauth,github-fine-grained', 500, 30000, 'Security Lab'),
    ('GitLab', 'hackerone', 'https://hackerone.com/gitlab', 'gitlab-pat,gitlab-pipeline,gitlab-runner', 500, 35000, NULL),
    ('Google', 'direct', 'https://bughunters.google.com/', 'gcp-api-key,gemini-api-key', 100, 31337, 'Google VRP'),
    ('Slack', 'hackerone', 'https://hackerone.com/slack', 'slack-bot-token,slack-user-token', 500, 5000, NULL),
    ('Discord', 'hackerone', 'https://hackerone.com/discord', 'discord-bot-token', 500, 5000, NULL),
    ('Twilio', 'hackerone', 'https://hackerone.com/twilio', 'twilio-api-key', 500, 10000, NULL),
    ('SendGrid', 'hackerone', 'https://hackerone.com/sendgrid', 'sendgrid-api-key', 500, 10000, NULL),
    ('npm', 'hackerone', 'https://hackerone.com/nodejs', 'npm-token', 250, 2500, NULL),
    ('AWS', 'direct', 'https://aws.amazon.com/security/vulnerability-reporting/', 'aws-access-key-id,aws-secret-key', NULL, NULL, 'AWS Security'),
    ('HuggingFace', 'direct', 'https://huggingface.co/security', 'huggingface-token,huggingface-model-token', NULL, NULL, NULL);

-- View for pending scans prioritized
CREATE VIEW IF NOT EXISTS v_pending_repos AS
SELECT
    id, url, platform, owner, name, source, priority,
    discovered_at, last_scanned_at, scan_count
FROM repos
WHERE status = 'pending'
ORDER BY priority DESC, discovered_at ASC;

-- View for active findings (not yet reported)
CREATE VIEW IF NOT EXISTS v_active_findings AS
SELECT
    f.id, f.rule_id, f.rule_name, f.file_path, f.line_number,
    f.secret_preview, f.verified, f.verification_status,
    r.url as repo_url, r.platform, r.owner, r.name as repo_name,
    f.found_at
FROM findings f
JOIN repos r ON f.repo_id = r.id
WHERE f.reported = FALSE
ORDER BY f.found_at DESC;

-- View for bounty-eligible findings
CREATE VIEW IF NOT EXISTS v_bounty_eligible AS
SELECT
    f.id, f.rule_id, f.rule_name, f.secret_preview,
    f.verified, f.verification_status,
    r.url as repo_url,
    bp.name as bounty_program, bp.platform as bounty_platform,
    bp.url as bounty_url, bp.min_payout, bp.max_payout
FROM findings f
JOIN repos r ON f.repo_id = r.id
JOIN bounty_programs bp ON (',' || bp.key_types || ',') LIKE ('%,' || f.rule_id || ',%')
WHERE f.reported = FALSE
  AND bp.active = TRUE
ORDER BY bp.max_payout DESC NULLS LAST;

EOF

echo "[init-db] Database initialized successfully"
echo "[init-db] Path: $DB_PATH"

# Show table counts
sqlite3 "$DB_PATH" << 'EOF'
SELECT 'repos: ' || COUNT(*) FROM repos
UNION ALL
SELECT 'findings: ' || COUNT(*) FROM findings
UNION ALL
SELECT 'scans: ' || COUNT(*) FROM scans
UNION ALL
SELECT 'bounty_programs: ' || COUNT(*) FROM bounty_programs;
EOF
