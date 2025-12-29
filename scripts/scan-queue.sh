#!/bin/bash
# libreleak queue scanner
# Scans repositories from the database queue and stores findings
#
# Usage:
#   ./scan-queue.sh              # Scan next batch (default: 50 repos)
#   ./scan-queue.sh 100          # Scan 100 repos
#   ./scan-queue.sh --continuous # Run continuously
#   ./scan-queue.sh --priority 8 # Only scan priority >= 8

set -e

DB_PATH="${LIBRELEAK_DB:-$HOME/.libreleak/libreleak.db}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCANNER="${SCRIPT_DIR}/../target/release/libreleak"

# Settings
BATCH_SIZE="${1:-50}"
SCAN_TIMEOUT=120
CONTINUOUS=false
MIN_PRIORITY=0

# Cross-platform timeout function
run_with_timeout() {
    local timeout_secs="$1"
    shift

    if command -v timeout >/dev/null 2>&1; then
        timeout "$timeout_secs" "$@"
    elif command -v gtimeout >/dev/null 2>&1; then
        gtimeout "$timeout_secs" "$@"
    else
        # Fallback: run without timeout on macOS without coreutils
        "$@"
    fi
}

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${BLUE}[scan]${NC} $1" >&2; }
success() { echo -e "${GREEN}[scan]${NC} $1" >&2; }
warn() { echo -e "${YELLOW}[scan]${NC} $1" >&2; }
error() { echo -e "${RED}[scan]${NC} $1" >&2; }
finding() { echo -e "${CYAN}[FINDING]${NC} $1" >&2; }

# Parse arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --continuous|-c)
                CONTINUOUS=true
                shift
                ;;
            --priority|-p)
                MIN_PRIORITY="$2"
                shift 2
                ;;
            --timeout|-t)
                SCAN_TIMEOUT="$2"
                shift 2
                ;;
            *)
                if [[ "$1" =~ ^[0-9]+$ ]]; then
                    BATCH_SIZE="$1"
                fi
                shift
                ;;
        esac
    done
}

# Check prerequisites
check_prereqs() {
    if [ ! -f "$DB_PATH" ]; then
        error "Database not found at $DB_PATH"
        error "Run: ./scripts/init-db.sh"
        exit 1
    fi

    if [ ! -x "$SCANNER" ]; then
        error "Scanner not found at $SCANNER"
        error "Run: cargo build --release"
        exit 1
    fi
}

# Get next repo to scan
get_next_repo() {
    sqlite3 "$DB_PATH" "
        SELECT id, url FROM repos
        WHERE status = 'pending'
          AND priority >= $MIN_PRIORITY
        ORDER BY priority DESC, discovered_at ASC
        LIMIT 1;
    " | head -1
}

# Mark repo as scanning
mark_scanning() {
    local repo_id="$1"
    sqlite3 "$DB_PATH" "UPDATE repos SET status = 'scanning' WHERE id = $repo_id;"
}

# Start a scan record
start_scan() {
    local repo_id="$1"
    sqlite3 "$DB_PATH" "
        INSERT INTO scans (repo_id, scanner_version)
        VALUES ($repo_id, 'libreleak-0.1.0');
        SELECT last_insert_rowid();
    "
}

# Complete a scan record
complete_scan() {
    local scan_id="$1"
    local status="$2"
    local findings_count="$3"
    local error_msg="$4"

    sqlite3 "$DB_PATH" "
        UPDATE scans SET
            completed_at = CURRENT_TIMESTAMP,
            duration_ms = (strftime('%s', 'now') - strftime('%s', started_at)) * 1000,
            status = '$status',
            findings_count = $findings_count,
            error_message = '$error_msg'
        WHERE id = $scan_id;
    "
}

# Update repo after scan
update_repo() {
    local repo_id="$1"
    local status="$2"
    local findings_count="$3"
    local error_msg="$4"

    sqlite3 "$DB_PATH" "
        UPDATE repos SET
            status = '$status',
            last_scanned_at = CURRENT_TIMESTAMP,
            scan_count = scan_count + 1,
            findings_count = $findings_count,
            error_message = '$error_msg'
        WHERE id = $repo_id;
    "
}

# Store a finding
store_finding() {
    local repo_id="$1"
    local scan_id="$2"
    local rule_id="$3"
    local rule_name="$4"
    local file_path="$5"
    local line_number="$6"
    local secret_preview="$7"
    local context="$8"

    # Generate a hash for deduplication (simplified)
    local secret_hash=$(echo -n "$rule_id$file_path$line_number$secret_preview" | shasum -a 256 | cut -d' ' -f1)

    # Escape single quotes for SQL
    file_path=$(echo "$file_path" | sed "s/'/''/g")
    secret_preview=$(echo "$secret_preview" | sed "s/'/''/g")
    context=$(echo "$context" | sed "s/'/''/g")
    rule_name=$(echo "$rule_name" | sed "s/'/''/g")

    sqlite3 "$DB_PATH" "
        INSERT OR IGNORE INTO findings
            (repo_id, scan_id, rule_id, rule_name, file_path, line_number, secret_preview, secret_hash, context)
        VALUES
            ($repo_id, $scan_id, '$rule_id', '$rule_name', '$file_path', $line_number, '$secret_preview', '$secret_hash', '$context');
    "
}

# Parse scanner output and store findings
parse_and_store_findings() {
    local repo_id="$1"
    local scan_id="$2"
    local output="$3"

    local count=0

    # Parse the text output format
    # Example:
    # [1;31mopenai-api-key[0m /path/to/file:123:45
    #   [1mRule:[0m OpenAI API Key
    #   [1mSecret:[0m sk-p...12Ab

    local rule_id=""
    local rule_name=""
    local file_path=""
    local line_number=""
    local secret_preview=""
    local context=""

    while IFS= read -r line; do
        # Strip ANSI codes
        line=$(echo "$line" | sed 's/\x1b\[[0-9;]*m//g')

        # Match rule ID line (e.g., "openai-api-key /path/file.py:123:45")
        if [[ "$line" =~ ^([a-z0-9-]+)[[:space:]]+(.+):([0-9]+):([0-9]+)$ ]]; then
            # Store previous finding if exists
            if [ -n "$rule_id" ] && [ -n "$file_path" ]; then
                store_finding "$repo_id" "$scan_id" "$rule_id" "$rule_name" "$file_path" "$line_number" "$secret_preview" "$context"
                ((count++))
            fi

            rule_id="${BASH_REMATCH[1]}"
            file_path="${BASH_REMATCH[2]}"
            line_number="${BASH_REMATCH[3]}"
            rule_name=""
            secret_preview=""
            context=""
        # Match rule name (e.g., "Rule: OpenAI API Key")
        elif [[ "$line" =~ Rule:[[:space:]]*(.+) ]]; then
            rule_name="${BASH_REMATCH[1]}"
        # Match secret preview (e.g., "Secret: sk-p...12Ab")
        elif [[ "$line" =~ Secret:[[:space:]]*(.+) ]]; then
            secret_preview="${BASH_REMATCH[1]}"
        # Match context lines
        elif [[ "$line" =~ ^\>[[:space:]]+[0-9]+[[:space:]]\|[[:space:]](.+) ]]; then
            context="${BASH_REMATCH[1]}"
        fi
    done <<< "$output"

    # Store last finding
    if [ -n "$rule_id" ] && [ -n "$file_path" ]; then
        store_finding "$repo_id" "$scan_id" "$rule_id" "$rule_name" "$file_path" "$line_number" "$secret_preview" "$context"
        ((count++))
    fi

    echo "$count"
}

# Scan a single repo
scan_repo() {
    local repo_id="$1"
    local repo_url="$2"

    log "Scanning: $repo_url"

    # Mark as scanning
    mark_scanning "$repo_id"

    # Start scan record
    local scan_id=$(start_scan "$repo_id")

    # Run scanner
    local output
    local exit_code=0

    output=$(run_with_timeout "$SCAN_TIMEOUT" "$SCANNER" "$repo_url" 2>&1) || exit_code=$?

    local findings_count=0
    local status="scanned"
    local error_msg=""

    if [ $exit_code -eq 124 ]; then
        # Timeout
        status="error"
        error_msg="Scan timeout after ${SCAN_TIMEOUT}s"
        warn "Timeout: $repo_url"
    elif [[ "$output" == *"error:"* ]] || [[ "$output" == *"fatal:"* ]]; then
        # Clone or other git errors
        status="error"
        error_msg="Git error"
        warn "Error scanning: $repo_url"
    elif [ $exit_code -ne 0 ] && [[ "$output" != *"Found"* ]] && [[ "$output" != *"No secrets found"* ]]; then
        # Unknown error
        status="error"
        error_msg="Scanner error code: $exit_code"
        warn "Error scanning: $repo_url"
    else
        # Success - either no findings or has findings
        status="scanned"

        # Parse output for findings if we have valid output with secrets
        if [ -n "$output" ] && [[ "$output" == *"Found"* ]]; then
            findings_count=$(parse_and_store_findings "$repo_id" "$scan_id" "$output")

            if [ "$findings_count" -gt 0 ]; then
                finding "Found $findings_count secret(s) in $repo_url"
            fi
        fi
    fi

    # Update records
    complete_scan "$scan_id" "$status" "$findings_count" "$error_msg"
    update_repo "$repo_id" "$status" "$findings_count" "$error_msg"

    return $findings_count
}

# Scan batch of repos
scan_batch() {
    local scanned=0
    local total_findings=0

    log "Starting batch scan (max: $BATCH_SIZE repos, priority >= $MIN_PRIORITY)"

    while [ $scanned -lt $BATCH_SIZE ]; do
        local repo_info=$(get_next_repo)

        if [ -z "$repo_info" ]; then
            log "No more pending repos"
            break
        fi

        local repo_id=$(echo "$repo_info" | cut -d'|' -f1)
        local repo_url=$(echo "$repo_info" | cut -d'|' -f2)

        local findings=0
        scan_repo "$repo_id" "$repo_url" && findings=$? || findings=$?

        total_findings=$((total_findings + findings))
        scanned=$((scanned + 1))

        # Progress
        if [ $((scanned % 10)) -eq 0 ]; then
            log "Progress: $scanned/$BATCH_SIZE repos scanned"
        fi
    done

    success "Batch complete: $scanned repos scanned, $total_findings findings"
}

# Show stats
show_stats() {
    echo ""
    log "Database statistics:"
    sqlite3 "$DB_PATH" "
        SELECT '  Total repos: ' || COUNT(*) FROM repos
        UNION ALL
        SELECT '  Pending: ' || COUNT(*) FROM repos WHERE status = 'pending'
        UNION ALL
        SELECT '  Scanned: ' || COUNT(*) FROM repos WHERE status = 'scanned'
        UNION ALL
        SELECT '  Errors: ' || COUNT(*) FROM repos WHERE status = 'error'
        UNION ALL
        SELECT '  Total findings: ' || COUNT(*) FROM findings
        UNION ALL
        SELECT '  Unreported findings: ' || COUNT(*) FROM findings WHERE reported = FALSE;
    "

    # Show recent findings
    local recent=$(sqlite3 "$DB_PATH" "
        SELECT f.rule_id, f.secret_preview, r.url
        FROM findings f
        JOIN repos r ON f.repo_id = r.id
        ORDER BY f.found_at DESC
        LIMIT 5;
    ")

    if [ -n "$recent" ]; then
        echo ""
        log "Recent findings:"
        echo "$recent" | while IFS='|' read -r rule secret url; do
            echo "  $rule: $secret"
            echo "    -> $url"
        done
    fi
}

# Main
main() {
    parse_args "$@"
    check_prereqs

    if [ "$CONTINUOUS" = true ]; then
        log "Starting continuous scanning mode (Ctrl+C to stop)"
        while true; do
            scan_batch
            show_stats
            log "Sleeping 60 seconds..."
            sleep 60
        done
    else
        scan_batch
        show_stats
    fi
}

main "$@"
