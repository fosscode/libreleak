#!/bin/sh
# libreleak continuous monitoring
# Discovers new repositories and automatically scans them
#
# Usage:
#   PLATFORM=github TARGET=microsoft ./monitor.sh
#   PLATFORM=codeberg TARGET=fosscode INTERVAL=3600 ./monitor.sh
#
# This script runs in a loop, discovering new repos and scanning them.
# State is persisted to avoid rescanning the same repos.

set -e

# Configuration
PLATFORM="${PLATFORM:-github}"
TARGET="${TARGET:-}"
DAYS="${DAYS:-1}"
INTERVAL="${INTERVAL:-1800}"  # 30 minutes default
STATE_DIR="${STATE_DIR:-/var/lib/libreleak}"
REPOS_FILE="${STATE_DIR}/repos.txt"
SCANNED_FILE="${STATE_DIR}/scanned.txt"
OUTPUT_DIR="${OUTPUT_DIR:-/reports}"
OUTPUT_FORMAT="${OUTPUT_FORMAT:-report}"
ENABLE_VERIFICATION="${ENABLE_VERIFICATION:-false}"
MAX_REPOS_PER_RUN="${MAX_REPOS_PER_RUN:-50}"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-600}"  # 10 min per repo

# Paths to scripts (Docker vs local)
SCRIPT_DIR="${SCRIPT_DIR:-/usr/local/bin}"
DISCOVER_SCRIPT="${SCRIPT_DIR}/discover-repos.sh"
SCAN_SCRIPT="${SCRIPT_DIR}/scan-repo.sh"

log() {
    echo "[monitor] $(date -u +%Y-%m-%dT%H:%M:%SZ) $*"
}

# Initialize state directory
init_state() {
    mkdir -p "$STATE_DIR"
    mkdir -p "$OUTPUT_DIR"
    touch "$REPOS_FILE"
    touch "$SCANNED_FILE"
    log "State directory: $STATE_DIR"
    log "Reports directory: $OUTPUT_DIR"
}

# Check if repo has been scanned
is_scanned() {
    local repo="$1"
    grep -qFx "$repo" "$SCANNED_FILE" 2>/dev/null
}

# Mark repo as scanned
mark_scanned() {
    local repo="$1"
    echo "$repo" >> "$SCANNED_FILE"
}

# Discover new repos
discover() {
    log "Discovering repos: platform=$PLATFORM target=$TARGET days=$DAYS"

    local new_repos
    new_repos=$("$DISCOVER_SCRIPT" "$PLATFORM" "$TARGET" "$DAYS" 2>&1 | grep -E '^https?://')

    if [ -z "$new_repos" ]; then
        log "No repos discovered"
        return 0
    fi

    # Count new repos
    local total=0
    local new=0

    echo "$new_repos" | while read repo; do
        [ -z "$repo" ] && continue
        total=$((total + 1))

        if ! is_scanned "$repo"; then
            echo "$repo" >> "$REPOS_FILE"
            new=$((new + 1))
        fi
    done

    # Deduplicate repos file
    if [ -f "$REPOS_FILE" ]; then
        sort -u "$REPOS_FILE" > "${REPOS_FILE}.tmp"
        mv "${REPOS_FILE}.tmp" "$REPOS_FILE"
    fi

    local queued=$(wc -l < "$REPOS_FILE" | tr -d ' ')
    log "Discovery complete: queued=$queued"
}

# Scan pending repos
scan_pending() {
    if [ ! -s "$REPOS_FILE" ]; then
        log "No pending repos to scan"
        return 0
    fi

    local count=0
    local temp_file="${REPOS_FILE}.processing"

    # Move repos to processing (atomic)
    mv "$REPOS_FILE" "$temp_file"
    touch "$REPOS_FILE"

    log "Scanning pending repos (max $MAX_REPOS_PER_RUN per run)"

    while IFS= read -r repo || [ -n "$repo" ]; do
        [ -z "$repo" ] && continue

        # Already scanned?
        if is_scanned "$repo"; then
            continue
        fi

        count=$((count + 1))
        if [ "$count" -gt "$MAX_REPOS_PER_RUN" ]; then
            # Put remaining back in queue
            echo "$repo" >> "$REPOS_FILE"
            continue
        fi

        log "[$count/$MAX_REPOS_PER_RUN] Scanning: $repo"

        # Scan with timeout
        local scan_start=$(date +%s)

        if timeout "$SCAN_TIMEOUT" env \
            REPO_URL="$repo" \
            OUTPUT_DIR="$OUTPUT_DIR" \
            OUTPUT_FORMAT="$OUTPUT_FORMAT" \
            ENABLE_VERIFICATION="$ENABLE_VERIFICATION" \
            "$SCAN_SCRIPT" 2>&1; then
            log "Scan complete: $repo"
        else
            local exit_code=$?
            if [ "$exit_code" -eq 124 ]; then
                log "Scan timeout: $repo"
            else
                log "Scan finished (exit $exit_code): $repo"
            fi
        fi

        local scan_end=$(date +%s)
        local duration=$((scan_end - scan_start))
        log "Duration: ${duration}s"

        # Mark as scanned regardless of result (to avoid retry loops)
        mark_scanned "$repo"

    done < "$temp_file"

    rm -f "$temp_file"

    # Put unprocessed repos back
    if [ -f "$temp_file" ]; then
        cat "$temp_file" >> "$REPOS_FILE"
        rm -f "$temp_file"
    fi

    log "Scan batch complete: processed=$count"
}

# Generate summary
summary() {
    local queued=$(wc -l < "$REPOS_FILE" 2>/dev/null | tr -d ' ' || echo "0")
    local scanned=$(wc -l < "$SCANNED_FILE" 2>/dev/null | tr -d ' ' || echo "0")
    local reports=$(ls -1 "$OUTPUT_DIR"/*.json 2>/dev/null | wc -l | tr -d ' ' || echo "0")

    log "Status: queued=$queued scanned=$scanned reports=$reports"
}

# Cleanup old state (optional)
cleanup_old() {
    # Keep scanned list manageable (last 100k entries)
    if [ -f "$SCANNED_FILE" ]; then
        local lines=$(wc -l < "$SCANNED_FILE" | tr -d ' ')
        if [ "$lines" -gt 100000 ]; then
            log "Trimming scanned history (was $lines)"
            tail -50000 "$SCANNED_FILE" > "${SCANNED_FILE}.tmp"
            mv "${SCANNED_FILE}.tmp" "$SCANNED_FILE"
        fi
    fi
}

# Main loop
main() {
    log "Starting libreleak monitor"
    log "Platform: $PLATFORM"
    log "Target: ${TARGET:-<all>}"
    log "Interval: ${INTERVAL}s"
    log "Max repos per run: $MAX_REPOS_PER_RUN"

    init_state

    while true; do
        log "=== Monitor cycle starting ==="

        # Discover new repos
        discover

        # Scan pending repos
        scan_pending

        # Show summary
        summary

        # Cleanup
        cleanup_old

        log "=== Cycle complete, sleeping ${INTERVAL}s ==="
        sleep "$INTERVAL"
    done
}

# Run once mode (for testing)
run_once() {
    log "Running single discovery+scan cycle"
    init_state
    discover
    scan_pending
    summary
}

# Handle arguments
case "${1:-}" in
    --once|-1)
        run_once
        ;;
    --discover-only)
        init_state
        discover
        ;;
    --scan-only)
        init_state
        scan_pending
        ;;
    --help|-h)
        cat << 'EOF'
libreleak continuous monitoring

Usage: monitor.sh [options]

Options:
  (none)           Run continuous monitoring loop
  --once, -1       Run single discovery+scan cycle
  --discover-only  Only discover repos (no scanning)
  --scan-only      Only scan pending repos
  --help, -h       Show this help

Environment:
  PLATFORM         Platform to monitor (github, codeberg, gitlab)
  TARGET           Org/user/query to filter
  DAYS             Look back N days for discovery (default: 1)
  INTERVAL         Seconds between cycles (default: 1800)
  STATE_DIR        State directory (default: /var/lib/libreleak)
  OUTPUT_DIR       Reports directory (default: /reports)
  OUTPUT_FORMAT    Output format (default: report)
  ENABLE_VERIFICATION  Enable secret verification (default: false)
  MAX_REPOS_PER_RUN    Max repos to scan per cycle (default: 50)
  SCAN_TIMEOUT     Per-repo scan timeout in seconds (default: 600)
  GITHUB_TOKEN     GitHub API token
  GITLAB_TOKEN     GitLab API token
  CODEBERG_TOKEN   Codeberg API token

Examples:
  # Monitor Microsoft GitHub repos
  PLATFORM=github TARGET=microsoft ./monitor.sh

  # Monitor Codeberg, run once
  PLATFORM=codeberg TARGET=fosscode ./monitor.sh --once

  # Monitor GitHub trending Rust repos every hour
  PLATFORM=github-trending TARGET=rust INTERVAL=3600 ./monitor.sh
EOF
        exit 0
        ;;
    *)
        main
        ;;
esac
