#!/bin/sh
# libreleak scan script for Docker
# Scans a repository and outputs a report in JSON format

set -e

OUTPUT_DIR="${OUTPUT_DIR:-/reports}"
OUTPUT_FORMAT="${OUTPUT_FORMAT:-report}"
ENABLE_VERIFICATION="${ENABLE_VERIFICATION:-false}"
SCAN_TARGET="${1:-}"

# If no target specified, use REPO_URL environment variable
if [ -z "$SCAN_TARGET" ] && [ -n "$REPO_URL" ]; then
    echo "[libreleak] Cloning repository: $REPO_URL"

    CLONE_DIR="/tmp/scan-repo"
    rm -rf "$CLONE_DIR"

    # Clone the repository
    if [ -n "$BRANCH" ]; then
        git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$CLONE_DIR"
    else
        git clone --depth 1 "$REPO_URL" "$CLONE_DIR"
    fi

    SCAN_TARGET="$CLONE_DIR"
elif [ -z "$SCAN_TARGET" ]; then
    echo "[libreleak] Error: No scan target specified"
    echo "Usage: Set REPO_URL environment variable or pass path as argument"
    exit 1
fi

# Get repo info for report metadata
REPO_NAME=$(basename "$SCAN_TARGET" .git 2>/dev/null || echo "unknown")
TIMESTAMP=$(date -u +%Y%m%d_%H%M%S)
REPORT_FILE="${OUTPUT_DIR}/${REPO_NAME}_${TIMESTAMP}.json"

echo "[libreleak] Scanning: $SCAN_TARGET"
echo "[libreleak] Output format: $OUTPUT_FORMAT"
echo "[libreleak] Report file: $REPORT_FILE"

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

# Build scan command
SCAN_CMD="libreleak -f $OUTPUT_FORMAT"
if [ "$ENABLE_VERIFICATION" = "true" ]; then
    SCAN_CMD="$SCAN_CMD --verify"
    echo "[libreleak] Verification enabled"
fi
SCAN_CMD="$SCAN_CMD $SCAN_TARGET"

# Run the scan
if $SCAN_CMD > "$REPORT_FILE" 2>&1; then
    FINDINGS=$(grep -c '"rule_id"' "$REPORT_FILE" 2>/dev/null || echo "0")
    echo "[libreleak] Scan complete: $FINDINGS potential secrets found"
    echo "[libreleak] Report saved to: $REPORT_FILE"
else
    echo "[libreleak] Scan completed with findings"
    FINDINGS=$(grep -c '"rule_id"' "$REPORT_FILE" 2>/dev/null || echo "0")
    echo "[libreleak] $FINDINGS potential secrets found"
    echo "[libreleak] Report saved to: $REPORT_FILE"
fi

# Clean up cloned repo if we cloned it
if [ -n "$REPO_URL" ] && [ -d "/tmp/scan-repo" ]; then
    rm -rf "/tmp/scan-repo"
fi

# Output summary to stdout
echo ""
echo "=== Scan Summary ==="
if [ -f "$REPORT_FILE" ]; then
    head -50 "$REPORT_FILE"
    echo "..."
    echo "(Full report saved to $REPORT_FILE)"
fi
