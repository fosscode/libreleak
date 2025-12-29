#!/bin/sh
# libreleak batch scanner
# Scans multiple repositories from a file and generates reports

set -e

REPOS_FILE="${REPOS_FILE:-/repos.txt}"
OUTPUT_DIR="${OUTPUT_DIR:-/reports}"
OUTPUT_FORMAT="${OUTPUT_FORMAT:-report}"
ENABLE_VERIFICATION="${ENABLE_VERIFICATION:-false}"

if [ ! -f "$REPOS_FILE" ]; then
    echo "[libreleak] Error: Repos file not found: $REPOS_FILE"
    echo "Create a file with one repository URL per line"
    exit 1
fi

echo "[libreleak] Starting batch scan"
echo "[libreleak] Reading repos from: $REPOS_FILE"
echo ""

TOTAL=0
SUCCESS=0
FAILED=0

mkdir -p "$OUTPUT_DIR"

# Create batch summary file
BATCH_ID=$(date -u +%Y%m%d_%H%M%S)
SUMMARY_FILE="${OUTPUT_DIR}/batch_${BATCH_ID}_summary.json"

echo "{" > "$SUMMARY_FILE"
echo "  \"batch_id\": \"$BATCH_ID\"," >> "$SUMMARY_FILE"
echo "  \"started_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"," >> "$SUMMARY_FILE"
echo "  \"repos\": [" >> "$SUMMARY_FILE"

FIRST=true

while IFS= read -r REPO_URL || [ -n "$REPO_URL" ]; do
    # Skip empty lines and comments
    case "$REPO_URL" in
        ""|\#*) continue ;;
    esac

    TOTAL=$((TOTAL + 1))
    REPO_NAME=$(basename "$REPO_URL" .git 2>/dev/null || echo "repo_$TOTAL")
    TIMESTAMP=$(date -u +%Y%m%d_%H%M%S)
    REPORT_FILE="${OUTPUT_DIR}/${REPO_NAME}_${TIMESTAMP}.json"

    echo "[libreleak] [$TOTAL] Scanning: $REPO_URL"

    # Clone repo
    CLONE_DIR="/tmp/scan-repo-$$"
    rm -rf "$CLONE_DIR"

    if git clone --depth 1 "$REPO_URL" "$CLONE_DIR" 2>/dev/null; then
        # Build scan command
        SCAN_CMD="libreleak -f $OUTPUT_FORMAT"
        if [ "$ENABLE_VERIFICATION" = "true" ]; then
            SCAN_CMD="$SCAN_CMD --verify"
        fi
        SCAN_CMD="$SCAN_CMD $CLONE_DIR"

        # Scan
        if $SCAN_CMD > "$REPORT_FILE" 2>&1; then
            FINDINGS=$(grep -c '"rule_id"' "$REPORT_FILE" 2>/dev/null || echo "0")
            echo "[libreleak] [$TOTAL] Complete: $FINDINGS findings"
            SUCCESS=$((SUCCESS + 1))
            STATUS="success"
        else
            FINDINGS=$(grep -c '"rule_id"' "$REPORT_FILE" 2>/dev/null || echo "0")
            echo "[libreleak] [$TOTAL] Complete: $FINDINGS findings (with findings/exit code)"
            SUCCESS=$((SUCCESS + 1))
            STATUS="success"
        fi
    else
        echo "[libreleak] [$TOTAL] Failed to clone"
        FAILED=$((FAILED + 1))
        FINDINGS=0
        STATUS="failed"
        echo "{\"error\": \"Failed to clone repository\"}" > "$REPORT_FILE"
    fi

    # Clean up
    rm -rf "$CLONE_DIR"

    # Add to summary
    if [ "$FIRST" = "true" ]; then
        FIRST=false
    else
        echo "," >> "$SUMMARY_FILE"
    fi

    echo "    {" >> "$SUMMARY_FILE"
    echo "      \"url\": \"$REPO_URL\"," >> "$SUMMARY_FILE"
    echo "      \"name\": \"$REPO_NAME\"," >> "$SUMMARY_FILE"
    echo "      \"status\": \"$STATUS\"," >> "$SUMMARY_FILE"
    echo "      \"findings\": $FINDINGS," >> "$SUMMARY_FILE"
    echo "      \"report_file\": \"$REPORT_FILE\"" >> "$SUMMARY_FILE"
    echo -n "    }" >> "$SUMMARY_FILE"

done < "$REPOS_FILE"

echo "" >> "$SUMMARY_FILE"
echo "  ]," >> "$SUMMARY_FILE"
echo "  \"completed_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"," >> "$SUMMARY_FILE"
echo "  \"summary\": {" >> "$SUMMARY_FILE"
echo "    \"total\": $TOTAL," >> "$SUMMARY_FILE"
echo "    \"success\": $SUCCESS," >> "$SUMMARY_FILE"
echo "    \"failed\": $FAILED" >> "$SUMMARY_FILE"
echo "  }" >> "$SUMMARY_FILE"
echo "}" >> "$SUMMARY_FILE"

echo ""
echo "=== Batch Scan Complete ==="
echo "Total repos:  $TOTAL"
echo "Successful:   $SUCCESS"
echo "Failed:       $FAILED"
echo "Summary file: $SUMMARY_FILE"
