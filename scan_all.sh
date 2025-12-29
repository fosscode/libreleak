#!/bin/bash
# Scan all Codeberg repos for secrets

SCANNER="./target/release/libreleak"
INPUT="/tmp/codeberg_repos.txt"
OUTPUT="/tmp/codeberg_findings.txt"

: > "$OUTPUT"  # Clear output file

count=0
found_count=0

cat "$INPUT" | sort -u | while read -r repo; do
    if [ -z "$repo" ]; then continue; fi

    count=$((count + 1))
    echo "[${count}] $repo" >&2

    # Scan with timeout
    result=$(timeout 120 "$SCANNER" "$repo" 2>/dev/null)

    if [ -n "$result" ] && [ "$result" != "No secrets found." ]; then
        echo ""
        echo "============================================="
        echo "REPO: $repo"
        echo "============================================="
        echo "$result"
        echo ""

        # Also append to file
        {
            echo "============================================="
            echo "REPO: $repo"
            echo "============================================="
            echo "$result"
            echo ""
        } >> "$OUTPUT"

        found_count=$((found_count + 1))
    fi
done

echo ""
echo "=== SCAN COMPLETE ==="
echo "Scanned repos from $INPUT"
echo "Results saved to $OUTPUT"
