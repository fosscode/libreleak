#!/bin/bash
# Scan GitHub repos for secrets

SCANNER="./target/release/libreleak"
INPUT="/tmp/github_repos.txt"
OUTPUT="/tmp/github_findings.txt"

: > "$OUTPUT"  # Clear output file

count=0

head -150 "$INPUT" | sort -u | while read -r repo; do
    if [ -z "$repo" ]; then continue; fi

    count=$((count + 1))
    echo "[${count}] $repo" >&2

    # Scan with timeout
    result=$(timeout 90 "$SCANNER" "$repo" 2>/dev/null)

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
    fi
done

echo ""
echo "=== SCAN COMPLETE ==="
