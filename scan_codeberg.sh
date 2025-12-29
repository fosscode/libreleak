#!/bin/bash
# Scan Codeberg repos for secrets

SCANNER="./target/release/libreleak"
INPUT="/tmp/codeberg_repos.txt"
RESULTS_DIR="./reports/codeberg"

mkdir -p "$RESULTS_DIR"

count=0
found=0

head -50 "$INPUT" | sort -u | while read -r repo; do
    if [ -z "$repo" ]; then continue; fi

    count=$((count + 1))
    echo "[${count}] Scanning: $repo" >&2

    # Create safe filename from repo URL
    filename=$(echo "$repo" | sed 's|https://codeberg.org/||; s|\.git$||; s|/|_|g')

    # Scan with timeout
    result=$(timeout 90 "$SCANNER" "$repo" 2>/dev/null)

    if [ -n "$result" ] && [ "$result" != "No secrets found." ]; then
        echo "*** FOUND SECRETS in: $repo ***"
        echo "$result"
        echo "---"
        echo "$result" > "$RESULTS_DIR/${filename}.txt"
        found=$((found + 1))
    fi
done

echo ""
echo "Scan complete. Results in $RESULTS_DIR"
