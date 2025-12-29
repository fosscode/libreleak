#!/bin/sh
# libreleak repository discovery script
# Discovers recently created/updated repositories from public code hosting platforms
# Zero-dependency: works without jq using grep/sed
#
# Usage:
#   ./discover-repos.sh github [org/user] [days]
#   ./discover-repos.sh gitlab [group/user] [days]
#   ./discover-repos.sh codeberg [user] [days]
#   ./discover-repos.sh github-trending [language] [days]
#
# Output: repo URLs to stdout, progress to stderr

set -e

PLATFORM="${1:-github}"
TARGET="${2:-}"
DAYS="${3:-7}"

# API tokens from environment
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
GITLAB_TOKEN="${GITLAB_TOKEN:-}"
CODEBERG_TOKEN="${CODEBERG_TOKEN:-}"

# Calculate date N days ago (works on both BSD and GNU date)
days_ago() {
    local n="$1"
    if date -v-1d > /dev/null 2>&1; then
        # BSD date (macOS)
        date -v-"${n}d" -u +%Y-%m-%dT00:00:00Z
    else
        # GNU date (Linux)
        date -u -d "$n days ago" +%Y-%m-%dT00:00:00Z
    fi
}

days_ago_simple() {
    local n="$1"
    if date -v-1d > /dev/null 2>&1; then
        date -v-"${n}d" -u +%Y-%m-%d
    else
        date -u -d "$n days ago" +%Y-%m-%d
    fi
}

# Extract JSON string value without jq
# Usage: json_extract "key" <<< "$json"
json_extract() {
    local key="$1"
    grep -o "\"$key\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | sed "s/\"$key\"[[:space:]]*:[[:space:]]*\"//" | sed 's/"$//'
}

# GitHub API discovery
discover_github() {
    local target="$1"
    local since_date=$(days_ago "$DAYS")
    local since_simple=$(days_ago_simple "$DAYS")
    local page=1
    local total_found=0
    local auth_header=""

    if [ -n "$GITHUB_TOKEN" ]; then
        auth_header="Authorization: Bearer $GITHUB_TOKEN"
    fi

    echo "[discover] GitHub: searching repos updated since $since_simple" >&2
    [ -n "$target" ] && echo "[discover] Filter: $target" >&2

    # Build query
    local query="pushed:>=$since_simple"
    if [ -n "$target" ]; then
        case "$target" in
            language:*|topic:*|stars:*|created:*|pushed:*|fork:*)
                # Direct search qualifiers
                query="$target $query"
                ;;
            */*)
                # org/repo format - search in org
                local org=$(echo "$target" | cut -d'/' -f1)
                query="org:$org $query"
                ;;
            *)
                # Assume org or user
                query="org:$target $query"
                ;;
        esac
    fi

    # URL encode query (basic)
    local encoded=$(printf '%s' "$query" | sed 's/ /%20/g; s/:/%3A/g; s/>/%3E/g; s/</%3C/g; s/=/%3D/g')

    while true; do
        local url="https://api.github.com/search/repositories?q=${encoded}&sort=updated&order=desc&per_page=100&page=${page}"

        echo "[discover] Fetching page $page..." >&2

        local response
        if [ -n "$auth_header" ]; then
            response=$(curl -s -H "$auth_header" -H "Accept: application/vnd.github.v3+json" "$url" 2>/dev/null)
        else
            response=$(curl -s -H "Accept: application/vnd.github.v3+json" "$url" 2>/dev/null)
        fi

        # Check for rate limit or error
        if echo "$response" | grep -q '"API rate limit exceeded'; then
            echo "[discover] GitHub rate limit exceeded. Set GITHUB_TOKEN for higher limits." >&2
            break
        fi

        if echo "$response" | grep -q '"Bad credentials"'; then
            echo "[discover] GitHub: Invalid token" >&2
            break
        fi

        # Extract clone URLs (html_url also works for git clone)
        local urls=$(echo "$response" | json_extract "clone_url" | grep -v '^$')

        if [ -z "$urls" ]; then
            break
        fi

        # Output URLs to stdout
        echo "$urls"

        local count=$(echo "$urls" | wc -l | tr -d ' ')
        total_found=$((total_found + count))

        # Less than 100 = last page
        if [ "$count" -lt 100 ]; then
            break
        fi

        page=$((page + 1))

        # Safety limit
        if [ "$page" -gt 10 ]; then
            echo "[discover] Stopping at 10 pages (1000 repos)" >&2
            break
        fi

        sleep 1
    done

    echo "[discover] GitHub: found $total_found repos" >&2
}

# GitHub trending (recently created with stars)
discover_github_trending() {
    local language="$1"
    local since_date=$(days_ago_simple "$DAYS")
    local page=1
    local total_found=0
    local auth_header=""

    if [ -n "$GITHUB_TOKEN" ]; then
        auth_header="Authorization: Bearer $GITHUB_TOKEN"
    fi

    echo "[discover] GitHub trending: repos created since $since_date" >&2
    [ -n "$language" ] && echo "[discover] Language: $language" >&2

    # Find repos created recently with stars (trending)
    local query="created:>=$since_date stars:>0"
    if [ -n "$language" ]; then
        query="language:$language $query"
    fi

    local encoded=$(printf '%s' "$query" | sed 's/ /%20/g; s/:/%3A/g; s/>/%3E/g; s/</%3C/g; s/=/%3D/g')

    while true; do
        local url="https://api.github.com/search/repositories?q=${encoded}&sort=stars&order=desc&per_page=100&page=${page}"

        echo "[discover] Fetching page $page..." >&2

        local response
        if [ -n "$auth_header" ]; then
            response=$(curl -s -H "$auth_header" -H "Accept: application/vnd.github.v3+json" "$url" 2>/dev/null)
        else
            response=$(curl -s -H "Accept: application/vnd.github.v3+json" "$url" 2>/dev/null)
        fi

        if echo "$response" | grep -q '"API rate limit exceeded'; then
            echo "[discover] GitHub rate limit exceeded" >&2
            break
        fi

        local urls=$(echo "$response" | json_extract "clone_url" | grep -v '^$')

        if [ -z "$urls" ]; then
            break
        fi

        echo "$urls"

        local count=$(echo "$urls" | wc -l | tr -d ' ')
        total_found=$((total_found + count))

        if [ "$count" -lt 100 ]; then
            break
        fi

        page=$((page + 1))

        if [ "$page" -gt 10 ]; then
            break
        fi

        sleep 1
    done

    echo "[discover] GitHub trending: found $total_found repos" >&2
}

# GitLab API discovery
discover_gitlab() {
    local target="$1"
    local since_date=$(days_ago "$DAYS")
    local page=1
    local total_found=0
    local auth_header=""

    if [ -n "$GITLAB_TOKEN" ]; then
        auth_header="PRIVATE-TOKEN: $GITLAB_TOKEN"
    fi

    echo "[discover] GitLab: searching repos updated since $(days_ago_simple "$DAYS")" >&2
    [ -n "$target" ] && echo "[discover] Filter: $target" >&2

    while true; do
        local url="https://gitlab.com/api/v4/projects?last_activity_after=${since_date}&order_by=last_activity_at&sort=desc&per_page=100&page=${page}"

        if [ -n "$target" ]; then
            # Try to filter by namespace
            url="$url&search=$target"
        fi

        echo "[discover] Fetching page $page..." >&2

        local response
        if [ -n "$auth_header" ]; then
            response=$(curl -s -H "$auth_header" "$url" 2>/dev/null)
        else
            response=$(curl -s "$url" 2>/dev/null)
        fi

        # Extract http_url_to_repo
        local urls=$(echo "$response" | json_extract "http_url_to_repo" | grep -v '^$')

        if [ -z "$urls" ]; then
            break
        fi

        echo "$urls"

        local count=$(echo "$urls" | wc -l | tr -d ' ')
        total_found=$((total_found + count))

        if [ "$count" -lt 100 ]; then
            break
        fi

        page=$((page + 1))

        if [ "$page" -gt 10 ]; then
            echo "[discover] Stopping at 10 pages" >&2
            break
        fi

        sleep 1
    done

    echo "[discover] GitLab: found $total_found repos" >&2
}

# Codeberg/Gitea API discovery
discover_codeberg() {
    local target="$1"
    local base_url="${CODEBERG_URL:-https://codeberg.org}"
    local page=1
    local total_found=0
    local auth_header=""

    if [ -n "$CODEBERG_TOKEN" ]; then
        auth_header="Authorization: token $CODEBERG_TOKEN"
    fi

    echo "[discover] Codeberg: searching repos" >&2
    [ -n "$target" ] && echo "[discover] Filter: $target" >&2

    # Codeberg uses Gitea API
    if [ -n "$target" ]; then
        # Search user/org repos
        while true; do
            # Try org first, then user
            local url="${base_url}/api/v1/orgs/${target}/repos?page=${page}&limit=50"

            echo "[discover] Fetching page $page..." >&2

            local response
            if [ -n "$auth_header" ]; then
                response=$(curl -s -H "$auth_header" "$url" 2>/dev/null)
            else
                response=$(curl -s "$url" 2>/dev/null)
            fi

            # If org not found, try user
            if echo "$response" | grep -q '"message"'; then
                url="${base_url}/api/v1/users/${target}/repos?page=${page}&limit=50"
                if [ -n "$auth_header" ]; then
                    response=$(curl -s -H "$auth_header" "$url" 2>/dev/null)
                else
                    response=$(curl -s "$url" 2>/dev/null)
                fi
            fi

            local urls=$(echo "$response" | json_extract "clone_url" | grep -v '^$')

            if [ -z "$urls" ]; then
                break
            fi

            echo "$urls"

            local count=$(echo "$urls" | wc -l | tr -d ' ')
            total_found=$((total_found + count))

            if [ "$count" -lt 50 ]; then
                break
            fi

            page=$((page + 1))

            if [ "$page" -gt 10 ]; then
                break
            fi

            sleep 0.5
        done
    else
        # Search all recent repos
        while true; do
            local url="${base_url}/api/v1/repos/search?sort=updated&order=desc&page=${page}&limit=50"

            echo "[discover] Fetching page $page..." >&2

            local response
            if [ -n "$auth_header" ]; then
                response=$(curl -s -H "$auth_header" "$url" 2>/dev/null)
            else
                response=$(curl -s "$url" 2>/dev/null)
            fi

            # Gitea search returns data in .data array
            local urls=$(echo "$response" | json_extract "clone_url" | grep -v '^$')

            if [ -z "$urls" ]; then
                break
            fi

            echo "$urls"

            local count=$(echo "$urls" | wc -l | tr -d ' ')
            total_found=$((total_found + count))

            if [ "$count" -lt 50 ]; then
                break
            fi

            page=$((page + 1))

            if [ "$page" -gt 5 ]; then
                break
            fi

            sleep 0.5
        done
    fi

    echo "[discover] Codeberg: found $total_found repos" >&2
}

# GitHub Events API - watch for new push events
discover_github_events() {
    local target="$1"
    local auth_header=""

    if [ -n "$GITHUB_TOKEN" ]; then
        auth_header="Authorization: Bearer $GITHUB_TOKEN"
    fi

    echo "[discover] GitHub Events: monitoring push events" >&2

    local url=""
    if [ -n "$target" ]; then
        # Org/user events
        url="https://api.github.com/orgs/$target/events?per_page=100"
        echo "[discover] Watching: $target" >&2
    else
        # Public events (very high volume)
        url="https://api.github.com/events?per_page=100"
        echo "[discover] Watching: public events" >&2
    fi

    local response
    if [ -n "$auth_header" ]; then
        response=$(curl -s -H "$auth_header" -H "Accept: application/vnd.github.v3+json" "$url" 2>/dev/null)
    else
        response=$(curl -s -H "Accept: application/vnd.github.v3+json" "$url" 2>/dev/null)
    fi

    # Extract unique repo URLs from PushEvents
    echo "$response" | grep -o '"url":"https://api.github.com/repos/[^"]*"' | \
        sed 's|"url":"https://api.github.com/repos/||; s|"$||; s|/events$||' | \
        sort -u | \
        while read repo; do
            [ -n "$repo" ] && echo "https://github.com/${repo}.git"
        done
}

# Usage
usage() {
    cat >&2 << 'EOF'
libreleak repository discovery

Usage: discover-repos.sh <platform> [target] [days]

Platforms:
  github          Search GitHub repos by org/user or query
  github-trending Find trending repos (new + stars)
  github-events   Monitor GitHub push events (real-time)
  gitlab          Search GitLab repos
  codeberg        Search Codeberg repos

Examples:
  discover-repos.sh github microsoft 7
    → Microsoft repos updated in last 7 days

  discover-repos.sh github "language:rust stars:>10" 1
    → Rust repos with >10 stars from today

  discover-repos.sh github-trending rust 7
    → Trending Rust repos from last week

  discover-repos.sh github-events kubernetes
    → Recent pushes to kubernetes org

  discover-repos.sh codeberg fosscode 30
    → fosscode repos from last month

  discover-repos.sh gitlab gnome 7
    → GNOME repos from last week

Environment:
  GITHUB_TOKEN   - GitHub token (5000 req/hr vs 60)
  GITLAB_TOKEN   - GitLab token
  CODEBERG_TOKEN - Codeberg token
  CODEBERG_URL   - Custom Gitea instance URL

Output:
  Repository URLs to stdout (one per line)
  Progress/status to stderr
EOF
    exit 1
}

# Main
case "$PLATFORM" in
    github)
        discover_github "$TARGET"
        ;;
    github-trending|trending)
        discover_github_trending "$TARGET"
        ;;
    github-events|events)
        discover_github_events "$TARGET"
        ;;
    gitlab)
        discover_gitlab "$TARGET"
        ;;
    codeberg|gitea)
        discover_codeberg "$TARGET"
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        echo "[discover] Unknown platform: $PLATFORM" >&2
        usage
        ;;
esac
