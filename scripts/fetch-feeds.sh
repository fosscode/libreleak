#!/bin/bash
# libreleak feed fetcher
# Fetches new repositories from various sources and adds them to the database
#
# Usage:
#   ./fetch-feeds.sh                    # Fetch from all sources
#   ./fetch-feeds.sh github-events      # GitHub public events (CreateEvent)
#   ./fetch-feeds.sh github-search      # GitHub search API
#   ./fetch-feeds.sh github-trending    # GitHub trending repos
#   ./fetch-feeds.sh gitlab             # GitLab recent repos
#   ./fetch-feeds.sh codeberg           # Codeberg recent repos

set -e

DB_PATH="${LIBRELEAK_DB:-$HOME/.libreleak/libreleak.db}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# API tokens
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
GITLAB_TOKEN="${GITLAB_TOKEN:-}"
CODEBERG_TOKEN="${CODEBERG_TOKEN:-}"
BITBUCKET_TOKEN="${BITBUCKET_TOKEN:-}"

# Rate limiting
GITHUB_DELAY=1
GITLAB_DELAY=0.5
CODEBERG_DELAY=0.5
BITBUCKET_DELAY=0.5

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[fetch]${NC} $1" >&2; }
success() { echo -e "${GREEN}[fetch]${NC} $1" >&2; }
warn() { echo -e "${YELLOW}[fetch]${NC} $1" >&2; }
error() { echo -e "${RED}[fetch]${NC} $1" >&2; }

# Check database exists
check_db() {
    if [ ! -f "$DB_PATH" ]; then
        error "Database not found at $DB_PATH"
        error "Run: ./scripts/init-db.sh"
        exit 1
    fi
}

# Add repo to database (returns 0 if new, 1 if exists)
add_repo() {
    local url="$1"
    local platform="$2"
    local source="$3"
    local priority="${4:-5}"
    local owner=""
    local name=""

    # Parse owner/name from URL
    case "$platform" in
        github)
            owner=$(echo "$url" | sed -n 's|.*github\.com/\([^/]*\)/.*|\1|p')
            name=$(echo "$url" | sed -n 's|.*github\.com/[^/]*/\([^/\.]*\).*|\1|p')
            ;;
        gitlab)
            owner=$(echo "$url" | sed -n 's|.*gitlab\.com/\([^/]*\)/.*|\1|p')
            name=$(echo "$url" | sed -n 's|.*gitlab\.com/[^/]*/\([^/\.]*\).*|\1|p')
            ;;
        codeberg)
            owner=$(echo "$url" | sed -n 's|.*codeberg\.org/\([^/]*\)/.*|\1|p')
            name=$(echo "$url" | sed -n 's|.*codeberg\.org/[^/]*/\([^/\.]*\).*|\1|p')
            ;;
        bitbucket)
            owner=$(echo "$url" | sed -n 's|.*bitbucket\.org/\([^/]*\)/.*|\1|p')
            name=$(echo "$url" | sed -n 's|.*bitbucket\.org/[^/]*/\([^/\.]*\).*|\1|p')
            ;;
    esac

    # Insert or ignore if exists
    result=$(sqlite3 "$DB_PATH" "
        INSERT OR IGNORE INTO repos (url, platform, owner, name, source, priority)
        VALUES ('$url', '$platform', '$owner', '$name', '$source', $priority);
        SELECT changes();
    ")

    if [ "$result" = "1" ]; then
        return 0  # New repo added
    else
        return 1  # Already exists
    fi
}

# Update feed source cursor
update_feed_cursor() {
    local feed_name="$1"
    local cursor="$2"
    local count="$3"

    sqlite3 "$DB_PATH" "
        INSERT INTO feed_sources (name, last_fetched_at, last_cursor, repos_fetched)
        VALUES ('$feed_name', CURRENT_TIMESTAMP, '$cursor', $count)
        ON CONFLICT(name) DO UPDATE SET
            last_fetched_at = CURRENT_TIMESTAMP,
            last_cursor = '$cursor',
            repos_fetched = repos_fetched + $count;
    "
}

# Fetch GitHub public events (CreateEvent = new repos)
fetch_github_events() {
    log "Fetching GitHub public events..."

    local auth_header=""
    if [ -n "$GITHUB_TOKEN" ]; then
        auth_header="Authorization: Bearer $GITHUB_TOKEN"
    fi

    local new_count=0
    local total=0

    # Fetch multiple pages of events
    for page in 1 2 3; do
        local url="https://api.github.com/events?per_page=100&page=$page"

        local response
        if [ -n "$auth_header" ]; then
            response=$(curl -s -H "$auth_header" -H "Accept: application/vnd.github.v3+json" "$url" 2>/dev/null)
        else
            response=$(curl -s -H "Accept: application/vnd.github.v3+json" "$url" 2>/dev/null)
        fi

        # Check for rate limit
        if echo "$response" | grep -q "rate limit"; then
            warn "GitHub rate limit hit"
            break
        fi

        # Extract all repo names from "repo": { ... "name": "owner/repo" ... }
        # Look for repo.name patterns which contain owner/repo format
        local repos=$(echo "$response" | grep -o '"name": "[^"]*\/[^"]*"' | \
            sed 's/"name": "//;s/"$//' | sort -u)

        if [ -z "$repos" ]; then
            break
        fi

        for repo in $repos; do
            local repo_url="https://github.com/${repo}.git"
            if add_repo "$repo_url" "github" "events_push" 6; then
                ((new_count++))
            fi
            ((total++))
        done

        sleep $GITHUB_DELAY
    done

    update_feed_cursor "github_events" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$new_count"
    success "GitHub events: $new_count new repos (from $total events)"
}

# Fetch GitHub search API - recently created repos
fetch_github_search() {
    local query="${1:-}"
    local days="${2:-1}"

    log "Fetching GitHub search (query: ${query:-all}, days: $days)..."

    local auth_header=""
    if [ -n "$GITHUB_TOKEN" ]; then
        auth_header="Authorization: Bearer $GITHUB_TOKEN"
    fi

    # Calculate date
    local since_date
    if date -v-1d > /dev/null 2>&1; then
        since_date=$(date -v-"${days}d" -u +%Y-%m-%d)
    else
        since_date=$(date -u -d "$days days ago" +%Y-%m-%d)
    fi

    local new_count=0
    local total=0

    # Build search query
    local search_query="created:>=$since_date"
    if [ -n "$query" ]; then
        search_query="$query $search_query"
    fi

    local encoded=$(printf '%s' "$search_query" | sed 's/ /%20/g; s/:/%3A/g; s/>/%3E/g; s/</%3C/g; s/=/%3D/g')

    for page in 1 2 3 4 5; do
        local url="https://api.github.com/search/repositories?q=${encoded}&sort=updated&order=desc&per_page=100&page=$page"

        local response
        if [ -n "$auth_header" ]; then
            response=$(curl -s -H "$auth_header" -H "Accept: application/vnd.github.v3+json" "$url" 2>/dev/null)
        else
            response=$(curl -s -H "Accept: application/vnd.github.v3+json" "$url" 2>/dev/null)
        fi

        if echo "$response" | grep -q "rate limit"; then
            warn "GitHub rate limit hit"
            break
        fi

        # Extract clone URLs
        local repos=$(echo "$response" | grep -o '"clone_url":"[^"]*"' | sed 's/"clone_url":"//;s/"//')

        if [ -z "$repos" ]; then
            break
        fi

        for repo_url in $repos; do
            local source="search"
            [ -n "$query" ] && source="search_${query// /_}"

            if add_repo "$repo_url" "github" "$source" 6; then
                ((new_count++))
            fi
            ((total++))
        done

        local count=$(echo "$repos" | wc -l | tr -d ' ')
        if [ "$count" -lt 100 ]; then
            break
        fi

        sleep $GITHUB_DELAY
    done

    update_feed_cursor "github_search_${query:-all}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$new_count"
    success "GitHub search: $new_count new repos (from $total results)"
}

# Fetch GitHub trending repos
fetch_github_trending() {
    local language="${1:-}"
    local days="${2:-7}"

    log "Fetching GitHub trending (lang: ${language:-all}, days: $days)..."

    local auth_header=""
    if [ -n "$GITHUB_TOKEN" ]; then
        auth_header="Authorization: Bearer $GITHUB_TOKEN"
    fi

    local since_date
    if date -v-1d > /dev/null 2>&1; then
        since_date=$(date -v-"${days}d" -u +%Y-%m-%d)
    else
        since_date=$(date -u -d "$days days ago" +%Y-%m-%d)
    fi

    local new_count=0
    local total=0

    # Search for recently created repos with stars (trending indicator)
    local search_query="created:>=$since_date stars:>0"
    if [ -n "$language" ]; then
        search_query="language:$language $search_query"
    fi

    local encoded=$(printf '%s' "$search_query" | sed 's/ /%20/g; s/:/%3A/g; s/>/%3E/g; s/</%3C/g; s/=/%3D/g')

    for page in 1 2 3; do
        local url="https://api.github.com/search/repositories?q=${encoded}&sort=stars&order=desc&per_page=100&page=$page"

        local response
        if [ -n "$auth_header" ]; then
            response=$(curl -s -H "$auth_header" -H "Accept: application/vnd.github.v3+json" "$url" 2>/dev/null)
        else
            response=$(curl -s -H "Accept: application/vnd.github.v3+json" "$url" 2>/dev/null)
        fi

        if echo "$response" | grep -q "rate limit"; then
            warn "GitHub rate limit hit"
            break
        fi

        local repos=$(echo "$response" | grep -o '"clone_url":"[^"]*"' | sed 's/"clone_url":"//;s/"//')

        if [ -z "$repos" ]; then
            break
        fi

        for repo_url in $repos; do
            # Trending repos get higher priority - more eyes = faster cleanup
            if add_repo "$repo_url" "github" "trending" 7; then
                ((new_count++))
            fi
            ((total++))
        done

        local count=$(echo "$repos" | wc -l | tr -d ' ')
        if [ "$count" -lt 100 ]; then
            break
        fi

        sleep $GITHUB_DELAY
    done

    update_feed_cursor "github_trending_${language:-all}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$new_count"
    success "GitHub trending: $new_count new repos (from $total results)"
}

# Fetch GitLab recent repos
fetch_gitlab() {
    local days="${1:-7}"

    log "Fetching GitLab repos (days: $days)..."

    local auth_header=""
    if [ -n "$GITLAB_TOKEN" ]; then
        auth_header="PRIVATE-TOKEN: $GITLAB_TOKEN"
    fi

    local since_date
    if date -v-1d > /dev/null 2>&1; then
        since_date=$(date -v-"${days}d" -u +%Y-%m-%dT00:00:00Z)
    else
        since_date=$(date -u -d "$days days ago" +%Y-%m-%dT00:00:00Z)
    fi

    local new_count=0
    local total=0

    for page in 1 2 3 4 5; do
        local url="https://gitlab.com/api/v4/projects?last_activity_after=${since_date}&order_by=last_activity_at&sort=desc&per_page=100&page=$page"

        local response
        if [ -n "$auth_header" ]; then
            response=$(curl -s -H "$auth_header" "$url" 2>/dev/null)
        else
            response=$(curl -s "$url" 2>/dev/null)
        fi

        local repos=$(echo "$response" | grep -o '"http_url_to_repo":"[^"]*"' | sed 's/"http_url_to_repo":"//;s/"//')

        if [ -z "$repos" ]; then
            break
        fi

        for repo_url in $repos; do
            if add_repo "$repo_url" "gitlab" "api" 5; then
                ((new_count++))
            fi
            ((total++))
        done

        local count=$(echo "$repos" | wc -l | tr -d ' ')
        if [ "$count" -lt 100 ]; then
            break
        fi

        sleep $GITLAB_DELAY
    done

    update_feed_cursor "gitlab" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$new_count"
    success "GitLab: $new_count new repos (from $total results)"
}

# Fetch Codeberg recent repos
fetch_codeberg() {
    log "Fetching Codeberg repos..."

    local auth_header=""
    if [ -n "$CODEBERG_TOKEN" ]; then
        auth_header="Authorization: token $CODEBERG_TOKEN"
    fi

    local new_count=0
    local total=0

    for page in 1 2 3 4 5; do
        local url="https://codeberg.org/api/v1/repos/search?sort=updated&order=desc&page=$page&limit=50"

        local response
        if [ -n "$auth_header" ]; then
            response=$(curl -s -H "$auth_header" "$url" 2>/dev/null)
        else
            response=$(curl -s "$url" 2>/dev/null)
        fi

        local repos=$(echo "$response" | grep -o '"clone_url":"[^"]*"' | sed 's/"clone_url":"//;s/"//')

        if [ -z "$repos" ]; then
            break
        fi

        for repo_url in $repos; do
            if add_repo "$repo_url" "codeberg" "api" 5; then
                ((new_count++))
            fi
            ((total++))
        done

        local count=$(echo "$repos" | wc -l | tr -d ' ')
        if [ "$count" -lt 50 ]; then
            break
        fi

        sleep $CODEBERG_DELAY
    done

    update_feed_cursor "codeberg" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$new_count"
    success "Codeberg: $new_count new repos (from $total results)"
}

# Fetch Bitbucket recent repos
fetch_bitbucket() {
    local days="${1:-7}"

    log "Fetching Bitbucket repos (days: $days)..."

    # Bitbucket API 2.0 - public repos
    # Note: For authenticated access, use BITBUCKET_TOKEN as app password
    local auth_header=""
    if [ -n "$BITBUCKET_TOKEN" ]; then
        # Format: username:app_password
        auth_header="Authorization: Basic $(echo -n "$BITBUCKET_TOKEN" | base64)"
    fi

    local new_count=0
    local total=0

    # Bitbucket API to search for recently updated repos
    # Paginated with next URL
    local next_url="https://api.bitbucket.org/2.0/repositories?sort=-updated_on&pagelen=100"

    for page in 1 2 3 4 5; do
        if [ -z "$next_url" ]; then
            break
        fi

        local response
        if [ -n "$auth_header" ]; then
            response=$(curl -s -H "$auth_header" "$next_url" 2>/dev/null)
        else
            response=$(curl -s "$next_url" 2>/dev/null)
        fi

        # Extract clone URLs (HTTPS)
        # Bitbucket returns links.clone array with href
        local repos=$(echo "$response" | grep -o '"href": "https://bitbucket.org/[^"]*\.git"' | \
            sed 's/"href": "//;s/"$//' | sort -u)

        if [ -z "$repos" ]; then
            # Try alternate format
            repos=$(echo "$response" | grep -o 'https://bitbucket\.org/[^"]*\.git' | sort -u)
        fi

        if [ -z "$repos" ]; then
            break
        fi

        for repo_url in $repos; do
            if add_repo "$repo_url" "bitbucket" "api" 5; then
                ((new_count++))
            fi
            ((total++))
        done

        # Get next page URL
        next_url=$(echo "$response" | grep -o '"next": "[^"]*"' | sed 's/"next": "//;s/"$//' | head -1)

        sleep $BITBUCKET_DELAY
    done

    update_feed_cursor "bitbucket" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$new_count"
    success "Bitbucket: $new_count new repos (from $total results)"
}

# Fetch repos from Reddit
fetch_reddit() {
    log "Fetching repos from Reddit..."

    local subreddits=("github" "opensource" "programming" "coolgithubprojects" "SideProject" "webdev" "Python" "rust" "golang" "javascript")
    local new_count=0
    local total=0

    for sub in "${subreddits[@]}"; do
        log "  Checking r/$sub..."

        # Reddit JSON API (no auth needed for public posts)
        local url="https://www.reddit.com/r/$sub/new.json?limit=100"

        local response
        response=$(curl -s -A "libreleak/1.0" "$url" 2>/dev/null)

        if [ -z "$response" ]; then
            continue
        fi

        # Extract GitHub URLs from post URLs and selftext
        local github_urls=$(echo "$response" | grep -oE 'https?://github\.com/[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+' | \
            sed 's|#.*||;s|/issues.*||;s|/pull.*||;s|/blob.*||;s|/tree.*||' | \
            sort -u)

        local gitlab_urls=$(echo "$response" | grep -oE 'https?://gitlab\.com/[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+' | \
            sed 's|#.*||;s|/-/.*||' | \
            sort -u)

        for repo_url in $github_urls; do
            # Clean URL and add .git
            repo_url="${repo_url%.git}.git"
            if add_repo "$repo_url" "github" "reddit_$sub" 7; then
                ((new_count++))
            fi
            ((total++))
        done

        for repo_url in $gitlab_urls; do
            repo_url="${repo_url%.git}.git"
            if add_repo "$repo_url" "gitlab" "reddit_$sub" 7; then
                ((new_count++))
            fi
            ((total++))
        done

        sleep 2  # Be nice to Reddit
    done

    update_feed_cursor "reddit" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$new_count"
    success "Reddit: $new_count new repos (from $total URLs)"
}

# Fetch repos from X/Twitter via Nitter instances
fetch_x() {
    log "Fetching repos from X/Twitter..."

    # Nitter instances that might work
    local nitter_instances=("nitter.poast.org" "nitter.privacydev.net" "nitter.1d4.us")

    # Search terms that often share repos
    local search_terms=("github.com" "new+repo" "open+source+release" "just+released")

    local new_count=0
    local total=0

    # Try to find a working nitter instance
    local working_nitter=""
    for instance in "${nitter_instances[@]}"; do
        if curl -s --max-time 5 "https://$instance" >/dev/null 2>&1; then
            working_nitter="$instance"
            log "  Using nitter instance: $working_nitter"
            break
        fi
    done

    if [ -z "$working_nitter" ]; then
        warn "No working Nitter instance found, trying direct search..."

        # Fallback: Use GitHub search for repos mentioned on Twitter
        # This won't work directly, so let's try scraping some known accounts that share repos
        local accounts=("github" "GitHubTrending" "pythontrending" "AiBreakfast")

        for account in "${accounts[@]}"; do
            log "  Checking @$account mentions..."

            # Search GitHub for repos that might be from this account's shares
            local url="https://api.github.com/search/repositories?q=created:>$(date -v-1d +%Y-%m-%d)&sort=stars&order=desc&per_page=50"

            local auth_header=""
            if [ -n "$GITHUB_TOKEN" ]; then
                auth_header="Authorization: Bearer $GITHUB_TOKEN"
            fi

            local response
            if [ -n "$auth_header" ]; then
                response=$(curl -s -H "$auth_header" -H "Accept: application/vnd.github.v3+json" "$url" 2>/dev/null)
            else
                response=$(curl -s -H "Accept: application/vnd.github.v3+json" "$url" 2>/dev/null)
            fi

            local repos=$(echo "$response" | grep -o '"clone_url":"[^"]*"' | sed 's/"clone_url":"//;s/"//' | head -30)

            for repo_url in $repos; do
                if add_repo "$repo_url" "github" "x_trending" 8; then
                    ((new_count++))
                fi
                ((total++))
            done

            sleep $GITHUB_DELAY
        done
    else
        # Use Nitter to search for repo links
        for term in "${search_terms[@]}"; do
            log "  Searching: $term"

            local url="https://$working_nitter/search?f=tweets&q=$term"
            local response
            response=$(curl -s -A "Mozilla/5.0" --max-time 10 "$url" 2>/dev/null)

            # Extract GitHub URLs
            local github_urls=$(echo "$response" | grep -oE 'https?://github\.com/[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+' | \
                sed 's|#.*||;s|/issues.*||;s|/pull.*||;s|/blob.*||;s|/tree.*||' | \
                sort -u | head -50)

            for repo_url in $github_urls; do
                repo_url="${repo_url%.git}.git"
                if add_repo "$repo_url" "github" "x_search" 7; then
                    ((new_count++))
                fi
                ((total++))
            done

            sleep 3
        done
    fi

    update_feed_cursor "x" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$new_count"
    success "X/Twitter: $new_count new repos (from $total URLs)"
}

# Fetch repos from lesser-known code forges
fetch_forges() {
    log "Fetching from alternative code forges..."

    local new_count=0
    local total=0

    # SourceHut (sr.ht)
    log "  Checking SourceHut..."
    local srht_repos=$(curl -s "https://git.sr.ht/api/repos" 2>/dev/null | \
        grep -oE '"clone_url":"[^"]*"' | sed 's/"clone_url":"//;s/"//' | head -50)
    for url in $srht_repos; do
        if add_repo "$url" "sourcehut" "srht_api" 8; then ((new_count++)); fi
        ((total++))
    done

    # NotABug.org (Gitea instance)
    log "  Checking NotABug.org..."
    local notabug_repos=$(curl -s "https://notabug.org/api/v1/repos/search?limit=50&sort=updated" 2>/dev/null | \
        grep -oE '"clone_url":"[^"]*"' | sed 's/"clone_url":"//;s/"//')
    for url in $notabug_repos; do
        if add_repo "$url" "notabug" "notabug_api" 8; then ((new_count++)); fi
        ((total++))
    done

    # Disroot Git (Gitea)
    log "  Checking Disroot Git..."
    local disroot_repos=$(curl -s "https://git.disroot.org/api/v1/repos/search?limit=50&sort=updated" 2>/dev/null | \
        grep -oE '"clone_url":"[^"]*"' | sed 's/"clone_url":"//;s/"//')
    for url in $disroot_repos; do
        if add_repo "$url" "disroot" "disroot_api" 8; then ((new_count++)); fi
        ((total++))
    done

    # Framagit (GitLab instance)
    log "  Checking Framagit..."
    local framagit_repos=$(curl -s "https://framagit.org/api/v4/projects?order_by=updated_at&per_page=50" 2>/dev/null | \
        grep -oE '"http_url_to_repo":"[^"]*"' | sed 's/"http_url_to_repo":"//;s/"//')
    for url in $framagit_repos; do
        if add_repo "$url" "framagit" "framagit_api" 8; then ((new_count++)); fi
        ((total++))
    done

    # Gitea.com
    log "  Checking Gitea.com..."
    local gitea_repos=$(curl -s "https://gitea.com/api/v1/repos/search?limit=50&sort=updated" 2>/dev/null | \
        grep -oE '"clone_url":"[^"]*"' | sed 's/"clone_url":"//;s/"//')
    for url in $gitea_repos; do
        if add_repo "$url" "gitea" "gitea_api" 8; then ((new_count++)); fi
        ((total++))
    done

    # 0xacab.org (GitLab for activists)
    log "  Checking 0xacab.org..."
    local acab_repos=$(curl -s "https://0xacab.org/api/v4/projects?order_by=updated_at&per_page=50" 2>/dev/null | \
        grep -oE '"http_url_to_repo":"[^"]*"' | sed 's/"http_url_to_repo":"//;s/"//')
    for url in $acab_repos; do
        if add_repo "$url" "0xacab" "0xacab_api" 7; then ((new_count++)); fi
        ((total++))
    done

    # Pagure (Fedora)
    log "  Checking Pagure (Fedora)..."
    local pagure_repos=$(curl -s "https://pagure.io/api/0/projects?per_page=50&order=date_modified" 2>/dev/null | \
        grep -oE '"fullname":"[^"]*"' | sed 's/"fullname":"//;s/"$//' | \
        while read name; do echo "https://pagure.io/$name.git"; done)
    for url in $pagure_repos; do
        if add_repo "$url" "pagure" "pagure_api" 7; then ((new_count++)); fi
        ((total++))
    done

    # Rocketgit
    log "  Checking RocketGit..."
    local rocketgit=$(curl -s "https://rocketgit.com/api/repos?limit=50" 2>/dev/null | \
        grep -oE 'https://rocketgit\.com/[^"]+\.git' | head -50)
    for url in $rocketgit; do
        if add_repo "$url" "rocketgit" "rocketgit_api" 7; then ((new_count++)); fi
        ((total++))
    done

    # repo.or.cz
    log "  Checking repo.or.cz..."
    local repocz=$(curl -s "https://repo.or.cz/" 2>/dev/null | \
        grep -oE 'href="/[^"]+\.git"' | sed 's/href="//;s/"$//' | \
        while read path; do echo "https://repo.or.cz$path"; done | head -30)
    for url in $repocz; do
        if add_repo "$url" "repocz" "repocz_scrape" 7; then ((new_count++)); fi
        ((total++))
    done

    update_feed_cursor "forges" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$new_count"
    success "Alternative forges: $new_count new repos (from $total URLs)"
}

# Fetch repos from Hacker News
fetch_hackernews() {
    log "Fetching repos from Hacker News..."

    local new_count=0
    local total=0

    # Get top and new stories
    for endpoint in "topstories" "newstories" "showstories"; do
        log "  Fetching $endpoint..."

        local ids=$(curl -s "https://hacker-news.firebaseio.com/v0/$endpoint.json" 2>/dev/null | \
            tr ',' '\n' | tr -d '[]' | head -100)

        for id in $ids; do
            if [ -z "$id" ]; then continue; fi

            local item=$(curl -s "https://hacker-news.firebaseio.com/v0/item/$id.json" 2>/dev/null)

            # Extract GitHub URLs from URL and text fields
            local github_urls=$(echo "$item" | grep -oE 'https?://github\.com/[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+' | \
                sed 's|#.*||;s|/issues.*||;s|/pull.*||;s|/blob.*||;s|/tree.*||' | \
                sort -u)

            for repo_url in $github_urls; do
                repo_url="${repo_url%.git}.git"
                if add_repo "$repo_url" "github" "hackernews" 8; then
                    ((new_count++))
                fi
                ((total++))
            done
        done

        sleep 0.5
    done

    update_feed_cursor "hackernews" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$new_count"
    success "Hacker News: $new_count new repos (from $total URLs)"
}

# Fetch high-value targets (AI/ML companies, etc.)
fetch_high_value() {
    log "Fetching high-value targets..."

    local targets=(
        "openai"
        "anthropic"
        "google-deepmind"
        "huggingface"
        "mistralai"
        "stability-ai"
        "replicate"
        "cohere-ai"
        "langchain-ai"
        "stripe"
        "twilio"
    )

    local new_count=0

    for target in "${targets[@]}"; do
        log "  Checking org: $target"

        local auth_header=""
        if [ -n "$GITHUB_TOKEN" ]; then
            auth_header="Authorization: Bearer $GITHUB_TOKEN"
        fi

        local url="https://api.github.com/orgs/$target/repos?sort=updated&direction=desc&per_page=100"

        local response
        if [ -n "$auth_header" ]; then
            response=$(curl -s -H "$auth_header" -H "Accept: application/vnd.github.v3+json" "$url" 2>/dev/null)
        else
            response=$(curl -s -H "Accept: application/vnd.github.v3+json" "$url" 2>/dev/null)
        fi

        local repos=$(echo "$response" | grep -o '"clone_url":"[^"]*"' | sed 's/"clone_url":"//;s/"//')

        for repo_url in $repos; do
            # High-value targets get max priority
            if add_repo "$repo_url" "github" "high_value_$target" 10; then
                ((new_count++))
            fi
        done

        sleep $GITHUB_DELAY
    done

    update_feed_cursor "high_value" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$new_count"
    success "High-value targets: $new_count new repos"
}

# Main
main() {
    check_db

    local source="${1:-all}"

    case "$source" in
        github-events|events)
            fetch_github_events
            ;;
        github-search|search)
            fetch_github_search "${2:-}" "${3:-1}"
            ;;
        github-trending|trending)
            fetch_github_trending "${2:-}" "${3:-7}"
            ;;
        gitlab)
            fetch_gitlab "${2:-7}"
            ;;
        codeberg)
            fetch_codeberg
            ;;
        bitbucket)
            fetch_bitbucket "${2:-7}"
            ;;
        high-value|hv)
            fetch_high_value
            ;;
        reddit)
            fetch_reddit
            ;;
        x|twitter)
            fetch_x
            ;;
        hackernews|hn)
            fetch_hackernews
            ;;
        social)
            fetch_reddit
            fetch_x
            fetch_hackernews
            ;;
        forges)
            fetch_forges
            ;;
        non-github|alt)
            fetch_gitlab 7
            fetch_codeberg
            fetch_bitbucket 7
            fetch_forges
            ;;
        all)
            fetch_github_events
            fetch_github_search "" 1
            fetch_github_trending "" 3
            fetch_gitlab 7
            fetch_codeberg
            fetch_bitbucket 7
            fetch_reddit
            fetch_x
            fetch_hackernews
            fetch_high_value
            ;;
        *)
            echo "Usage: $0 [source]"
            echo ""
            echo "Sources:"
            echo "  github-events    GitHub public events (CreateEvent, PushEvent)"
            echo "  github-search    GitHub search API (recently created)"
            echo "  github-trending  GitHub trending repos"
            echo "  gitlab           GitLab recent repos"
            echo "  codeberg         Codeberg recent repos"
            echo "  bitbucket        Bitbucket recent repos"
            echo "  reddit           Reddit subreddits (r/github, r/programming, etc.)"
            echo "  x|twitter        X/Twitter via Nitter or trending"
            echo "  hackernews|hn    Hacker News top/new stories"
            echo "  social           All social sources (reddit, x, hackernews)"
            echo "  high-value       High-value org targets (OpenAI, Anthropic, etc.)"
            echo "  all              Fetch from all sources (default)"
            exit 1
            ;;
    esac

    # Show stats
    echo ""
    log "Database stats:"
    sqlite3 "$DB_PATH" "
        SELECT '  Total repos: ' || COUNT(*) FROM repos;
        SELECT '  Pending: ' || COUNT(*) FROM repos WHERE status = 'pending';
        SELECT '  Scanned: ' || COUNT(*) FROM repos WHERE status = 'scanned';
        SELECT '  With findings: ' || COUNT(*) FROM repos WHERE findings_count > 0;
    "
}

main "$@"
