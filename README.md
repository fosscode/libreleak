# LibreLeak Docker Setup for Scanning Public Repositories

LibreLeak is designed to scan recently created repositories on public code hosting platforms for leaked secrets. This Docker setup provides automated discovery and scanning workflows.

## Quick Start

### Scan a Single Repository
```bash
# Scan a specific repository
REPO_URL=https://github.com/example/repo docker compose up scanner

# With verification enabled
ENABLE_VERIFICATION=true REPO_URL=https://github.com/example/repo docker compose up scanner
```

### Discover and Scan New Repositories

```bash
# Discover recently created GitHub repos (last 7 days)
PLATFORM=github DAYS=7 docker compose up repo-discovery > repos.txt

# Discover repos from specific organization
PLATFORM=github TARGET=microsoft DAYS=1 docker compose up repo-discovery > repos.txt

# Discover GitLab repos
PLATFORM=gitlab TARGET=gnome DAYS=7 docker compose up repo-discovery > repos.txt

# Then scan all discovered repos
docker compose up batch-scanner
```

## Services Overview

### 🔍 `repo-discovery`
Discovers recently created repositories from public code hosting platforms.

**Supported Platforms:**
- **GitHub** - Most popular, requires API token for higher rate limits
- **GitLab** - Second largest, good for FOSS projects
- **Codeberg** - Privacy-focused Git hosting

**Environment Variables:**
- `PLATFORM=github|gitlab|codeberg` - Target platform
- `TARGET` - Organization/user to filter by (optional)
- `DAYS=7` - Days to look back for new repos
- `GITHUB_TOKEN` - GitHub API token for higher rate limits

### 🏃 `scanner`
Scans a single repository specified by URL.

**Environment Variables:**
- `REPO_URL` - Git repository URL to scan
- `BRANCH` - Specific branch to scan (optional)
- `OUTPUT_FORMAT=report|json|sarif` - Output format
- `ENABLE_VERIFICATION=true` - Enable secret verification

### 📊 `batch-scanner`
Scans multiple repositories listed in `repos.txt`.

**Input:** `repos.txt` file with one repository URL per line
**Environment Variables:**
- `OUTPUT_FORMAT=report|json|sarif` - Output format
- `ENABLE_VERIFICATION=true` - Enable secret verification

### 🗄️ `postgres` (Optional)
PostgreSQL database for storing scan reports.

**Profiles:** `database` - Enable with `--profile database`

### 📊 `report-compiler`
Compiles multiple scan reports into researcher-friendly summaries and presentations.

**Outputs:**
- **Markdown reports** for documentation
- **HTML reports** with styling and charts
- **Research insights** and statistics

**Usage:**
```bash
docker compose up report-compiler
```

### 🏆 `bounty-reporter`
Automatically reports high-value findings to appropriate bug bounty programs.

**Supported Programs:**
- **OpenAI Bug Bounty** - Automated form submission
- **Anthropic** - Guided manual submission
- **Stripe** - Vulnerability disclosure guidance
- **GitHub Security Lab** - Security advisory guidance

**Safety Features:**
- **Dry-run mode** (default) - Shows what would be reported
- **Manual review** for sensitive findings
- **Rate limiting** and ethical submission practices

**Usage:**
```bash
# Dry run (safe)
docker compose up bounty-reporter

# Live reporting (use with caution)
DRY_RUN=false docker compose up bounty-reporter
```

### 📈 `aggregator` (Optional)
Imports JSON reports into the PostgreSQL database.

**Profiles:** `database` - Enable with `--profile database`

## Discovery Strategies

### Finding New Repositories

#### High-Value Targets
```bash
# Large tech companies (often have many new repos)
PLATFORM=github TARGET=microsoft DAYS=1 docker compose up repo-discovery

# Open source organizations
PLATFORM=github TARGET=google DAYS=7 docker compose up repo-discovery
PLATFORM=gitlab TARGET=gnome DAYS=7 docker compose up repo-discovery

# Individual developers (may leak personal tokens)
PLATFORM=github TARGET=some-developer DAYS=30 docker compose up repo-discovery
```

#### FOSS Platforms
```bash
# Codeberg - Privacy-focused repos
PLATFORM=codeberg DAYS=14 docker compose up repo-discovery

# GitLab - Enterprise and community projects
PLATFORM=gitlab DAYS=7 docker compose up repo-discovery
```

### Automated Workflows

#### Daily Discovery and Scanning
```bash
#!/bin/bash
# daily-scan.sh

# Discover new repos from yesterday
PLATFORM=github DAYS=1 docker compose up repo-discovery > repos.txt

# Scan them with verification
ENABLE_VERIFICATION=true docker compose up batch-scanner

# Generate research report
docker compose up report-compiler

# Archive results
mkdir -p archives/$(date +%Y%m%d)
mv reports/* archives/$(date +%Y%m%d)/ 2>/dev/null || true
mv compiled-reports/* archives/$(date +%Y%m%d)/ 2>/dev/null || true
```

#### Complete Research Workflow
```bash
#!/bin/bash
# full-research-workflow.sh

echo "🔍 Starting comprehensive security research scan..."

# 1. Discover new repositories from high-value targets
echo "📡 Discovering new repositories..."
PLATFORM=github TARGET=microsoft DAYS=1 docker compose up repo-discovery >> repos_microsoft.txt
PLATFORM=github TARGET=google DAYS=1 docker compose up repo-discovery >> repos_google.txt
PLATFORM=gitlab TARGET=gnome DAYS=7 docker compose up repo-discovery >> repos_gnome.txt

# 2. Batch scan all discovered repositories with verification
echo "🔎 Scanning repositories with verification..."
ENABLE_VERIFICATION=true docker compose up batch-scanner

# 3. Compile comprehensive research report
echo "📊 Generating research report..."
docker compose up report-compiler

# 4. Report high-value findings to bug bounty programs (dry run)
echo "🏆 Analyzing findings for bug bounty reporting..."
docker compose up bounty-reporter

echo "✅ Research workflow complete!"
echo "📁 Check ./reports/ for scan results"
echo "📄 Check ./compiled-reports/ for research summaries"
echo "🏅 Check ./bounty-reports/ for bug bounty submissions"
```

#### Continuous Monitoring
```bash
# Cron job example (add to crontab)
# Run daily at 2 AM
0 2 * * * cd /path/to/libreleak && ./daily-scan.sh
```

## Configuration Files

### `repos.txt` Format
```
# One repository URL per line
# Lines starting with # are comments
# Empty lines are ignored

https://github.com/example/repo1
https://github.com/example/repo2
git@gitlab.com:group/project.git
https://codeberg.org/user/repo
```

### Environment Configuration
```bash
# .env file
GITHUB_TOKEN=ghp_your_github_token_here
PLATFORM=github
TARGET=microsoft
DAYS=1
OUTPUT_FORMAT=report
ENABLE_VERIFICATION=true
POSTGRES_PASSWORD=secure_password
```

## Output and Reports

### Report Formats
- **`report`** - Enhanced JSON with metadata (default)
- **`json`** - Simple JSON array of findings
- **`sarif`** - GitHub Advanced Security format

### Report Structure
```json
{
  "scan_metadata": {
    "timestamp": "2025-01-15T10:30:00Z",
    "target": "https://github.com/example/repo",
    "libreleak_version": "0.1.0"
  },
  "findings": [
    {
      "rule_id": "openai-api-key",
      "rule_name": "OpenAI API Key",
      "file": "config.py",
      "line": 5,
      "secret": "sk-****...****",
      "verification_status": {
        "status": "Inactive",
        "message": "Secret is invalid or revoked"
      }
    }
  ]
}
```

## Advanced Usage

### Database Storage
```bash
# Start with database
docker compose --profile database up -d postgres

# Run aggregator to import reports
docker compose --profile database up aggregator
```

### Custom Discovery Scripts
```bash
#!/bin/bash
# Discover repos with high activity (potential for secrets)

# Get trending repos from GitHub
curl -s "https://api.github.com/search/repositories?q=created:>$(date -d '7 days ago' +%Y-%m-%d)&sort=stars&order=desc&per_page=50" \
  | jq -r '.items[].html_url' > trending_repos.txt

# Scan trending repos
docker compose up batch-scanner
```

### Verification-Only Scanning
```bash
# Scan without saving results, only verify existing secrets
ENABLE_VERIFICATION=true OUTPUT_FORMAT=json \
  docker compose up scanner > verification_results.json
```

## Security Considerations

### API Rate Limits
- **GitHub**: 60 requests/hour (authenticated: 5000/hour)
- **GitLab**: 2000 requests/hour
- **Codeberg**: Undocumented, be respectful

### Ethical Scanning
- Only scan public repositories
- Respect robots.txt and platform terms
- Don't overwhelm platforms with requests
- Use verification responsibly (makes network calls)

### Data Privacy
- Scan results contain sensitive information
- Store reports securely
- Consider data retention policies
- Use encryption for persistent storage

## Troubleshooting

### Common Issues

**"Rate limit exceeded"**
```bash
# Use GitHub token for higher limits
export GITHUB_TOKEN=your_token_here
docker compose up repo-discovery
```

**"Repository not found"**
```bash
# Check repository URL format
# Ensure repository is public
# Verify network connectivity
```

**"Verification network errors"**
```bash
# Check internet connectivity
# Some corporate networks block API calls
# Try without verification: ENABLE_VERIFICATION=false
```

**"Database connection failed"**
```bash
# Ensure PostgreSQL is running
docker compose --profile database ps
docker compose --profile database up postgres -d
```

### Debugging

```bash
# View container logs
docker compose logs scanner

# Run interactive shell
docker compose run scanner /bin/sh

# Test discovery manually
docker compose run repo-discovery /usr/local/bin/discover-repos.sh github microsoft 1
```

## Production Deployment

### Docker Swarm/Kubernetes
```yaml
# Example Kubernetes deployment
apiVersion: apps/v1
kind: CronJob
metadata:
  name: daily-repo-scan
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: libreleak
            image: libreleak:latest
            command: ["/usr/local/bin/discover-repos.sh", "github", "", "1"]
            env:
            - name: GITHUB_TOKEN
              valueFrom:
                secretKeyRef:
                  name: github-token
                  key: token
```

### CI/CD Integration
```yaml
# GitHub Actions example
name: Daily Secret Scan
on:
  schedule:
    - cron: '0 2 * * *'
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Discover new repos
        run: |
          docker compose up repo-discovery > repos.txt
      - name: Scan repositories
        run: |
          docker compose up batch-scanner
      - name: Upload reports
        uses: actions/upload-artifact@v4
        with:
          name: scan-reports
          path: reports/
```

---

**Ready to scan the public code commons for leaked secrets! 🔍**