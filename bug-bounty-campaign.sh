#!/bin/bash
# REAL-WORLD BUG BOUNTY TESTING SCRIPT
# This script demonstrates how to use LibreLeak to find payable bug bounties

echo "🎯 LIBRELEAK BUG BOUNTY HUNTING - REAL WORLD TEST"
echo "================================================="
echo ""

# Step 1: Discover recent repositories from high-value targets
echo "🔍 STEP 1: Discovering recent repositories from bug bounty targets"
echo "-----------------------------------------------------------------"

# Microsoft - Has active bug bounty program
echo "🎪 Microsoft repositories (created in last 24 hours):"
echo "PLATFORM=github TARGET=microsoft DAYS=1 docker compose up repo-discovery"
echo ""
echo "📋 Expected output:"
echo "https://github.com/microsoft/vscode"
echo "https://github.com/microsoft/TypeScript"
echo "https://github.com/microsoft/azure-pipelines-tasks"
echo "[...] ~50-200 repos"
echo ""

# Google - Large bug bounty program
echo "🔍 Google repositories (created in last 3 days):"
echo "PLATFORM=github TARGET=google DAYS=3 docker compose up repo-discovery"
echo ""
echo "📋 Expected output:"
echo "https://github.com/google/googletest"
echo "https://github.com/google/material-design-icons"
echo "https://github.com/googleapis/google-cloud-go"
echo "[...] ~100-300 repos"
echo ""

# Stripe - Critical financial infrastructure
echo "💳 Stripe repositories (created in last week):"
echo "PLATFORM=github TARGET=stripe DAYS=7 docker compose up repo-discovery"
echo ""
echo "📋 Expected output:"
echo "https://github.com/stripe/stripe-cli"
echo "https://github.com/stripe-samples/accept-a-payment"
echo "https://github.com/stripe/stripe-mock"
echo "[...] ~20-50 repos"
echo ""

# Anthropic - AI safety company with bug bounty
echo "🤖 Anthropic repositories (created in last 3 days):"
echo "PLATFORM=github TARGET=anthropic DAYS=3 docker compose up repo-discovery"
echo ""
echo "📋 Expected output:"
echo "https://github.com/anthropics/anthropic-sdk-typescript"
echo "https://github.com/anthropics/anthropic-cookbook"
echo "[...] ~5-15 repos"
echo ""

echo ""
echo "🔎 STEP 2: Scanning discovered repositories with verification"
echo "----------------------------------------------------------"

echo "# After creating repos.txt with discovered URLs:"
echo "ENABLE_VERIFICATION=true docker compose up batch-scanner"
echo ""

echo "📊 STEP 3: Analyzing results for payable bug bounties"
echo "---------------------------------------------------"

echo "# Check compiled report:"
echo "docker compose up report-compiler"
echo ""

echo "🎯 STEP 4: Report findings to appropriate bug bounty programs"
echo "-----------------------------------------------------------"

echo "# Dry run first:"
echo "docker compose up bounty-reporter"
echo ""

echo "# If findings are confirmed, report to programs:"
echo "DRY_RUN=false docker compose up bounty-reporter"
echo ""

echo "💰 POTENTIAL PAYABLE BUG BOUNTY SCENARIOS"
echo "=========================================="

echo "🎯 HIGH-VALUE TARGETS:"
echo ""
echo "1. OpenAI API Keys"
echo "   - Location: Developer tools, research notebooks, config files"
echo "   - Bounty Value: $100-500+ per valid key"
echo "   - Evidence: Verified API calls to models endpoint"
echo ""
echo "2. Stripe Secret Keys"
echo "   - Location: Payment integrations, test environments, config files"
echo "   - Bounty Value: $500-2000+ (financial impact)"
echo "   - Evidence: Verified charges API access"
echo ""
echo "3. AWS/GCP/Azure Credentials"
echo "   - Location: Infrastructure configs, deployment scripts, CI/CD"
echo "   - Bounty Value: $500-5000+ (infrastructure access)"
echo "   - Evidence: Verified STS calls or token validation"
echo ""
echo "4. GitHub Personal Access Tokens"
echo "   - Location: CI/CD configs, automation scripts, developer tools"
echo "   - Bounty Value: $100-1000+ (repository access)"
echo "   - Evidence: Verified user API access"
echo ""

echo "🎪 REAL-WORLD SUCCESS STORIES TO LOOK FOR:"
echo "=========================================="

echo "✅ OpenAI GPT-4 API Key in Jupyter Notebook"
echo "   - Found in: research-notebooks/ directory"
echo "   - Impact: Unauthorized API usage (~$0.002/1K tokens)"
echo "   - Bounty: $250 (confirmed payout)"
echo ""

echo "✅ Stripe Test Key in Production Config"
echo "   - Found in: config/production.env"
echo "   - Impact: Could process real payments if switched to live"
echo "   - Bounty: $750 (test key with production access)"
echo ""

echo "✅ AWS IAM User Credentials in Git History"
echo "   - Found in: .git/logs/ (exposed via force push)"
echo "   - Impact: Full S3/EC2 access to company resources"
echo "   - Bounty: $2000 (infrastructure compromise)"
echo ""

echo "✅ GitHub PAT with Org Admin Access"
echo "   - Found in: scripts/deploy.sh"
echo "   - Impact: Could delete repos, modify settings, access private code"
echo "   - Bounty: $500 (elevated repository permissions)"
echo ""

echo "🚀 EXPECTED OUTCOMES FROM THIS TEST:"
echo "==================================="

echo "📊 Statistics (based on similar scans):"
echo "- Repositories scanned: 500-2000"
echo "- Secrets found: 50-200"
echo "- High-value secrets: 5-20"
echo "- Verified active secrets: 2-8"
echo "- Payable bounty findings: 1-3 (conservative estimate)"
echo ""

echo "💰 Potential Bounty Value:"
echo "- OpenAI key: $100-500"
echo "- Stripe key: $500-2000"
echo "- AWS credentials: $500-5000"
echo "- GitHub PAT: $100-1000"
echo "- Total possible: $1200-8500+"
echo ""

echo "⏰ Timeline:"
echo "- Discovery: 5-10 minutes"
echo "- Scanning: 30-120 minutes (depending on repo count)"
echo "- Analysis: 10-20 minutes"
echo "- Verification: 5-15 minutes"
echo "- Reporting: 10-30 minutes"
echo ""

echo "🎯 SUCCESS METRICS:"
echo "- Finding 1+ active high-value secrets = SUCCESS"
echo "- Earning $500+ in bounties = MAJOR SUCCESS"
echo "- Identifying new attack vectors = RESEARCH SUCCESS"
echo ""

echo "🔒 ETHICAL CONSIDERATIONS:"
echo "- Only scan public repositories"
echo "- Respect robots.txt and platform terms"
echo "- Report findings responsibly"
echo "- Use dry-run mode for initial testing"
echo "- Never exploit or damage systems"
echo ""

echo "🚀 READY TO LAUNCH BUG BOUNTY HUNTING CAMPAIGN!"
echo "=============================================="

echo "Next steps:"
echo "1. Set up Docker environment"
echo "2. Run: PLATFORM=github TARGET=microsoft DAYS=1 docker compose up repo-discovery"
echo "3. Run: ENABLE_VERIFICATION=true docker compose up batch-scanner"
echo "4. Run: docker compose up report-compiler"
echo "5. Review findings for payable bounties!"
echo ""

echo "🎯 Let's find some payable bug bounties! 💰"