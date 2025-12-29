#!/bin/bash
# Test script for report compilation functionality

echo "🧪 Testing LibreLeak Report Compilation"
echo "======================================="

# Create some sample report files for testing
mkdir -p test-reports

# Sample report 1 - GitHub findings
cat > test-reports/repo1_20250115_120000.json << 'EOF'
{
  "scanner": "libreleak",
  "version": "0.1.0",
  "timestamp": "2025-01-15T12:00:00Z",
  "target": "https://github.com/example/repo1",
  "findings": [
    {
      "rule_id": "github-pat",
      "rule_name": "GitHub Personal Access Token",
      "file": "config.py",
      "line": 5,
      "secret": "ghp_1234567890123456789012345678901234567890",
      "verification_status": {
        "status": "Active",
        "message": "Secret is valid"
      }
    },
    {
      "rule_id": "openai-api-key",
      "rule_name": "OpenAI API Key",
      "file": ".env",
      "line": 10,
      "secret": "sk-123456789012345678901234567890123456789012345678",
      "verification_status": {
        "status": "Inactive",
        "message": "Secret is invalid or revoked"
      }
    }
  ]
}
EOF

# Sample report 2 - More findings
cat > test-reports/repo2_20250115_130000.json << 'EOF'
{
  "scanner": "libreleak",
  "version": "0.1.0",
  "timestamp": "2025-01-15T13:00:00Z",
  "target": "https://github.com/example/repo2",
  "findings": [
    {
      "rule_id": "stripe-secret-key",
      "rule_name": "Stripe Secret Key",
      "file": "secrets.py",
      "line": 3,
      "secret": "sk_live_TESTFAKEKEYTESTFAKEKEYTESTFAKEKEYTESTFAKEKEY00",
      "verification_status": {
        "status": "Active",
        "message": "Stripe key is valid"
      }
    }
  ]
}
EOF

echo "📁 Created sample report files"

# Build the Docker image
echo "🔨 Building Docker image..."
docker build -t libreleak:test . > /dev/null 2>&1

if [ $? -ne 0 ]; then
    echo "❌ Build failed"
    exit 1
fi

echo "✅ Build successful"

# Test report compilation
echo "📊 Testing report compilation..."
docker run --rm -v $(pwd)/test-reports:/reports:ro -v $(pwd)/compiled-reports:/compiled-reports libreleak:test python /usr/local/bin/compile-reports.py --format markdown /reports

if [ $? -ne 0 ]; then
    echo "❌ Report compilation failed"
    exit 1
fi

echo "✅ Report compilation successful"

# Check if report was generated
if [ -f "compiled-reports/security-research-report-*.md" ]; then
    echo "📄 Report generated successfully"
    ls -la compiled-reports/
else
    echo "❌ Report file not found"
    exit 1
fi

# Test bug bounty reporting (dry run)
echo "🏆 Testing bug bounty reporting (dry run)..."
docker run --rm -v $(pwd)/test-reports:/reports:ro -v $(pwd)/bounty-reports:/bounty-reports libreleak:test python /usr/local/bin/report-bounties.py --dry-run /reports

if [ $? -ne 0 ]; then
    echo "❌ Bug bounty reporting failed"
    exit 1
fi

echo "✅ Bug bounty reporting successful"

echo ""
echo "🎯 All tests passed! Report compilation and bug bounty reporting are working."
echo ""
echo "📊 Generated Reports:"
ls -la compiled-reports/ 2>/dev/null || echo "No compiled reports"
ls -la bounty-reports/ 2>/dev/null || echo "No bounty reports"

# Cleanup
rm -rf test-reports compiled-reports bounty-reports 2>/dev/null || true

echo "🧹 Cleanup complete"