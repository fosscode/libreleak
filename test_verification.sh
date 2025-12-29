#!/bin/bash
# Test script to demonstrate verification functionality

echo "🧪 Testing LibreLeak Verification System"
echo "========================================="

# Create test file with various secrets
cat > test_secrets.py << 'EOF'
# Test file with various API keys for verification testing

# GitHub token (should be invalid)
GITHUB_TOKEN = "ghp_invalid_token_12345"

# OpenAI key (should be invalid) 
OPENAI_API_KEY = "sk-invalid-key-12345"

# Slack token (should be invalid)
SLACK_TOKEN = "xoxb-invalid-token-12345"

# Valid-looking but fake Stripe key
STRIPE_KEY = "sk_live_fake_key_for_testing"
EOF

echo "📁 Created test file with fake secrets"

# Build with verification feature
echo "🔨 Building with verification support..."
cargo build --release --features verify > /dev/null 2>&1

if [ $? -ne 0 ]; then
    echo "❌ Build failed"
    exit 1
fi

echo "✅ Build successful"

# Run verification scan
echo "🔍 Running scan with verification..."
./target/release/libreleak --verify test_secrets.py

echo ""
echo "🎯 Verification test complete!"
echo "Expected results:"
echo "- GitHub token: ❌ Inactive (invalid token)"
echo "- OpenAI key: ❌ Inactive (invalid key)"  
echo "- Slack token: ❌ Inactive (invalid token)"
echo "- Stripe key: ❌ Inactive (invalid key)"

# Cleanup
rm test_secrets.py

echo "🧹 Cleanup complete"