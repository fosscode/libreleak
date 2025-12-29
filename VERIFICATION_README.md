# Secret Verification Features

## Overview

LibreLeak includes optional secret verification capabilities that can validate whether discovered API keys and tokens are still active. This feature is particularly valuable for bug bounty hunters and security researchers who need to prioritize findings.

## ⚠️ Important Security Notice

**VERIFICATION MAKES NETWORK CALLS TO EXTERNAL APIs**

- Only use with explicit authorization from system owners
- Verification may trigger security alerts or rate limiting
- Some services charge for API calls
- Never verify secrets in production environments without permission

## Compilation

Verification is a compile-time feature that must be explicitly enabled:

```bash
cargo build --release --features verify
```

Without the `verify` feature, verification functions return `NotSupported` status.

## Supported Services

### High-Priority (Bug Bounty Value)

#### OpenAI
- **Rules**: `openai-api-key`, `openai-project-key`
- **Verification**: API models endpoint
- **Bug Bounty**: ✅ Pays $100-500+ per valid leaked key

#### Anthropic/Claude
- **Rules**: `anthropic-api-key`, `claude-3-api-key`
- **Verification**: Messages API with minimal request
- **Bug Bounty**: ✅ Active program

#### GitHub
- **Rules**: `github-pat`, `github-oauth`, `github-app`, `github-refresh`
- **Verification**: User API endpoint
- **Bug Bounty**: ✅ GitHub Security Lab

### Medium-Priority

#### Cloud Providers
- **AWS**: `aws-access-key-id` (requires both key + secret)
- **GCP**: `gcp-service-account` (requires JSON parsing)
- **Azure**: `azure-sas-token` (requires SAS parsing)

#### Communication
- **Slack**: `slack-bot-token`, `slack-user-token`, `slack-app-token`
- **Discord**: `discord-bot-token`

#### Payment
- **Stripe**: `stripe-secret-key`, `stripe-restricted-key`

#### ML/AI Platforms
- **OpenRouter**: `openrouter-api-key`
- **Groq**: `groq-api-key`
- **Hugging Face**: `huggingface-token`
- **Replicate**: `replicate-token`

### DevOps & Monitoring
- **GitLab**: `gitlab-pat`, `gitlab-pipeline`, `gitlab-runner`
- **CircleCI**: `circleci-token`
- **Travis CI**: `travisci-token`
- **DataDog**: `datadog-api-key`
- **New Relic**: `newrelic-api-key`

## Usage

### Basic Verification

```rust
use libreleak::verify::verify_secret;

let result = verify_secret(&finding);
match result.status {
    VerificationStatus::Active => println!("🔴 SECRET IS ACTIVE!"),
    VerificationStatus::Inactive => println!("✅ Secret is revoked"),
    VerificationStatus::Unknown => println!("❓ Cannot determine status"),
    VerificationStatus::NotSupported => println!("🚫 No verifier for this type"),
}
```

### CLI Integration

```bash
# Build with verification support
cargo build --release --features verify

# Scan with verification (if implemented in CLI)
libreleak scan --verify /path/to/code
```

## Verification Results

### Status Types

- **`Active`**: Secret is confirmed valid and working
- **`Inactive`**: Secret is invalid, revoked, or expired
- **`Unknown`**: Cannot determine status (network error, rate limit, etc.)
- **`NotSupported`**: No verification logic for this secret type

### Response Details

Each verification result includes:
- `status`: One of the four status types above
- `message`: Human-readable explanation

## Rate Limiting & Ethics

### Rate Limiting Considerations
- **OpenAI**: 60 requests/minute free tier
- **GitHub**: 5000 requests/hour for authenticated users
- **Stripe**: No specific limits but monitor usage
- **Anthropic**: Token-based limits

### Ethical Guidelines
1. **Get Permission**: Only verify secrets with explicit authorization
2. **Respect Limits**: Implement delays between verification calls
3. **Bug Bounty Only**: Use verification for authorized testing only
4. **Cost Awareness**: Some APIs charge for usage

## Implementation Details

### HTTP Verification Pattern

Most verifiers use a common `http_verify()` function:

```rust
fn verify_service(token: &str) -> VerificationResult {
    http_verify(
        "https://api.service.com/endpoint",
        &[("Authorization", &format!("Bearer {}", token))],
    )
}
```

### Custom Verification

Services requiring complex requests use custom implementations:

- **Anthropic**: POST request with JSON body
- **Stripe**: Basic auth with token as username
- **New Relic**: GraphQL query
- **Twilio**: Account SID + Auth token combination

### Error Handling

- Network timeouts default to 30 seconds
- SSL/TLS handled by `curl` command
- Rate limit responses (429) return `Unknown` status
- Connection errors return `Unknown` status

## Extending Verification

### Adding New Services

1. Add rule ID to the match statement in `verify_secret()`
2. Implement verification function following the pattern:

```rust
#[cfg(feature = "verify")]
fn verify_new_service(token: &str) -> VerificationResult {
    http_verify(
        "https://api.newservice.com/verify",
        &[("X-API-Key", token)],
    )
}
```

3. Add test cases for the new verification function

### Testing Verification

```rust
#[test]
#[cfg(feature = "verify")]
fn test_new_service_verification() {
    let finding = Finding {
        rule_id: "new-service-key".to_string(),
        secret: "invalid_key_123".to_string(),
        // ... other fields
    };

    let result = verify_secret(&finding);
    assert_eq!(result.status, VerificationStatus::Inactive);
}
```

## Dependencies

Verification requires `curl` command to be available on the system path for TLS support. The verification code shells out to `curl` for HTTP requests.

## Future Enhancements

### Planned Features
- **Async verification** for better performance
- **Batch verification** to reduce network overhead
- **Rate limit handling** with automatic backoff
- **Proxy support** for enterprise environments
- **Custom CA certificates** for private APIs

### Advanced Verification
- **AWS STS calls** with credential validation
- **GCP service account** JSON parsing and token generation
- **Azure OAuth flows** with tenant validation
- **Multi-factor verification** (API key + secret combinations)

## Bug Bounty Integration

### High-Value Targets
1. **OpenAI keys**: $100-500+ per valid key
2. **Stripe secrets**: Critical financial impact
3. **AWS credentials**: Infrastructure compromise
4. **GitHub tokens**: Source code access
5. **Slack tokens**: Communication access

### Submission Guidelines
- Use [OpenAI's bug bounty form](https://docs.google.com/forms/d/e/1FAIpQLScki3qaI5iZuPkxVTuiP9sWmoL-6Q04HpI-NnLRfo2xx_SGgQ/viewform)
- Include verification evidence
- Only submit unique keys
- Respect responsible disclosure policies

## Troubleshooting

### Common Issues

**"NotSupported" status**
- Ensure `--features verify` was used during compilation
- Check that the rule ID is in the verification match statement

**"Network error" messages**
- Verify internet connectivity
- Check firewall/proxy settings
- Ensure `curl` command is available

**Rate limiting**
- Implement delays between verification calls
- Use different IP addresses if available
- Check service-specific rate limit documentation

**SSL/TLS errors**
- Update system CA certificates
- Use `--insecure` flag if necessary (not recommended)

---

**Remember**: Verification is a privilege that comes with responsibility. Always obtain explicit permission before verifying secrets against external APIs.