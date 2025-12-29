# API Key Validation Research & Bug Bounty Programs (2025-2026)

## Overview

This document outlines services with public API validation endpoints and active bug bounty programs that pay for leaked API keys. This research is specifically focused on 2025-2026 security landscape, with emphasis on AI services and cloud infrastructure.

## 🔑 Services with Validation APIs

### AI/ML Services

#### OpenAI
- **Validation Endpoint**: `https://api.openai.com/v1/models`
- **Headers**: `Authorization: Bearer {token}`
- **Bug Bounty**: ✅ Active (Bugcrowd) - Pays for leaked keys
- **Key Format**: `sk-...` or `sess-...`
- **Test Command**:
  ```bash
  curl https://api.openai.com/v1/models \
    -H "Authorization: Bearer sk-your-key-here"
  ```

#### Anthropic/Claude
- **Validation Endpoint**: `https://api.anthropic.com/v1/messages`
- **Headers**: `x-api-key: {token}`, `anthropic-version: 2023-06-01`
- **Bug Bounty**: ✅ Active
- **Key Format**: `sk-ant-api03-...`
- **Test Command**:
  ```bash
  curl https://api.anthropic.com/v1/messages \
    -H "x-api-key: sk-ant-api03-your-key" \
    -H "anthropic-version: 2023-06-01" \
    -H "content-type: application/json" \
    -d '{"model": "claude-3-haiku-20240307", "max_tokens": 1, "messages": [{"role": "user", "content": "test"}]}'
  ```

#### OpenRouter
- **Validation Endpoint**: `https://openrouter.ai/api/v1/models`
- **Headers**: `Authorization: Bearer {token}`
- **Bug Bounty**: ❌ None
- **Key Format**: `sk-or-v1-...`
- **Test Command**:
  ```bash
  curl https://openrouter.ai/api/v1/models \
    -H "Authorization: Bearer sk-or-v1-your-key"
  ```

#### Groq
- **Validation Endpoint**: `https://api.groq.com/openai/v1/models`
- **Headers**: `Authorization: Bearer {token}`
- **Bug Bounty**: ⚠️ Limited
- **Key Format**: `gsk_...`
- **Test Command**:
  ```bash
  curl https://api.groq.com/openai/v1/models \
    -H "Authorization: Bearer gsk_your-key"
  ```

#### Perplexity
- **Validation Endpoint**: `https://api.perplexity.ai/chat/completions`
- **Headers**: `Authorization: Bearer {token}`
- **Bug Bounty**: ❌ None
- **Key Format**: `pplx-...`
- **Test Command**:
  ```bash
  curl https://api.perplexity.ai/chat/completions \
    -H "Authorization: Bearer pplx-your-key" \
    -H "Content-Type: application/json" \
    -d '{"model": "llama-3.1-sonar-small-128k-online", "messages": [{"role": "user", "content": "test"}]}'
  ```

### Cloud Providers

#### AWS
- **Validation Method**: AWS CLI/SDK calls
- **Bug Bounty**: ✅ Active (AWS Vulnerability Reporting)
- **Key Format**: Access Key ID + Secret Key
- **Test Command**:
  ```bash
  AWS_ACCESS_KEY_ID=AKIA... AWS_SECRET_ACCESS_KEY=secret aws sts get-caller-identity
  ```

#### Google Cloud
- **Validation Method**: Service account token generation
- **Bug Bounty**: ✅ Active
- **Key Format**: Service account JSON
- **Test Command**:
  ```bash
  gcloud auth activate-service-account --key-file=service-account.json
  gcloud auth print-access-token
  ```

#### Azure
- **Validation Method**: OAuth token requests
- **Bug Bounty**: ✅ Active (Microsoft Bug Bounty)
- **Key Format**: Client ID/Secret, SAS tokens
- **Test Command**:
  ```bash
  curl -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=ID&scope=https://graph.microsoft.com/.default&client_secret=SECRET&grant_type=client_credentials" \
    "https://login.microsoftonline.com/TENANT/oauth2/v2.0/token"
  ```

### DevOps/CI Platforms

#### GitHub
- **Validation Endpoint**: `https://api.github.com/user`
- **Headers**: `Authorization: token {token}`
- **Bug Bounty**: ✅ Active (GitHub Security Lab)
- **Key Format**: `ghp_...`, `github_pat_...`
- **Test Command**:
  ```bash
  curl -H "Authorization: token ghp_your_token" https://api.github.com/user
  ```

#### GitLab
- **Validation Endpoint**: `https://gitlab.com/api/v4/user`
- **Headers**: `PRIVATE-TOKEN: {token}`
- **Bug Bounty**: ✅ Active
- **Key Format**: `glpat-...`
- **Test Command**:
  ```bash
  curl --header "PRIVATE-TOKEN: glpat-your-token" https://gitlab.com/api/v4/user
  ```

#### CircleCI
- **Validation Endpoint**: `https://circleci.com/api/v1.1/me`
- **Query Params**: `circle-token={token}`
- **Bug Bounty**: ⚠️ Limited
- **Key Format**: CircleCI tokens
- **Test Command**:
  ```bash
  curl "https://circleci.com/api/v1.1/me?circle-token=your-token"
  ```

### Communication Platforms

#### Slack
- **Validation Endpoint**: `https://slack.com/api/auth.test`
- **Headers**: `Authorization: Bearer {token}`
- **Bug Bounty**: ✅ Active
- **Key Format**: `xoxb-...`, `xoxp-...`, `xapp-...`
- **Test Command**:
  ```bash
  curl -H "Authorization: Bearer xoxb-your-token" https://slack.com/api/auth.test
  ```

#### Discord
- **Validation Endpoint**: `https://discord.com/api/users/@me`
- **Headers**: `Authorization: {token}`
- **Bug Bounty**: ✅ Active
- **Key Format**: `MTA...` (base64)
- **Test Command**:
  ```bash
  curl -H "Authorization: MTAyour-token" https://discord.com/api/users/@me
  ```

### Payment Services

#### Stripe
- **Validation Endpoint**: `https://api.stripe.com/v1/charges`
- **Auth**: Basic auth with token as username
- **Bug Bounty**: ✅ Active
- **Key Format**: `sk_live_...`, `rk_live_...`
- **Test Command**:
  ```bash
  curl https://api.stripe.com/v1/charges -u sk_live_your_key:
  ```

### Monitoring/Infrastructure

#### New Relic
- **Validation Endpoint**: `https://api.newrelic.com/graphql`
- **Headers**: `API-Key: {key}`
- **Bug Bounty**: ⚠️ Limited
- **Key Format**: New Relic API keys
- **Test Command**:
  ```bash
  curl -X POST https://api.newrelic.com/graphql \
    -H "API-Key: your-key" \
    -H "Content-Type: application/json" \
    -d '{"query": "{ requestContext { userId apiKey } }"}'
  ```

#### DataDog
- **Validation Endpoint**: `https://api.datadoghq.com/api/v1/dashboard`
- **Query Params**: `api_key={key}&application_key={app_key}`
- **Bug Bounty**: ✅ Active
- **Key Format**: DataDog API keys
- **Test Command**:
  ```bash
  curl "https://api.datadoghq.com/api/v1/dashboard?api_key=your-api-key&application_key=your-app-key"
  ```

## 🏆 Bug Bounty Programs by Value

### High-Value (Pay for Leaked Keys)
1. **OpenAI** - $100-500+ per valid leaked key
2. **Stripe** - Critical financial data exposure
3. **AWS/Azure/GCP** - Cloud infrastructure compromise
4. **GitHub/GitLab** - Source code and organization access
5. **Slack** - Communication platform access

### Medium-Value
- Anthropic/Claude
- Firebase
- Twilio
- SendGrid
- MailGun
- Heroku

### Low-Value
- Travis CI
- CircleCI
- DataDog
- New Relic

## 🛠️ Validation Method Categories

### Bearer Token
```bash
curl -H "Authorization: Bearer TOKEN" https://api.service.com/endpoint
```

### Basic Auth
```bash
curl -u "username:TOKEN" https://api.service.com/endpoint
```

### Custom Headers
```bash
curl -H "X-API-Key: TOKEN" https://api.service.com/endpoint
```

### Query Parameters
```bash
curl "https://api.service.com/endpoint?api_key=TOKEN"
```

### OAuth Flows
```bash
curl -X POST -d "grant_type=client_credentials&client_id=ID&client_secret=SECRET" https://auth.service.com/token
```

## 📊 Key Statistics (2025-2026 Focus)

- **AI Services**: 5 major platforms with validation APIs
- **Cloud Providers**: 3 major platforms (AWS/GCP/Azure)
- **DevOps**: 3 major platforms (GitHub/GitLab/CircleCI)
- **Bug Bounty Programs**: 15+ active programs
- **High-Value Targets**: 8 services paying for leaked keys

## 🔗 References

- [Keyhacks Repository](https://github.com/streaak/keyhacks) - Comprehensive API key validation methods
- [OpenAI Bug Bounty](https://bugcrowd.com/openai)
- [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning)
- [GitGuardian Validation](https://docs.gitguardian.com/secrets-detection/customize-detection/validity-checks)

## 🎯 Implementation Priority

### Phase 1 (Critical)
- OpenAI (bug bounty payouts)
- AWS/GCP/Azure cloud credentials
- GitHub/GitLab tokens
- Stripe payment keys

### Phase 2 (High)
- Anthropic/Claude
- Slack/Discord
- Firebase
- Twilio

### Phase 3 (Medium)
- CircleCI/Travis CI
- DataDog/New Relic
- MailGun/SendGrid