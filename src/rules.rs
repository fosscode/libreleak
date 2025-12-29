#![allow(dead_code)]

//! Detection rules for secrets
//!
//! Zero dependencies - all pattern matching is hand-rolled for full auditability.

pub struct Rule {
    pub id: &'static str,
    pub name: &'static str,
    pub detector: Detector,
}

pub enum Detector {
    Prefix {
        prefix: &'static str,
        min_len: usize,
        charset: Charset,
    },
    Contains {
        needle: &'static str,
    },
    KeyValue {
        keys: &'static [&'static str],
        min_value_len: usize,
    },
    /// Detect endpoints/URLs in config (for local AI services)
    Endpoint {
        keys: &'static [&'static str],
        patterns: &'static [&'static str],
    },
}

#[derive(Clone, Copy)]
pub enum Charset {
    AlphaNum,
    AlphaNumDash,
    Base64,
    Hex,
    /// URL-safe characters
    Url,
}

impl Charset {
    pub fn matches(self, c: char) -> bool {
        match self {
            Charset::AlphaNum => c.is_ascii_alphanumeric(),
            Charset::AlphaNumDash => c.is_ascii_alphanumeric() || c == '_' || c == '-',
            Charset::Base64 => {
                c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '.'
            }
            Charset::Hex => c.is_ascii_hexdigit(),
            Charset::Url => {
                c.is_ascii_alphanumeric()
                    || matches!(
                        c,
                        '-' | '_'
                            | '.'
                            | '~'
                            | ':'
                            | '/'
                            | '?'
                            | '#'
                            | '['
                            | ']'
                            | '@'
                            | '!'
                            | '$'
                            | '&'
                            | '\''
                            | '('
                            | ')'
                            | '*'
                            | '+'
                            | ','
                            | ';'
                            | '='
                            | '%'
                    )
            }
        }
    }
}

pub fn load_rules() -> Result<Vec<Rule>, Box<dyn std::error::Error>> {
    Ok(builtin_rules())
}

pub fn builtin_rules() -> Vec<Rule> {
    vec![
        // === AWS ===
        Rule {
            id: "aws-access-key-id",
            name: "AWS Access Key ID",
            detector: Detector::Prefix {
                prefix: "AKIA",
                min_len: 20,
                charset: Charset::AlphaNum,
            },
        },
        Rule {
            id: "aws-secret-key",
            name: "AWS Secret Access Key",
            detector: Detector::KeyValue {
                keys: &["aws_secret_access_key", "aws_secret_key", "AWS_SECRET"],
                min_value_len: 40,
            },
        },
        // === GitHub ===
        Rule {
            id: "github-pat",
            name: "GitHub Personal Access Token",
            detector: Detector::Prefix {
                prefix: "ghp_",
                min_len: 40,
                charset: Charset::AlphaNum,
            },
        },
        Rule {
            id: "github-oauth",
            name: "GitHub OAuth Access Token",
            detector: Detector::Prefix {
                prefix: "gho_",
                min_len: 40,
                charset: Charset::AlphaNum,
            },
        },
        Rule {
            id: "github-app",
            name: "GitHub App Token",
            detector: Detector::Prefix {
                prefix: "ghu_",
                min_len: 40,
                charset: Charset::AlphaNum,
            },
        },
        Rule {
            id: "github-refresh",
            name: "GitHub Refresh Token",
            detector: Detector::Prefix {
                prefix: "ghr_",
                min_len: 40,
                charset: Charset::AlphaNum,
            },
        },
        Rule {
            id: "github-fine-grained",
            name: "GitHub Fine-Grained PAT",
            detector: Detector::Prefix {
                prefix: "github_pat_",
                min_len: 80,
                charset: Charset::AlphaNum,
            },
        },
        // === GitLab ===
        Rule {
            id: "gitlab-pat",
            name: "GitLab Personal Access Token",
            detector: Detector::Prefix {
                prefix: "glpat-",
                min_len: 26,
                charset: Charset::AlphaNumDash,
            },
        },
        Rule {
            id: "gitlab-pipeline",
            name: "GitLab Pipeline Token",
            detector: Detector::Prefix {
                prefix: "glptt-",
                min_len: 26,
                charset: Charset::AlphaNumDash,
            },
        },
        Rule {
            id: "gitlab-runner",
            name: "GitLab Runner Token",
            detector: Detector::Prefix {
                prefix: "glrt-",
                min_len: 26,
                charset: Charset::AlphaNumDash,
            },
        },
        // === Google / GCP ===
        Rule {
            id: "gcp-api-key",
            name: "Google Cloud API Key",
            detector: Detector::Prefix {
                prefix: "AIza",
                min_len: 39,
                charset: Charset::AlphaNumDash,
            },
        },
        // === Google Gemini (TruffleHog gap) ===
        Rule {
            id: "gemini-api-key",
            name: "Google Gemini API Key",
            detector: Detector::Prefix {
                prefix: "AIza",
                min_len: 39,
                charset: Charset::AlphaNumDash,
            },
        },
        // === OpenRouter (TruffleHog gap) ===
        Rule {
            id: "openrouter-api-key",
            name: "OpenRouter API Key",
            detector: Detector::Prefix {
                prefix: "sk-or-v1-",
                min_len: 64,
                charset: Charset::AlphaNum,
            },
        },
        // === OpenAI ===
        Rule {
            id: "openai-api-key",
            name: "OpenAI API Key",
            detector: Detector::Prefix {
                prefix: "sk-",
                min_len: 48,
                charset: Charset::AlphaNumDash,
            },
        },
        Rule {
            id: "openai-project-key",
            name: "OpenAI Project API Key",
            detector: Detector::Prefix {
                prefix: "sk-proj-",
                min_len: 48,
                charset: Charset::AlphaNumDash,
            },
        },
        // === Anthropic / Claude ===
        Rule {
            id: "anthropic-api-key",
            name: "Anthropic API Key",
            detector: Detector::Prefix {
                prefix: "sk-ant-",
                min_len: 40,
                charset: Charset::AlphaNumDash,
            },
        },
        Rule {
            id: "anthropic-api-key-env",
            name: "Anthropic API Key (env)",
            detector: Detector::KeyValue {
                keys: &[
                    "ANTHROPIC_API_KEY",
                    "CLAUDE_API_KEY",
                    "anthropic_api_key",
                    "claude_api_key",
                ],
                min_value_len: 40,
            },
        },
        // === xAI / Grok ===
        Rule {
            id: "xai-api-key",
            name: "xAI API Key",
            detector: Detector::Prefix {
                prefix: "xai-",
                min_len: 40,
                charset: Charset::AlphaNumDash,
            },
        },
        Rule {
            id: "xai-api-key-env",
            name: "xAI API Key (env)",
            detector: Detector::KeyValue {
                keys: &["XAI_API_KEY", "GROK_API_KEY", "xai_api_key", "grok_api_key"],
                min_value_len: 40,
            },
        },
        // === Mistral ===
        Rule {
            id: "mistral-api-key",
            name: "Mistral API Key",
            detector: Detector::KeyValue {
                keys: &["MISTRAL_API_KEY", "mistral_api_key"],
                min_value_len: 32,
            },
        },
        // === Perplexity ===
        Rule {
            id: "perplexity-api-key",
            name: "Perplexity API Key",
            detector: Detector::Prefix {
                prefix: "pplx-",
                min_len: 48,
                charset: Charset::AlphaNum,
            },
        },
        Rule {
            id: "perplexity-api-key-env",
            name: "Perplexity API Key (env)",
            detector: Detector::KeyValue {
                keys: &["PERPLEXITY_API_KEY", "PPLX_API_KEY", "perplexity_api_key"],
                min_value_len: 40,
            },
        },
        // === Fireworks AI ===
        Rule {
            id: "fireworks-api-key",
            name: "Fireworks AI API Key",
            detector: Detector::Prefix {
                prefix: "fw_",
                min_len: 40,
                charset: Charset::AlphaNumDash,
            },
        },
        Rule {
            id: "fireworks-api-key-env",
            name: "Fireworks AI API Key (env)",
            detector: Detector::KeyValue {
                keys: &["FIREWORKS_API_KEY", "fireworks_api_key"],
                min_value_len: 40,
            },
        },
        // === DeepSeek ===
        Rule {
            id: "deepseek-api-key",
            name: "DeepSeek API Key",
            detector: Detector::Prefix {
                prefix: "sk-",
                min_len: 32,
                charset: Charset::AlphaNum,
            },
        },
        Rule {
            id: "deepseek-api-key-env",
            name: "DeepSeek API Key (env)",
            detector: Detector::KeyValue {
                keys: &["DEEPSEEK_API_KEY", "deepseek_api_key"],
                min_value_len: 32,
            },
        },
        // === Cerebras ===
        Rule {
            id: "cerebras-api-key",
            name: "Cerebras API Key",
            detector: Detector::Prefix {
                prefix: "csk-",
                min_len: 40,
                charset: Charset::AlphaNumDash,
            },
        },
        // === SambaNova ===
        Rule {
            id: "sambanova-api-key",
            name: "SambaNova API Key",
            detector: Detector::KeyValue {
                keys: &["SAMBANOVA_API_KEY", "sambanova_api_key"],
                min_value_len: 32,
            },
        },
        // === AI21 ===
        Rule {
            id: "ai21-api-key",
            name: "AI21 API Key",
            detector: Detector::KeyValue {
                keys: &["AI21_API_KEY", "ai21_api_key"],
                min_value_len: 32,
            },
        },
        // === Voyage AI ===
        Rule {
            id: "voyage-api-key",
            name: "Voyage AI API Key",
            detector: Detector::Prefix {
                prefix: "pa-",
                min_len: 40,
                charset: Charset::AlphaNumDash,
            },
        },
        // === Anyscale ===
        Rule {
            id: "anyscale-api-key",
            name: "Anyscale API Key",
            detector: Detector::Prefix {
                prefix: "esecret_",
                min_len: 40,
                charset: Charset::AlphaNumDash,
            },
        },
        // === Slack ===
        Rule {
            id: "slack-bot-token",
            name: "Slack Bot Token",
            detector: Detector::Prefix {
                prefix: "xoxb-",
                min_len: 50,
                charset: Charset::AlphaNumDash,
            },
        },
        Rule {
            id: "slack-user-token",
            name: "Slack User Token",
            detector: Detector::Prefix {
                prefix: "xoxp-",
                min_len: 50,
                charset: Charset::AlphaNumDash,
            },
        },
        Rule {
            id: "slack-app-token",
            name: "Slack App Token",
            detector: Detector::Prefix {
                prefix: "xapp-",
                min_len: 50,
                charset: Charset::AlphaNumDash,
            },
        },
        // === Stripe ===
        Rule {
            id: "stripe-secret-key",
            name: "Stripe Secret Key",
            detector: Detector::Prefix {
                prefix: "sk_live_",
                min_len: 32,
                charset: Charset::AlphaNum,
            },
        },
        Rule {
            id: "stripe-restricted-key",
            name: "Stripe Restricted Key",
            detector: Detector::Prefix {
                prefix: "rk_live_",
                min_len: 32,
                charset: Charset::AlphaNum,
            },
        },
        // === Twilio ===
        Rule {
            id: "twilio-api-key",
            name: "Twilio API Key",
            detector: Detector::Prefix {
                prefix: "SK",
                min_len: 34,
                charset: Charset::AlphaNum,
            },
        },
        // === SendGrid ===
        Rule {
            id: "sendgrid-api-key",
            name: "SendGrid API Key",
            detector: Detector::Prefix {
                prefix: "SG.",
                min_len: 69,
                charset: Charset::Base64,
            },
        },
        // === npm ===
        Rule {
            id: "npm-token",
            name: "npm Access Token",
            detector: Detector::Prefix {
                prefix: "npm_",
                min_len: 36,
                charset: Charset::AlphaNum,
            },
        },
        // === PyPI ===
        Rule {
            id: "pypi-token",
            name: "PyPI API Token",
            detector: Detector::Prefix {
                prefix: "pypi-",
                min_len: 50,
                charset: Charset::AlphaNumDash,
            },
        },
        // === Discord ===
        Rule {
            id: "discord-bot-token",
            name: "Discord Bot Token",
            detector: Detector::Prefix {
                prefix: "MTA",
                min_len: 59,
                charset: Charset::Base64,
            },
        },
        Rule {
            id: "discord-bot-token-mti",
            name: "Discord Bot Token (MTI)",
            detector: Detector::Prefix {
                prefix: "MTI",
                min_len: 59,
                charset: Charset::Base64,
            },
        },
        // ============================================================
        // HIGH-VALUE BUG BOUNTY TARGETS (2024-2025)
        // Services with active bug bounty programs paying for leaked creds
        // ============================================================

        // === Shopify (up to $50k bounties) ===
        Rule {
            id: "shopify-access-token",
            name: "Shopify Access Token",
            detector: Detector::Prefix {
                prefix: "shpat_",
                min_len: 38,
                charset: Charset::AlphaNum,
            },
        },
        Rule {
            id: "shopify-custom-app-token",
            name: "Shopify Custom App Token",
            detector: Detector::Prefix {
                prefix: "shpca_",
                min_len: 38,
                charset: Charset::AlphaNum,
            },
        },
        Rule {
            id: "shopify-private-app-token",
            name: "Shopify Private App Token",
            detector: Detector::Prefix {
                prefix: "shppa_",
                min_len: 38,
                charset: Charset::AlphaNum,
            },
        },
        Rule {
            id: "shopify-shared-secret",
            name: "Shopify Shared Secret",
            detector: Detector::Prefix {
                prefix: "shpss_",
                min_len: 38,
                charset: Charset::AlphaNum,
            },
        },
        // === Databricks (enterprise data platform) ===
        Rule {
            id: "databricks-pat",
            name: "Databricks Personal Access Token",
            detector: Detector::Prefix {
                prefix: "dapi",
                min_len: 32,
                charset: Charset::AlphaNum,
            },
        },
        // === Telegram ===
        Rule {
            id: "telegram-bot-token",
            name: "Telegram Bot Token",
            detector: Detector::KeyValue {
                keys: &[
                    "TELEGRAM_BOT_TOKEN",
                    "TELEGRAM_TOKEN",
                    "telegram_bot_token",
                    "telegram_token",
                    "BOT_TOKEN",
                ],
                min_value_len: 40,
            },
        },
        // === Mailgun ===
        Rule {
            id: "mailgun-api-key",
            name: "Mailgun API Key",
            detector: Detector::KeyValue {
                keys: &["MAILGUN_API_KEY", "MAILGUN_KEY", "mailgun_api_key"],
                min_value_len: 32,
            },
        },
        // === Square (payment processing) ===
        Rule {
            id: "square-access-token",
            name: "Square Access Token",
            detector: Detector::Prefix {
                prefix: "EAAAE",
                min_len: 50,
                charset: Charset::AlphaNumDash,
            },
        },
        Rule {
            id: "square-access-token-sandbox",
            name: "Square Sandbox Access Token",
            detector: Detector::Prefix {
                prefix: "EAAAl",
                min_len: 50,
                charset: Charset::AlphaNumDash,
            },
        },
        // === PayPal ===
        Rule {
            id: "paypal-client-id",
            name: "PayPal Client ID",
            detector: Detector::KeyValue {
                keys: &["PAYPAL_CLIENT_ID", "PAYPAL_CLIENTID", "paypal_client_id"],
                min_value_len: 20,
            },
        },
        Rule {
            id: "paypal-secret",
            name: "PayPal Client Secret",
            detector: Detector::KeyValue {
                keys: &["PAYPAL_SECRET", "PAYPAL_CLIENT_SECRET", "paypal_secret"],
                min_value_len: 20,
            },
        },
        // === Datadog (observability platform) ===
        Rule {
            id: "datadog-api-key",
            name: "Datadog API Key",
            detector: Detector::KeyValue {
                keys: &["DD_API_KEY", "DATADOG_API_KEY", "datadog_api_key"],
                min_value_len: 32,
            },
        },
        Rule {
            id: "datadog-app-key",
            name: "Datadog Application Key",
            detector: Detector::KeyValue {
                keys: &["DD_APP_KEY", "DATADOG_APP_KEY", "datadog_app_key"],
                min_value_len: 40,
            },
        },
        // === New Relic ===
        Rule {
            id: "newrelic-api-key",
            name: "New Relic API Key",
            detector: Detector::Prefix {
                prefix: "NRAK-",
                min_len: 32,
                charset: Charset::AlphaNum,
            },
        },
        Rule {
            id: "newrelic-license-key",
            name: "New Relic License Key",
            detector: Detector::KeyValue {
                keys: &[
                    "NEW_RELIC_LICENSE_KEY",
                    "NEWRELIC_LICENSE_KEY",
                    "newrelic_license_key",
                ],
                min_value_len: 40,
            },
        },
        // === Vercel ===
        Rule {
            id: "vercel-api-token",
            name: "Vercel API Token",
            detector: Detector::KeyValue {
                keys: &["VERCEL_TOKEN", "VERCEL_API_TOKEN", "vercel_token"],
                min_value_len: 24,
            },
        },
        // === Supabase ===
        Rule {
            id: "supabase-anon-key",
            name: "Supabase Anon Key",
            detector: Detector::KeyValue {
                keys: &[
                    "SUPABASE_ANON_KEY",
                    "SUPABASE_KEY",
                    "supabase_anon_key",
                    "NEXT_PUBLIC_SUPABASE_ANON_KEY",
                ],
                min_value_len: 30,
            },
        },
        Rule {
            id: "supabase-service-key",
            name: "Supabase Service Role Key",
            detector: Detector::KeyValue {
                keys: &[
                    "SUPABASE_SERVICE_ROLE_KEY",
                    "SUPABASE_SERVICE_KEY",
                    "supabase_service_role_key",
                ],
                min_value_len: 30,
            },
        },
        // === PlanetScale ===
        Rule {
            id: "planetscale-password",
            name: "PlanetScale Database Password",
            detector: Detector::Prefix {
                prefix: "pscale_pw_",
                min_len: 40,
                charset: Charset::AlphaNum,
            },
        },
        Rule {
            id: "planetscale-token",
            name: "PlanetScale OAuth Token",
            detector: Detector::Prefix {
                prefix: "pscale_tkn_",
                min_len: 40,
                charset: Charset::AlphaNum,
            },
        },
        // === Cloudflare ===
        Rule {
            id: "cloudflare-api-token",
            name: "Cloudflare API Token",
            detector: Detector::KeyValue {
                keys: &[
                    "CLOUDFLARE_API_TOKEN",
                    "CF_API_TOKEN",
                    "cloudflare_api_token",
                ],
                min_value_len: 40,
            },
        },
        Rule {
            id: "cloudflare-api-key",
            name: "Cloudflare API Key",
            detector: Detector::KeyValue {
                keys: &["CLOUDFLARE_API_KEY", "CF_API_KEY", "cloudflare_api_key"],
                min_value_len: 37,
            },
        },
        // === Linear (project management) ===
        Rule {
            id: "linear-api-key",
            name: "Linear API Key",
            detector: Detector::Prefix {
                prefix: "lin_api_",
                min_len: 40,
                charset: Charset::AlphaNum,
            },
        },
        // === Notion ===
        Rule {
            id: "notion-integration-token",
            name: "Notion Integration Token",
            detector: Detector::Prefix {
                prefix: "secret_",
                min_len: 43,
                charset: Charset::AlphaNum,
            },
        },
        // === Airtable ===
        Rule {
            id: "airtable-api-key",
            name: "Airtable API Key",
            detector: Detector::Prefix {
                prefix: "pat",
                min_len: 50,
                charset: Charset::AlphaNumDash,
            },
        },
        // === Asana ===
        Rule {
            id: "asana-pat",
            name: "Asana Personal Access Token",
            detector: Detector::KeyValue {
                keys: &["ASANA_ACCESS_TOKEN", "ASANA_PAT", "asana_access_token"],
                min_value_len: 32,
            },
        },
        // === Figma ===
        Rule {
            id: "figma-pat",
            name: "Figma Personal Access Token",
            detector: Detector::Prefix {
                prefix: "figd_",
                min_len: 40,
                charset: Charset::AlphaNumDash,
            },
        },
        // === CircleCI ===
        Rule {
            id: "circleci-token",
            name: "CircleCI API Token",
            detector: Detector::KeyValue {
                keys: &["CIRCLECI_TOKEN", "CIRCLE_TOKEN", "circleci_token"],
                min_value_len: 40,
            },
        },
        // === Travis CI ===
        Rule {
            id: "travis-ci-token",
            name: "Travis CI Token",
            detector: Detector::KeyValue {
                keys: &["TRAVIS_TOKEN", "TRAVIS_API_TOKEN", "travis_token"],
                min_value_len: 20,
            },
        },
        // === Heroku ===
        Rule {
            id: "heroku-api-key",
            name: "Heroku API Key",
            detector: Detector::KeyValue {
                keys: &["HEROKU_API_KEY", "HEROKU_TOKEN", "heroku_api_key"],
                min_value_len: 32,
            },
        },
        // === DigitalOcean ===
        Rule {
            id: "digitalocean-token",
            name: "DigitalOcean API Token",
            detector: Detector::Prefix {
                prefix: "dop_v1_",
                min_len: 64,
                charset: Charset::AlphaNum,
            },
        },
        Rule {
            id: "digitalocean-pat",
            name: "DigitalOcean Personal Access Token",
            detector: Detector::Prefix {
                prefix: "doo_v1_",
                min_len: 64,
                charset: Charset::AlphaNum,
            },
        },
        Rule {
            id: "digitalocean-refresh-token",
            name: "DigitalOcean Refresh Token",
            detector: Detector::Prefix {
                prefix: "dor_v1_",
                min_len: 64,
                charset: Charset::AlphaNum,
            },
        },
        // === Doppler (secrets management) ===
        Rule {
            id: "doppler-api-token",
            name: "Doppler API Token",
            detector: Detector::Prefix {
                prefix: "dp.pt.",
                min_len: 40,
                charset: Charset::AlphaNum,
            },
        },
        // === Algolia ===
        Rule {
            id: "algolia-api-key",
            name: "Algolia API Key",
            detector: Detector::KeyValue {
                keys: &["ALGOLIA_API_KEY", "ALGOLIA_ADMIN_KEY", "algolia_api_key"],
                min_value_len: 32,
            },
        },
        // === Mapbox ===
        Rule {
            id: "mapbox-access-token",
            name: "Mapbox Access Token",
            detector: Detector::Prefix {
                prefix: "pk.eyJ",
                min_len: 80,
                charset: Charset::Base64,
            },
        },
        Rule {
            id: "mapbox-secret-token",
            name: "Mapbox Secret Token",
            detector: Detector::Prefix {
                prefix: "sk.eyJ",
                min_len: 80,
                charset: Charset::Base64,
            },
        },
        // === Age Encryption (modern encryption tool) ===
        Rule {
            id: "age-secret-key",
            name: "Age Secret Key",
            detector: Detector::Prefix {
                prefix: "AGE-SECRET-KEY-",
                min_len: 59,
                charset: Charset::AlphaNum,
            },
        },
        // === Hugging Face ===
        Rule {
            id: "huggingface-token",
            name: "Hugging Face Token",
            detector: Detector::Prefix {
                prefix: "hf_",
                min_len: 37,
                charset: Charset::AlphaNum,
            },
        },
        // === Replicate ===
        Rule {
            id: "replicate-token",
            name: "Replicate API Token",
            detector: Detector::Prefix {
                prefix: "r8_",
                min_len: 40,
                charset: Charset::AlphaNum,
            },
        },
        // === Together AI ===
        Rule {
            id: "together-api-key",
            name: "Together AI API Key",
            detector: Detector::KeyValue {
                keys: &["TOGETHER_API_KEY", "together_api_key"],
                min_value_len: 40,
            },
        },
        // === Groq ===
        Rule {
            id: "groq-api-key",
            name: "Groq API Key",
            detector: Detector::Prefix {
                prefix: "gsk_",
                min_len: 52,
                charset: Charset::AlphaNum,
            },
        },
        // === Emerging AI Providers (2025-2026) ===
        Rule {
            id: "claude-3-api-key",
            name: "Claude 3.x API Key",
            detector: Detector::Prefix {
                prefix: "sk-ant-api03-",
                min_len: 108,
                charset: Charset::AlphaNumDash,
            },
        },
        Rule {
            id: "grok-2-api-key",
            name: "Grok-2 API Key",
            detector: Detector::Prefix {
                prefix: "xai-grok2-",
                min_len: 64,
                charset: Charset::AlphaNumDash,
            },
        },
        Rule {
            id: "gpt-5-api-key",
            name: "GPT-5 API Key",
            detector: Detector::Prefix {
                prefix: "sk-gpt5-",
                min_len: 64,
                charset: Charset::AlphaNumDash,
            },
        },
        Rule {
            id: "gemini-ultra-api-key",
            name: "Gemini Ultra API Key",
            detector: Detector::Prefix {
                prefix: "AIzaSy",
                min_len: 39,
                charset: Charset::AlphaNumDash,
            },
        },
        Rule {
            id: "midjourney-v6-api-key",
            name: "Midjourney V6 API Key",
            detector: Detector::Prefix {
                prefix: "mj-",
                min_len: 40,
                charset: Charset::AlphaNumDash,
            },
        },
        Rule {
            id: "stability-ai-v3-key",
            name: "Stability AI V3 API Key",
            detector: Detector::Prefix {
                prefix: "sk-stability-",
                min_len: 64,
                charset: Charset::AlphaNumDash,
            },
        },
        // === Cohere ===
        Rule {
            id: "cohere-api-key",
            name: "Cohere API Key",
            detector: Detector::KeyValue {
                keys: &["COHERE_API_KEY", "cohere_api_key", "CO_API_KEY"],
                min_value_len: 40,
            },
        },
        // === Database connection strings ===
        Rule {
            id: "postgres-uri",
            name: "PostgreSQL Connection URI",
            detector: Detector::Prefix {
                prefix: "postgres://",
                min_len: 20,
                charset: Charset::Url,
            },
        },
        Rule {
            id: "postgresql-uri",
            name: "PostgreSQL Connection URI",
            detector: Detector::Prefix {
                prefix: "postgresql://",
                min_len: 20,
                charset: Charset::Url,
            },
        },
        Rule {
            id: "mysql-uri",
            name: "MySQL Connection URI",
            detector: Detector::Prefix {
                prefix: "mysql://",
                min_len: 15,
                charset: Charset::Url,
            },
        },
        Rule {
            id: "mongodb-uri",
            name: "MongoDB Connection URI",
            detector: Detector::Prefix {
                prefix: "mongodb://",
                min_len: 20,
                charset: Charset::Url,
            },
        },
        Rule {
            id: "mongodb-srv-uri",
            name: "MongoDB SRV Connection URI",
            detector: Detector::Prefix {
                prefix: "mongodb+srv://",
                min_len: 20,
                charset: Charset::Url,
            },
        },
        Rule {
            id: "redis-uri",
            name: "Redis Connection URI",
            detector: Detector::Prefix {
                prefix: "redis://",
                min_len: 15,
                charset: Charset::Url,
            },
        },
        // === Private Keys ===
        Rule {
            id: "private-key-rsa",
            name: "RSA Private Key",
            detector: Detector::Contains {
                needle: "-----BEGIN RSA PRIVATE KEY-----",
            },
        },
        Rule {
            id: "private-key-openssh",
            name: "OpenSSH Private Key",
            detector: Detector::Contains {
                needle: "-----BEGIN OPENSSH PRIVATE KEY-----",
            },
        },
        Rule {
            id: "private-key-ec",
            name: "EC Private Key",
            detector: Detector::Contains {
                needle: "-----BEGIN EC PRIVATE KEY-----",
            },
        },
        Rule {
            id: "private-key-generic",
            name: "Private Key",
            detector: Detector::Contains {
                needle: "-----BEGIN PRIVATE KEY-----",
            },
        },
        // === Generic patterns ===
        Rule {
            id: "generic-api-key",
            name: "Generic API Key",
            detector: Detector::KeyValue {
                keys: &["api_key", "api-key", "apikey", "API_KEY", "APIKEY"],
                min_value_len: 20,
            },
        },
        Rule {
            id: "generic-secret",
            name: "Generic Secret",
            detector: Detector::KeyValue {
                keys: &["secret", "secret_key", "secret-key", "SECRET", "SECRET_KEY"],
                min_value_len: 20,
            },
        },
        Rule {
            id: "generic-password",
            name: "Password in Config",
            detector: Detector::KeyValue {
                keys: &["password", "PASSWORD", "passwd", "PASSWD"],
                min_value_len: 8,
            },
        },
        Rule {
            id: "generic-token",
            name: "Generic Token",
            detector: Detector::KeyValue {
                keys: &[
                    "token",
                    "TOKEN",
                    "access_token",
                    "ACCESS_TOKEN",
                    "auth_token",
                    "AUTH_TOKEN",
                ],
                min_value_len: 20,
            },
        },
        // === JDBC (context-aware) ===
        Rule {
            id: "jdbc-connection",
            name: "JDBC Connection String",
            detector: Detector::Prefix {
                prefix: "jdbc:",
                min_len: 20,
                charset: Charset::Url,
            },
        },
        // ============================================================
        // LOCAL AI INFERENCE ENDPOINTS
        // These may expose local services or contain embedded credentials
        // ============================================================

        // === Ollama ===
        Rule {
            id: "ollama-endpoint",
            name: "Ollama API Endpoint",
            detector: Detector::Endpoint {
                keys: &[
                    "OLLAMA_HOST",
                    "OLLAMA_BASE_URL",
                    "OLLAMA_API_BASE",
                    "ollama_host",
                    "ollama_url",
                ],
                patterns: &[":11434", "localhost:11434", "127.0.0.1:11434"],
            },
        },
        Rule {
            id: "ollama-api-key",
            name: "Ollama API Key",
            detector: Detector::KeyValue {
                keys: &["OLLAMA_API_KEY", "ollama_api_key"],
                min_value_len: 16,
            },
        },
        // === LM Studio ===
        Rule {
            id: "lmstudio-endpoint",
            name: "LM Studio API Endpoint",
            detector: Detector::Endpoint {
                keys: &[
                    "LMSTUDIO_HOST",
                    "LMSTUDIO_BASE_URL",
                    "LM_STUDIO_URL",
                    "lmstudio_host",
                ],
                patterns: &[":1234", "localhost:1234", "127.0.0.1:1234"],
            },
        },
        Rule {
            id: "lmstudio-api-key",
            name: "LM Studio API Key",
            detector: Detector::KeyValue {
                keys: &["LMSTUDIO_API_KEY", "LM_STUDIO_API_KEY", "lmstudio_api_key"],
                min_value_len: 16,
            },
        },
        // === Exo (distributed inference) ===
        Rule {
            id: "exo-endpoint",
            name: "Exo API Endpoint",
            detector: Detector::Endpoint {
                keys: &[
                    "EXO_HOST",
                    "EXO_BASE_URL",
                    "EXO_API_BASE",
                    "exo_host",
                    "exo_url",
                ],
                patterns: &[":52415", "localhost:52415", "127.0.0.1:52415"],
            },
        },
        Rule {
            id: "exo-api-key",
            name: "Exo API Key",
            detector: Detector::KeyValue {
                keys: &["EXO_API_KEY", "exo_api_key"],
                min_value_len: 16,
            },
        },
        // === LocalAI ===
        Rule {
            id: "localai-endpoint",
            name: "LocalAI API Endpoint",
            detector: Detector::Endpoint {
                keys: &[
                    "LOCALAI_HOST",
                    "LOCALAI_BASE_URL",
                    "LOCAL_AI_URL",
                    "localai_host",
                ],
                patterns: &[":8080/v1", "localhost:8080"],
            },
        },
        Rule {
            id: "localai-api-key",
            name: "LocalAI API Key",
            detector: Detector::KeyValue {
                keys: &["LOCALAI_API_KEY", "localai_api_key"],
                min_value_len: 16,
            },
        },
        // === vLLM ===
        Rule {
            id: "vllm-endpoint",
            name: "vLLM API Endpoint",
            detector: Detector::Endpoint {
                keys: &["VLLM_HOST", "VLLM_BASE_URL", "vllm_host", "vllm_url"],
                patterns: &[":8000/v1", "localhost:8000"],
            },
        },
        Rule {
            id: "vllm-api-key",
            name: "vLLM API Key",
            detector: Detector::KeyValue {
                keys: &["VLLM_API_KEY", "vllm_api_key"],
                min_value_len: 16,
            },
        },
        // === Text Generation Inference (TGI) ===
        Rule {
            id: "tgi-endpoint",
            name: "TGI API Endpoint",
            detector: Detector::Endpoint {
                keys: &["TGI_HOST", "TGI_BASE_URL", "tgi_host", "tgi_url"],
                patterns: &[":8080/generate", ":80/generate"],
            },
        },
        // === llama.cpp server ===
        Rule {
            id: "llamacpp-endpoint",
            name: "llama.cpp Server Endpoint",
            detector: Detector::Endpoint {
                keys: &["LLAMA_HOST", "LLAMA_CPP_HOST", "LLAMACPP_URL", "llama_host"],
                patterns: &[":8080/completion", ":8080/v1"],
            },
        },
        // === Kobold ===
        Rule {
            id: "kobold-endpoint",
            name: "KoboldAI/KoboldCpp Endpoint",
            detector: Detector::Endpoint {
                keys: &["KOBOLD_HOST", "KOBOLD_URL", "kobold_host"],
                patterns: &[":5001", "localhost:5001", ":5000/api"],
            },
        },
        // === OpenAI-compatible endpoints (catch-all) ===
        Rule {
            id: "openai-base-url",
            name: "OpenAI Base URL Override",
            detector: Detector::KeyValue {
                keys: &[
                    "OPENAI_BASE_URL",
                    "OPENAI_API_BASE",
                    "openai_base_url",
                    "openai_api_base",
                ],
                min_value_len: 10,
            },
        },
        // ============================================================
        // WEB3 / BLOCKCHAIN KEYS (2025-2026)
        // ============================================================

        // === Ethereum ===
        Rule {
            id: "ethereum-private-key",
            name: "Ethereum Private Key",
            detector: Detector::KeyValue {
                keys: &[
                    "ETHEREUM_PRIVATE_KEY",
                    "ETH_PRIVATE_KEY",
                    "PRIVATE_KEY",
                    "ethereum_private_key",
                ],
                min_value_len: 64,
            },
        },
        Rule {
            id: "ethereum-mnemonic",
            name: "Ethereum/BIP39 Mnemonic",
            detector: Detector::KeyValue {
                keys: &[
                    "MNEMONIC",
                    "SEED_PHRASE",
                    "WALLET_MNEMONIC",
                    "mnemonic",
                    "seed_phrase",
                ],
                min_value_len: 50,
            },
        },
        // === Solana ===
        Rule {
            id: "solana-private-key",
            name: "Solana Private Key",
            detector: Detector::Contains { needle: "solana" },
        },
        Rule {
            id: "solana-keypair-json",
            name: "Solana Keypair JSON",
            detector: Detector::KeyValue {
                keys: &["SOLANA_KEYPAIR", "SOLANA_PRIVATE_KEY", "solana_keypair"],
                min_value_len: 64,
            },
        },
        // === Polygon ===
        Rule {
            id: "polygon-private-key",
            name: "Polygon Private Key",
            detector: Detector::KeyValue {
                keys: &[
                    "POLYGON_PRIVATE_KEY",
                    "MATIC_PRIVATE_KEY",
                    "polygon_private_key",
                ],
                min_value_len: 64,
            },
        },
        // === Avalanche ===
        Rule {
            id: "avalanche-private-key",
            name: "Avalanche Private Key",
            detector: Detector::KeyValue {
                keys: &[
                    "AVALANCHE_PRIVATE_KEY",
                    "AVAX_PRIVATE_KEY",
                    "avalanche_private_key",
                ],
                min_value_len: 64,
            },
        },
        // === BSC (Binance Smart Chain) ===
        Rule {
            id: "bsc-private-key",
            name: "BSC Private Key",
            detector: Detector::KeyValue {
                keys: &["BSC_PRIVATE_KEY", "BINANCE_PRIVATE_KEY", "bsc_private_key"],
                min_value_len: 64,
            },
        },
        // === Arbitrum ===
        Rule {
            id: "arbitrum-private-key",
            name: "Arbitrum Private Key",
            detector: Detector::KeyValue {
                keys: &[
                    "ARBITRUM_PRIVATE_KEY",
                    "ARB_PRIVATE_KEY",
                    "arbitrum_private_key",
                ],
                min_value_len: 64,
            },
        },
        // === Optimism ===
        Rule {
            id: "optimism-private-key",
            name: "Optimism Private Key",
            detector: Detector::KeyValue {
                keys: &[
                    "OPTIMISM_PRIVATE_KEY",
                    "OP_PRIVATE_KEY",
                    "optimism_private_key",
                ],
                min_value_len: 64,
            },
        },
        // === Wallet Connect ===
        Rule {
            id: "walletconnect-uri",
            name: "WalletConnect URI",
            detector: Detector::Prefix {
                prefix: "wc:",
                min_len: 50,
                charset: Charset::AlphaNumDash,
            },
        },
        // === MetaMask ===
        Rule {
            id: "metamask-seed",
            name: "MetaMask Seed Phrase",
            detector: Detector::KeyValue {
                keys: &["METAMASK_SEED", "METAMASK_PHRASE", "metamask_seed"],
                min_value_len: 50,
            },
        },
        // === Coinbase Wallet ===
        Rule {
            id: "coinbase-seed",
            name: "Coinbase Wallet Seed",
            detector: Detector::KeyValue {
                keys: &["COINBASE_SEED", "COINBASE_PHRASE", "coinbase_seed"],
                min_value_len: 50,
            },
        },
        // ============================================================
        // QUANTUM-RESISTANT CRYPTOGRAPHY (2025-2026)
        // Post-quantum cryptographic keys and algorithms
        // ============================================================

        // === NIST Post-Quantum Cryptography Standardization ===
        Rule {
            id: "pq-crystals-kyber",
            name: "CRYSTALS-Kyber Key",
            detector: Detector::Prefix {
                prefix: "kyber",
                min_len: 32,
                charset: Charset::AlphaNumDash,
            },
        },
        Rule {
            id: "pq-crystals-dilithium",
            name: "CRYSTALS-Dilithium Key",
            detector: Detector::Prefix {
                prefix: "dilithium",
                min_len: 32,
                charset: Charset::AlphaNumDash,
            },
        },
        Rule {
            id: "pq-falcon",
            name: "Falcon Signature Key",
            detector: Detector::Prefix {
                prefix: "falcon",
                min_len: 32,
                charset: Charset::AlphaNumDash,
            },
        },
        Rule {
            id: "pq-sphincs",
            name: "SPHINCS+ Key",
            detector: Detector::Prefix {
                prefix: "sphincs",
                min_len: 32,
                charset: Charset::AlphaNumDash,
            },
        },
        Rule {
            id: "pq-bike",
            name: "BIKE Key",
            detector: Detector::Prefix {
                prefix: "bike",
                min_len: 32,
                charset: Charset::AlphaNumDash,
            },
        },
        Rule {
            id: "pq-hqc",
            name: "HQC Key",
            detector: Detector::Prefix {
                prefix: "hqc",
                min_len: 32,
                charset: Charset::AlphaNumDash,
            },
        },
        // === Quantum-Safe Key Exchange ===
        Rule {
            id: "pq-newhope",
            name: "NewHope Key Exchange",
            detector: Detector::Prefix {
                prefix: "newhope",
                min_len: 32,
                charset: Charset::AlphaNumDash,
            },
        },
        Rule {
            id: "pq-frodo",
            name: "FrodoKEM Key",
            detector: Detector::Prefix {
                prefix: "frodo",
                min_len: 32,
                charset: Charset::AlphaNumDash,
            },
        },
        // === Quantum Key Distribution ===
        Rule {
            id: "qkd-key",
            name: "Quantum Key Distribution Key",
            detector: Detector::KeyValue {
                keys: &["QKD_KEY", "QUANTUM_KEY", "QKEY", "qkd_key"],
                min_value_len: 32,
            },
        },
        // ============================================================
        // AI MODEL WEIGHTS & CLOUD STORAGE (2025-2026)
        // Credentials for accessing AI models and training data
        // ============================================================

        // === AI Model Hub Tokens ===
        Rule {
            id: "huggingface-model-token",
            name: "Hugging Face Model Access Token",
            detector: Detector::KeyValue {
                keys: &[
                    "HF_MODEL_TOKEN",
                    "HUGGINGFACE_MODEL_TOKEN",
                    "hf_model_token",
                ],
                min_value_len: 20,
            },
        },
        Rule {
            id: "replicate-model-token",
            name: "Replicate Model API Token",
            detector: Detector::KeyValue {
                keys: &["REPLICATE_MODEL_TOKEN", "replicate_model_token"],
                min_value_len: 20,
            },
        },
        Rule {
            id: "openai-model-token",
            name: "OpenAI Model Access Token",
            detector: Detector::KeyValue {
                keys: &["OPENAI_MODEL_TOKEN", "openai_model_token"],
                min_value_len: 20,
            },
        },
        // === ML Experiment Tracking ===
        Rule {
            id: "mlflow-tracking-uri",
            name: "MLflow Tracking URI",
            detector: Detector::KeyValue {
                keys: &["MLFLOW_TRACKING_URI", "mlflow_tracking_uri"],
                min_value_len: 15,
            },
        },
        Rule {
            id: "weights-and-biases",
            name: "Weights & Biases API Key",
            detector: Detector::KeyValue {
                keys: &["WANDB_API_KEY", "WANDB_KEY", "wandb_api_key"],
                min_value_len: 20,
            },
        },
        Rule {
            id: "comet-ml-api-key",
            name: "Comet ML API Key",
            detector: Detector::KeyValue {
                keys: &["COMET_API_KEY", "comet_api_key"],
                min_value_len: 20,
            },
        },
        Rule {
            id: "neptune-api-token",
            name: "Neptune AI API Token",
            detector: Detector::KeyValue {
                keys: &["NEPTUNE_API_TOKEN", "neptune_api_token"],
                min_value_len: 20,
            },
        },
        // === Cloud Storage Buckets for AI Models ===
        Rule {
            id: "aws-s3-model-bucket",
            name: "AWS S3 Model Bucket Credentials",
            detector: Detector::KeyValue {
                keys: &["AWS_MODEL_BUCKET", "S3_MODEL_BUCKET", "MODEL_BUCKET_URL"],
                min_value_len: 10,
            },
        },
        Rule {
            id: "gcp-model-bucket",
            name: "GCP Model Bucket Credentials",
            detector: Detector::KeyValue {
                keys: &["GCP_MODEL_BUCKET", "GC_MODEL_BUCKET", "MODEL_BUCKET_GCS"],
                min_value_len: 10,
            },
        },
        Rule {
            id: "azure-model-blob",
            name: "Azure Model Blob Storage",
            detector: Detector::KeyValue {
                keys: &["AZURE_MODEL_CONTAINER", "MODEL_BLOB_URL"],
                min_value_len: 10,
            },
        },
        // === Data Version Control ===
        Rule {
            id: "dvc-remote-token",
            name: "DVC Remote Storage Token",
            detector: Detector::KeyValue {
                keys: &["DVC_REMOTE_TOKEN", "dvc_remote_token"],
                min_value_len: 20,
            },
        },
        // ============================================================
        // FEDERATED IDENTITY TOKENS (2025-2026)
        // OAuth 2.1, JWT, SAML, and modern identity tokens
        // ============================================================

        // === OAuth 2.1 Access Tokens ===
        Rule {
            id: "oauth21-access-token",
            name: "OAuth 2.1 Access Token",
            detector: Detector::KeyValue {
                keys: &["OAUTH21_TOKEN", "OAUTH_2_1_TOKEN", "oauth21_access_token"],
                min_value_len: 20,
            },
        },
        // === JWT Tokens ===
        Rule {
            id: "jwt-access-token",
            name: "JWT Access Token",
            detector: Detector::KeyValue {
                keys: &["JWT_TOKEN", "ACCESS_TOKEN", "BEARER_TOKEN"],
                min_value_len: 20,
            },
        },
        Rule {
            id: "jwt-refresh-token",
            name: "JWT Refresh Token",
            detector: Detector::KeyValue {
                keys: &["JWT_REFRESH_TOKEN", "REFRESH_TOKEN", "jwt_refresh_token"],
                min_value_len: 20,
            },
        },
        // === SAML Assertions ===
        Rule {
            id: "saml-assertion",
            name: "SAML 2.0 Assertion",
            detector: Detector::KeyValue {
                keys: &["SAML_ASSERTION", "SAML_TOKEN", "saml_assertion"],
                min_value_len: 50,
            },
        },
        // === OIDC ID Tokens ===
        Rule {
            id: "oidc-id-token",
            name: "OIDC ID Token",
            detector: Detector::KeyValue {
                keys: &["OIDC_ID_TOKEN", "ID_TOKEN", "oidc_id_token"],
                min_value_len: 20,
            },
        },
        // === Service Account Tokens ===
        Rule {
            id: "gcp-service-account-token",
            name: "GCP Service Account Token",
            detector: Detector::KeyValue {
                keys: &[
                    "GCP_SA_TOKEN",
                    "SERVICE_ACCOUNT_TOKEN",
                    "gcp_service_account_token",
                ],
                min_value_len: 20,
            },
        },
        Rule {
            id: "aws-service-account-token",
            name: "AWS Service Account Token",
            detector: Detector::KeyValue {
                keys: &["AWS_SA_TOKEN", "aws_service_account_token"],
                min_value_len: 20,
            },
        },
        // === Cross-Domain Identity Tokens ===
        Rule {
            id: "federated-identity-token",
            name: "Federated Identity Token",
            detector: Detector::KeyValue {
                keys: &[
                    "FEDERATED_TOKEN",
                    "IDENTITY_TOKEN",
                    "federated_identity_token",
                ],
                min_value_len: 20,
            },
        },
        // === Workload Identity Tokens ===
        Rule {
            id: "workload-identity-token",
            name: "Workload Identity Token",
            detector: Detector::KeyValue {
                keys: &["WORKLOAD_IDENTITY_TOKEN", "workload_identity_token"],
                min_value_len: 20,
            },
        },
        // ============================================================
        // ENHANCED DATABASE DETECTION
        // ============================================================

        // MongoDB with credentials
        Rule {
            id: "mongodb-credentials",
            name: "MongoDB with Credentials",
            detector: Detector::Contains {
                needle: "mongodb://",
            },
        },
        Rule {
            id: "mongodb-srv-credentials",
            name: "MongoDB SRV with Credentials",
            detector: Detector::Contains {
                needle: "mongodb+srv://",
            },
        },
        // MongoDB Atlas connection strings
        Rule {
            id: "mongodb-atlas",
            name: "MongoDB Atlas Connection",
            detector: Detector::Contains {
                needle: ".mongodb.net",
            },
        },
        // MongoDB environment variables
        Rule {
            id: "mongodb-env",
            name: "MongoDB Connection (env)",
            detector: Detector::KeyValue {
                keys: &[
                    "MONGODB_URI",
                    "MONGO_URI",
                    "MONGO_URL",
                    "MONGODB_URL",
                    "MONGO_CONNECTION_STRING",
                    "mongodb_uri",
                ],
                min_value_len: 20,
            },
        },
        // === Additional database env vars ===
        Rule {
            id: "database-url-env",
            name: "Database URL (env)",
            detector: Detector::KeyValue {
                keys: &[
                    "DATABASE_URL",
                    "DB_URL",
                    "DB_CONNECTION_STRING",
                    "database_url",
                ],
                min_value_len: 15,
            },
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // RULE LOADING TESTS
    // ========================================================================

    #[test]
    fn test_load_rules_succeeds() {
        let rules = load_rules().unwrap();
        assert!(!rules.is_empty(), "Should load at least one rule");
    }

    #[test]
    fn test_builtin_rules_count() {
        let rules = builtin_rules();
        // We should have a substantial number of rules
        assert!(
            rules.len() >= 50,
            "Should have at least 50 builtin rules, got {}",
            rules.len()
        );
    }

    #[test]
    fn test_all_rules_have_ids() {
        let rules = builtin_rules();
        for rule in &rules {
            assert!(!rule.id.is_empty(), "Rule should have an ID");
            assert!(!rule.name.is_empty(), "Rule should have a name");
        }
    }

    #[test]
    fn test_rule_ids_are_unique() {
        let rules = builtin_rules();
        let mut seen = std::collections::HashSet::new();
        for rule in &rules {
            assert!(seen.insert(rule.id), "Duplicate rule ID found: {}", rule.id);
        }
    }

    #[test]
    fn test_rule_ids_are_kebab_case() {
        let rules = builtin_rules();
        for rule in &rules {
            assert!(
                rule.id
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "Rule ID should be kebab-case: {}",
                rule.id
            );
        }
    }

    // ========================================================================
    // SPECIFIC RULE EXISTENCE TESTS
    // ========================================================================

    fn has_rule(id: &str) -> bool {
        builtin_rules().iter().any(|r| r.id == id)
    }

    #[test]
    fn test_has_aws_rules() {
        assert!(
            has_rule("aws-access-key-id"),
            "Should have AWS access key rule"
        );
        assert!(
            has_rule("aws-secret-key"),
            "Should have AWS secret key rule"
        );
    }

    #[test]
    fn test_has_github_rules() {
        assert!(has_rule("github-pat"), "Should have GitHub PAT rule");
        assert!(has_rule("github-oauth"), "Should have GitHub OAuth rule");
        assert!(
            has_rule("github-fine-grained"),
            "Should have GitHub fine-grained PAT rule"
        );
    }

    #[test]
    fn test_has_gitlab_rules() {
        assert!(has_rule("gitlab-pat"), "Should have GitLab PAT rule");
        assert!(
            has_rule("gitlab-pipeline"),
            "Should have GitLab pipeline rule"
        );
    }

    #[test]
    fn test_has_openai_rules() {
        assert!(
            has_rule("openai-api-key"),
            "Should have OpenAI API key rule"
        );
        assert!(
            has_rule("openai-project-key"),
            "Should have OpenAI project key rule"
        );
    }

    #[test]
    fn test_has_anthropic_rules() {
        assert!(
            has_rule("anthropic-api-key"),
            "Should have Anthropic API key rule"
        );
        assert!(
            has_rule("anthropic-api-key-env"),
            "Should have Anthropic env var rule"
        );
    }

    #[test]
    fn test_has_xai_grok_rules() {
        assert!(has_rule("xai-api-key"), "Should have xAI API key rule");
        assert!(
            has_rule("xai-api-key-env"),
            "Should have xAI/Grok env var rule"
        );
    }

    #[test]
    fn test_has_gemini_rules() {
        assert!(
            has_rule("gemini-api-key"),
            "Should have Gemini API key rule"
        );
        assert!(has_rule("gcp-api-key"), "Should have GCP API key rule");
    }

    #[test]
    fn test_has_openrouter_rules() {
        assert!(
            has_rule("openrouter-api-key"),
            "Should have OpenRouter API key rule"
        );
    }

    #[test]
    fn test_has_groq_rules() {
        assert!(has_rule("groq-api-key"), "Should have Groq API key rule");
    }

    #[test]
    fn test_has_perplexity_rules() {
        assert!(
            has_rule("perplexity-api-key"),
            "Should have Perplexity API key rule"
        );
    }

    #[test]
    fn test_has_fireworks_rules() {
        assert!(
            has_rule("fireworks-api-key"),
            "Should have Fireworks API key rule"
        );
    }

    #[test]
    fn test_has_cerebras_rules() {
        assert!(
            has_rule("cerebras-api-key"),
            "Should have Cerebras API key rule"
        );
    }

    #[test]
    fn test_has_huggingface_rules() {
        assert!(
            has_rule("huggingface-token"),
            "Should have Hugging Face token rule"
        );
    }

    #[test]
    fn test_has_replicate_rules() {
        assert!(
            has_rule("replicate-token"),
            "Should have Replicate token rule"
        );
    }

    #[test]
    fn test_has_slack_rules() {
        assert!(
            has_rule("slack-bot-token"),
            "Should have Slack bot token rule"
        );
        assert!(
            has_rule("slack-user-token"),
            "Should have Slack user token rule"
        );
    }

    #[test]
    fn test_has_stripe_rules() {
        assert!(
            has_rule("stripe-secret-key"),
            "Should have Stripe secret key rule"
        );
        assert!(
            has_rule("stripe-restricted-key"),
            "Should have Stripe restricted key rule"
        );
    }

    #[test]
    fn test_has_database_rules() {
        assert!(has_rule("postgres-uri"), "Should have PostgreSQL URI rule");
        assert!(has_rule("mysql-uri"), "Should have MySQL URI rule");
        assert!(has_rule("mongodb-uri"), "Should have MongoDB URI rule");
        assert!(has_rule("mongodb-srv-uri"), "Should have MongoDB SRV rule");
        assert!(has_rule("redis-uri"), "Should have Redis URI rule");
        assert!(has_rule("jdbc-connection"), "Should have JDBC rule");
    }

    #[test]
    fn test_has_mongodb_extended_rules() {
        assert!(
            has_rule("mongodb-credentials"),
            "Should have MongoDB credentials rule"
        );
        assert!(has_rule("mongodb-atlas"), "Should have MongoDB Atlas rule");
        assert!(has_rule("mongodb-env"), "Should have MongoDB env var rule");
    }

    #[test]
    fn test_has_private_key_rules() {
        assert!(
            has_rule("private-key-rsa"),
            "Should have RSA private key rule"
        );
        assert!(
            has_rule("private-key-openssh"),
            "Should have OpenSSH private key rule"
        );
        assert!(
            has_rule("private-key-ec"),
            "Should have EC private key rule"
        );
    }

    #[test]
    fn test_has_local_ai_endpoint_rules() {
        assert!(
            has_rule("ollama-endpoint"),
            "Should have Ollama endpoint rule"
        );
        assert!(
            has_rule("lmstudio-endpoint"),
            "Should have LM Studio endpoint rule"
        );
        assert!(has_rule("exo-endpoint"), "Should have Exo endpoint rule");
        assert!(
            has_rule("localai-endpoint"),
            "Should have LocalAI endpoint rule"
        );
        assert!(has_rule("vllm-endpoint"), "Should have vLLM endpoint rule");
        assert!(
            has_rule("llamacpp-endpoint"),
            "Should have llama.cpp endpoint rule"
        );
        assert!(
            has_rule("kobold-endpoint"),
            "Should have Kobold endpoint rule"
        );
    }

    #[test]
    fn test_has_generic_rules() {
        assert!(
            has_rule("generic-api-key"),
            "Should have generic API key rule"
        );
        assert!(
            has_rule("generic-secret"),
            "Should have generic secret rule"
        );
        assert!(
            has_rule("generic-password"),
            "Should have generic password rule"
        );
        assert!(has_rule("generic-token"), "Should have generic token rule");
    }

    // ========================================================================
    // DETECTOR TYPE TESTS
    // ========================================================================

    fn count_detector_type<F: Fn(&Detector) -> bool>(f: F) -> usize {
        builtin_rules().iter().filter(|r| f(&r.detector)).count()
    }

    #[test]
    fn test_has_prefix_detectors() {
        let count = count_detector_type(|d| matches!(d, Detector::Prefix { .. }));
        assert!(count > 20, "Should have many prefix detectors");
    }

    #[test]
    fn test_has_keyvalue_detectors() {
        let count = count_detector_type(|d| matches!(d, Detector::KeyValue { .. }));
        assert!(count > 10, "Should have many key-value detectors");
    }

    #[test]
    fn test_has_contains_detectors() {
        let count = count_detector_type(|d| matches!(d, Detector::Contains { .. }));
        assert!(
            count >= 4,
            "Should have contains detectors for private keys"
        );
    }

    #[test]
    fn test_has_endpoint_detectors() {
        let count = count_detector_type(|d| matches!(d, Detector::Endpoint { .. }));
        assert!(count >= 5, "Should have endpoint detectors for local AI");
    }

    // ========================================================================
    // DETECTOR CONFIGURATION TESTS
    // ========================================================================

    #[test]
    fn test_prefix_detectors_have_reasonable_min_len() {
        let rules = builtin_rules();
        for rule in &rules {
            if let Detector::Prefix {
                min_len, prefix, ..
            } = &rule.detector
            {
                assert!(
                    *min_len >= prefix.len(),
                    "Rule {} min_len {} should be >= prefix len {}",
                    rule.id,
                    min_len,
                    prefix.len()
                );
                assert!(
                    *min_len <= 150,
                    "Rule {} min_len {} seems too long",
                    rule.id,
                    min_len
                );
            }
        }
    }

    #[test]
    fn test_keyvalue_detectors_have_reasonable_min_len() {
        let rules = builtin_rules();
        for rule in &rules {
            if let Detector::KeyValue { min_value_len, .. } = &rule.detector {
                assert!(
                    *min_value_len >= 5,
                    "Rule {} min_value_len {} seems too short",
                    rule.id,
                    min_value_len
                );
                assert!(
                    *min_value_len <= 100,
                    "Rule {} min_value_len {} seems too long",
                    rule.id,
                    min_value_len
                );
            }
        }
    }

    #[test]
    fn test_keyvalue_detectors_have_keys() {
        let rules = builtin_rules();
        for rule in &rules {
            if let Detector::KeyValue { keys, .. } = &rule.detector {
                assert!(
                    !keys.is_empty(),
                    "Rule {} should have at least one key",
                    rule.id
                );
            }
        }
    }

    #[test]
    fn test_endpoint_detectors_have_patterns() {
        let rules = builtin_rules();
        for rule in &rules {
            if let Detector::Endpoint { patterns, keys, .. } = &rule.detector {
                assert!(
                    !patterns.is_empty() || !keys.is_empty(),
                    "Rule {} should have patterns or keys",
                    rule.id
                );
            }
        }
    }

    // ========================================================================
    // CHARSET TESTS
    // ========================================================================

    #[test]
    fn test_charset_alphanum_matches() {
        let charset = Charset::AlphaNum;
        assert!(charset.matches('a'));
        assert!(charset.matches('z'));
        assert!(charset.matches('A'));
        assert!(charset.matches('Z'));
        assert!(charset.matches('0'));
        assert!(charset.matches('9'));
        assert!(!charset.matches('-'));
        assert!(!charset.matches('_'));
        assert!(!charset.matches(' '));
        assert!(!charset.matches('!'));
    }

    #[test]
    fn test_charset_alphanum_dash_matches() {
        let charset = Charset::AlphaNumDash;
        assert!(charset.matches('a'));
        assert!(charset.matches('Z'));
        assert!(charset.matches('5'));
        assert!(charset.matches('-'));
        assert!(charset.matches('_'));
        assert!(!charset.matches(' '));
        assert!(!charset.matches('!'));
        assert!(!charset.matches('@'));
    }

    #[test]
    fn test_charset_base64_matches() {
        let charset = Charset::Base64;
        assert!(charset.matches('a'));
        assert!(charset.matches('Z'));
        assert!(charset.matches('0'));
        assert!(charset.matches('+'));
        assert!(charset.matches('/'));
        assert!(charset.matches('='));
        assert!(!charset.matches('-'));
        assert!(!charset.matches('_'));
    }

    #[test]
    fn test_charset_hex_matches() {
        let charset = Charset::Hex;
        for c in "0123456789abcdefABCDEF".chars() {
            assert!(charset.matches(c), "Should match hex char: {}", c);
        }
        for c in "ghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ!@#".chars() {
            assert!(!charset.matches(c), "Should not match non-hex char: {}", c);
        }
    }

    #[test]
    fn test_charset_url_matches() {
        let charset = Charset::Url;
        // Should match URL characters
        for c in "abcABC123-._~:/?#[]@!$&'()*+,;=%".chars() {
            assert!(charset.matches(c), "Should match URL char: {}", c);
        }
        // Should not match spaces or other chars
        assert!(!charset.matches(' '));
        assert!(!charset.matches('\n'));
        assert!(!charset.matches('"'));
    }
}
