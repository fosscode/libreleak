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

#[derive(Clone, Copy, Debug)]
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
        // Note: DeepSeek uses sk- prefix like OpenAI but with different key format
        // Use KeyValue detection to avoid false positives with OpenAI keys
        Rule {
            id: "deepseek-api-key",
            name: "DeepSeek API Key",
            detector: Detector::KeyValue {
                keys: &["DEEPSEEK_API_KEY", "deepseek_api_key", "DEEPSEEK_KEY"],
                min_value_len: 32,
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
                patterns: &[":5001/api", "koboldcpp", "koboldai"],
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
        // ============================================================
        // CHINESE CLOUD & AI SERVICES
        // Major Chinese tech platforms with paid API services
        // ============================================================

        // === Alibaba Cloud (Aliyun) ===
        Rule {
            id: "aliyun-access-key-id",
            name: "Alibaba Cloud Access Key ID",
            detector: Detector::Prefix {
                prefix: "LTAI",
                min_len: 24,
                charset: Charset::AlphaNum,
            },
        },
        Rule {
            id: "aliyun-secret-key",
            name: "Alibaba Cloud Secret Key",
            detector: Detector::KeyValue {
                keys: &[
                    "ALIBABA_CLOUD_ACCESS_KEY_SECRET",
                    "ALIYUN_SECRET_KEY",
                    "ALIYUN_ACCESS_KEY_SECRET",
                    "aliyun_secret_key",
                    "alicloud_secret_key",
                ],
                min_value_len: 30,
            },
        },
        // === Tencent Cloud ===
        Rule {
            id: "tencent-secret-id",
            name: "Tencent Cloud Secret ID",
            detector: Detector::Prefix {
                prefix: "AKID",
                min_len: 36,
                charset: Charset::AlphaNum,
            },
        },
        Rule {
            id: "tencent-secret-key",
            name: "Tencent Cloud Secret Key",
            detector: Detector::KeyValue {
                keys: &[
                    "TENCENT_SECRET_KEY",
                    "TENCENTCLOUD_SECRET_KEY",
                    "TC_SECRET_KEY",
                    "tencent_secret_key",
                    "QCLOUD_SECRET_KEY",
                ],
                min_value_len: 32,
            },
        },
        // === Baidu Cloud / Baidu AI ===
        Rule {
            id: "baidu-api-key",
            name: "Baidu Cloud API Key",
            detector: Detector::KeyValue {
                keys: &[
                    "BAIDU_API_KEY",
                    "BAIDU_AK",
                    "BAIDU_ACCESS_KEY",
                    "baidu_api_key",
                    "BCE_ACCESS_KEY_ID",
                ],
                min_value_len: 24,
            },
        },
        Rule {
            id: "baidu-secret-key",
            name: "Baidu Cloud Secret Key",
            detector: Detector::KeyValue {
                keys: &[
                    "BAIDU_SECRET_KEY",
                    "BAIDU_SK",
                    "baidu_secret_key",
                    "BCE_SECRET_ACCESS_KEY",
                ],
                min_value_len: 32,
            },
        },
        Rule {
            id: "baidu-ernie-api-key",
            name: "Baidu ERNIE Bot API Key",
            detector: Detector::KeyValue {
                keys: &[
                    "ERNIE_API_KEY",
                    "ERNIE_BOT_API_KEY",
                    "QIANFAN_API_KEY",
                    "QIANFAN_AK",
                    "ernie_api_key",
                ],
                min_value_len: 24,
            },
        },
        // === Huawei Cloud ===
        Rule {
            id: "huawei-access-key",
            name: "Huawei Cloud Access Key",
            detector: Detector::KeyValue {
                keys: &[
                    "HUAWEI_ACCESS_KEY",
                    "HUAWEICLOUD_SDK_AK",
                    "HW_ACCESS_KEY",
                    "huawei_access_key",
                ],
                min_value_len: 20,
            },
        },
        Rule {
            id: "huawei-secret-key",
            name: "Huawei Cloud Secret Key",
            detector: Detector::KeyValue {
                keys: &[
                    "HUAWEI_SECRET_KEY",
                    "HUAWEICLOUD_SDK_SK",
                    "HW_SECRET_KEY",
                    "huawei_secret_key",
                ],
                min_value_len: 32,
            },
        },
        // === ByteDance / Volcengine ===
        Rule {
            id: "volcengine-access-key",
            name: "Volcengine Access Key",
            detector: Detector::Prefix {
                prefix: "AKLT",
                min_len: 32,
                charset: Charset::AlphaNum,
            },
        },
        Rule {
            id: "volcengine-secret-key",
            name: "Volcengine Secret Key",
            detector: Detector::KeyValue {
                keys: &[
                    "VOLCENGINE_SECRET_KEY",
                    "VOLC_SECRET_KEY",
                    "volcengine_secret_key",
                    "BYTEDANCE_SECRET_KEY",
                ],
                min_value_len: 32,
            },
        },
        // === Zhipu AI (ChatGLM) ===
        Rule {
            id: "zhipu-api-key",
            name: "Zhipu AI API Key",
            detector: Detector::KeyValue {
                keys: &[
                    "ZHIPU_API_KEY",
                    "ZHIPUAI_API_KEY",
                    "CHATGLM_API_KEY",
                    "GLM_API_KEY",
                    "zhipu_api_key",
                ],
                min_value_len: 32,
            },
        },
        // === Baichuan AI ===
        Rule {
            id: "baichuan-api-key",
            name: "Baichuan AI API Key",
            detector: Detector::KeyValue {
                keys: &[
                    "BAICHUAN_API_KEY",
                    "BAICHUAN_SECRET_KEY",
                    "baichuan_api_key",
                ],
                min_value_len: 32,
            },
        },
        // === MiniMax AI ===
        Rule {
            id: "minimax-api-key",
            name: "MiniMax API Key",
            detector: Detector::KeyValue {
                keys: &["MINIMAX_API_KEY", "MINIMAX_GROUP_ID", "minimax_api_key"],
                min_value_len: 32,
            },
        },
        // === Moonshot AI (Kimi) ===
        Rule {
            id: "moonshot-api-key",
            name: "Moonshot AI API Key",
            detector: Detector::KeyValue {
                keys: &["MOONSHOT_API_KEY", "KIMI_API_KEY", "moonshot_api_key"],
                min_value_len: 32,
            },
        },
        // === iFlytek (讯飞) ===
        Rule {
            id: "iflytek-api-key",
            name: "iFlytek API Key",
            detector: Detector::KeyValue {
                keys: &[
                    "IFLYTEK_API_KEY",
                    "IFLYTEK_APP_ID",
                    "XUNFEI_API_KEY",
                    "SPARK_API_KEY",
                    "iflytek_api_key",
                ],
                min_value_len: 16,
            },
        },
        Rule {
            id: "iflytek-api-secret",
            name: "iFlytek API Secret",
            detector: Detector::KeyValue {
                keys: &[
                    "IFLYTEK_API_SECRET",
                    "XUNFEI_API_SECRET",
                    "SPARK_API_SECRET",
                    "iflytek_api_secret",
                ],
                min_value_len: 32,
            },
        },
        // === SenseTime ===
        Rule {
            id: "sensetime-api-key",
            name: "SenseTime API Key",
            detector: Detector::KeyValue {
                keys: &[
                    "SENSETIME_API_KEY",
                    "SENSENOVA_API_KEY",
                    "sensetime_api_key",
                ],
                min_value_len: 32,
            },
        },
        // === Megvii (Face++) ===
        Rule {
            id: "faceplusplus-api-key",
            name: "Face++ API Key",
            detector: Detector::KeyValue {
                keys: &[
                    "FACEPP_API_KEY",
                    "FACEPLUSPLUS_API_KEY",
                    "MEGVII_API_KEY",
                    "facepp_api_key",
                ],
                min_value_len: 20,
            },
        },
        Rule {
            id: "faceplusplus-api-secret",
            name: "Face++ API Secret",
            detector: Detector::KeyValue {
                keys: &[
                    "FACEPP_API_SECRET",
                    "FACEPLUSPLUS_API_SECRET",
                    "facepp_api_secret",
                ],
                min_value_len: 20,
            },
        },
        // === WeChat / WeCom API ===
        Rule {
            id: "wechat-app-secret",
            name: "WeChat App Secret",
            detector: Detector::KeyValue {
                keys: &[
                    "WECHAT_APP_SECRET",
                    "WEIXIN_APP_SECRET",
                    "WX_APP_SECRET",
                    "wechat_app_secret",
                    "WECHAT_SECRET",
                ],
                min_value_len: 32,
            },
        },
        Rule {
            id: "wecom-secret",
            name: "WeCom (Enterprise WeChat) Secret",
            detector: Detector::KeyValue {
                keys: &[
                    "WECOM_SECRET",
                    "WEWORK_SECRET",
                    "ENTERPRISE_WECHAT_SECRET",
                    "wecom_secret",
                ],
                min_value_len: 32,
            },
        },
        // === Alipay ===
        Rule {
            id: "alipay-app-private-key",
            name: "Alipay App Private Key",
            detector: Detector::KeyValue {
                keys: &[
                    "ALIPAY_PRIVATE_KEY",
                    "ALIPAY_APP_PRIVATE_KEY",
                    "alipay_private_key",
                ],
                min_value_len: 64,
            },
        },
        Rule {
            id: "alipay-public-key",
            name: "Alipay Public Key",
            detector: Detector::KeyValue {
                keys: &[
                    "ALIPAY_PUBLIC_KEY",
                    "ALIPAY_PLATFORM_PUBLIC_KEY",
                    "alipay_public_key",
                ],
                min_value_len: 64,
            },
        },
        // === JD Cloud ===
        Rule {
            id: "jdcloud-access-key",
            name: "JD Cloud Access Key",
            detector: Detector::KeyValue {
                keys: &["JDCLOUD_ACCESS_KEY", "JD_ACCESS_KEY", "jdcloud_access_key"],
                min_value_len: 20,
            },
        },
        Rule {
            id: "jdcloud-secret-key",
            name: "JD Cloud Secret Key",
            detector: Detector::KeyValue {
                keys: &["JDCLOUD_SECRET_KEY", "JD_SECRET_KEY", "jdcloud_secret_key"],
                min_value_len: 32,
            },
        },
        // === Kingsoft Cloud ===
        Rule {
            id: "ksyun-access-key",
            name: "Kingsoft Cloud Access Key",
            detector: Detector::Prefix {
                prefix: "AKLT",
                min_len: 20,
                charset: Charset::AlphaNum,
            },
        },
        Rule {
            id: "ksyun-secret-key",
            name: "Kingsoft Cloud Secret Key",
            detector: Detector::KeyValue {
                keys: &[
                    "KSYUN_SECRET_KEY",
                    "KINGSOFT_SECRET_KEY",
                    "ksyun_secret_key",
                ],
                min_value_len: 32,
            },
        },
        // === DingTalk (钉钉) ===
        Rule {
            id: "dingtalk-app-secret",
            name: "DingTalk App Secret",
            detector: Detector::KeyValue {
                keys: &[
                    "DINGTALK_APP_SECRET",
                    "DINGTALK_SECRET",
                    "DD_APP_SECRET",
                    "dingtalk_app_secret",
                ],
                min_value_len: 32,
            },
        },
        // === Gitee API Token ===
        Rule {
            id: "gitee-access-token",
            name: "Gitee Access Token",
            detector: Detector::KeyValue {
                keys: &[
                    "GITEE_ACCESS_TOKEN",
                    "GITEE_TOKEN",
                    "GITEE_PRIVATE_TOKEN",
                    "gitee_access_token",
                ],
                min_value_len: 32,
            },
        },
        // ============================================================
        // INDIAN PAYMENT & SAAS SERVICES
        // Major Indian fintech and SaaS platforms
        // ============================================================

        // === Razorpay ===
        Rule {
            id: "razorpay-key-id",
            name: "Razorpay Key ID",
            detector: Detector::Prefix {
                prefix: "rzp_live_",
                min_len: 20,
                charset: Charset::AlphaNum,
            },
        },
        Rule {
            id: "razorpay-test-key",
            name: "Razorpay Test Key",
            detector: Detector::Prefix {
                prefix: "rzp_test_",
                min_len: 20,
                charset: Charset::AlphaNum,
            },
        },
        Rule {
            id: "razorpay-secret",
            name: "Razorpay Secret Key",
            detector: Detector::KeyValue {
                keys: &[
                    "RAZORPAY_SECRET",
                    "RAZORPAY_KEY_SECRET",
                    "razorpay_secret",
                    "RZP_SECRET",
                ],
                min_value_len: 20,
            },
        },
        // === Paytm ===
        Rule {
            id: "paytm-merchant-key",
            name: "Paytm Merchant Key",
            detector: Detector::KeyValue {
                keys: &["PAYTM_MERCHANT_KEY", "PAYTM_KEY", "paytm_merchant_key"],
                min_value_len: 16,
            },
        },
        Rule {
            id: "paytm-merchant-id",
            name: "Paytm Merchant ID",
            detector: Detector::KeyValue {
                keys: &["PAYTM_MERCHANT_ID", "PAYTM_MID", "paytm_merchant_id"],
                min_value_len: 10,
            },
        },
        // === PhonePe ===
        Rule {
            id: "phonepe-salt-key",
            name: "PhonePe Salt Key",
            detector: Detector::KeyValue {
                keys: &["PHONEPE_SALT_KEY", "PHONEPE_KEY", "phonepe_salt_key"],
                min_value_len: 32,
            },
        },
        Rule {
            id: "phonepe-merchant-id",
            name: "PhonePe Merchant ID",
            detector: Detector::KeyValue {
                keys: &["PHONEPE_MERCHANT_ID", "PHONEPE_MID", "phonepe_merchant_id"],
                min_value_len: 10,
            },
        },
        // === Cashfree ===
        Rule {
            id: "cashfree-app-id",
            name: "Cashfree App ID",
            detector: Detector::KeyValue {
                keys: &["CASHFREE_APP_ID", "CF_APP_ID", "cashfree_app_id"],
                min_value_len: 10,
            },
        },
        Rule {
            id: "cashfree-secret-key",
            name: "Cashfree Secret Key",
            detector: Detector::KeyValue {
                keys: &[
                    "CASHFREE_SECRET_KEY",
                    "CF_SECRET_KEY",
                    "cashfree_secret_key",
                ],
                min_value_len: 32,
            },
        },
        // === Instamojo ===
        Rule {
            id: "instamojo-api-key",
            name: "Instamojo API Key",
            detector: Detector::KeyValue {
                keys: &["INSTAMOJO_API_KEY", "INSTAMOJO_KEY", "instamojo_api_key"],
                min_value_len: 20,
            },
        },
        Rule {
            id: "instamojo-auth-token",
            name: "Instamojo Auth Token",
            detector: Detector::KeyValue {
                keys: &[
                    "INSTAMOJO_AUTH_TOKEN",
                    "INSTAMOJO_TOKEN",
                    "instamojo_auth_token",
                ],
                min_value_len: 20,
            },
        },
        // === Zoho ===
        Rule {
            id: "zoho-client-secret",
            name: "Zoho Client Secret",
            detector: Detector::KeyValue {
                keys: &["ZOHO_CLIENT_SECRET", "ZOHO_SECRET", "zoho_client_secret"],
                min_value_len: 32,
            },
        },
        Rule {
            id: "zoho-refresh-token",
            name: "Zoho Refresh Token",
            detector: Detector::KeyValue {
                keys: &["ZOHO_REFRESH_TOKEN", "zoho_refresh_token"],
                min_value_len: 32,
            },
        },
        // === Freshworks ===
        Rule {
            id: "freshworks-api-key",
            name: "Freshworks API Key",
            detector: Detector::KeyValue {
                keys: &[
                    "FRESHWORKS_API_KEY",
                    "FRESHDESK_API_KEY",
                    "FRESHSALES_API_KEY",
                    "freshworks_api_key",
                ],
                min_value_len: 20,
            },
        },
        // === MapmyIndia ===
        Rule {
            id: "mapmyindia-api-key",
            name: "MapmyIndia API Key",
            detector: Detector::KeyValue {
                keys: &[
                    "MAPMYINDIA_API_KEY",
                    "MMI_API_KEY",
                    "MAPPLS_API_KEY",
                    "mapmyindia_api_key",
                ],
                min_value_len: 20,
            },
        },
        Rule {
            id: "mapmyindia-secret",
            name: "MapmyIndia Secret",
            detector: Detector::KeyValue {
                keys: &[
                    "MAPMYINDIA_SECRET",
                    "MMI_SECRET",
                    "MAPPLS_SECRET",
                    "mapmyindia_secret",
                ],
                min_value_len: 20,
            },
        },
        // === Ola Maps ===
        Rule {
            id: "ola-api-key",
            name: "Ola Maps API Key",
            detector: Detector::KeyValue {
                keys: &["OLA_API_KEY", "OLA_MAPS_KEY", "ola_api_key"],
                min_value_len: 20,
            },
        },
        // === MSG91 (Indian SMS) ===
        Rule {
            id: "msg91-auth-key",
            name: "MSG91 Auth Key",
            detector: Detector::KeyValue {
                keys: &["MSG91_AUTH_KEY", "MSG91_KEY", "msg91_auth_key"],
                min_value_len: 20,
            },
        },
        // === Shiprocket ===
        Rule {
            id: "shiprocket-api-key",
            name: "Shiprocket API Key",
            detector: Detector::KeyValue {
                keys: &[
                    "SHIPROCKET_API_KEY",
                    "SHIPROCKET_TOKEN",
                    "shiprocket_api_key",
                ],
                min_value_len: 20,
            },
        },
        // === Delhivery ===
        Rule {
            id: "delhivery-api-key",
            name: "Delhivery API Key",
            detector: Detector::KeyValue {
                keys: &["DELHIVERY_API_KEY", "DELHIVERY_TOKEN", "delhivery_api_key"],
                min_value_len: 20,
            },
        },
        // === ICICI Bank API ===
        Rule {
            id: "icici-api-key",
            name: "ICICI Bank API Key",
            detector: Detector::KeyValue {
                keys: &["ICICI_API_KEY", "ICICI_CLIENT_ID", "icici_api_key"],
                min_value_len: 20,
            },
        },
        // === HDFC Bank API ===
        Rule {
            id: "hdfc-api-key",
            name: "HDFC Bank API Key",
            detector: Detector::KeyValue {
                keys: &["HDFC_API_KEY", "HDFC_CLIENT_ID", "hdfc_api_key"],
                min_value_len: 20,
            },
        },
        // === UPI / NPCI ===
        Rule {
            id: "upi-merchant-key",
            name: "UPI Merchant Key",
            detector: Detector::KeyValue {
                keys: &[
                    "UPI_MERCHANT_KEY",
                    "UPI_SECRET",
                    "NPCI_API_KEY",
                    "upi_merchant_key",
                ],
                min_value_len: 20,
            },
        },
        // === Juspay ===
        Rule {
            id: "juspay-api-key",
            name: "Juspay API Key",
            detector: Detector::KeyValue {
                keys: &["JUSPAY_API_KEY", "JUSPAY_MERCHANT_ID", "juspay_api_key"],
                min_value_len: 20,
            },
        },
        // === BillDesk ===
        Rule {
            id: "billdesk-secret-key",
            name: "BillDesk Secret Key",
            detector: Detector::KeyValue {
                keys: &["BILLDESK_SECRET_KEY", "BILLDESK_KEY", "billdesk_secret_key"],
                min_value_len: 20,
            },
        },
        // === CCAvenue ===
        Rule {
            id: "ccavenue-working-key",
            name: "CCAvenue Working Key",
            detector: Detector::KeyValue {
                keys: &[
                    "CCAVENUE_WORKING_KEY",
                    "CCAVENUE_KEY",
                    "ccavenue_working_key",
                ],
                min_value_len: 20,
            },
        },
        Rule {
            id: "ccavenue-access-code",
            name: "CCAvenue Access Code",
            detector: Detector::KeyValue {
                keys: &["CCAVENUE_ACCESS_CODE", "ccavenue_access_code"],
                min_value_len: 10,
            },
        },
        // ============================================================
        // LLM ROUTER / AGGREGATOR APIs
        // Unified gateways to multiple LLM providers
        // ============================================================

        // === LiteLLM ===
        Rule {
            id: "litellm-api-key",
            name: "LiteLLM API Key",
            detector: Detector::KeyValue {
                keys: &[
                    "LITELLM_API_KEY",
                    "LITELLM_MASTER_KEY",
                    "LITELLM_PROXY_KEY",
                    "litellm_api_key",
                ],
                min_value_len: 20,
            },
        },
        Rule {
            id: "litellm-endpoint",
            name: "LiteLLM Proxy Endpoint",
            detector: Detector::Endpoint {
                keys: &["LITELLM_ENDPOINT", "LITELLM_BASE_URL", "LITELLM_PROXY_URL"],
                patterns: &[":4000/v1", ":8000/chat/completions", "localhost:4000"],
            },
        },
        // === Portkey ===
        Rule {
            id: "portkey-api-key",
            name: "Portkey API Key",
            detector: Detector::KeyValue {
                keys: &["PORTKEY_API_KEY", "PORTKEY_KEY", "portkey_api_key"],
                min_value_len: 20,
            },
        },
        // === Helicone ===
        Rule {
            id: "helicone-api-key",
            name: "Helicone API Key",
            detector: Detector::KeyValue {
                keys: &["HELICONE_API_KEY", "HELICONE_KEY", "helicone_api_key"],
                min_value_len: 20,
            },
        },
        // === Unify AI ===
        Rule {
            id: "unify-api-key",
            name: "Unify AI API Key",
            detector: Detector::KeyValue {
                keys: &["UNIFY_API_KEY", "UNIFY_KEY", "unify_api_key"],
                min_value_len: 20,
            },
        },
        // === Eden AI ===
        Rule {
            id: "edenai-api-key",
            name: "Eden AI API Key",
            detector: Detector::KeyValue {
                keys: &["EDENAI_API_KEY", "EDEN_AI_KEY", "edenai_api_key"],
                min_value_len: 20,
            },
        },
        // === Requesty ===
        Rule {
            id: "requesty-api-key",
            name: "Requesty API Key",
            detector: Detector::KeyValue {
                keys: &["REQUESTY_API_KEY", "REQUESTY_KEY", "requesty_api_key"],
                min_value_len: 20,
            },
        },
        // === Baseten ===
        Rule {
            id: "baseten-api-key",
            name: "Baseten API Key",
            detector: Detector::KeyValue {
                keys: &["BASETEN_API_KEY", "BASETEN_KEY", "baseten_api_key"],
                min_value_len: 20,
            },
        },
        // === Modal ===
        Rule {
            id: "modal-token",
            name: "Modal Token",
            detector: Detector::KeyValue {
                keys: &["MODAL_TOKEN_ID", "MODAL_TOKEN_SECRET", "modal_token"],
                min_value_len: 20,
            },
        },
        // === Banana.dev ===
        Rule {
            id: "banana-api-key",
            name: "Banana.dev API Key",
            detector: Detector::KeyValue {
                keys: &["BANANA_API_KEY", "BANANA_MODEL_KEY", "banana_api_key"],
                min_value_len: 20,
            },
        },
        // ============================================================
        // ADDITIONAL SELF-HOSTED INFERENCE ENDPOINTS
        // ============================================================

        // === Text Generation WebUI (Oobabooga) ===
        Rule {
            id: "textgen-webui-endpoint",
            name: "Text Generation WebUI Endpoint",
            detector: Detector::Endpoint {
                keys: &["TEXTGEN_API_URL", "OOBABOOGA_API_URL", "TEXTGEN_ENDPOINT"],
                patterns: &[":5000/api/v1", ":5001/api", ":7860/api", "localhost:5000"],
            },
        },
        // === GPT4All Server ===
        Rule {
            id: "gpt4all-endpoint",
            name: "GPT4All Server Endpoint",
            detector: Detector::Endpoint {
                keys: &["GPT4ALL_API_URL", "GPT4ALL_ENDPOINT"],
                patterns: &[":4891/v1", "localhost:4891"],
            },
        },
        // === Jan AI ===
        Rule {
            id: "jan-endpoint",
            name: "Jan AI Endpoint",
            detector: Detector::Endpoint {
                keys: &["JAN_API_URL", "JAN_ENDPOINT"],
                patterns: &[":1337/v1", "localhost:1337"],
            },
        },
        // === TabbyML (Code) ===
        Rule {
            id: "tabby-endpoint",
            name: "TabbyML Endpoint",
            detector: Detector::Endpoint {
                keys: &["TABBY_API_URL", "TABBY_ENDPOINT", "TABBY_SERVER_URL"],
                patterns: &[":8080/v1", "tabby."],
            },
        },
        Rule {
            id: "tabby-api-key",
            name: "TabbyML API Key",
            detector: Detector::KeyValue {
                keys: &["TABBY_API_KEY", "TABBY_TOKEN", "tabby_api_key"],
                min_value_len: 20,
            },
        },
        // === Ray Serve / RayLLM ===
        Rule {
            id: "ray-serve-endpoint",
            name: "Ray Serve LLM Endpoint",
            detector: Detector::Endpoint {
                keys: &["RAY_SERVE_URL", "RAYLLM_ENDPOINT", "RAY_LLM_URL"],
                patterns: &["ray-serve", "rayllm", ":8265/api"],
            },
        },
        // === Triton Inference Server ===
        Rule {
            id: "triton-endpoint",
            name: "Triton Inference Server Endpoint",
            detector: Detector::Endpoint {
                keys: &["TRITON_URL", "TRITON_ENDPOINT", "TRITON_SERVER_URL"],
                patterns: &[":8000/v2/models", ":8001/v2", ":8002/v2", "tritonserver"],
            },
        },
        // === TensorRT-LLM ===
        Rule {
            id: "tensorrt-llm-endpoint",
            name: "TensorRT-LLM Endpoint",
            detector: Detector::Endpoint {
                keys: &["TENSORRT_LLM_URL", "TRT_LLM_ENDPOINT"],
                patterns: &[":8000/v2/models", "tritonserver"],
            },
        },
        // === MLC LLM ===
        Rule {
            id: "mlc-llm-endpoint",
            name: "MLC LLM Endpoint",
            detector: Detector::Endpoint {
                keys: &["MLC_LLM_URL", "MLC_ENDPOINT"],
                patterns: &["/v1/chat/completions", "mlc."],
            },
        },
        // === SGLang ===
        Rule {
            id: "sglang-endpoint",
            name: "SGLang Endpoint",
            detector: Detector::Endpoint {
                keys: &["SGLANG_URL", "SGLANG_ENDPOINT"],
                patterns: &[":30000/v1", "sglang.serve"],
            },
        },
        // ============================================================
        // JAPANESE TECH SERVICES
        // ============================================================

        // === LINE ===
        Rule {
            id: "line-channel-secret",
            name: "LINE Channel Secret",
            detector: Detector::KeyValue {
                keys: &["LINE_CHANNEL_SECRET", "LINE_SECRET", "line_channel_secret"],
                min_value_len: 32,
            },
        },
        Rule {
            id: "line-channel-access-token",
            name: "LINE Channel Access Token",
            detector: Detector::KeyValue {
                keys: &[
                    "LINE_CHANNEL_ACCESS_TOKEN",
                    "LINE_ACCESS_TOKEN",
                    "line_access_token",
                ],
                min_value_len: 100,
            },
        },
        // === Yahoo Japan ===
        Rule {
            id: "yahoo-japan-api-key",
            name: "Yahoo Japan API Key",
            detector: Detector::KeyValue {
                keys: &["YAHOO_JAPAN_API_KEY", "YJ_API_KEY", "yahoo_japan_api_key"],
                min_value_len: 20,
            },
        },
        // === Rakuten ===
        Rule {
            id: "rakuten-api-key",
            name: "Rakuten API Key",
            detector: Detector::KeyValue {
                keys: &["RAKUTEN_API_KEY", "RAKUTEN_APP_ID", "rakuten_api_key"],
                min_value_len: 16,
            },
        },
        // === PayPay ===
        Rule {
            id: "paypay-api-key",
            name: "PayPay API Key",
            detector: Detector::KeyValue {
                keys: &["PAYPAY_API_KEY", "PAYPAY_SECRET", "paypay_api_key"],
                min_value_len: 20,
            },
        },
        // ============================================================
        // KOREAN TECH SERVICES
        // ============================================================

        // === Kakao ===
        Rule {
            id: "kakao-rest-api-key",
            name: "Kakao REST API Key",
            detector: Detector::KeyValue {
                keys: &["KAKAO_REST_API_KEY", "KAKAO_API_KEY", "kakao_rest_api_key"],
                min_value_len: 32,
            },
        },
        Rule {
            id: "kakao-admin-key",
            name: "Kakao Admin Key",
            detector: Detector::KeyValue {
                keys: &["KAKAO_ADMIN_KEY", "kakao_admin_key"],
                min_value_len: 32,
            },
        },
        // === Naver ===
        Rule {
            id: "naver-client-secret",
            name: "Naver Client Secret",
            detector: Detector::KeyValue {
                keys: &["NAVER_CLIENT_SECRET", "NAVER_SECRET", "naver_client_secret"],
                min_value_len: 10,
            },
        },
        Rule {
            id: "naver-api-key",
            name: "Naver API Key",
            detector: Detector::KeyValue {
                keys: &["NAVER_API_KEY", "NAVER_CLIENT_ID", "naver_api_key"],
                min_value_len: 10,
            },
        },
        // === Naver Cloud (Clova) ===
        Rule {
            id: "naver-cloud-secret",
            name: "Naver Cloud Secret Key",
            detector: Detector::KeyValue {
                keys: &[
                    "NAVER_CLOUD_SECRET_KEY",
                    "NCP_SECRET_KEY",
                    "CLOVA_SECRET_KEY",
                    "naver_cloud_secret",
                ],
                min_value_len: 32,
            },
        },
        // === Toss Payments (Korea) ===
        Rule {
            id: "toss-secret-key",
            name: "Toss Payments Secret Key",
            detector: Detector::KeyValue {
                keys: &["TOSS_SECRET_KEY", "TOSS_PAYMENTS_SECRET", "toss_secret_key"],
                min_value_len: 20,
            },
        },
        // === Coupang ===
        Rule {
            id: "coupang-secret-key",
            name: "Coupang API Secret Key",
            detector: Detector::KeyValue {
                keys: &[
                    "COUPANG_SECRET_KEY",
                    "COUPANG_API_SECRET",
                    "coupang_secret_key",
                ],
                min_value_len: 32,
            },
        },
        // ============================================================
        // SOUTHEAST ASIAN TECH SERVICES
        // ============================================================

        // === Grab ===
        Rule {
            id: "grab-client-secret",
            name: "Grab API Client Secret",
            detector: Detector::KeyValue {
                keys: &["GRAB_CLIENT_SECRET", "GRAB_SECRET", "grab_client_secret"],
                min_value_len: 32,
            },
        },
        // === Gojek ===
        Rule {
            id: "gojek-api-key",
            name: "Gojek API Key",
            detector: Detector::KeyValue {
                keys: &["GOJEK_API_KEY", "GOJEK_SECRET", "gojek_api_key"],
                min_value_len: 20,
            },
        },
        // === Sea/Shopee ===
        Rule {
            id: "shopee-partner-key",
            name: "Shopee Partner Key",
            detector: Detector::KeyValue {
                keys: &["SHOPEE_PARTNER_KEY", "SHOPEE_SECRET", "shopee_partner_key"],
                min_value_len: 32,
            },
        },
        // === Lazada ===
        Rule {
            id: "lazada-app-secret",
            name: "Lazada App Secret",
            detector: Detector::KeyValue {
                keys: &["LAZADA_APP_SECRET", "LAZADA_SECRET", "lazada_app_secret"],
                min_value_len: 32,
            },
        },
        // === Tokopedia ===
        Rule {
            id: "tokopedia-secret",
            name: "Tokopedia Secret Key",
            detector: Detector::KeyValue {
                keys: &[
                    "TOKOPEDIA_SECRET",
                    "TOKOPEDIA_CLIENT_SECRET",
                    "tokopedia_secret",
                ],
                min_value_len: 32,
            },
        },
        // === Xendit (SE Asia Payments) ===
        Rule {
            id: "xendit-secret-key",
            name: "Xendit Secret Key",
            detector: Detector::KeyValue {
                keys: &["XENDIT_SECRET_KEY", "XENDIT_API_KEY", "xendit_secret_key"],
                min_value_len: 20,
            },
        },
        // === 2C2P (SE Asia Payments) ===
        Rule {
            id: "2c2p-secret-key",
            name: "2C2P Secret Key",
            detector: Detector::KeyValue {
                keys: &["TWOC2P_SECRET_KEY", "C2P_SECRET", "2c2p_secret_key"],
                min_value_len: 20,
            },
        },
        // === VNPay (Vietnam) ===
        Rule {
            id: "vnpay-hash-secret",
            name: "VNPay Hash Secret",
            detector: Detector::KeyValue {
                keys: &["VNPAY_HASH_SECRET", "VNPAY_SECRET", "vnpay_hash_secret"],
                min_value_len: 20,
            },
        },
        // === MoMo (Vietnam) ===
        Rule {
            id: "momo-secret-key",
            name: "MoMo Secret Key",
            detector: Detector::KeyValue {
                keys: &["MOMO_SECRET_KEY", "MOMO_PARTNER_SECRET", "momo_secret_key"],
                min_value_len: 20,
            },
        },
        // === GCash (Philippines) ===
        Rule {
            id: "gcash-secret",
            name: "GCash API Secret",
            detector: Detector::KeyValue {
                keys: &["GCASH_SECRET", "GCASH_API_SECRET", "gcash_secret"],
                min_value_len: 20,
            },
        },
        // === Maya/PayMaya (Philippines) ===
        Rule {
            id: "paymaya-secret",
            name: "Maya/PayMaya Secret Key",
            detector: Detector::KeyValue {
                keys: &["PAYMAYA_SECRET_KEY", "MAYA_SECRET", "paymaya_secret"],
                min_value_len: 20,
            },
        },
        // === PromptPay (Thailand) ===
        Rule {
            id: "promptpay-api-key",
            name: "PromptPay API Key",
            detector: Detector::KeyValue {
                keys: &["PROMPTPAY_API_KEY", "PROMPTPAY_SECRET", "promptpay_api_key"],
                min_value_len: 20,
            },
        },
        // === Touch 'n Go (Malaysia) ===
        Rule {
            id: "touchngo-secret",
            name: "Touch 'n Go API Secret",
            detector: Detector::KeyValue {
                keys: &["TNG_SECRET", "TOUCHNGO_SECRET", "touchngo_secret"],
                min_value_len: 20,
            },
        },
        // ============================================================
        // BRAZILIAN / LATIN AMERICAN FINTECH
        // ============================================================

        // === Nubank ===
        Rule {
            id: "nubank-api-key",
            name: "Nubank API Key",
            detector: Detector::KeyValue {
                keys: &["NUBANK_API_KEY", "NUBANK_SECRET", "nubank_api_key"],
                min_value_len: 20,
            },
        },
        // === PagSeguro ===
        Rule {
            id: "pagseguro-token",
            name: "PagSeguro Token",
            detector: Detector::KeyValue {
                keys: &["PAGSEGURO_TOKEN", "PAGSEGURO_API_TOKEN", "pagseguro_token"],
                min_value_len: 32,
            },
        },
        // === MercadoPago ===
        Rule {
            id: "mercadopago-access-token",
            name: "MercadoPago Access Token",
            detector: Detector::KeyValue {
                keys: &[
                    "MERCADOPAGO_ACCESS_TOKEN",
                    "MP_ACCESS_TOKEN",
                    "mercadopago_access_token",
                ],
                min_value_len: 40,
            },
        },
        // === Pix (Brazil) ===
        Rule {
            id: "pix-api-key",
            name: "PIX API Key",
            detector: Detector::KeyValue {
                keys: &["PIX_API_KEY", "PIX_CLIENT_SECRET", "pix_api_key"],
                min_value_len: 20,
            },
        },
        // === iFood ===
        Rule {
            id: "ifood-client-secret",
            name: "iFood Client Secret",
            detector: Detector::KeyValue {
                keys: &["IFOOD_CLIENT_SECRET", "IFOOD_SECRET", "ifood_client_secret"],
                min_value_len: 32,
            },
        },
        // === Rappi ===
        Rule {
            id: "rappi-api-key",
            name: "Rappi API Key",
            detector: Detector::KeyValue {
                keys: &["RAPPI_API_KEY", "RAPPI_SECRET", "rappi_api_key"],
                min_value_len: 20,
            },
        },
        // === dLocal (LatAm Payments) ===
        Rule {
            id: "dlocal-secret-key",
            name: "dLocal Secret Key",
            detector: Detector::KeyValue {
                keys: &[
                    "DLOCAL_SECRET_KEY",
                    "DLOCAL_API_SECRET",
                    "dlocal_secret_key",
                ],
                min_value_len: 32,
            },
        },
        // === EBANX ===
        Rule {
            id: "ebanx-secret-key",
            name: "EBANX Secret Key",
            detector: Detector::KeyValue {
                keys: &[
                    "EBANX_SECRET_KEY",
                    "EBANX_INTEGRATION_KEY",
                    "ebanx_secret_key",
                ],
                min_value_len: 32,
            },
        },
        // === Conekta (Mexico) ===
        Rule {
            id: "conekta-private-key",
            name: "Conekta Private Key",
            detector: Detector::Prefix {
                prefix: "key_",
                min_len: 20,
                charset: Charset::AlphaNum,
            },
        },
        Rule {
            id: "conekta-api-key",
            name: "Conekta API Key",
            detector: Detector::KeyValue {
                keys: &["CONEKTA_API_KEY", "CONEKTA_PRIVATE_KEY", "conekta_api_key"],
                min_value_len: 20,
            },
        },
        // === Clip (Mexico) ===
        Rule {
            id: "clip-api-key",
            name: "Clip API Key",
            detector: Detector::KeyValue {
                keys: &["CLIP_API_KEY", "CLIP_SECRET", "clip_api_key"],
                min_value_len: 20,
            },
        },
        // === Transbank (Chile) ===
        Rule {
            id: "transbank-api-key",
            name: "Transbank API Key",
            detector: Detector::KeyValue {
                keys: &["TRANSBANK_API_KEY", "TRANSBANK_SECRET", "transbank_api_key"],
                min_value_len: 32,
            },
        },
        // ============================================================
        // AFRICAN FINTECH
        // ============================================================

        // === Flutterwave ===
        Rule {
            id: "flutterwave-secret-key",
            name: "Flutterwave Secret Key",
            detector: Detector::Prefix {
                prefix: "FLWSECK-",
                min_len: 40,
                charset: Charset::AlphaNumDash,
            },
        },
        Rule {
            id: "flutterwave-public-key",
            name: "Flutterwave Public Key",
            detector: Detector::Prefix {
                prefix: "FLWPUBK-",
                min_len: 40,
                charset: Charset::AlphaNumDash,
            },
        },
        Rule {
            id: "flutterwave-api-key",
            name: "Flutterwave API Key",
            detector: Detector::KeyValue {
                keys: &[
                    "FLUTTERWAVE_SECRET_KEY",
                    "FLW_SECRET_KEY",
                    "flutterwave_secret_key",
                ],
                min_value_len: 32,
            },
        },
        // === Paystack ===
        Rule {
            id: "paystack-secret-key",
            name: "Paystack Secret Key",
            detector: Detector::Prefix {
                prefix: "sk_live_",
                min_len: 40,
                charset: Charset::AlphaNum,
            },
        },
        Rule {
            id: "paystack-test-key",
            name: "Paystack Test Key",
            detector: Detector::Prefix {
                prefix: "sk_test_",
                min_len: 40,
                charset: Charset::AlphaNum,
            },
        },
        Rule {
            id: "paystack-api-key",
            name: "Paystack API Key",
            detector: Detector::KeyValue {
                keys: &[
                    "PAYSTACK_SECRET_KEY",
                    "PAYSTACK_API_KEY",
                    "paystack_secret_key",
                ],
                min_value_len: 32,
            },
        },
        // === M-Pesa ===
        Rule {
            id: "mpesa-consumer-secret",
            name: "M-Pesa Consumer Secret",
            detector: Detector::KeyValue {
                keys: &[
                    "MPESA_CONSUMER_SECRET",
                    "MPESA_SECRET",
                    "mpesa_consumer_secret",
                ],
                min_value_len: 20,
            },
        },
        Rule {
            id: "mpesa-passkey",
            name: "M-Pesa Passkey",
            detector: Detector::KeyValue {
                keys: &["MPESA_PASSKEY", "MPESA_LIPA_PASSKEY", "mpesa_passkey"],
                min_value_len: 32,
            },
        },
        // === Chipper Cash ===
        Rule {
            id: "chipper-api-key",
            name: "Chipper Cash API Key",
            detector: Detector::KeyValue {
                keys: &["CHIPPER_API_KEY", "CHIPPER_SECRET", "chipper_api_key"],
                min_value_len: 20,
            },
        },
        // === Interswitch ===
        Rule {
            id: "interswitch-secret",
            name: "Interswitch Secret Key",
            detector: Detector::KeyValue {
                keys: &[
                    "INTERSWITCH_SECRET_KEY",
                    "INTERSWITCH_MAC_KEY",
                    "interswitch_secret",
                ],
                min_value_len: 32,
            },
        },
        // === Ozow (South Africa) ===
        Rule {
            id: "ozow-api-key",
            name: "Ozow API Key",
            detector: Detector::KeyValue {
                keys: &["OZOW_API_KEY", "OZOW_PRIVATE_KEY", "ozow_api_key"],
                min_value_len: 20,
            },
        },
        // === Yoco (South Africa) ===
        Rule {
            id: "yoco-secret-key",
            name: "Yoco Secret Key",
            detector: Detector::KeyValue {
                keys: &["YOCO_SECRET_KEY", "YOCO_API_KEY", "yoco_secret_key"],
                min_value_len: 20,
            },
        },
        // === DPO (Africa) ===
        Rule {
            id: "dpo-company-token",
            name: "DPO Company Token",
            detector: Detector::KeyValue {
                keys: &["DPO_COMPANY_TOKEN", "DPO_SERVICE_TYPE", "dpo_company_token"],
                min_value_len: 20,
            },
        },
        // ============================================================
        // RUSSIAN / CIS TECH SERVICES
        // ============================================================

        // === Yandex ===
        Rule {
            id: "yandex-api-key",
            name: "Yandex API Key",
            detector: Detector::KeyValue {
                keys: &["YANDEX_API_KEY", "YANDEX_SECRET", "yandex_api_key"],
                min_value_len: 32,
            },
        },
        Rule {
            id: "yandex-cloud-token",
            name: "Yandex Cloud IAM Token",
            detector: Detector::KeyValue {
                keys: &[
                    "YANDEX_CLOUD_TOKEN",
                    "YC_TOKEN",
                    "YC_IAM_TOKEN",
                    "yandex_cloud_token",
                ],
                min_value_len: 100,
            },
        },
        // === Yandex GPT ===
        Rule {
            id: "yandex-gpt-api-key",
            name: "YandexGPT API Key",
            detector: Detector::KeyValue {
                keys: &["YANDEX_GPT_API_KEY", "YANDEXGPT_KEY", "yandex_gpt_api_key"],
                min_value_len: 32,
            },
        },
        // === VK ===
        Rule {
            id: "vk-access-token",
            name: "VK Access Token",
            detector: Detector::KeyValue {
                keys: &[
                    "VK_ACCESS_TOKEN",
                    "VK_TOKEN",
                    "VK_API_TOKEN",
                    "vk_access_token",
                ],
                min_value_len: 50,
            },
        },
        Rule {
            id: "vk-service-token",
            name: "VK Service Token",
            detector: Detector::KeyValue {
                keys: &["VK_SERVICE_TOKEN", "VK_SERVICE_KEY", "vk_service_token"],
                min_value_len: 50,
            },
        },
        // === Sberbank ===
        Rule {
            id: "sber-api-key",
            name: "Sberbank API Key",
            detector: Detector::KeyValue {
                keys: &["SBER_API_KEY", "SBERBANK_SECRET", "sber_api_key"],
                min_value_len: 32,
            },
        },
        // === GigaChat (Sber AI) ===
        Rule {
            id: "gigachat-api-key",
            name: "GigaChat API Key",
            detector: Detector::KeyValue {
                keys: &[
                    "GIGACHAT_API_KEY",
                    "GIGACHAT_CREDENTIALS",
                    "gigachat_api_key",
                ],
                min_value_len: 32,
            },
        },
        // === Tinkoff ===
        Rule {
            id: "tinkoff-secret-key",
            name: "Tinkoff Secret Key",
            detector: Detector::KeyValue {
                keys: &[
                    "TINKOFF_SECRET_KEY",
                    "TINKOFF_PASSWORD",
                    "tinkoff_secret_key",
                ],
                min_value_len: 20,
            },
        },
        // === Kaspi (Kazakhstan) ===
        Rule {
            id: "kaspi-api-key",
            name: "Kaspi API Key",
            detector: Detector::KeyValue {
                keys: &["KASPI_API_KEY", "KASPI_SECRET", "kaspi_api_key"],
                min_value_len: 20,
            },
        },
        // ============================================================
        // MIDDLE EASTERN TECH SERVICES
        // ============================================================

        // === Careem ===
        Rule {
            id: "careem-api-key",
            name: "Careem API Key",
            detector: Detector::KeyValue {
                keys: &["CAREEM_API_KEY", "CAREEM_SECRET", "careem_api_key"],
                min_value_len: 20,
            },
        },
        // === Noon ===
        Rule {
            id: "noon-api-key",
            name: "Noon API Key",
            detector: Detector::KeyValue {
                keys: &["NOON_API_KEY", "NOON_SECRET", "noon_api_key"],
                min_value_len: 20,
            },
        },
        // === Talabat ===
        Rule {
            id: "talabat-api-key",
            name: "Talabat API Key",
            detector: Detector::KeyValue {
                keys: &["TALABAT_API_KEY", "TALABAT_SECRET", "talabat_api_key"],
                min_value_len: 20,
            },
        },
        // === Tabby (MENA BNPL) ===
        Rule {
            id: "tabby-payments-secret",
            name: "Tabby Payments Secret Key",
            detector: Detector::KeyValue {
                keys: &["TABBY_SECRET_KEY", "TABBY_PUBLIC_KEY", "tabby_secret_key"],
                min_value_len: 20,
            },
        },
        // === Tamara (MENA BNPL) ===
        Rule {
            id: "tamara-api-token",
            name: "Tamara API Token",
            detector: Detector::KeyValue {
                keys: &["TAMARA_API_TOKEN", "TAMARA_SECRET", "tamara_api_token"],
                min_value_len: 32,
            },
        },
        // === HyperPay (MENA) ===
        Rule {
            id: "hyperpay-secret",
            name: "HyperPay Secret",
            detector: Detector::KeyValue {
                keys: &[
                    "HYPERPAY_SECRET",
                    "HYPERPAY_ACCESS_TOKEN",
                    "hyperpay_secret",
                ],
                min_value_len: 32,
            },
        },
        // === PayTabs ===
        Rule {
            id: "paytabs-server-key",
            name: "PayTabs Server Key",
            detector: Detector::KeyValue {
                keys: &["PAYTABS_SERVER_KEY", "PAYTABS_SECRET", "paytabs_server_key"],
                min_value_len: 20,
            },
        },
        // ============================================================
        // EUROPEAN LLM / CLOUD PROVIDERS
        // ============================================================

        // === Scaleway (France) ===
        Rule {
            id: "scaleway-secret-key",
            name: "Scaleway Secret Key",
            detector: Detector::KeyValue {
                keys: &[
                    "SCW_SECRET_KEY",
                    "SCALEWAY_SECRET_KEY",
                    "scaleway_secret_key",
                ],
                min_value_len: 32,
            },
        },
        Rule {
            id: "scaleway-access-key",
            name: "Scaleway Access Key",
            detector: Detector::Prefix {
                prefix: "SCW",
                min_len: 20,
                charset: Charset::AlphaNum,
            },
        },
        // === OVH ===
        Rule {
            id: "ovh-application-secret",
            name: "OVH Application Secret",
            detector: Detector::KeyValue {
                keys: &[
                    "OVH_APPLICATION_SECRET",
                    "OVH_SECRET",
                    "ovh_application_secret",
                ],
                min_value_len: 32,
            },
        },
        Rule {
            id: "ovh-consumer-key",
            name: "OVH Consumer Key",
            detector: Detector::KeyValue {
                keys: &["OVH_CONSUMER_KEY", "ovh_consumer_key"],
                min_value_len: 32,
            },
        },
        // === Hetzner ===
        Rule {
            id: "hetzner-api-token",
            name: "Hetzner API Token",
            detector: Detector::KeyValue {
                keys: &["HETZNER_API_TOKEN", "HCLOUD_TOKEN", "hetzner_api_token"],
                min_value_len: 64,
            },
        },
        // === Klarna (Sweden) ===
        Rule {
            id: "klarna-api-secret",
            name: "Klarna API Secret",
            detector: Detector::KeyValue {
                keys: &["KLARNA_API_SECRET", "KLARNA_SECRET", "klarna_api_secret"],
                min_value_len: 20,
            },
        },
        // === Adyen (Netherlands) ===
        Rule {
            id: "adyen-api-key",
            name: "Adyen API Key",
            detector: Detector::KeyValue {
                keys: &["ADYEN_API_KEY", "ADYEN_SECRET", "adyen_api_key"],
                min_value_len: 32,
            },
        },
        // === Mollie (Netherlands) ===
        Rule {
            id: "mollie-api-key",
            name: "Mollie API Key",
            detector: Detector::Prefix {
                prefix: "live_",
                min_len: 35,
                charset: Charset::AlphaNum,
            },
        },
        Rule {
            id: "mollie-test-key",
            name: "Mollie Test Key",
            detector: Detector::KeyValue {
                keys: &["MOLLIE_API_KEY", "MOLLIE_KEY", "MOLLIE_TEST_KEY"],
                min_value_len: 35,
            },
        },
        // === Revolut ===
        Rule {
            id: "revolut-api-key",
            name: "Revolut API Key",
            detector: Detector::KeyValue {
                keys: &["REVOLUT_API_KEY", "REVOLUT_SECRET", "revolut_api_key"],
                min_value_len: 32,
            },
        },
        // === Wise (TransferWise) ===
        Rule {
            id: "wise-api-token",
            name: "Wise API Token",
            detector: Detector::KeyValue {
                keys: &["WISE_API_TOKEN", "TRANSFERWISE_TOKEN", "wise_api_token"],
                min_value_len: 32,
            },
        },
        // === SumUp ===
        Rule {
            id: "sumup-api-key",
            name: "SumUp API Key",
            detector: Detector::KeyValue {
                keys: &["SUMUP_API_KEY", "SUMUP_SECRET", "sumup_api_key"],
                min_value_len: 20,
            },
        },
        // === iDEAL (Netherlands) ===
        Rule {
            id: "ideal-merchant-key",
            name: "iDEAL Merchant Key",
            detector: Detector::KeyValue {
                keys: &["IDEAL_MERCHANT_KEY", "IDEAL_SECRET", "ideal_merchant_key"],
                min_value_len: 20,
            },
        },
        // === GoCardless (UK) ===
        Rule {
            id: "gocardless-access-token",
            name: "GoCardless Access Token",
            detector: Detector::KeyValue {
                keys: &[
                    "GOCARDLESS_ACCESS_TOKEN",
                    "GC_ACCESS_TOKEN",
                    "gocardless_access_token",
                ],
                min_value_len: 40,
            },
        },
        // === Checkout.com (UK) ===
        Rule {
            id: "checkout-secret-key",
            name: "Checkout.com Secret Key",
            detector: Detector::Prefix {
                prefix: "sk_",
                min_len: 40,
                charset: Charset::AlphaNum,
            },
        },
        Rule {
            id: "checkout-api-key",
            name: "Checkout.com API Key",
            detector: Detector::KeyValue {
                keys: &[
                    "CHECKOUT_SECRET_KEY",
                    "CHECKOUT_API_KEY",
                    "checkout_secret_key",
                ],
                min_value_len: 32,
            },
        },
        // === Trustly (Sweden) ===
        Rule {
            id: "trustly-api-secret",
            name: "Trustly API Secret",
            detector: Detector::KeyValue {
                keys: &["TRUSTLY_API_SECRET", "TRUSTLY_SECRET", "trustly_api_secret"],
                min_value_len: 20,
            },
        },
        // === SOFORT/Klarna (Germany) ===
        Rule {
            id: "sofort-api-key",
            name: "SOFORT API Key",
            detector: Detector::KeyValue {
                keys: &["SOFORT_API_KEY", "SOFORT_CONFIG_KEY", "sofort_api_key"],
                min_value_len: 20,
            },
        },
        // === Giropay (Germany) ===
        Rule {
            id: "giropay-api-key",
            name: "Giropay API Key",
            detector: Detector::KeyValue {
                keys: &["GIROPAY_API_KEY", "GIROPAY_SECRET", "giropay_api_key"],
                min_value_len: 20,
            },
        },
        // === Bancontact (Belgium) ===
        Rule {
            id: "bancontact-api-key",
            name: "Bancontact API Key",
            detector: Detector::KeyValue {
                keys: &[
                    "BANCONTACT_API_KEY",
                    "BANCONTACT_SECRET",
                    "bancontact_api_key",
                ],
                min_value_len: 20,
            },
        },
        // === BLIK (Poland) ===
        Rule {
            id: "blik-api-key",
            name: "BLIK API Key",
            detector: Detector::KeyValue {
                keys: &["BLIK_API_KEY", "BLIK_SECRET", "blik_api_key"],
                min_value_len: 20,
            },
        },
        // === MBWay (Portugal) ===
        Rule {
            id: "mbway-api-key",
            name: "MBWay API Key",
            detector: Detector::KeyValue {
                keys: &["MBWAY_API_KEY", "MBWAY_SECRET", "mbway_api_key"],
                min_value_len: 20,
            },
        },
        // === Bizum (Spain) ===
        Rule {
            id: "bizum-api-key",
            name: "Bizum API Key",
            detector: Detector::KeyValue {
                keys: &["BIZUM_API_KEY", "BIZUM_SECRET", "bizum_api_key"],
                min_value_len: 20,
            },
        },
        // === Swish (Sweden) ===
        Rule {
            id: "swish-api-key",
            name: "Swish API Key",
            detector: Detector::KeyValue {
                keys: &[
                    "SWISH_API_KEY",
                    "SWISH_SECRET",
                    "SWISH_CERTIFICATE_PASSWORD",
                    "swish_api_key",
                ],
                min_value_len: 16,
            },
        },
        // === Vipps (Norway) ===
        Rule {
            id: "vipps-client-secret",
            name: "Vipps Client Secret",
            detector: Detector::KeyValue {
                keys: &[
                    "VIPPS_CLIENT_SECRET",
                    "VIPPS_SECRET",
                    "VIPPS_SUBSCRIPTION_KEY",
                    "vipps_client_secret",
                ],
                min_value_len: 20,
            },
        },
        // === MobilePay (Denmark) ===
        Rule {
            id: "mobilepay-api-key",
            name: "MobilePay API Key",
            detector: Detector::KeyValue {
                keys: &["MOBILEPAY_API_KEY", "MOBILEPAY_SECRET", "mobilepay_api_key"],
                min_value_len: 20,
            },
        },
        // === N26 (Germany) ===
        Rule {
            id: "n26-api-key",
            name: "N26 API Key",
            detector: Detector::KeyValue {
                keys: &["N26_API_KEY", "N26_SECRET", "n26_api_key"],
                min_value_len: 20,
            },
        },
        // === Monzo (UK) ===
        Rule {
            id: "monzo-access-token",
            name: "Monzo Access Token",
            detector: Detector::KeyValue {
                keys: &["MONZO_ACCESS_TOKEN", "MONZO_TOKEN", "monzo_access_token"],
                min_value_len: 40,
            },
        },
        // === Starling Bank (UK) ===
        Rule {
            id: "starling-access-token",
            name: "Starling Bank Access Token",
            detector: Detector::KeyValue {
                keys: &[
                    "STARLING_ACCESS_TOKEN",
                    "STARLING_TOKEN",
                    "starling_access_token",
                ],
                min_value_len: 40,
            },
        },
        // === Bunq (Netherlands) ===
        Rule {
            id: "bunq-api-key",
            name: "Bunq API Key",
            detector: Detector::KeyValue {
                keys: &["BUNQ_API_KEY", "BUNQ_TOKEN", "bunq_api_key"],
                min_value_len: 64,
            },
        },
        // === Aleph Alpha (Germany - AI) ===
        Rule {
            id: "aleph-alpha-api-key",
            name: "Aleph Alpha API Key",
            detector: Detector::KeyValue {
                keys: &["ALEPH_ALPHA_API_KEY", "AA_API_KEY", "aleph_alpha_api_key"],
                min_value_len: 32,
            },
        },
        // === LightOn (France - AI) ===
        Rule {
            id: "lighton-api-key",
            name: "LightOn API Key",
            detector: Detector::KeyValue {
                keys: &["LIGHTON_API_KEY", "LIGHTON_TOKEN", "lighton_api_key"],
                min_value_len: 32,
            },
        },
        // === IONOS (Germany - Cloud) ===
        Rule {
            id: "ionos-api-key",
            name: "IONOS API Key",
            detector: Detector::KeyValue {
                keys: &["IONOS_API_KEY", "IONOS_TOKEN", "ionos_api_key"],
                min_value_len: 32,
            },
        },
        // === Exoscale (Switzerland - Cloud) ===
        Rule {
            id: "exoscale-api-secret",
            name: "Exoscale API Secret",
            detector: Detector::KeyValue {
                keys: &[
                    "EXOSCALE_API_SECRET",
                    "EXOSCALE_SECRET",
                    "exoscale_api_secret",
                ],
                min_value_len: 32,
            },
        },
        // === UpCloud (Finland - Cloud) ===
        Rule {
            id: "upcloud-password",
            name: "UpCloud Password",
            detector: Detector::KeyValue {
                keys: &[
                    "UPCLOUD_PASSWORD",
                    "UPCLOUD_API_PASSWORD",
                    "upcloud_password",
                ],
                min_value_len: 16,
            },
        },
        // ============================================================
        // AUSTRALIAN / OCEANIA TECH SERVICES
        // ============================================================

        // === Atlassian ===
        Rule {
            id: "atlassian-api-token",
            name: "Atlassian API Token",
            detector: Detector::KeyValue {
                keys: &[
                    "ATLASSIAN_API_TOKEN",
                    "JIRA_API_TOKEN",
                    "CONFLUENCE_API_TOKEN",
                    "atlassian_api_token",
                ],
                min_value_len: 24,
            },
        },
        // === Canva ===
        Rule {
            id: "canva-api-key",
            name: "Canva API Key",
            detector: Detector::KeyValue {
                keys: &["CANVA_API_KEY", "CANVA_SECRET", "canva_api_key"],
                min_value_len: 32,
            },
        },
        // === Afterpay/Clearpay ===
        Rule {
            id: "afterpay-secret",
            name: "Afterpay Secret Key",
            detector: Detector::KeyValue {
                keys: &["AFTERPAY_SECRET_KEY", "CLEARPAY_SECRET", "afterpay_secret"],
                min_value_len: 32,
            },
        },
        // === Zip (Australia) ===
        Rule {
            id: "zip-api-key",
            name: "Zip API Key",
            detector: Detector::KeyValue {
                keys: &["ZIP_API_KEY", "ZIP_SECRET", "zip_api_key"],
                min_value_len: 20,
            },
        },
        // ============================================================
        // TURKISH TECH SERVICES
        // ============================================================

        // === Getir ===
        Rule {
            id: "getir-api-key",
            name: "Getir API Key",
            detector: Detector::KeyValue {
                keys: &["GETIR_API_KEY", "GETIR_SECRET", "getir_api_key"],
                min_value_len: 20,
            },
        },
        // === Trendyol ===
        Rule {
            id: "trendyol-api-key",
            name: "Trendyol API Key",
            detector: Detector::KeyValue {
                keys: &["TRENDYOL_API_KEY", "TRENDYOL_SECRET", "trendyol_api_key"],
                min_value_len: 20,
            },
        },
        // === iyzico (Turkey Payments) ===
        Rule {
            id: "iyzico-secret-key",
            name: "iyzico Secret Key",
            detector: Detector::KeyValue {
                keys: &["IYZICO_SECRET_KEY", "IYZICO_API_KEY", "iyzico_secret_key"],
                min_value_len: 20,
            },
        },
        // === PayTR ===
        Rule {
            id: "paytr-merchant-key",
            name: "PayTR Merchant Key",
            detector: Detector::KeyValue {
                keys: &["PAYTR_MERCHANT_KEY", "PAYTR_SECRET", "paytr_merchant_key"],
                min_value_len: 20,
            },
        },
        // ============================================================
        // PAKISTANI / BANGLADESHI TECH SERVICES
        // ============================================================

        // === JazzCash (Pakistan) ===
        Rule {
            id: "jazzcash-secret",
            name: "JazzCash Secret",
            detector: Detector::KeyValue {
                keys: &["JAZZCASH_SECRET", "JAZZCASH_PASSWORD", "jazzcash_secret"],
                min_value_len: 16,
            },
        },
        // === EasyPaisa (Pakistan) ===
        Rule {
            id: "easypaisa-secret",
            name: "EasyPaisa Secret",
            detector: Detector::KeyValue {
                keys: &["EASYPAISA_SECRET", "EASYPAISA_KEY", "easypaisa_secret"],
                min_value_len: 16,
            },
        },
        // === bKash (Bangladesh) ===
        Rule {
            id: "bkash-app-secret",
            name: "bKash App Secret",
            detector: Detector::KeyValue {
                keys: &["BKASH_APP_SECRET", "BKASH_SECRET_KEY", "bkash_app_secret"],
                min_value_len: 20,
            },
        },
        // === Nagad (Bangladesh) ===
        Rule {
            id: "nagad-private-key",
            name: "Nagad Private Key",
            detector: Detector::KeyValue {
                keys: &["NAGAD_PRIVATE_KEY", "NAGAD_SECRET", "nagad_private_key"],
                min_value_len: 32,
            },
        },
        // ============================================================
        // ADDITIONAL BUG BOUNTY ELIGIBLE SERVICES
        // ============================================================

        // === Vercel ===
        Rule {
            id: "vercel-token",
            name: "Vercel Token",
            detector: Detector::KeyValue {
                keys: &["VERCEL_TOKEN", "VERCEL_API_TOKEN", "vercel_token"],
                min_value_len: 24,
            },
        },
        // === Netlify ===
        Rule {
            id: "netlify-access-token",
            name: "Netlify Access Token",
            detector: Detector::KeyValue {
                keys: &[
                    "NETLIFY_ACCESS_TOKEN",
                    "NETLIFY_AUTH_TOKEN",
                    "netlify_access_token",
                ],
                min_value_len: 40,
            },
        },
        // === Railway ===
        Rule {
            id: "railway-token",
            name: "Railway Token",
            detector: Detector::KeyValue {
                keys: &["RAILWAY_TOKEN", "RAILWAY_API_TOKEN", "railway_token"],
                min_value_len: 32,
            },
        },
        // === Render ===
        Rule {
            id: "render-api-key",
            name: "Render API Key",
            detector: Detector::KeyValue {
                keys: &["RENDER_API_KEY", "RENDER_TOKEN", "render_api_key"],
                min_value_len: 32,
            },
        },
        // === Fly.io ===
        Rule {
            id: "fly-api-token",
            name: "Fly.io API Token",
            detector: Detector::KeyValue {
                keys: &["FLY_API_TOKEN", "FLY_ACCESS_TOKEN", "fly_api_token"],
                min_value_len: 32,
            },
        },
        // === Neon (Postgres) ===
        Rule {
            id: "neon-api-key",
            name: "Neon API Key",
            detector: Detector::KeyValue {
                keys: &["NEON_API_KEY", "neon_api_key"],
                min_value_len: 32,
            },
        },
        // === Turso ===
        Rule {
            id: "turso-auth-token",
            name: "Turso Auth Token",
            detector: Detector::KeyValue {
                keys: &[
                    "TURSO_AUTH_TOKEN",
                    "TURSO_DATABASE_TOKEN",
                    "turso_auth_token",
                ],
                min_value_len: 32,
            },
        },
        // === Upstash ===
        Rule {
            id: "upstash-redis-token",
            name: "Upstash Redis Token",
            detector: Detector::KeyValue {
                keys: &[
                    "UPSTASH_REDIS_REST_TOKEN",
                    "UPSTASH_TOKEN",
                    "upstash_redis_token",
                ],
                min_value_len: 32,
            },
        },
        // === Convex ===
        Rule {
            id: "convex-deploy-key",
            name: "Convex Deploy Key",
            detector: Detector::KeyValue {
                keys: &["CONVEX_DEPLOY_KEY", "convex_deploy_key"],
                min_value_len: 32,
            },
        },
        // === Clerk ===
        Rule {
            id: "clerk-secret-key",
            name: "Clerk Secret Key",
            detector: Detector::Prefix {
                prefix: "sk_live_",
                min_len: 50,
                charset: Charset::AlphaNum,
            },
        },
        Rule {
            id: "clerk-api-key",
            name: "Clerk API Key",
            detector: Detector::KeyValue {
                keys: &["CLERK_SECRET_KEY", "CLERK_API_KEY", "clerk_secret_key"],
                min_value_len: 32,
            },
        },
        // === Auth0 ===
        Rule {
            id: "auth0-client-secret",
            name: "Auth0 Client Secret",
            detector: Detector::KeyValue {
                keys: &["AUTH0_CLIENT_SECRET", "AUTH0_SECRET", "auth0_client_secret"],
                min_value_len: 32,
            },
        },
        // === Okta ===
        Rule {
            id: "okta-api-token",
            name: "Okta API Token",
            detector: Detector::KeyValue {
                keys: &["OKTA_API_TOKEN", "OKTA_CLIENT_SECRET", "okta_api_token"],
                min_value_len: 32,
            },
        },
        // === Segment ===
        Rule {
            id: "segment-write-key",
            name: "Segment Write Key",
            detector: Detector::KeyValue {
                keys: &["SEGMENT_WRITE_KEY", "SEGMENT_API_KEY", "segment_write_key"],
                min_value_len: 20,
            },
        },
        // === Amplitude ===
        Rule {
            id: "amplitude-api-key",
            name: "Amplitude API Key",
            detector: Detector::KeyValue {
                keys: &["AMPLITUDE_API_KEY", "AMPLITUDE_SECRET", "amplitude_api_key"],
                min_value_len: 32,
            },
        },
        // === Mixpanel ===
        Rule {
            id: "mixpanel-secret",
            name: "Mixpanel Secret",
            detector: Detector::KeyValue {
                keys: &["MIXPANEL_SECRET", "MIXPANEL_API_SECRET", "mixpanel_secret"],
                min_value_len: 32,
            },
        },
        // === Posthog ===
        Rule {
            id: "posthog-api-key",
            name: "PostHog API Key",
            detector: Detector::Prefix {
                prefix: "phc_",
                min_len: 40,
                charset: Charset::AlphaNum,
            },
        },
        // === LaunchDarkly ===
        Rule {
            id: "launchdarkly-sdk-key",
            name: "LaunchDarkly SDK Key",
            detector: Detector::KeyValue {
                keys: &["LAUNCHDARKLY_SDK_KEY", "LD_SDK_KEY", "launchdarkly_sdk_key"],
                min_value_len: 32,
            },
        },
        // === Sentry ===
        Rule {
            id: "sentry-auth-token",
            name: "Sentry Auth Token",
            detector: Detector::KeyValue {
                keys: &["SENTRY_AUTH_TOKEN", "SENTRY_TOKEN", "sentry_auth_token"],
                min_value_len: 64,
            },
        },
        // === Cloudinary ===
        Rule {
            id: "cloudinary-api-secret",
            name: "Cloudinary API Secret",
            detector: Detector::KeyValue {
                keys: &[
                    "CLOUDINARY_API_SECRET",
                    "CLOUDINARY_SECRET",
                    "cloudinary_api_secret",
                ],
                min_value_len: 20,
            },
        },
        // === Imgix ===
        Rule {
            id: "imgix-api-key",
            name: "Imgix API Key",
            detector: Detector::KeyValue {
                keys: &["IMGIX_API_KEY", "IMGIX_SECURE_URL_TOKEN", "imgix_api_key"],
                min_value_len: 20,
            },
        },
        // === Uploadcare ===
        Rule {
            id: "uploadcare-secret-key",
            name: "Uploadcare Secret Key",
            detector: Detector::KeyValue {
                keys: &["UPLOADCARE_SECRET_KEY", "uploadcare_secret_key"],
                min_value_len: 20,
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

    // ========================================================================
    // CHINESE CLOUD & AI SERVICE RULES TESTS
    // ========================================================================

    #[test]
    fn test_has_aliyun_rules() {
        assert!(
            has_rule("aliyun-access-key-id"),
            "Should have Alibaba Cloud access key rule"
        );
        assert!(
            has_rule("aliyun-secret-key"),
            "Should have Alibaba Cloud secret key rule"
        );
    }

    #[test]
    fn test_has_tencent_cloud_rules() {
        assert!(
            has_rule("tencent-secret-id"),
            "Should have Tencent Cloud secret ID rule"
        );
        assert!(
            has_rule("tencent-secret-key"),
            "Should have Tencent Cloud secret key rule"
        );
    }

    #[test]
    fn test_has_baidu_rules() {
        assert!(
            has_rule("baidu-api-key"),
            "Should have Baidu Cloud API key rule"
        );
        assert!(
            has_rule("baidu-ernie-api-key"),
            "Should have Baidu ERNIE API key rule"
        );
    }

    #[test]
    fn test_has_huawei_cloud_rules() {
        assert!(
            has_rule("huawei-access-key"),
            "Should have Huawei Cloud access key rule"
        );
        assert!(
            has_rule("huawei-secret-key"),
            "Should have Huawei Cloud secret key rule"
        );
    }

    #[test]
    fn test_has_bytedance_volcengine_rules() {
        assert!(
            has_rule("volcengine-access-key"),
            "Should have Volcengine access key rule"
        );
        assert!(
            has_rule("volcengine-secret-key"),
            "Should have Volcengine secret key rule"
        );
    }

    #[test]
    fn test_has_chinese_ai_rules() {
        assert!(
            has_rule("zhipu-api-key"),
            "Should have Zhipu AI (ChatGLM) rule"
        );
        assert!(has_rule("baichuan-api-key"), "Should have Baichuan AI rule");
        assert!(has_rule("minimax-api-key"), "Should have MiniMax AI rule");
        assert!(
            has_rule("moonshot-api-key"),
            "Should have Moonshot AI (Kimi) rule"
        );
        assert!(
            has_rule("iflytek-api-key"),
            "Should have iFlytek API key rule"
        );
        assert!(
            has_rule("sensetime-api-key"),
            "Should have SenseTime API key rule"
        );
    }

    #[test]
    fn test_has_chinese_payment_rules() {
        assert!(
            has_rule("wechat-app-secret"),
            "Should have WeChat app secret rule"
        );
        assert!(
            has_rule("alipay-app-private-key"),
            "Should have Alipay private key rule"
        );
        assert!(
            has_rule("dingtalk-app-secret"),
            "Should have DingTalk app secret rule"
        );
    }

    #[test]
    fn test_has_gitee_rules() {
        assert!(
            has_rule("gitee-access-token"),
            "Should have Gitee access token rule"
        );
    }

    // ========================================================================
    // INDIAN PAYMENT & SAAS SERVICE RULES TESTS
    // ========================================================================

    #[test]
    fn test_has_razorpay_rules() {
        assert!(
            has_rule("razorpay-key-id"),
            "Should have Razorpay key ID rule"
        );
        assert!(
            has_rule("razorpay-test-key"),
            "Should have Razorpay test key rule"
        );
        assert!(
            has_rule("razorpay-secret"),
            "Should have Razorpay secret rule"
        );
    }

    #[test]
    fn test_has_paytm_rules() {
        assert!(
            has_rule("paytm-merchant-key"),
            "Should have Paytm merchant key rule"
        );
        assert!(
            has_rule("paytm-merchant-id"),
            "Should have Paytm merchant ID rule"
        );
    }

    #[test]
    fn test_has_phonepe_rules() {
        assert!(
            has_rule("phonepe-salt-key"),
            "Should have PhonePe salt key rule"
        );
    }

    #[test]
    fn test_has_cashfree_rules() {
        assert!(
            has_rule("cashfree-app-id"),
            "Should have Cashfree app ID rule"
        );
        assert!(
            has_rule("cashfree-secret-key"),
            "Should have Cashfree secret key rule"
        );
    }

    #[test]
    fn test_has_indian_saas_rules() {
        assert!(
            has_rule("zoho-client-secret"),
            "Should have Zoho client secret rule"
        );
        assert!(
            has_rule("freshworks-api-key"),
            "Should have Freshworks API key rule"
        );
    }

    #[test]
    fn test_has_indian_mapping_rules() {
        assert!(
            has_rule("mapmyindia-api-key"),
            "Should have MapmyIndia API key rule"
        );
        assert!(has_rule("ola-api-key"), "Should have Ola Maps API key rule");
    }

    #[test]
    fn test_has_indian_banking_rules() {
        assert!(
            has_rule("icici-api-key"),
            "Should have ICICI Bank API key rule"
        );
        assert!(
            has_rule("hdfc-api-key"),
            "Should have HDFC Bank API key rule"
        );
        assert!(
            has_rule("upi-merchant-key"),
            "Should have UPI merchant key rule"
        );
    }

    #[test]
    fn test_has_indian_payment_gateway_rules() {
        assert!(
            has_rule("juspay-api-key"),
            "Should have Juspay API key rule"
        );
        assert!(
            has_rule("billdesk-secret-key"),
            "Should have BillDesk secret key rule"
        );
        assert!(
            has_rule("ccavenue-working-key"),
            "Should have CCAvenue working key rule"
        );
    }

    // ========================================================================
    // CHARSET EDGE CASE TESTS
    // ========================================================================

    #[test]
    fn test_charset_alphanum_boundary_chars() {
        let charset = Charset::AlphaNum;
        // Test all boundary characters
        assert!(charset.matches('0'), "First digit");
        assert!(charset.matches('9'), "Last digit");
        assert!(charset.matches('a'), "First lowercase");
        assert!(charset.matches('z'), "Last lowercase");
        assert!(charset.matches('A'), "First uppercase");
        assert!(charset.matches('Z'), "Last uppercase");
    }

    #[test]
    fn test_charset_alphanum_rejects_adjacent_ascii() {
        let charset = Charset::AlphaNum;
        // Characters adjacent to alphanumeric range
        assert!(!charset.matches('/'), "Char before '0'");
        assert!(!charset.matches(':'), "Char after '9'");
        assert!(!charset.matches('@'), "Char before 'A'");
        assert!(!charset.matches('['), "Char after 'Z'");
        assert!(!charset.matches('`'), "Char before 'a'");
        assert!(!charset.matches('{'), "Char after 'z'");
    }

    #[test]
    fn test_charset_base64_with_padding() {
        let charset = Charset::Base64;
        // Base64 should handle padding chars
        assert!(charset.matches('='), "Padding char");
        assert!(charset.matches('.'), "Dot (used in some base64 variants)");
        // Standard base64 alphabet
        for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".chars() {
            assert!(charset.matches(c), "Base64 char '{}' should match", c);
        }
    }

    #[test]
    fn test_charset_hex_all_valid() {
        let charset = Charset::Hex;
        for c in "0123456789abcdefABCDEF".chars() {
            assert!(charset.matches(c), "Hex char '{}' should match", c);
        }
    }

    #[test]
    fn test_charset_hex_rejects_beyond_f() {
        let charset = Charset::Hex;
        for c in "ghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ".chars() {
            assert!(!charset.matches(c), "Non-hex char '{}' should not match", c);
        }
    }

    #[test]
    fn test_charset_url_full_set() {
        let charset = Charset::Url;
        // RFC 3986 unreserved characters
        let unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        for c in unreserved.chars() {
            assert!(charset.matches(c), "URL unreserved '{}' should match", c);
        }
        // RFC 3986 reserved characters (gen-delims + sub-delims)
        let reserved = ":/?#[]@!$&'()*+,;=%";
        for c in reserved.chars() {
            assert!(charset.matches(c), "URL reserved '{}' should match", c);
        }
    }

    #[test]
    fn test_charset_url_rejects_invalid() {
        let charset = Charset::Url;
        assert!(!charset.matches(' '), "Space");
        assert!(!charset.matches('\t'), "Tab");
        assert!(!charset.matches('\n'), "Newline");
        assert!(!charset.matches('"'), "Double quote");
        assert!(!charset.matches('<'), "Less than");
        assert!(!charset.matches('>'), "Greater than");
        assert!(!charset.matches('^'), "Caret");
        assert!(!charset.matches('\\'), "Backslash");
        assert!(!charset.matches('|'), "Pipe");
    }

    #[test]
    fn test_charset_unicode_handling() {
        // All charsets should reject non-ASCII
        let charsets = [
            Charset::AlphaNum,
            Charset::AlphaNumDash,
            Charset::Base64,
            Charset::Hex,
            Charset::Url,
        ];
        let unicode_chars = ['é', 'ñ', '中', '日', '😀', '€'];
        for charset in &charsets {
            for c in &unicode_chars {
                assert!(
                    !charset.matches(*c),
                    "Unicode char '{}' should not match {:?}",
                    c,
                    charset
                );
            }
        }
    }

    // ========================================================================
    // RULE CONFIGURATION VALIDATION TESTS
    // ========================================================================

    #[test]
    fn test_prefix_rules_have_non_empty_prefix() {
        let rules = builtin_rules();
        for rule in &rules {
            if let Detector::Prefix { prefix, .. } = &rule.detector {
                assert!(!prefix.is_empty(), "Rule {} has empty prefix", rule.id);
            }
        }
    }

    #[test]
    fn test_contains_rules_have_non_empty_needle() {
        let rules = builtin_rules();
        for rule in &rules {
            if let Detector::Contains { needle } = &rule.detector {
                assert!(!needle.is_empty(), "Rule {} has empty needle", rule.id);
            }
        }
    }

    #[test]
    fn test_keyvalue_keys_are_non_empty() {
        let rules = builtin_rules();
        for rule in &rules {
            if let Detector::KeyValue { keys, .. } = &rule.detector {
                for key in *keys {
                    assert!(
                        !key.is_empty(),
                        "Rule {} has empty key in keys array",
                        rule.id
                    );
                }
            }
        }
    }

    #[test]
    fn test_endpoint_configuration() {
        let rules = builtin_rules();
        for rule in &rules {
            if let Detector::Endpoint { keys, patterns } = &rule.detector {
                // At least one of keys or patterns must be non-empty
                assert!(
                    !keys.is_empty() || !patterns.is_empty(),
                    "Rule {} has empty keys and patterns",
                    rule.id
                );
                // Patterns should contain valid port or path indicators
                for pattern in *patterns {
                    assert!(!pattern.is_empty(), "Rule {} has empty pattern", rule.id);
                }
            }
        }
    }

    // ========================================================================
    // RULE ID CONSISTENCY TESTS
    // ========================================================================

    #[test]
    fn test_rule_id_no_leading_trailing_whitespace() {
        let rules = builtin_rules();
        for rule in &rules {
            assert_eq!(
                rule.id.trim(),
                rule.id,
                "Rule ID '{}' has leading/trailing whitespace",
                rule.id
            );
        }
    }

    #[test]
    fn test_rule_name_no_leading_trailing_whitespace() {
        let rules = builtin_rules();
        for rule in &rules {
            assert_eq!(
                rule.name.trim(),
                rule.name,
                "Rule name '{}' has leading/trailing whitespace",
                rule.name
            );
        }
    }

    #[test]
    fn test_rule_ids_no_double_dashes() {
        let rules = builtin_rules();
        for rule in &rules {
            assert!(
                !rule.id.contains("--"),
                "Rule ID '{}' contains double dashes",
                rule.id
            );
        }
    }

    #[test]
    fn test_rule_ids_no_leading_or_trailing_dash() {
        let rules = builtin_rules();
        for rule in &rules {
            assert!(
                !rule.id.starts_with('-'),
                "Rule ID '{}' starts with dash",
                rule.id
            );
            assert!(
                !rule.id.ends_with('-'),
                "Rule ID '{}' ends with dash",
                rule.id
            );
        }
    }

    // ========================================================================
    // SPECIFIC RULE DETECTOR CONFIGURATION TESTS
    // ========================================================================

    fn get_rule(id: &str) -> Option<Rule> {
        builtin_rules().into_iter().find(|r| r.id == id)
    }

    #[test]
    fn test_aws_access_key_config() {
        let rule = get_rule("aws-access-key-id").unwrap();
        if let Detector::Prefix {
            prefix,
            min_len,
            charset,
        } = rule.detector
        {
            assert_eq!(prefix, "AKIA");
            assert_eq!(min_len, 20);
            assert!(matches!(charset, Charset::AlphaNum));
        } else {
            panic!("Expected Prefix detector");
        }
    }

    #[test]
    fn test_github_pat_config() {
        let rule = get_rule("github-pat").unwrap();
        if let Detector::Prefix {
            prefix,
            min_len,
            charset,
        } = rule.detector
        {
            assert_eq!(prefix, "ghp_");
            assert_eq!(min_len, 40);
            assert!(matches!(charset, Charset::AlphaNum));
        } else {
            panic!("Expected Prefix detector");
        }
    }

    #[test]
    fn test_gitlab_pat_config() {
        let rule = get_rule("gitlab-pat").unwrap();
        if let Detector::Prefix {
            prefix,
            min_len,
            charset,
        } = rule.detector
        {
            assert_eq!(prefix, "glpat-");
            assert_eq!(min_len, 26);
            assert!(matches!(charset, Charset::AlphaNumDash));
        } else {
            panic!("Expected Prefix detector");
        }
    }

    #[test]
    fn test_openai_api_key_config() {
        let rule = get_rule("openai-api-key").unwrap();
        if let Detector::Prefix {
            prefix,
            min_len,
            charset,
        } = rule.detector
        {
            assert_eq!(prefix, "sk-");
            assert!(min_len >= 48);
            assert!(matches!(charset, Charset::AlphaNumDash));
        } else {
            panic!("Expected Prefix detector");
        }
    }

    #[test]
    fn test_anthropic_api_key_config() {
        let rule = get_rule("anthropic-api-key").unwrap();
        if let Detector::Prefix {
            prefix,
            min_len,
            charset,
        } = rule.detector
        {
            assert_eq!(prefix, "sk-ant-");
            assert!(min_len >= 40);
            assert!(matches!(charset, Charset::AlphaNumDash));
        } else {
            panic!("Expected Prefix detector");
        }
    }

    #[test]
    fn test_slack_token_configs() {
        let bot = get_rule("slack-bot-token").unwrap();
        let user = get_rule("slack-user-token").unwrap();
        let app = get_rule("slack-app-token").unwrap();

        if let Detector::Prefix { prefix, .. } = bot.detector {
            assert_eq!(prefix, "xoxb-");
        } else {
            panic!("Expected Prefix detector for bot token");
        }

        if let Detector::Prefix { prefix, .. } = user.detector {
            assert_eq!(prefix, "xoxp-");
        } else {
            panic!("Expected Prefix detector for user token");
        }

        if let Detector::Prefix { prefix, .. } = app.detector {
            assert_eq!(prefix, "xapp-");
        } else {
            panic!("Expected Prefix detector for app token");
        }
    }

    #[test]
    fn test_database_uri_configs() {
        let postgres = get_rule("postgres-uri").unwrap();
        let mysql = get_rule("mysql-uri").unwrap();

        if let Detector::Prefix {
            prefix, charset, ..
        } = postgres.detector
        {
            assert_eq!(prefix, "postgres://");
            assert!(matches!(charset, Charset::Url));
        } else {
            panic!("Expected Prefix detector for postgres");
        }

        if let Detector::Prefix {
            prefix, charset, ..
        } = mysql.detector
        {
            assert_eq!(prefix, "mysql://");
            assert!(matches!(charset, Charset::Url));
        } else {
            panic!("Expected Prefix detector for mysql");
        }
    }

    #[test]
    fn test_private_key_contains_config() {
        let rsa = get_rule("private-key-rsa").unwrap();
        if let Detector::Contains { needle } = rsa.detector {
            assert!(needle.contains("RSA PRIVATE KEY"));
        } else {
            panic!("Expected Contains detector for RSA key");
        }
    }

    #[test]
    fn test_keyvalue_detector_has_case_variants() {
        let rule = get_rule("anthropic-api-key-env").unwrap();
        if let Detector::KeyValue { keys, .. } = rule.detector {
            // Should have both uppercase and lowercase variants
            let has_upper = keys.iter().any(|k| k.contains("ANTHROPIC"));
            let has_lower = keys
                .iter()
                .any(|k| k.contains("anthropic") || k.contains("claude"));
            assert!(
                has_upper && has_lower,
                "Should have both case variants: {:?}",
                keys
            );
        } else {
            panic!("Expected KeyValue detector");
        }
    }

    // ========================================================================
    // RULE FILTERING TESTS
    // ========================================================================

    #[test]
    fn test_filter_rules_by_id() {
        let rules = builtin_rules();
        let filtered: Vec<_> = rules.iter().filter(|r| r.id == "github-pat").collect();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, "github-pat");
    }

    #[test]
    fn test_filter_rules_by_multiple_ids() {
        let rules = builtin_rules();
        let target_ids = ["github-pat", "aws-access-key-id", "openai-api-key"];
        let filtered: Vec<_> = rules
            .iter()
            .filter(|r| target_ids.contains(&r.id))
            .collect();
        assert_eq!(filtered.len(), 3);
    }

    #[test]
    fn test_filter_rules_exclude() {
        let rules = builtin_rules();
        let exclude_ids = ["github-pat"];
        let filtered: Vec<_> = rules
            .iter()
            .filter(|r| !exclude_ids.contains(&r.id))
            .collect();
        assert!(filtered.len() > 50); // Should still have many rules
        assert!(!filtered.iter().any(|r| r.id == "github-pat"));
    }

    #[test]
    fn test_filter_nonexistent_rule() {
        let rules = builtin_rules();
        let filtered: Vec<_> = rules
            .iter()
            .filter(|r| r.id == "nonexistent-rule-xyz")
            .collect();
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_filter_by_detector_type() {
        let rules = builtin_rules();
        let prefix_rules: Vec<_> = rules
            .iter()
            .filter(|r| matches!(r.detector, Detector::Prefix { .. }))
            .collect();
        let keyvalue_rules: Vec<_> = rules
            .iter()
            .filter(|r| matches!(r.detector, Detector::KeyValue { .. }))
            .collect();
        let contains_rules: Vec<_> = rules
            .iter()
            .filter(|r| matches!(r.detector, Detector::Contains { .. }))
            .collect();

        assert!(!prefix_rules.is_empty());
        assert!(!keyvalue_rules.is_empty());
        assert!(!contains_rules.is_empty());
    }

    // ========================================================================
    // RULE COVERAGE TESTS
    // ========================================================================

    #[test]
    fn test_all_ai_providers_covered() {
        // Major AI providers should all be covered
        let ai_providers = [
            "openai-api-key",
            "anthropic-api-key",
            "gcp-api-key",
            "groq-api-key",
            "huggingface-token",
            "replicate-token",
            "cohere-api-key",
            "perplexity-api-key",
        ];
        for id in &ai_providers {
            assert!(has_rule(id), "Missing AI provider rule: {}", id);
        }
    }

    #[test]
    fn test_all_cloud_providers_covered() {
        // Major cloud providers should all be covered
        let cloud_providers = [
            "aws-access-key-id",
            "gcp-api-key",
            "digitalocean-token",
            "heroku-api-key",
            "vercel-api-token",
        ];
        for id in &cloud_providers {
            assert!(has_rule(id), "Missing cloud provider rule: {}", id);
        }
    }

    #[test]
    fn test_all_payment_providers_covered() {
        // Major payment providers should all be covered
        let payment_providers = [
            "stripe-secret-key",
            "paypal-client-id",
            "square-access-token",
        ];
        for id in &payment_providers {
            assert!(has_rule(id), "Missing payment provider rule: {}", id);
        }
    }

    // ========================================================================
    // MIN_LEN VALIDATION TESTS
    // ========================================================================

    #[test]
    fn test_min_len_not_zero() {
        let rules = builtin_rules();
        for rule in &rules {
            match &rule.detector {
                Detector::Prefix { min_len, .. } => {
                    assert!(*min_len > 0, "Rule {} has zero min_len", rule.id);
                }
                Detector::KeyValue { min_value_len, .. } => {
                    assert!(
                        *min_value_len > 0,
                        "Rule {} has zero min_value_len",
                        rule.id
                    );
                }
                _ => {}
            }
        }
    }

    #[test]
    fn test_prefix_min_len_greater_than_prefix_len() {
        let rules = builtin_rules();
        for rule in &rules {
            if let Detector::Prefix {
                prefix, min_len, ..
            } = &rule.detector
            {
                assert!(
                    *min_len > prefix.len(),
                    "Rule {} min_len ({}) should be > prefix len ({})",
                    rule.id,
                    min_len,
                    prefix.len()
                );
            }
        }
    }

    // ========================================================================
    // CHARSET COPY TRAIT TEST
    // ========================================================================

    #[test]
    fn test_charset_is_copy() {
        let charset = Charset::AlphaNum;
        let charset_copy = charset; // This should work because Charset is Copy
        assert!(charset.matches('a'));
        assert!(charset_copy.matches('a'));
    }
}
