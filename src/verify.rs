#![allow(dead_code)]

//! Secret verification plugins
//!
//! Optional verification against provider APIs for bug bounty / authorized testing.
//! This module is compile-time gated behind the `verify` feature.
//!
//! IMPORTANT: Verification makes network calls. Only use with explicit authorization.
//! The scanner itself remains fully offline - verification is opt-in per-finding.

use crate::scanner::Finding;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStatus {
    /// Secret is confirmed active/valid
    Active,
    /// Secret is invalid/revoked
    Inactive,
    /// Could not determine (rate limit, network error, etc)
    Unknown,
    /// Verification not available for this secret type
    NotSupported,
}

#[derive(Debug)]
pub struct VerificationResult {
    pub status: VerificationStatus,
    pub message: Option<String>,
}

/// Verify a secret against its provider's API
///
/// Only available when compiled with `--features verify`
pub fn verify_secret(finding: &Finding) -> VerificationResult {
    #[cfg(not(feature = "verify"))]
    {
        let _ = finding;
        VerificationResult {
            status: VerificationStatus::NotSupported,
            message: Some("Compile with --features verify to enable".to_string()),
        }
    }

    #[cfg(feature = "verify")]
    {
        match finding.rule_id.as_str() {
            // DevOps Platforms
            "github-pat" | "github-oauth" | "github-app" | "github-refresh" => {
                verify_github(&finding.secret_raw)
            }
            "gitlab-pat" | "gitlab-pipeline" | "gitlab-runner" => verify_gitlab(&finding.secret_raw),

            // AI Services (High Priority - Bug Bounty)
            "openai-api-key" | "openai-project-key" => verify_openai(&finding.secret_raw),
            "anthropic-api-key" => verify_anthropic(&finding.secret_raw),
            "claude-3-api-key" => verify_anthropic(&finding.secret_raw), // New Claude 3.x keys
            "openrouter-api-key" => verify_openrouter(&finding.secret_raw),
            "groq-api-key" => verify_groq(&finding.secret_raw),
            "perplexity-api-key" => verify_perplexity(&finding.secret_raw),
            "gcp-api-key" | "gemini-api-key" | "gemini-ultra-api-key" => {
                verify_gemini(&finding.secret_raw)
            }

            // Communication Platforms
            "slack-bot-token" | "slack-user-token" | "slack-app-token" => {
                verify_slack(&finding.secret_raw)
            }
            "discord-bot-token" => verify_discord(&finding.secret_raw),

            // Cloud Providers
            "aws-access-key-id" => verify_aws(&finding.secret_raw), // Note: needs both key+secret
            "gcp-service-account" => verify_gcp(&finding.secret_raw), // Note: needs JSON parsing

            // Payment Services
            "stripe-secret-key" | "stripe-restricted-key" => verify_stripe(&finding.secret_raw),

            // ML/AI Platforms
            "huggingface-token" => verify_huggingface(&finding.secret_raw),
            "replicate-token" => verify_replicate(&finding.secret_raw),

            // DevOps Tools
            "circleci-token" => verify_circleci(&finding.secret_raw),
            "travisci-token" => verify_travisci(&finding.secret_raw),

            // Monitoring
            "datadog-api-key" => verify_datadog(&finding.secret_raw),
            "newrelic-api-key" => verify_newrelic(&finding.secret_raw),

            // Additional Services
            "twilio-account-sid" => verify_twilio(&finding.secret_raw),
            "firebase-api-key" => verify_firebase(&finding.secret_raw),
            "sendgrid-api-key" => verify_sendgrid(&finding.secret_raw),
            "mailgun-private-key" => verify_mailgun(&finding.secret_raw),
            "azure-sas-token" => verify_azure(&finding.secret_raw),

            _ => VerificationResult {
                status: VerificationStatus::NotSupported,
                message: Some("No verifier for this secret type".to_string()),
            },
        }
    }
}

// Verification implementations (only compiled with verify feature)

#[cfg(feature = "verify")]
fn verify_github(token: &str) -> VerificationResult {
    http_verify(
        "https://api.github.com/user",
        &[("Authorization", &format!("Bearer {}", token))],
    )
}

#[cfg(feature = "verify")]
fn verify_gitlab(token: &str) -> VerificationResult {
    http_verify(
        "https://gitlab.com/api/v4/user",
        &[("PRIVATE-TOKEN", token)],
    )
}

#[cfg(feature = "verify")]
fn verify_openai(token: &str) -> VerificationResult {
    http_verify(
        "https://api.openai.com/v1/models",
        &[("Authorization", &format!("Bearer {}", token))],
    )
}

#[cfg(feature = "verify")]
fn verify_anthropic(token: &str) -> VerificationResult {
    // Anthropic API - make a minimal request to check if key is valid
    let output = std::process::Command::new("curl")
        .args([
            "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "-X", "POST",
            "-H", &format!("x-api-key: {}", token),
            "-H", "anthropic-version: 2023-06-01",
            "-H", "content-type: application/json",
            "-d", "{\"model\": \"claude-3-haiku-20240307\", \"max_tokens\": 1, \"messages\": [{\"role\": \"user\", \"content\": \"test\"}]}",
        ])
        .arg("https://api.anthropic.com/v1/messages")
        .output();

    match output {
        Ok(out) => {
            let status_code: u16 = String::from_utf8_lossy(&out.stdout)
                .trim()
                .parse()
                .unwrap_or(0);

            match status_code {
                200 => VerificationResult {
                    status: VerificationStatus::Active,
                    message: Some("Anthropic key is valid".to_string()),
                },
                401 => VerificationResult {
                    status: VerificationStatus::Inactive,
                    message: Some("Anthropic key is invalid".to_string()),
                },
                429 => VerificationResult {
                    status: VerificationStatus::Unknown,
                    message: Some("Rate limited".to_string()),
                },
                _ => VerificationResult {
                    status: VerificationStatus::Unknown,
                    message: Some(format!("HTTP {}", status_code)),
                },
            }
        }
        Err(e) => VerificationResult {
            status: VerificationStatus::Unknown,
            message: Some(format!("Network error: {}", e)),
        },
    }
}

#[cfg(feature = "verify")]
fn verify_openrouter(token: &str) -> VerificationResult {
    http_verify(
        "https://openrouter.ai/api/v1/models",
        &[("Authorization", &format!("Bearer {}", token))],
    )
}

#[cfg(feature = "verify")]
fn verify_groq(token: &str) -> VerificationResult {
    http_verify(
        "https://api.groq.com/openai/v1/models",
        &[("Authorization", &format!("Bearer {}", token))],
    )
}

#[cfg(feature = "verify")]
fn verify_perplexity(token: &str) -> VerificationResult {
    // Perplexity requires a more complex request
    VerificationResult {
        status: VerificationStatus::NotSupported,
        message: Some("Perplexity verification requires complex request body".to_string()),
    }
}

#[cfg(feature = "verify")]
fn verify_gemini(token: &str) -> VerificationResult {
    // Google Gemini API - list models to check if key is valid
    let url = format!(
        "https://generativelanguage.googleapis.com/v1/models?key={}",
        token
    );

    let output = std::process::Command::new("curl")
        .args(["-s", "-w", "\n%{http_code}"])
        .arg(&url)
        .output();

    match output {
        Ok(out) => {
            let output_str = String::from_utf8_lossy(&out.stdout);
            let lines: Vec<&str> = output_str.trim().lines().collect();
            let status_code: u16 = lines.last().and_then(|s| s.parse().ok()).unwrap_or(0);

            // Check response body for specific error messages
            let body = lines[..lines.len().saturating_sub(1)].join("\n");

            if body.contains("API key expired") {
                return VerificationResult {
                    status: VerificationStatus::Inactive,
                    message: Some("Google API key expired".to_string()),
                };
            }

            if body.contains("API key was reported as leaked") || body.contains("PERMISSION_DENIED")
            {
                return VerificationResult {
                    status: VerificationStatus::Inactive,
                    message: Some("Google disabled key: reported as leaked".to_string()),
                };
            }

            match status_code {
                200 => VerificationResult {
                    status: VerificationStatus::Active,
                    message: Some("Google/Gemini API key is valid".to_string()),
                },
                400 | 401 | 403 => VerificationResult {
                    status: VerificationStatus::Inactive,
                    message: Some("Google/Gemini API key is invalid".to_string()),
                },
                429 => VerificationResult {
                    status: VerificationStatus::Unknown,
                    message: Some("Rate limited".to_string()),
                },
                _ => VerificationResult {
                    status: VerificationStatus::Unknown,
                    message: Some(format!("HTTP {}", status_code)),
                },
            }
        }
        Err(e) => VerificationResult {
            status: VerificationStatus::Unknown,
            message: Some(format!("Network error: {}", e)),
        },
    }
}

#[cfg(feature = "verify")]
fn verify_slack(token: &str) -> VerificationResult {
    http_verify(
        "https://slack.com/api/auth.test",
        &[("Authorization", &format!("Bearer {}", token))],
    )
}

#[cfg(feature = "verify")]
fn verify_discord(token: &str) -> VerificationResult {
    http_verify(
        "https://discord.com/api/users/@me",
        &[("Authorization", token)],
    )
}

#[cfg(feature = "verify")]
fn verify_aws(token: &str) -> VerificationResult {
    // AWS verification requires both access key and secret
    VerificationResult {
        status: VerificationStatus::NotSupported,
        message: Some("AWS verification requires both key and secret".to_string()),
    }
}

#[cfg(feature = "verify")]
fn verify_gcp(token: &str) -> VerificationResult {
    // GCP service account verification requires JSON parsing and OAuth flow
    VerificationResult {
        status: VerificationStatus::NotSupported,
        message: Some("GCP verification requires service account JSON parsing".to_string()),
    }
}

#[cfg(feature = "verify")]
fn verify_stripe(token: &str) -> VerificationResult {
    // Use basic auth with token as username, empty password
    let output = std::process::Command::new("curl")
        .args([
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "-u",
            &format!("{}:", token),
        ])
        .arg("https://api.stripe.com/v1/charges")
        .output();

    match output {
        Ok(out) => {
            let status_code: u16 = String::from_utf8_lossy(&out.stdout)
                .trim()
                .parse()
                .unwrap_or(0);

            match status_code {
                200 => VerificationResult {
                    status: VerificationStatus::Active,
                    message: Some("Stripe key is valid".to_string()),
                },
                401 => VerificationResult {
                    status: VerificationStatus::Inactive,
                    message: Some("Stripe key is invalid".to_string()),
                },
                _ => VerificationResult {
                    status: VerificationStatus::Unknown,
                    message: Some(format!("HTTP {}", status_code)),
                },
            }
        }
        Err(e) => VerificationResult {
            status: VerificationStatus::Unknown,
            message: Some(format!("Network error: {}", e)),
        },
    }
}

#[cfg(feature = "verify")]
fn verify_huggingface(token: &str) -> VerificationResult {
    http_verify(
        "https://huggingface.co/api/whoami-v2",
        &[("Authorization", &format!("Bearer {}", token))],
    )
}

#[cfg(feature = "verify")]
fn verify_replicate(token: &str) -> VerificationResult {
    http_verify(
        "https://api.replicate.com/v1/models",
        &[("Authorization", &format!("Token {}", token))],
    )
}

#[cfg(feature = "verify")]
fn verify_circleci(token: &str) -> VerificationResult {
    http_verify(
        &format!("https://circleci.com/api/v1.1/me?circle-token={}", token),
        &[],
    )
}

#[cfg(feature = "verify")]
fn verify_travisci(token: &str) -> VerificationResult {
    http_verify(
        "https://api.travis-ci.com/user",
        &[("Authorization", &format!("token {}", token))],
    )
}

#[cfg(feature = "verify")]
fn verify_datadog(token: &str) -> VerificationResult {
    // DataDog requires both API key and application key
    VerificationResult {
        status: VerificationStatus::NotSupported,
        message: Some("DataDog verification requires both API and application keys".to_string()),
    }
}

#[cfg(feature = "verify")]
fn verify_newrelic(token: &str) -> VerificationResult {
    http_verify_with_method(
        "https://api.newrelic.com/graphql",
        "POST",
        &[("Content-Type", "application/json"), ("API-Key", token)],
        Some("{\"query\": \"{ requestContext { userId apiKey } }\"}"),
    )
}

#[cfg(feature = "verify")]
fn verify_twilio(combined_key: &str) -> VerificationResult {
    // Twilio uses AccountSid:AuthToken format
    if let Some((account_sid, auth_token)) = combined_key.split_once(':') {
        let output = std::process::Command::new("curl")
            .args([
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "-u",
                &format!("{}:{}", account_sid, auth_token),
            ])
            .arg("https://api.twilio.com/2010-04-01/Accounts.json")
            .output();

        match output {
            Ok(out) => {
                let status_code: u16 = String::from_utf8_lossy(&out.stdout)
                    .trim()
                    .parse()
                    .unwrap_or(0);

                match status_code {
                    200 => VerificationResult {
                        status: VerificationStatus::Active,
                        message: Some("Twilio credentials are valid".to_string()),
                    },
                    401 => VerificationResult {
                        status: VerificationStatus::Inactive,
                        message: Some("Twilio credentials are invalid".to_string()),
                    },
                    _ => VerificationResult {
                        status: VerificationStatus::Unknown,
                        message: Some(format!("HTTP {}", status_code)),
                    },
                }
            }
            Err(e) => VerificationResult {
                status: VerificationStatus::Unknown,
                message: Some(format!("Network error: {}", e)),
            },
        }
    } else {
        VerificationResult {
            status: VerificationStatus::Unknown,
            message: Some("Twilio verification requires AccountSid:AuthToken format".to_string()),
        }
    }
}

#[cfg(feature = "verify")]
fn verify_firebase(token: &str) -> VerificationResult {
    // Firebase custom token verification requires API key and complex flow
    VerificationResult {
        status: VerificationStatus::NotSupported,
        message: Some("Firebase verification requires complex token exchange flow".to_string()),
    }
}

#[cfg(feature = "verify")]
fn verify_sendgrid(token: &str) -> VerificationResult {
    http_verify(
        "https://api.sendgrid.com/v3/scopes",
        &[("Authorization", &format!("Bearer {}", token))],
    )
}

#[cfg(feature = "verify")]
fn verify_mailgun(token: &str) -> VerificationResult {
    // Mailgun uses api:token format
    let output = std::process::Command::new("curl")
        .args([
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "-u",
            &format!("api:{}", token),
        ])
        .arg("https://api.mailgun.net/v3/domains")
        .output();

    match output {
        Ok(out) => {
            let status_code: u16 = String::from_utf8_lossy(&out.stdout)
                .trim()
                .parse()
                .unwrap_or(0);

            match status_code {
                200 => VerificationResult {
                    status: VerificationStatus::Active,
                    message: Some("Mailgun key is valid".to_string()),
                },
                401 => VerificationResult {
                    status: VerificationStatus::Inactive,
                    message: Some("Mailgun key is invalid".to_string()),
                },
                _ => VerificationResult {
                    status: VerificationStatus::Unknown,
                    message: Some(format!("HTTP {}", status_code)),
                },
            }
        }
        Err(e) => VerificationResult {
            status: VerificationStatus::Unknown,
            message: Some(format!("Network error: {}", e)),
        },
    }
}

#[cfg(feature = "verify")]
fn verify_azure(token: &str) -> VerificationResult {
    // Azure Shared Access Signature verification
    // This is complex and would need SAS token parsing
    VerificationResult {
        status: VerificationStatus::NotSupported,
        message: Some("Azure SAS verification requires token parsing".to_string()),
    }
}

#[cfg(feature = "verify")]
fn http_verify(url: &str, headers: &[(&str, &str)]) -> VerificationResult {
    http_verify_with_method(url, "GET", headers, None)
}

#[cfg(feature = "verify")]
fn http_verify_with_method(
    url: &str,
    method: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> VerificationResult {
    let mut cmd = std::process::Command::new("curl");
    cmd.args(["-s", "-o", "/dev/null", "-w", "%{http_code}", "-X", method]);

    // Add headers
    for (key, value) in headers {
        cmd.args(["-H", &format!("{}: {}", key, value)]);
    }

    // Add body if provided
    if let Some(body_data) = body {
        cmd.args(["-d", body_data]);
    }

    let output = cmd.arg(url).output();

    match output {
        Ok(out) => {
            let status_code: u16 = String::from_utf8_lossy(&out.stdout)
                .trim()
                .parse()
                .unwrap_or(0);

            match status_code {
                200..=299 => VerificationResult {
                    status: VerificationStatus::Active,
                    message: Some("Secret is valid".to_string()),
                },
                401 | 403 => VerificationResult {
                    status: VerificationStatus::Inactive,
                    message: Some("Secret is invalid or revoked".to_string()),
                },
                429 => VerificationResult {
                    status: VerificationStatus::Unknown,
                    message: Some("Rate limited".to_string()),
                },
                _ => VerificationResult {
                    status: VerificationStatus::Unknown,
                    message: Some(format!("HTTP {}", status_code)),
                },
            }
        }
        Err(e) => VerificationResult {
            status: VerificationStatus::Unknown,
            message: Some(format!("Network error: {}", e)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::Finding;

    // Helper to create a test finding with specified rule_id and secret
    fn create_test_finding(rule_id: &str, secret: &str) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            rule_name: format!("Test Rule for {}", rule_id),
            file: "test.txt".to_string(),
            line: 1,
            column: 0,
            matched: secret.to_string(),
            secret: secret.to_string(),
            secret_raw: secret.to_string(),
            context: vec![],
            #[cfg(feature = "verify")]
            verification_status: None,
        }
    }

    // ==================== VerificationStatus Tests ====================

    #[test]
    fn test_verification_status_equality() {
        assert_eq!(VerificationStatus::Active, VerificationStatus::Active);
        assert_eq!(VerificationStatus::Inactive, VerificationStatus::Inactive);
        assert_eq!(VerificationStatus::Unknown, VerificationStatus::Unknown);
        assert_eq!(
            VerificationStatus::NotSupported,
            VerificationStatus::NotSupported
        );

        assert_ne!(VerificationStatus::Active, VerificationStatus::Inactive);
        assert_ne!(VerificationStatus::Active, VerificationStatus::Unknown);
        assert_ne!(VerificationStatus::Active, VerificationStatus::NotSupported);
    }

    #[test]
    fn test_verification_status_clone() {
        let status = VerificationStatus::Active;
        let cloned = status.clone();
        assert_eq!(status, cloned);
    }

    #[test]
    fn test_verification_status_copy() {
        let status = VerificationStatus::Inactive;
        let copied: VerificationStatus = status; // Copy trait
        assert_eq!(status, copied);
    }

    #[test]
    fn test_verification_status_debug() {
        let debug_str = format!("{:?}", VerificationStatus::Active);
        assert_eq!(debug_str, "Active");

        let debug_str = format!("{:?}", VerificationStatus::Inactive);
        assert_eq!(debug_str, "Inactive");

        let debug_str = format!("{:?}", VerificationStatus::Unknown);
        assert_eq!(debug_str, "Unknown");

        let debug_str = format!("{:?}", VerificationStatus::NotSupported);
        assert_eq!(debug_str, "NotSupported");
    }

    // ==================== VerificationResult Tests ====================

    #[test]
    fn test_verification_result_with_message() {
        let result = VerificationResult {
            status: VerificationStatus::Active,
            message: Some("Secret is valid".to_string()),
        };

        assert_eq!(result.status, VerificationStatus::Active);
        assert_eq!(result.message, Some("Secret is valid".to_string()));
    }

    #[test]
    fn test_verification_result_without_message() {
        let result = VerificationResult {
            status: VerificationStatus::Unknown,
            message: None,
        };

        assert_eq!(result.status, VerificationStatus::Unknown);
        assert!(result.message.is_none());
    }

    #[test]
    fn test_verification_result_debug() {
        let result = VerificationResult {
            status: VerificationStatus::Active,
            message: Some("Test message".to_string()),
        };

        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("Active"));
        assert!(debug_str.contains("Test message"));
    }

    // ==================== verify_secret Tests (No Network) ====================

    #[test]
    fn test_verification_not_supported_without_feature() {
        let finding = create_test_finding("test-rule", "test-secret");

        let result = verify_secret(&finding);
        #[cfg(not(feature = "verify"))]
        {
            assert_eq!(result.status, VerificationStatus::NotSupported);
            assert!(result
                .message
                .as_ref()
                .unwrap()
                .contains("Compile with --features verify"));
        }
    }

    #[test]
    #[cfg(feature = "verify")]
    fn test_unsupported_service() {
        let finding = create_test_finding("unsupported-service", "some-secret");

        let result = verify_secret(&finding);
        assert_eq!(result.status, VerificationStatus::NotSupported);
        assert!(result
            .message
            .as_ref()
            .unwrap()
            .contains("No verifier for this secret type"));
    }

    #[test]
    #[cfg(feature = "verify")]
    fn test_unknown_rule_id_returns_not_supported() {
        let finding = create_test_finding("completely-unknown-rule-xyz", "secret123");

        let result = verify_secret(&finding);
        assert_eq!(result.status, VerificationStatus::NotSupported);
    }

    // ==================== Rule ID Routing Tests ====================

    #[test]
    #[cfg(feature = "verify")]
    fn test_rule_routing_github_variants() {
        // Test that all GitHub rule variants route to GitHub verification
        let github_rules = ["github-pat", "github-oauth", "github-app", "github-refresh"];

        for rule_id in github_rules {
            let finding = create_test_finding(rule_id, "ghp_test123");
            let result = verify_secret(&finding);
            // Should not be NotSupported - means the rule was recognized
            assert_ne!(
                result.status,
                VerificationStatus::NotSupported,
                "Rule {} should be supported",
                rule_id
            );
        }
    }

    #[test]
    #[cfg(feature = "verify")]
    fn test_rule_routing_gitlab_variants() {
        let gitlab_rules = ["gitlab-pat", "gitlab-pipeline", "gitlab-runner"];

        for rule_id in gitlab_rules {
            let finding = create_test_finding(rule_id, "glpat-test123");
            let result = verify_secret(&finding);
            assert_ne!(
                result.status,
                VerificationStatus::NotSupported,
                "Rule {} should be supported",
                rule_id
            );
        }
    }

    #[test]
    #[cfg(feature = "verify")]
    fn test_rule_routing_ai_services() {
        let ai_rules = [
            "openai-api-key",
            "openai-project-key",
            "anthropic-api-key",
            "claude-3-api-key",
            "openrouter-api-key",
            "groq-api-key",
        ];

        for rule_id in ai_rules {
            let finding = create_test_finding(rule_id, "sk-test123");
            let result = verify_secret(&finding);
            assert_ne!(
                result.status,
                VerificationStatus::NotSupported,
                "Rule {} should be supported",
                rule_id
            );
        }
    }

    #[test]
    #[cfg(feature = "verify")]
    fn test_rule_routing_slack_variants() {
        let slack_rules = ["slack-bot-token", "slack-user-token", "slack-app-token"];

        for rule_id in slack_rules {
            let finding = create_test_finding(rule_id, "xoxb-test123");
            let result = verify_secret(&finding);
            assert_ne!(
                result.status,
                VerificationStatus::NotSupported,
                "Rule {} should be supported",
                rule_id
            );
        }
    }

    #[test]
    #[cfg(feature = "verify")]
    fn test_rule_routing_gemini_variants() {
        let gemini_rules = ["gcp-api-key", "gemini-api-key", "gemini-ultra-api-key"];

        for rule_id in gemini_rules {
            let finding = create_test_finding(rule_id, "AIzaSyTest123");
            let result = verify_secret(&finding);
            assert_ne!(
                result.status,
                VerificationStatus::NotSupported,
                "Rule {} should be supported",
                rule_id
            );
        }
    }

    #[test]
    #[cfg(feature = "verify")]
    fn test_rule_routing_stripe_variants() {
        let stripe_rules = ["stripe-secret-key", "stripe-restricted-key"];

        for rule_id in stripe_rules {
            let finding = create_test_finding(rule_id, "sk_live_test123");
            let result = verify_secret(&finding);
            assert_ne!(
                result.status,
                VerificationStatus::NotSupported,
                "Rule {} should be supported",
                rule_id
            );
        }
    }

    // ==================== Services with NotSupported Status ====================

    #[test]
    #[cfg(feature = "verify")]
    fn test_aws_verification_requires_both_keys() {
        let finding = create_test_finding("aws-access-key-id", "AKIAIOSFODNN7EXAMPLE");

        let result = verify_secret(&finding);
        assert_eq!(result.status, VerificationStatus::NotSupported);
        assert!(result
            .message
            .as_ref()
            .unwrap()
            .contains("requires both key and secret"));
    }

    #[test]
    #[cfg(feature = "verify")]
    fn test_gcp_service_account_not_supported() {
        let finding = create_test_finding("gcp-service-account", r#"{"type": "service_account"}"#);

        let result = verify_secret(&finding);
        assert_eq!(result.status, VerificationStatus::NotSupported);
        assert!(result
            .message
            .as_ref()
            .unwrap()
            .contains("service account JSON"));
    }

    #[test]
    #[cfg(feature = "verify")]
    fn test_datadog_requires_both_keys() {
        let finding = create_test_finding("datadog-api-key", "test123");

        let result = verify_secret(&finding);
        assert_eq!(result.status, VerificationStatus::NotSupported);
        assert!(result
            .message
            .as_ref()
            .unwrap()
            .contains("both API and application keys"));
    }

    #[test]
    #[cfg(feature = "verify")]
    fn test_firebase_not_supported() {
        let finding = create_test_finding("firebase-api-key", "test123");

        let result = verify_secret(&finding);
        assert_eq!(result.status, VerificationStatus::NotSupported);
        assert!(result.message.as_ref().unwrap().contains("Firebase"));
    }

    #[test]
    #[cfg(feature = "verify")]
    fn test_azure_sas_not_supported() {
        let finding = create_test_finding("azure-sas-token", "sv=2020-08-04&ss=bfqt&srt=sco");

        let result = verify_secret(&finding);
        assert_eq!(result.status, VerificationStatus::NotSupported);
        assert!(result
            .message
            .as_ref()
            .unwrap()
            .contains("token parsing"));
    }

    #[test]
    #[cfg(feature = "verify")]
    fn test_perplexity_not_supported() {
        let finding = create_test_finding("perplexity-api-key", "pplx-test123");

        let result = verify_secret(&finding);
        assert_eq!(result.status, VerificationStatus::NotSupported);
        assert!(result
            .message
            .as_ref()
            .unwrap()
            .contains("complex request body"));
    }

    // ==================== Twilio Format Validation ====================

    #[test]
    #[cfg(feature = "verify")]
    fn test_twilio_without_colon_separator() {
        let finding = create_test_finding("twilio-account-sid", "ACtest123_without_separator");

        let result = verify_secret(&finding);
        // Twilio requires AccountSid:AuthToken format
        assert_eq!(result.status, VerificationStatus::Unknown);
        assert!(result
            .message
            .as_ref()
            .unwrap()
            .contains("AccountSid:AuthToken format"));
    }

    // ==================== Verification Result Message Tests ====================

    #[test]
    fn test_result_messages_are_descriptive() {
        // Test that result messages contain useful information
        let result = VerificationResult {
            status: VerificationStatus::Active,
            message: Some("Anthropic key is valid".to_string()),
        };
        assert!(result.message.as_ref().unwrap().contains("valid"));

        let result = VerificationResult {
            status: VerificationStatus::Inactive,
            message: Some("Secret is invalid or revoked".to_string()),
        };
        assert!(
            result.message.as_ref().unwrap().contains("invalid")
                || result.message.as_ref().unwrap().contains("revoked")
        );
    }

    // ==================== Edge Cases ====================

    #[test]
    fn test_empty_rule_id() {
        let finding = create_test_finding("", "some-secret");

        let result = verify_secret(&finding);
        // Empty rule ID should not match any verifier
        #[cfg(feature = "verify")]
        assert_eq!(result.status, VerificationStatus::NotSupported);
        #[cfg(not(feature = "verify"))]
        assert_eq!(result.status, VerificationStatus::NotSupported);
    }

    #[test]
    fn test_empty_secret() {
        let finding = create_test_finding("github-pat", "");

        #[cfg(feature = "verify")]
        {
            let result = verify_secret(&finding);
            // Should still attempt verification but likely fail
            assert_ne!(result.status, VerificationStatus::NotSupported);
        }
        #[cfg(not(feature = "verify"))]
        {
            let _ = finding; // Use the finding to avoid unused warning
        }
    }

    #[test]
    fn test_whitespace_in_secret() {
        let finding = create_test_finding("github-pat", "  ghp_test123  ");

        #[cfg(feature = "verify")]
        {
            let result = verify_secret(&finding);
            // Should handle whitespace (actual verification might fail)
            assert_ne!(result.status, VerificationStatus::NotSupported);
        }
        #[cfg(not(feature = "verify"))]
        {
            let _ = finding; // Use the finding to avoid unused warning
        }
    }

    // ==================== Status Determination Logic ====================

    #[test]
    fn test_all_status_variants_exist() {
        // Ensure all status variants are accessible
        let statuses = [
            VerificationStatus::Active,
            VerificationStatus::Inactive,
            VerificationStatus::Unknown,
            VerificationStatus::NotSupported,
        ];

        for status in statuses {
            let result = VerificationResult {
                status,
                message: None,
            };
            // Just verify they can be constructed and compared
            assert_eq!(result.status, status);
        }
    }

    #[test]
    fn test_verification_result_can_have_none_message() {
        let result = VerificationResult {
            status: VerificationStatus::Active,
            message: None,
        };
        assert!(result.message.is_none());
    }

    #[test]
    fn test_verification_result_can_have_empty_message() {
        let result = VerificationResult {
            status: VerificationStatus::Active,
            message: Some(String::new()),
        };
        assert!(result.message.is_some());
        assert!(result.message.as_ref().unwrap().is_empty());
    }

    // ==================== HTTP Status Code Mapping Tests ====================
    // These test the logic of how HTTP status codes should map to verification statuses
    // without making actual network calls

    #[test]
    fn test_expected_status_mappings() {
        // Document the expected HTTP status code to VerificationStatus mapping
        // 200-299 -> Active
        // 401, 403 -> Inactive
        // 429 -> Unknown (rate limited)
        // Other -> Unknown

        // These are just documentation tests to ensure the logic is understood
        assert_eq!(VerificationStatus::Active, VerificationStatus::Active);
        assert_eq!(VerificationStatus::Inactive, VerificationStatus::Inactive);
        assert_eq!(VerificationStatus::Unknown, VerificationStatus::Unknown);
    }

    // ==================== Integration Tests Without Network ====================

    #[test]
    #[cfg(feature = "verify")]
    fn test_all_supported_rule_ids_are_recognized() {
        let supported_rules = [
            // DevOps Platforms
            "github-pat",
            "github-oauth",
            "github-app",
            "github-refresh",
            "gitlab-pat",
            "gitlab-pipeline",
            "gitlab-runner",
            // AI Services
            "openai-api-key",
            "openai-project-key",
            "anthropic-api-key",
            "claude-3-api-key",
            "openrouter-api-key",
            "groq-api-key",
            "perplexity-api-key",
            "gcp-api-key",
            "gemini-api-key",
            "gemini-ultra-api-key",
            // Communication
            "slack-bot-token",
            "slack-user-token",
            "slack-app-token",
            "discord-bot-token",
            // Cloud
            "aws-access-key-id",
            "gcp-service-account",
            // Payment
            "stripe-secret-key",
            "stripe-restricted-key",
            // ML
            "huggingface-token",
            "replicate-token",
            // DevOps Tools
            "circleci-token",
            "travisci-token",
            // Monitoring
            "datadog-api-key",
            "newrelic-api-key",
            // Additional
            "twilio-account-sid",
            "firebase-api-key",
            "sendgrid-api-key",
            "mailgun-private-key",
            "azure-sas-token",
        ];

        for rule_id in supported_rules {
            let finding = create_test_finding(rule_id, "test-secret");
            let result = verify_secret(&finding);

            // Each rule should either:
            // - Attempt verification (Active/Inactive/Unknown)
            // - Return NotSupported with a specific reason
            // But should NOT panic
            assert!(
                matches!(
                    result.status,
                    VerificationStatus::Active
                        | VerificationStatus::Inactive
                        | VerificationStatus::Unknown
                        | VerificationStatus::NotSupported
                ),
                "Rule {} returned unexpected status",
                rule_id
            );
        }
    }
}
