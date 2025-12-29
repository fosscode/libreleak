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
                verify_github(&finding.secret)
            }
            "gitlab-pat" | "gitlab-pipeline" | "gitlab-runner" => verify_gitlab(&finding.secret),

            // AI Services (High Priority - Bug Bounty)
            "openai-api-key" | "openai-project-key" => verify_openai(&finding.secret),
            "anthropic-api-key" => verify_anthropic(&finding.secret),
            "claude-3-api-key" => verify_anthropic(&finding.secret), // New Claude 3.x keys
            "openrouter-api-key" => verify_openrouter(&finding.secret),
            "groq-api-key" => verify_groq(&finding.secret),
            "perplexity-api-key" => verify_perplexity(&finding.secret),
            "gcp-api-key" | "gemini-api-key" | "gemini-ultra-api-key" => {
                verify_gemini(&finding.secret)
            }

            // Communication Platforms
            "slack-bot-token" | "slack-user-token" | "slack-app-token" => {
                verify_slack(&finding.secret)
            }
            "discord-bot-token" => verify_discord(&finding.secret),

            // Cloud Providers
            "aws-access-key-id" => verify_aws(&finding.secret), // Note: needs both key+secret
            "gcp-service-account" => verify_gcp(&finding.secret), // Note: needs JSON parsing

            // Payment Services
            "stripe-secret-key" | "stripe-restricted-key" => verify_stripe(&finding.secret),

            // ML/AI Platforms
            "huggingface-token" => verify_huggingface(&finding.secret),
            "replicate-token" => verify_replicate(&finding.secret),

            // DevOps Tools
            "circleci-token" => verify_circleci(&finding.secret),
            "travisci-token" => verify_travisci(&finding.secret),

            // Monitoring
            "datadog-api-key" => verify_datadog(&finding.secret),
            "newrelic-api-key" => verify_newrelic(&finding.secret),

            // Additional Services
            "twilio-account-sid" => verify_twilio(&finding.secret),
            "firebase-api-key" => verify_firebase(&finding.secret),
            "sendgrid-api-key" => verify_sendgrid(&finding.secret),
            "mailgun-private-key" => verify_mailgun(&finding.secret),
            "azure-sas-token" => verify_azure(&finding.secret),

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

    #[test]
    fn test_verification_not_supported_without_feature() {
        let finding = Finding {
            rule_id: "test-rule".to_string(),
            rule_name: "Test Rule".to_string(),
            file: "test.txt".to_string(),
            line: 1,
            column: 0,
            matched: "test-secret".to_string(),
            secret: "test-secret".to_string(),
            context: vec![],
            #[cfg(feature = "verify")]
            verification_status: None,
        };

        let result = verify_secret(&finding);
        #[cfg(not(feature = "verify"))]
        assert_eq!(result.status, VerificationStatus::NotSupported);
    }

    #[test]
    #[cfg(feature = "verify")]
    fn test_github_verification_invalid_token() {
        let finding = Finding {
            rule_id: "github-pat".to_string(),
            rule_name: "GitHub Personal Access Token".to_string(),
            file: "test.txt".to_string(),
            line: 1,
            column: 0,
            matched: "ghp_invalid_token_12345".to_string(),
            secret: "ghp_invalid_token_12345".to_string(),
            context: vec![],
            #[cfg(feature = "verify")]
            verification_status: None,
        };

        let result = verify_secret(&finding);
        // Should return Inactive for invalid token (401 response)
        assert_eq!(result.status, VerificationStatus::Inactive);
    }

    #[test]
    #[cfg(feature = "verify")]
    fn test_unsupported_service() {
        let finding = Finding {
            rule_id: "unsupported-service".to_string(),
            rule_name: "Unsupported Service".to_string(),
            file: "test.txt".to_string(),
            line: 1,
            column: 0,
            matched: "some-secret".to_string(),
            secret: "some-secret".to_string(),
            context: vec![],
            #[cfg(feature = "verify")]
            verification_status: None,
        };

        let result = verify_secret(&finding);
        assert_eq!(result.status, VerificationStatus::NotSupported);
    }

    #[test]
    #[cfg(feature = "verify")]
    fn test_openai_verification_structure() {
        // Test that the verification function is properly called
        let finding = Finding {
            rule_id: "openai-api-key".to_string(),
            rule_name: "OpenAI API Key".to_string(),
            file: "test.txt".to_string(),
            line: 1,
            column: 0,
            matched: "sk-invalid-key".to_string(),
            secret: "sk-invalid-key".to_string(),
            context: vec![],
            #[cfg(feature = "verify")]
            verification_status: None,
        };

        let result = verify_secret(&finding);
        // Should attempt verification and likely fail with network error or invalid response
        // We just test that it doesn't panic and returns a reasonable status
        assert!(matches!(
            result.status,
            VerificationStatus::Active | VerificationStatus::Inactive | VerificationStatus::Unknown
        ));
    }
}
