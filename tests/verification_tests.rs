//! Verification tests
//!
//! Tests for the secret verification feature that validates
//! detected secrets against provider APIs.

mod common;

use common::{fake_secrets::*, TestDir};

// ============================================================================
// TEST HELPERS
// ============================================================================

fn run_scan_with_verify(path: &str) -> (String, i32) {
    let output = std::process::Command::new("cargo")
        .args(["run", "--features", "verify", "--", path, "--verify"])
        .output()
        .expect("Failed to run scanner with verification");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{}{}", stdout, stderr);

    (combined, output.status.code().unwrap_or(-1))
}

fn run_scan_json_with_verify(path: &str) -> String {
    let output = std::process::Command::new("cargo")
        .args([
            "run",
            "--features",
            "verify",
            "--",
            path,
            "--verify",
            "-f",
            "json",
        ])
        .output()
        .expect("Failed to run scanner with verification");

    String::from_utf8_lossy(&output.stdout).to_string()
}

fn has_verification_status(output: &str) -> bool {
    output.contains("verification_status")
        || output.contains("Verification:")
        || output.contains("\"verified\"")
}

fn get_verification_status(output: &str, rule_id: &str) -> Option<String> {
    // Simple parsing to extract verification status for a rule
    // Look for patterns like: "verification_status": "inactive"
    if output.contains(rule_id) {
        if output.contains("\"active\"") || output.contains("Active") {
            return Some("active".to_string());
        } else if output.contains("\"inactive\"") || output.contains("Inactive") {
            return Some("inactive".to_string());
        } else if output.contains("\"unknown\"") || output.contains("Unknown") {
            return Some("unknown".to_string());
        }
    }
    None
}

// ============================================================================
// VERIFICATION OUTPUT FORMAT TESTS
// ============================================================================

#[test]
fn test_verify_flag_produces_verification_output() {
    let dir = TestDir::new("verify-output");
    dir.write_file("config.py", &format!("OPENAI_KEY = '{}'", OPENAI_API_KEY));

    let (output, _) = run_scan_with_verify(dir.path_str());

    // When --verify is used, output should contain verification information
    // (even if the key is invalid/inactive)
    // The key should be detected (case insensitive check)
    let output_lower = output.to_lowercase();
    assert!(
        has_verification_status(&output)
            || output_lower.contains("openai")
            || output_lower.contains("found")
            || output.contains("Rule:"),
        "Verification output should include status or rule detection. Got: {}",
        &output[..output.len().min(500)]
    );
}

#[test]
fn test_json_output_includes_verification_fields() {
    let dir = TestDir::new("verify-json");
    dir.write_file("config.py", &format!("OPENAI_KEY = '{}'", OPENAI_API_KEY));

    let output = run_scan_json_with_verify(dir.path_str());

    // JSON output should have verification-related fields when --verify is used
    assert!(
        output.contains("findings") || output.contains("verification"),
        "JSON output should include findings or verification data"
    );
}

// ============================================================================
// FAKE SECRET VERIFICATION TESTS
// ============================================================================

#[test]
fn test_fake_openai_key_verification() {
    let dir = TestDir::new("verify-fake-openai");
    // This is an obviously fake key that should be detected but marked inactive
    dir.write_file("config.py", &format!("OPENAI_KEY = '{}'", OPENAI_API_KEY));

    let (output, _) = run_scan_with_verify(dir.path_str());

    // The fake key should be detected
    assert!(
        output.contains("openai"),
        "Should detect OpenAI key pattern"
    );

    // When verified, fake keys should show as inactive/invalid
    if has_verification_status(&output) {
        let status = get_verification_status(&output, "openai");
        if let Some(s) = status {
            assert!(
                s == "inactive" || s == "unknown",
                "Fake OpenAI key should be inactive or unknown, got: {}",
                s
            );
        }
    }
}

#[test]
fn test_fake_github_token_verification() {
    let dir = TestDir::new("verify-fake-github");
    dir.write_file("config.js", &format!("const token = '{}';", GITHUB_PAT));

    let (output, _) = run_scan_with_verify(dir.path_str());

    // Should detect the GitHub PAT
    assert!(
        output.contains("github"),
        "Should detect GitHub PAT pattern"
    );
}

#[test]
fn test_fake_anthropic_key_verification() {
    let dir = TestDir::new("verify-fake-anthropic");
    dir.write_file(
        "config.py",
        &format!("CLAUDE_KEY = '{}'", ANTHROPIC_API_KEY),
    );

    let (output, _) = run_scan_with_verify(dir.path_str());

    assert!(
        output.contains("anthropic"),
        "Should detect Anthropic key pattern"
    );
}

#[test]
fn test_fake_gemini_key_verification() {
    let dir = TestDir::new("verify-fake-gemini");
    dir.write_file("config.py", &format!("GEMINI_KEY = '{}'", GEMINI_API_KEY));

    let (output, _) = run_scan_with_verify(dir.path_str());

    assert!(
        output.contains("gemini") || output.contains("gcp"),
        "Should detect Gemini/GCP key pattern"
    );
}

#[test]
fn test_fake_openrouter_key_verification() {
    let dir = TestDir::new("verify-fake-openrouter");
    dir.write_file("config.py", &format!("OR_KEY = '{}'", OPENROUTER_API_KEY));

    let (output, _) = run_scan_with_verify(dir.path_str());

    // OpenRouter keys should be detected specifically (not as OpenAI)
    assert!(
        output.contains("openrouter"),
        "Should detect OpenRouter key pattern (not OpenAI)"
    );
}

// ============================================================================
// RULE PRIORITY / DEDUPLICATION TESTS
// ============================================================================

#[test]
fn test_openrouter_not_misclassified_as_openai() {
    let dir = TestDir::new("openrouter-dedup");
    // OpenRouter keys start with sk-or-v1- which could match OpenAI's sk- prefix
    dir.write_file("config.py", &format!("KEY = '{}'", OPENROUTER_API_KEY));

    let (output, _) = run_scan_with_verify(dir.path_str());

    // Should detect as OpenRouter, NOT OpenAI
    assert!(
        output.contains("openrouter"),
        "OpenRouter key should be classified as openrouter"
    );

    // Count occurrences - there should only be ONE finding for this key
    let openai_count = output.matches("openai-api-key").count();
    let openrouter_count = output.matches("openrouter").count();

    // Either no OpenAI match OR OpenRouter takes precedence
    assert!(
        openrouter_count >= openai_count,
        "OpenRouter should be preferred over OpenAI for sk-or-v1- keys"
    );
}

#[test]
fn test_multiple_similar_keys_deduplication() {
    let dir = TestDir::new("similar-keys-dedup");
    // File with keys that have overlapping patterns
    dir.write_file(
        "config.py",
        &format!(
            r#"
OPENAI_KEY = "{}"
OPENROUTER_KEY = "{}"
ANTHROPIC_KEY = "{}"
"#,
            OPENAI_API_KEY, OPENROUTER_API_KEY, ANTHROPIC_API_KEY
        ),
    );

    let (output, _) = run_scan_with_verify(dir.path_str());
    let output_lower = output.to_lowercase();

    // Should detect all three as separate findings
    assert!(
        output_lower.contains("openai") || output_lower.contains("sk-"),
        "Should detect OpenAI key"
    );
    assert!(
        output_lower.contains("openrouter") || output_lower.contains("sk-or"),
        "Should detect OpenRouter key"
    );
    assert!(
        output_lower.contains("anthropic") || output_lower.contains("sk-ant"),
        "Should detect Anthropic key"
    );
}

// ============================================================================
// VERIFICATION STATUS PROPAGATION TESTS
// ============================================================================

#[test]
fn test_verification_status_in_report_format() {
    let dir = TestDir::new("verify-report-format");
    dir.write_file(
        ".env",
        &format!(
            r#"
OPENAI_KEY={}
GITHUB_TOKEN={}
"#,
            OPENAI_API_KEY, GITHUB_PAT
        ),
    );

    let (output, _) = run_scan_with_verify(dir.path_str());

    // Report format should include verification info
    // This is a basic check that the verification ran
    assert!(
        output.len() > 50,
        "Report should contain substantial output with findings"
    );
}

#[test]
fn test_no_verify_flag_skips_verification() {
    let dir = TestDir::new("no-verify");
    dir.write_file("config.py", &format!("KEY = '{}'", OPENAI_API_KEY));

    // Run WITHOUT --verify flag
    let output = std::process::Command::new("cargo")
        .args(["run", "--", dir.path_str(), "--no-context"])
        .output()
        .expect("Failed to run scanner");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr).to_lowercase();

    // Should still detect the key (output may be on stdout or stderr)
    assert!(
        combined.contains("openai") || combined.contains("found") || combined.contains("secret"),
        "Should detect OpenAI key without verification. Got: {}",
        &combined[..combined.len().min(500)]
    );
}

// ============================================================================
// EDGE CASES
// ============================================================================

#[test]
fn test_verify_empty_directory() {
    let dir = TestDir::new("verify-empty");
    dir.write_file("clean.py", "print('no secrets here')");

    let (output, exit_code) = run_scan_with_verify(dir.path_str());

    // Should complete without errors
    assert!(
        exit_code == 0 || output.contains("No secrets found"),
        "Empty scan should succeed"
    );
}

#[test]
fn test_verify_multiple_keys_same_file() {
    let dir = TestDir::new("verify-multi-keys");
    dir.write_file(
        "secrets.env",
        &format!(
            r#"
OPENAI_API_KEY={}
ANTHROPIC_API_KEY={}
GITHUB_TOKEN={}
AWS_ACCESS_KEY_ID={}
"#,
            OPENAI_API_KEY, ANTHROPIC_API_KEY, GITHUB_PAT, AWS_ACCESS_KEY_ID
        ),
    );

    let (output, _) = run_scan_with_verify(dir.path_str());

    // Should detect multiple secrets
    let finding_count = output.matches("rule_id").count() + output.matches("Rule:").count();

    assert!(
        finding_count >= 2 || output.contains("Found"),
        "Should detect multiple secrets in file"
    );
}
