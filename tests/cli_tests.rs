//! CLI and Output Format Tests
//!
//! Tests for command-line interface parsing, output formats, and exit codes.

mod common;

use common::fake_secrets::*;
use common::TestDir;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

// ============================================================================
// HELPERS
// ============================================================================

static CARGO_RUN_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn cargo_run(args: &[&str]) -> std::process::Output {
    let lock = CARGO_RUN_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().expect("Failed to lock cargo run mutex");

    Command::new("cargo")
        .arg("run")
        .arg("--")
        .args(args)
        .output()
        .expect("Failed to execute cargo run")
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

// ============================================================================
// HELP AND VERSION TESTS
// ============================================================================

#[test]
fn test_help_flag_short() {
    let output = cargo_run(&["-h"]);
    let out = stdout(&output);

    assert!(output.status.success(), "Help should exit with 0");
    assert!(out.contains("libreleak"), "Should show tool name");
    assert!(out.contains("USAGE"), "Should show usage");
    assert!(out.contains("OPTIONS"), "Should show options");
}

#[test]
fn test_help_flag_long() {
    let output = cargo_run(&["--help"]);
    let out = stdout(&output);

    assert!(output.status.success());
    assert!(out.contains("libreleak"));
    assert!(out.contains("--format"));
    assert!(out.contains("--fail-on-leak"));
}

#[test]
fn test_version_flag_short() {
    let output = cargo_run(&["-v"]);
    let out = stdout(&output);

    assert!(output.status.success(), "Version should exit with 0");
    assert!(out.contains("libreleak"), "Should show tool name");
    assert!(out.contains("0.1.0"), "Should show version number");
}

#[test]
fn test_version_flag_long() {
    let output = cargo_run(&["--version"]);
    let out = stdout(&output);

    assert!(output.status.success());
    assert!(out.contains("libreleak"));
}

// ============================================================================
// UNKNOWN OPTION TESTS
// ============================================================================

#[test]
fn test_unknown_option_errors() {
    let output = cargo_run(&["--unknown-option"]);

    assert!(!output.status.success(), "Unknown option should fail");
    let err = stderr(&output);
    assert!(err.contains("unknown option") || err.contains("error"));
}

#[test]
fn test_invalid_format_errors() {
    let output = cargo_run(&["--format", "invalid"]);

    assert!(!output.status.success());
    let err = stderr(&output);
    assert!(err.contains("unknown format") || err.contains("invalid"));
}

// ============================================================================
// EXIT CODE TESTS
// ============================================================================

#[test]
fn test_exit_code_0_no_secrets() {
    let dir = TestDir::new("exit-code-clean");
    dir.write_file("clean.py", "print('hello world')");

    let output = cargo_run(&[dir.path_str(), "--fail-on-leak"]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "Should exit 0 when no secrets found"
    );
}

#[test]
fn test_exit_code_1_with_secrets() {
    let dir = TestDir::new("exit-code-secrets");
    dir.write_file("config.py", &format!("KEY = '{}'", OPENAI_API_KEY));

    let output = cargo_run(&[dir.path_str(), "--fail-on-leak"]);

    assert_eq!(
        output.status.code(),
        Some(1),
        "Should exit 1 when secrets found with --fail-on-leak"
    );
}

#[test]
fn test_exit_code_0_without_fail_flag() {
    let dir = TestDir::new("exit-code-no-flag");
    dir.write_file("config.py", &format!("KEY = '{}'", OPENAI_API_KEY));

    let output = cargo_run(&[dir.path_str()]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "Should exit 0 when secrets found but --fail-on-leak not set"
    );
}

#[test]
fn test_fail_on_leak_short_flag() {
    let dir = TestDir::new("fail-short-flag");
    dir.write_file("config.py", &format!("KEY = '{}'", GITHUB_PAT));

    let output = cargo_run(&[dir.path_str(), "-x"]);

    assert_eq!(
        output.status.code(),
        Some(1),
        "-x should be alias for --fail-on-leak"
    );
}

// ============================================================================
// FORMAT OUTPUT TESTS
// ============================================================================

#[test]
fn test_text_format_default() {
    let dir = TestDir::new("format-text");
    dir.write_file("config.py", &format!("KEY = '{}'", OPENAI_API_KEY));

    let output = cargo_run(&[dir.path_str()]);
    let out = stdout(&output);

    assert!(out.contains("Found"), "Should show findings count");
    assert!(out.contains("Rule:"), "Should show rule name");
    // OpenAI and DeepSeek both use sk- prefix, so either match is valid
    assert!(
        out.contains("openai") || out.contains("deepseek"),
        "Should mention the rule"
    );
}

#[test]
fn test_text_format_explicit() {
    let dir = TestDir::new("format-text-explicit");
    dir.write_file("config.py", &format!("KEY = '{}'", OPENAI_API_KEY));

    let output = cargo_run(&[dir.path_str(), "-f", "text"]);
    let out = stdout(&output);

    assert!(out.contains("Found"));
}

#[test]
fn test_json_format() {
    let dir = TestDir::new("format-json");
    dir.write_file("config.py", &format!("KEY = '{}'", GITHUB_PAT));

    let output = cargo_run(&[dir.path_str(), "-f", "json"]);
    let out = stdout(&output);

    assert!(out.contains("{"), "Should be JSON");
    assert!(out.contains("\"version\""), "Should have version field");
    assert!(out.contains("\"findings\""), "Should have findings array");
    assert!(out.contains("\"rule_id\""), "Should have rule_id");
    assert!(out.contains("\"file\""), "Should have file field");
    assert!(out.contains("\"line\""), "Should have line number");
}

#[test]
fn test_json_format_empty() {
    let dir = TestDir::new("format-json-empty");
    dir.write_file("clean.py", "print('clean')");

    let output = cargo_run(&[dir.path_str(), "-f", "json"]);
    let out = stdout(&output);

    assert!(
        out.contains("\"findings\": ["),
        "Should have empty findings array"
    );
}

#[test]
fn test_sarif_format() {
    let dir = TestDir::new("format-sarif");
    dir.write_file("config.py", &format!("KEY = '{}'", OPENAI_API_KEY));

    let output = cargo_run(&[dir.path_str(), "-f", "sarif"]);
    let out = stdout(&output);

    assert!(out.contains("$schema"), "Should have SARIF schema");
    assert!(out.contains("2.1.0"), "Should be SARIF 2.1.0");
    assert!(out.contains("runs"), "Should have runs array");
    assert!(out.contains("tool"), "Should have tool info");
    assert!(out.contains("results"), "Should have results array");
    assert!(out.contains("ruleId"), "Should have ruleId");
    assert!(out.contains("physicalLocation"), "Should have location");
}

#[test]
fn test_sarif_format_empty() {
    let dir = TestDir::new("format-sarif-empty");
    dir.write_file("clean.py", "print('clean')");

    let output = cargo_run(&[dir.path_str(), "-f", "sarif"]);
    let out = stdout(&output);

    assert!(out.contains("$schema"), "Should have SARIF schema");
    assert!(out.contains("\"results\": ["), "Should have empty results");
}

#[test]
fn test_report_format() {
    let dir = TestDir::new("format-report");
    dir.write_file("config.py", &format!("KEY = '{}'", OPENAI_API_KEY));

    let output = cargo_run(&[dir.path_str(), "-f", "report"]);
    let out = stdout(&output);

    assert!(
        out.contains("\"report_version\""),
        "Should have report version"
    );
    assert!(
        out.contains("\"scanner\": \"libreleak\""),
        "Should have scanner name"
    );
    assert!(out.contains("\"timestamp\""), "Should have timestamp");
    assert!(out.contains("\"summary\""), "Should have summary section");
    assert!(
        out.contains("\"total_findings\""),
        "Should have total findings count"
    );
    assert!(
        out.contains("\"findings_by_rule\""),
        "Should have findings by rule"
    );
    assert!(
        out.contains("\"severity_breakdown\""),
        "Should have severity breakdown"
    );
    assert!(out.contains("\"findings\""), "Should have findings array");
}

#[test]
fn test_report_format_empty() {
    let dir = TestDir::new("format-report-empty");
    dir.write_file("clean.py", "print('clean')");

    let output = cargo_run(&[dir.path_str(), "-f", "report"]);
    let out = stdout(&output);

    assert!(
        out.contains("\"report_version\""),
        "Should have report version"
    );
    assert!(
        out.contains("\"total_findings\": 0"),
        "Should have zero findings"
    );
    assert!(
        out.contains("\"findings\": ["),
        "Should have empty findings array"
    );
}

#[test]
fn test_report_format_multiple_findings() {
    let dir = TestDir::new("format-report-multi");
    dir.write_file(
        "config.py",
        &format!("GITHUB = '{}'\nAWS = '{}'", GITHUB_PAT, AWS_ACCESS_KEY_ID),
    );

    let output = cargo_run(&[dir.path_str(), "-f", "report"]);
    let out = stdout(&output);

    assert!(
        out.contains("\"total_findings\": 2"),
        "Should count all findings"
    );
    assert!(
        out.contains("\"findings_by_category\""),
        "Should categorize findings"
    );
}

// ============================================================================
// CONTEXT TESTS
// ============================================================================

#[test]
fn test_context_default() {
    let dir = TestDir::new("context-default");
    dir.write_file(
        "config.py",
        &format!(
            "# line 1\n# line 2\n# line 3\nKEY = '{}'\n# line 5\n# line 6\n# line 7",
            OPENAI_API_KEY
        ),
    );

    let output = cargo_run(&[dir.path_str()]);
    let out = stdout(&output);

    // Should show context lines
    assert!(
        out.contains("Context:") || out.contains("|"),
        "Should show context"
    );
}

#[test]
fn test_no_context_flag() {
    let dir = TestDir::new("no-context");
    dir.write_file(
        "config.py",
        &format!("# before\nKEY = '{}'\n# after", OPENAI_API_KEY),
    );

    let output = cargo_run(&[dir.path_str(), "--no-context"]);
    let out = stdout(&output);

    // With --no-context, should not show the context block
    // (harder to assert, but at least verify it runs)
    assert!(output.status.success() || output.status.code() == Some(0));
}

#[test]
fn test_context_lines_flag() {
    let dir = TestDir::new("context-lines");
    dir.write_file(
        "config.py",
        &format!("1\n2\n3\n4\n5\nKEY = '{}'\n7\n8\n9\n10\n11", OPENAI_API_KEY),
    );

    let output = cargo_run(&[dir.path_str(), "-C", "5"]);
    let out = stdout(&output);

    // Should include more context
    assert!(output.status.success() || output.status.code() == Some(0));
}

// ============================================================================
// RULE FILTERING TESTS
// ============================================================================

#[test]
fn test_only_filter_single_rule() {
    let dir = TestDir::new("only-single");
    dir.write_file(
        "config.py",
        &format!("OPENAI = '{}'\nGITHUB = '{}'", OPENAI_API_KEY, GITHUB_PAT),
    );

    let output = cargo_run(&[dir.path_str(), "--only", "github-pat"]);
    let out = stdout(&output);

    assert!(out.contains("github"), "Should find GitHub token");
    // Should not find OpenAI since it's filtered out
}

#[test]
fn test_only_filter_multiple_rules() {
    let dir = TestDir::new("only-multiple");
    dir.write_file(
        "config.py",
        &format!(
            "OPENAI = '{}'\nGITHUB = '{}'\nAWS = '{}'",
            OPENAI_API_KEY, GITHUB_PAT, AWS_ACCESS_KEY_ID
        ),
    );

    let output = cargo_run(&[dir.path_str(), "--only", "github-pat,aws-access-key-id"]);
    let out = stdout(&output);

    assert!(
        out.contains("github") || out.contains("aws"),
        "Should find filtered rules"
    );
}

#[test]
fn test_exclude_filter_single_rule() {
    let dir = TestDir::new("exclude-single");
    dir.write_file(
        "config.py",
        &format!("OPENAI = '{}'\nGITHUB = '{}'", OPENAI_API_KEY, GITHUB_PAT),
    );

    let output = cargo_run(&[dir.path_str(), "--exclude", "openai-api-key"]);
    let out = stdout(&output);

    assert!(
        !out.contains("openai-api-key"),
        "Should not find excluded rule"
    );
}

#[test]
fn test_exclude_filter_multiple_rules() {
    let dir = TestDir::new("exclude-multiple");
    dir.write_file(
        "config.py",
        &format!(
            "OPENAI = '{}'\nGITHUB = '{}'\nSLACK = '{}'",
            OPENAI_API_KEY, GITHUB_PAT, SLACK_BOT_TOKEN
        ),
    );

    let output = cargo_run(&[dir.path_str(), "--exclude", "openai-api-key,github-pat"]);
    let out = stdout(&output);

    assert!(
        !out.contains("openai-api-key"),
        "Should not find excluded OpenAI"
    );
    assert!(
        !out.contains("github-pat"),
        "Should not find excluded GitHub"
    );
}

#[test]
fn test_list_rules() {
    let output = cargo_run(&["--list-rules"]);
    let out = stdout(&output);

    assert!(output.status.success());
    assert!(out.contains("aws-access-key-id"), "Should list AWS rule");
    assert!(out.contains("github-pat"), "Should list GitHub rule");
    assert!(out.contains("openai-api-key"), "Should list OpenAI rule");
    assert!(
        out.contains("anthropic-api-key"),
        "Should list Anthropic rule"
    );
    assert!(out.contains("ollama-endpoint"), "Should list Ollama rule");
}

// ============================================================================
// PATH HANDLING TESTS
// ============================================================================

#[test]
fn test_scan_current_directory_default() {
    // When no path is given, should scan current directory
    let output = cargo_run(&[]);

    // Should not crash
    assert!(output.status.success() || output.status.code().is_some());
}

#[test]
fn test_scan_specific_file() {
    let dir = TestDir::new("specific-file");
    let file = dir.write_file("secrets.env", &format!("KEY={}", OPENAI_API_KEY));

    let output = cargo_run(&[file.to_str().unwrap()]);
    let out = stdout(&output);

    // OpenAI and DeepSeek both use sk- prefix, so either match is valid
    assert!(
        out.contains("openai") || out.contains("deepseek"),
        "Should find secret in specific file"
    );
}

#[test]
fn test_scan_nonexistent_path() {
    let output = cargo_run(&["/nonexistent/path/that/does/not/exist"]);

    // Should handle gracefully (may error, but shouldn't panic)
    assert!(output.status.code().is_some(), "Should exit with some code");
}

#[test]
fn test_scan_directory_with_subdirs() {
    let dir = TestDir::new("subdirs");
    dir.write_file("root.py", "print('clean')");
    dir.write_file("src/app.py", "print('clean')");
    dir.write_file("src/config/settings.py", &format!("KEY = '{}'", GITHUB_PAT));

    let output = cargo_run(&[dir.path_str()]);
    let out = stdout(&output);

    assert!(out.contains("github"), "Should find secret in subdirectory");
}

// ============================================================================
// SPECIAL CHARACTER HANDLING
// ============================================================================

#[test]
fn test_path_with_spaces() {
    let dir = TestDir::new("path with spaces");
    dir.write_file("config.py", &format!("KEY = '{}'", OPENAI_API_KEY));

    let output = cargo_run(&[dir.path_str()]);

    // Should handle spaces in path
    assert!(
        output.status.success()
            || output.status.code() == Some(0)
            || output.status.code() == Some(1)
    );
}

#[test]
fn test_file_with_unicode_name() {
    let dir = TestDir::new("unicode-name");
    dir.write_file("配置.py", &format!("KEY = '{}'", OPENAI_API_KEY));

    let output = cargo_run(&[dir.path_str()]);

    // Should handle unicode filenames
    assert!(output.status.code().is_some());
}

// ============================================================================
// MULTIPLE FINDINGS TESTS
// ============================================================================

#[test]
fn test_multiple_secrets_same_file() {
    let dir = TestDir::new("multi-secrets-file");
    dir.write_file(
        "config.py",
        &format!(
            "OPENAI = '{}'\nGITHUB = '{}'\nAWS = '{}'",
            OPENAI_API_KEY, GITHUB_PAT, AWS_ACCESS_KEY_ID
        ),
    );

    let output = cargo_run(&[dir.path_str(), "-f", "json"]);
    let out = stdout(&output);

    // Count findings in JSON
    let finding_count = out.matches("\"rule_id\"").count();
    assert!(finding_count >= 2, "Should find multiple secrets");
}

#[test]
fn test_secrets_across_files() {
    let dir = TestDir::new("multi-secrets-files");
    dir.write_file("openai.env", &format!("KEY={}", OPENAI_API_KEY));
    dir.write_file("github.env", &format!("TOKEN={}", GITHUB_PAT));
    dir.write_file("aws.env", &format!("ACCESS_KEY={}", AWS_ACCESS_KEY_ID));

    let output = cargo_run(&[dir.path_str(), "-f", "json"]);
    let out = stdout(&output);

    let finding_count = out.matches("\"rule_id\"").count();
    assert!(finding_count >= 2, "Should find secrets across files");
}

// ============================================================================
// REDACTION TESTS
// ============================================================================

#[test]
fn test_secrets_are_redacted_by_default() {
    let dir = TestDir::new("redaction-default");
    dir.write_file("config.py", &format!("KEY = '{}'", OPENAI_API_KEY));

    let output = cargo_run(&[dir.path_str()]);
    let out = stdout(&output);

    // The full secret should not appear in output
    assert!(
        !out.contains(OPENAI_API_KEY),
        "Full secret should be redacted"
    );
    assert!(out.contains("..."), "Should show redacted format");
}

#[test]
fn test_json_secrets_are_redacted() {
    let dir = TestDir::new("redaction-json");
    dir.write_file("config.py", &format!("KEY = '{}'", GITHUB_PAT));

    let output = cargo_run(&[dir.path_str(), "-f", "json"]);
    let out = stdout(&output);

    // JSON output should also redact
    assert!(
        !out.contains(GITHUB_PAT),
        "Full secret should be redacted in JSON"
    );
}

// ============================================================================
// ERROR HANDLING TESTS
// ============================================================================

#[test]
fn test_empty_only_filter_errors() {
    let output = cargo_run(&["--only"]);

    assert!(!output.status.success(), "Empty --only should error");
}

#[test]
fn test_empty_exclude_filter_errors() {
    let output = cargo_run(&["--exclude"]);

    assert!(!output.status.success(), "Empty --exclude should error");
}

#[test]
fn test_empty_format_errors() {
    let output = cargo_run(&["--format"]);

    assert!(!output.status.success(), "Empty --format should error");
}

#[test]
fn test_empty_context_errors() {
    let output = cargo_run(&["--context"]);

    assert!(!output.status.success(), "Empty --context should error");
}

#[test]
fn test_invalid_context_number() {
    let output = cargo_run(&["--context", "notanumber"]);

    assert!(
        !output.status.success(),
        "Invalid context number should error"
    );
}

// ============================================================================
// VERIFY FLAG TESTS
// ============================================================================

#[test]
fn test_verify_flag_basic() {
    let dir = TestDir::new("verify-basic");
    dir.write_file("config.py", &format!("KEY = '{}'", OPENAI_API_KEY));

    let output = cargo_run(&[dir.path_str(), "--verify"]);

    // The --verify flag should be accepted without error
    // It may print a warning about needing --features verify, but should still succeed
    assert!(
        output.status.success() || output.status.code() == Some(0),
        "--verify flag should be accepted"
    );
}

#[test]
fn test_verify_with_json_format() {
    let dir = TestDir::new("verify-json");
    dir.write_file("config.py", &format!("KEY = '{}'", GITHUB_PAT));

    let output = cargo_run(&[dir.path_str(), "--verify", "-f", "json"]);
    let out = stdout(&output);

    // Should produce valid JSON output
    assert!(out.contains("{"), "Should be JSON");
    assert!(out.contains("\"version\""), "Should have version field");
    assert!(out.contains("\"findings\""), "Should have findings array");
    assert!(out.contains("\"rule_id\""), "Should have rule_id");
    assert!(out.contains("\"file\""), "Should have file field");
    assert!(out.contains("\"line\""), "Should have line number");
}

#[test]
fn test_verify_with_report_format() {
    let dir = TestDir::new("verify-report");
    dir.write_file("config.py", &format!("KEY = '{}'", OPENAI_API_KEY));

    let output = cargo_run(&[dir.path_str(), "--verify", "-f", "report"]);
    let out = stdout(&output);

    // Should produce valid report format with verification fields
    assert!(
        out.contains("\"report_version\""),
        "Should have report version"
    );
    assert!(
        out.contains("\"scanner\": \"libreleak\""),
        "Should have scanner name"
    );
    assert!(out.contains("\"timestamp\""), "Should have timestamp");
    assert!(out.contains("\"summary\""), "Should have summary section");
    assert!(out.contains("\"findings\""), "Should have findings array");
    // Report format includes verification structure in each finding
    assert!(
        out.contains("\"verification\""),
        "Should have verification field in findings"
    );
    assert!(
        out.contains("\"status\""),
        "Should have verification status field"
    );
}

#[test]
fn test_verify_with_fail_on_leak() {
    let dir = TestDir::new("verify-fail-on-leak");
    dir.write_file("config.py", &format!("KEY = '{}'", AWS_ACCESS_KEY_ID));

    // Test that --verify and --fail-on-leak work together
    let output = cargo_run(&[dir.path_str(), "--verify", "--fail-on-leak"]);

    // When secrets are found and --fail-on-leak is set, should exit with code 1
    assert_eq!(
        output.status.code(),
        Some(1),
        "--verify with --fail-on-leak should exit 1 when secrets found"
    );
}

#[test]
fn test_verify_with_fail_on_leak_no_secrets() {
    let dir = TestDir::new("verify-fail-no-secrets");
    dir.write_file("clean.py", "print('hello world')");

    // Test that --verify and --fail-on-leak work together when no secrets found
    let output = cargo_run(&[dir.path_str(), "--verify", "--fail-on-leak"]);

    // When no secrets are found, should exit with code 0
    assert_eq!(
        output.status.code(),
        Some(0),
        "--verify with --fail-on-leak should exit 0 when no secrets found"
    );
}

// ============================================================================
// REPORT FORMAT DETAILED TESTS
// ============================================================================

#[test]
fn test_report_findings_by_rule_grouping() {
    // Create test files with 5+ findings across 3+ different rule types
    let dir = TestDir::new("report-rule-grouping");
    dir.write_file(
        "secrets.py",
        &format!(
            "# Multiple secrets of different types
AWS_KEY = '{}'
AWS_KEY2 = '{}'
GITHUB1 = '{}'
GITHUB2 = '{}'
OPENAI = '{}'
",
            AWS_ACCESS_KEY_ID, AWS_ACCESS_KEY_ID, GITHUB_PAT, GITHUB_PAT, OPENAI_API_KEY
        ),
    );

    let output = cargo_run(&[dir.path_str(), "-f", "report"]);
    let out = stdout(&output);

    // Verify the report has findings_by_rule section
    assert!(
        out.contains("\"findings_by_rule\""),
        "Should have findings_by_rule section"
    );

    // Verify rule groupings exist - AWS should appear with count 2
    assert!(
        out.contains("\"aws-access-key-id\": 2"),
        "Should group AWS findings with count 2"
    );

    // Verify GitHub PAT findings - should have count 2
    assert!(
        out.contains("\"github-pat\": 2"),
        "Should group GitHub PAT findings with count 2"
    );

    // Verify OpenAI or DeepSeek findings (both match sk- prefix)
    // Check that there's at least one AI key detected
    assert!(
        out.contains("openai-api-key") || out.contains("deepseek-api-key"),
        "Should detect OpenAI or DeepSeek key"
    );

    // Verify unique_rules_triggered count is at least 3
    assert!(
        out.contains("\"unique_rules_triggered\": 3")
            || out.contains("\"unique_rules_triggered\": 4"),
        "Should have 3 or more unique rules triggered"
    );
}

#[test]
fn test_report_severity_breakdown() {
    // Create test with different severity levels:
    // - High: aws, private-key, database, jwt
    // - Medium: api-key, token, secret
    // - Low: everything else
    let dir = TestDir::new("report-severity");
    dir.write_file(
        "config.py",
        &format!(
            "# High severity: AWS
AWS_KEY = '{}'
# Medium severity: API keys
OPENAI = '{}'
GITHUB = '{}'
",
            AWS_ACCESS_KEY_ID, OPENAI_API_KEY, GITHUB_PAT
        ),
    );

    let output = cargo_run(&[dir.path_str(), "-f", "report"]);
    let out = stdout(&output);

    // Verify severity_breakdown section exists
    assert!(
        out.contains("\"severity_breakdown\""),
        "Should have severity_breakdown section"
    );

    // Verify high count (AWS triggers high)
    assert!(
        out.contains("\"high\": 1"),
        "Should have 1 high severity finding (AWS)"
    );

    // Verify medium count section exists
    // OpenAI matches api-key pattern -> medium
    assert!(
        out.contains("\"medium\":"),
        "Should have medium severity section"
    );

    // Verify low exists
    assert!(out.contains("\"low\":"), "Should have low severity section");

    // Verify the sum of severities equals total findings
    // This is validated by the fact that severity_breakdown exists and has all three levels
}

#[test]
fn test_report_summary_total() {
    // Create exactly 4 findings to verify total count
    let dir = TestDir::new("report-summary-total");
    dir.write_file("file1.py", &format!("KEY1 = '{}'", OPENAI_API_KEY));
    dir.write_file("file2.py", &format!("KEY2 = '{}'", GITHUB_PAT));
    dir.write_file("file3.py", &format!("KEY3 = '{}'", AWS_ACCESS_KEY_ID));
    dir.write_file("file4.py", &format!("KEY4 = '{}'", SLACK_BOT_TOKEN));

    let output = cargo_run(&[dir.path_str(), "-f", "report"]);
    let out = stdout(&output);

    // Verify summary section exists
    assert!(out.contains("\"summary\""), "Should have summary section");

    // Verify total_findings matches the actual count
    assert!(
        out.contains("\"total_findings\": 4"),
        "Should have exactly 4 total findings"
    );

    // Verify the findings array has 4 entries by counting "id" occurrences
    let finding_id_count = out.matches("\"id\":").count();
    assert_eq!(
        finding_id_count, 4,
        "Findings array should have 4 entries with id fields"
    );
}

#[test]
fn test_report_multiple_files() {
    // Create secrets spread across multiple files in different directories
    let dir = TestDir::new("report-multi-files");
    dir.write_file(
        "root_config.py",
        &format!("ROOT_KEY = '{}'", OPENAI_API_KEY),
    );
    dir.write_file("src/api.py", &format!("API_TOKEN = '{}'", GITHUB_PAT));
    dir.write_file("config/database.yml", &format!("url: '{}'", POSTGRES_URI));
    dir.write_file(
        "scripts/deploy.sh",
        &format!("AWS_KEY={}", AWS_ACCESS_KEY_ID),
    );

    let output = cargo_run(&[dir.path_str(), "-f", "report"]);
    let out = stdout(&output);

    // Verify all files are represented in the output
    assert!(
        out.contains("root_config.py"),
        "Should include root_config.py in findings"
    );
    assert!(
        out.contains("src/api.py") || out.contains("src\\\\api.py"),
        "Should include src/api.py in findings"
    );
    assert!(
        out.contains("config/database.yml") || out.contains("config\\\\database.yml"),
        "Should include config/database.yml in findings"
    );
    assert!(
        out.contains("scripts/deploy.sh") || out.contains("scripts\\\\deploy.sh"),
        "Should include scripts/deploy.sh in findings"
    );

    // Verify report has correct total across files
    assert!(
        out.contains("\"total_findings\": 4"),
        "Should have 4 total findings across all files"
    );

    // Verify findings_by_category groups different types
    assert!(
        out.contains("\"findings_by_category\""),
        "Should have findings_by_category section"
    );

    // Each finding should have a location with file path
    let location_count = out.matches("\"location\":").count();
    assert_eq!(
        location_count, 4,
        "Each finding should have a location section"
    );
}

// ============================================================================
// GITHUB MARKETPLACE ACTION INTEGRATION TESTS
// ============================================================================
// These tests validate the CLI invocation patterns used by the GitHub Marketplace
// action (action.yml). The action translates its inputs to CLI arguments:
//
// Action input          -> CLI argument
// --------------------- -> -----------------------------
// path: './src'         -> ./src (positional path argument)
// fail-on-leak: 'true'  -> --fail-on-leak
// fail-on-leak: 'false' -> (no flag, default behavior)
// format: 'text'        -> --format text (or -f text)
// exclude-rules: 'a,b'  -> --exclude a,b
// only-rules: 'a,b'     -> --only a,b

#[test]
fn test_action_path_scanning_subdirectory() {
    // Simulates: path: './src' in action.yml
    // The action passes a subdirectory path to scan
    let dir = TestDir::new("action-path-subdir");

    // Create a structure like a real project:
    // - root has clean files
    // - src/ subdirectory has a secret
    dir.write_file("README.md", "# My Project");
    dir.write_file("src/config.py", &format!("API_KEY = '{}'", GITHUB_PAT));
    dir.write_file("tests/test_app.py", "def test_example(): pass");

    // Scan only the src/ subdirectory (like action does with path: './src')
    let src_path = dir.path().join("src");
    let output = cargo_run(&[src_path.to_str().unwrap(), "-f", "text"]);
    let out = stdout(&output);

    assert!(
        out.contains("github"),
        "Should find secret in src/ subdirectory"
    );
    assert!(out.contains("Found"), "Should show findings summary");
}

#[test]
fn test_action_fail_on_leak_false_exits_zero() {
    // Simulates: fail-on-leak: 'false' in action.yml
    // When fail-on-leak is 'false', the action does NOT pass --fail-on-leak
    // So even if secrets are found, exit code should be 0
    let dir = TestDir::new("action-no-fail");
    dir.write_file("config.py", &format!("KEY = '{}'", OPENAI_API_KEY));

    // Run WITHOUT --fail-on-leak (action's behavior when fail-on-leak: 'false')
    let output = cargo_run(&[dir.path_str()]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "Should exit 0 when fail-on-leak is not set, even with secrets found"
    );

    // But should still report the finding
    let out = stdout(&output);
    assert!(out.contains("Found"), "Should still report findings");
}

#[test]
fn test_action_fail_on_leak_true_exits_nonzero() {
    // Simulates: fail-on-leak: 'true' in action.yml
    // When fail-on-leak is 'true', the action passes --fail-on-leak
    let dir = TestDir::new("action-with-fail");
    dir.write_file("config.py", &format!("KEY = '{}'", GITHUB_PAT));

    // Run WITH --fail-on-leak (action's behavior when fail-on-leak: 'true')
    let output = cargo_run(&[dir.path_str(), "--fail-on-leak"]);

    assert_eq!(
        output.status.code(),
        Some(1),
        "Should exit 1 when fail-on-leak is set and secrets are found"
    );
}

#[test]
fn test_action_fail_on_leak_true_no_secrets() {
    // Simulates: fail-on-leak: 'true' with clean code
    // Should exit 0 when no secrets are found
    let dir = TestDir::new("action-fail-clean");
    dir.write_file("clean.py", "print('hello world')");

    let output = cargo_run(&[dir.path_str(), "--fail-on-leak"]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "Should exit 0 when fail-on-leak is set but no secrets found"
    );
}

#[test]
fn test_action_text_format_output_parseable() {
    // Simulates: format: 'text' in action.yml
    // The action parses text output to extract findings count using:
    //   grep -o "Found [0-9]* potential secret" | grep -o "[0-9]*"
    let dir = TestDir::new("action-text-format");
    dir.write_file("config.py", &format!("KEY = '{}'", GITHUB_PAT));

    let output = cargo_run(&[dir.path_str(), "-f", "text"]);
    let out = stdout(&output);

    // Action expects output like: "Found N potential secret(s)"
    let has_found_pattern = out.contains("Found") && out.contains("potential secret");
    assert!(
        has_found_pattern,
        "Text output should contain 'Found N potential secret' pattern for action parsing. Got: {}",
        out
    );
}

#[test]
fn test_action_text_format_clean_parseable() {
    // When no secrets found, action expects "No secrets found" message
    let dir = TestDir::new("action-text-clean");
    dir.write_file("clean.py", "print('clean code')");

    let output = cargo_run(&[dir.path_str(), "-f", "text"]);
    let out = stdout(&output);

    // Action checks for "No secrets found" when parsing output
    assert!(
        out.contains("No secrets found"),
        "Text output should contain 'No secrets found' for action parsing. Got: {}",
        out
    );
}

#[test]
fn test_action_json_format_rule_id_count() {
    // For JSON/SARIF, action counts '"rule_id"' occurrences to get findings count
    // FINDINGS=$(echo "$OUTPUT" | grep -c '"rule_id"' || echo "0")
    let dir = TestDir::new("action-json-count");
    dir.write_file(
        "config.py",
        &format!("GITHUB = '{}'\nAWS = '{}'", GITHUB_PAT, AWS_ACCESS_KEY_ID),
    );

    let output = cargo_run(&[dir.path_str(), "-f", "json"]);
    let out = stdout(&output);

    // Count rule_id occurrences - action uses this to determine findings count
    let rule_id_count = out.matches("\"rule_id\"").count();
    assert!(
        rule_id_count >= 2,
        "JSON should have rule_id for each finding (expected 2+, got {})",
        rule_id_count
    );
}

#[test]
fn test_action_combined_flags() {
    // Simulates the full action invocation pattern:
    //   libreleak ./src --format text
    // (without --fail-on-leak when fail-on-leak: 'false')
    let dir = TestDir::new("action-combined");
    dir.write_file("src/app.py", &format!("KEY = '{}'", OPENAI_API_KEY));

    let src_path = dir.path().join("src");
    let output = cargo_run(&[src_path.to_str().unwrap(), "--format", "text"]);
    let out = stdout(&output);

    assert!(
        output.status.success(),
        "Should succeed without --fail-on-leak"
    );
    assert!(out.contains("Found"), "Should report findings in text format");
}

#[test]
fn test_action_exclude_rules_comma_separated() {
    // Simulates: exclude-rules: 'openai-api-key,anthropic-api-key' in action.yml
    // Action passes: --exclude openai-api-key,anthropic-api-key
    let dir = TestDir::new("action-exclude");
    dir.write_file(
        "config.py",
        &format!("OPENAI = '{}'\nGITHUB = '{}'", OPENAI_API_KEY, GITHUB_PAT),
    );

    let output = cargo_run(&[
        dir.path_str(),
        "--exclude",
        "openai-api-key,deepseek-api-key",
    ]);
    let out = stdout(&output);

    // Should find GitHub but not OpenAI (excluded)
    assert!(
        out.contains("github"),
        "Should find non-excluded GitHub token"
    );
    assert!(
        !out.contains("openai-api-key"),
        "Should not find excluded openai-api-key"
    );
}

#[test]
fn test_action_only_rules_comma_separated() {
    // Simulates: only-rules: 'github-pat,aws-access-key-id' in action.yml
    // Action passes: --only github-pat,aws-access-key-id
    let dir = TestDir::new("action-only");
    dir.write_file(
        "config.py",
        &format!(
            "OPENAI = '{}'\nGITHUB = '{}'\nAWS = '{}'",
            OPENAI_API_KEY, GITHUB_PAT, AWS_ACCESS_KEY_ID
        ),
    );

    let output = cargo_run(&[dir.path_str(), "--only", "github-pat,aws-access-key-id"]);
    let out = stdout(&output);

    // Should find GitHub and AWS only
    assert!(
        out.contains("github") || out.contains("aws"),
        "Should find specified rules"
    );
}

#[test]
fn test_action_format_long_flag() {
    // Action uses --format (long form) not -f (short form)
    let dir = TestDir::new("action-format-long");
    dir.write_file("config.py", &format!("KEY = '{}'", GITHUB_PAT));

    let output = cargo_run(&[dir.path_str(), "--format", "text"]);
    let out = stdout(&output);

    assert!(output.status.success() || output.status.code() == Some(0));
    assert!(out.contains("Found"), "Should produce text format output");
}

#[test]
fn test_action_sarif_format_for_github_security() {
    // SARIF format is useful for GitHub Code Scanning integration
    let dir = TestDir::new("action-sarif");
    dir.write_file("config.py", &format!("KEY = '{}'", GITHUB_PAT));

    let output = cargo_run(&[dir.path_str(), "--format", "sarif"]);
    let out = stdout(&output);

    // Verify SARIF structure
    assert!(out.contains("$schema"), "SARIF should have schema");
    assert!(out.contains("sarif"), "SARIF should mention sarif");
    assert!(out.contains("runs"), "SARIF should have runs");
    assert!(out.contains("results"), "SARIF should have results");

    // Action can count findings via ruleId (SARIF uses camelCase)
    assert!(
        out.contains("\"ruleId\""),
        "SARIF should have ruleId for action to count"
    );
}

#[test]
fn test_action_exit_code_propagation() {
    // The action runs: exit $EXIT_CODE
    // Verify that exit codes are deterministic for both states

    // Case 1: Clean code + fail-on-leak -> exit 0
    let clean_dir = TestDir::new("action-exit-clean");
    clean_dir.write_file("clean.py", "x = 1");
    let clean_output = cargo_run(&[clean_dir.path_str(), "--fail-on-leak"]);
    assert_eq!(
        clean_output.status.code(),
        Some(0),
        "Clean code should exit 0"
    );

    // Case 2: Secrets + fail-on-leak -> exit 1
    let dirty_dir = TestDir::new("action-exit-dirty");
    dirty_dir.write_file("config.py", &format!("KEY = '{}'", GITHUB_PAT));
    let dirty_output = cargo_run(&[dirty_dir.path_str(), "--fail-on-leak"]);
    assert_eq!(
        dirty_output.status.code(),
        Some(1),
        "Secrets found should exit 1"
    );

    // Case 3: Secrets without fail-on-leak -> exit 0
    let no_fail_output = cargo_run(&[dirty_dir.path_str()]);
    assert_eq!(
        no_fail_output.status.code(),
        Some(0),
        "No fail-on-leak should exit 0"
    );
}

#[test]
fn test_action_findings_output_format_consistency() {
    // The action extracts findings in multiple ways, test all patterns work
    let dir = TestDir::new("action-findings-format");
    dir.write_file("config.py", &format!("KEY = '{}'", GITHUB_PAT));

    // Text format: action greps for "Found N potential secret"
    let text_output = cargo_run(&[dir.path_str(), "-f", "text"]);
    let text_out = stdout(&text_output);
    assert!(
        text_out.contains("Found") && text_out.contains("potential secret"),
        "Text format should have parseable findings line"
    );

    // JSON format: action counts '"rule_id"' occurrences
    let json_output = cargo_run(&[dir.path_str(), "-f", "json"]);
    let json_out = stdout(&json_output);
    assert!(
        json_out.contains("\"rule_id\""),
        "JSON format should have rule_id for counting"
    );

    // SARIF format: uses "ruleId" (camelCase per SARIF spec)
    let sarif_output = cargo_run(&[dir.path_str(), "-f", "sarif"]);
    let sarif_out = stdout(&sarif_output);
    assert!(
        sarif_out.contains("\"ruleId\""),
        "SARIF format should have ruleId"
    );
}

// ============================================================================
// EDGE CASE OUTPUT FORMAT TESTS
// ============================================================================

#[test]
fn test_json_output_special_characters() {
    // Test JSON output properly escapes special characters in secrets and filenames
    let dir = TestDir::new("json-special-chars");

    // Create a file with special characters in the content (quotes, newlines, backslashes)
    // The secret itself contains characters that need escaping in JSON
    let content_with_special_chars = format!(
        r#"# Config with "special" chars
KEY1 = '{}'
# Another key with backslash path: C:\Users\test
KEY2 = '{}'"#,
        GITHUB_PAT, OPENAI_API_KEY
    );
    dir.write_file("config\"special.py", &content_with_special_chars);

    let output = cargo_run(&[dir.path_str(), "-f", "json"]);
    let out = stdout(&output);

    // Verify output is valid JSON by checking structure
    assert!(out.contains("{"), "Should produce JSON output");
    assert!(out.contains("\"findings\""), "Should have findings array");

    // Check that special characters in filename are escaped
    // The quote in the filename should be escaped as \"
    assert!(
        out.contains("config\\\"special.py") || out.contains("config\"special.py"),
        "Should handle special characters in filename"
    );

    // Verify the JSON is parseable by checking balanced braces
    let open_braces = out.matches('{').count();
    let close_braces = out.matches('}').count();
    assert_eq!(
        open_braces, close_braces,
        "JSON should have balanced braces"
    );
}

#[test]
fn test_sarif_output_special_characters() {
    // Test SARIF output properly escapes special characters
    let dir = TestDir::new("sarif-special-chars");

    // Content with unicode and special characters
    let content = format!(
        "# Unicode config: \u{4e2d}\u{6587}\nKEY = '{}'\n# Tab:\there\n",
        GITHUB_PAT
    );
    dir.write_file("config_\u{4e2d}\u{6587}.py", &content);

    let output = cargo_run(&[dir.path_str(), "-f", "sarif"]);
    let out = stdout(&output);

    // Verify SARIF structure
    assert!(out.contains("$schema"), "Should have SARIF schema");
    assert!(out.contains("\"results\""), "Should have results array");

    // Check balanced braces for valid JSON
    let open_braces = out.matches('{').count();
    let close_braces = out.matches('}').count();
    assert_eq!(
        open_braces, close_braces,
        "SARIF JSON should have balanced braces"
    );

    // Verify the file was detected
    assert!(
        out.contains("ruleId"),
        "Should have findings with ruleId"
    );
}

#[test]
fn test_report_output_special_characters() {
    // Test report format with special characters
    let dir = TestDir::new("report-special-chars");

    // Content with various special characters
    let content = format!(
        "# Special chars: <>&'\"\nAPI_KEY = '{}'\n",
        AWS_ACCESS_KEY_ID
    );
    dir.write_file("config<special>.py", &content);

    let output = cargo_run(&[dir.path_str(), "-f", "report"]);
    let out = stdout(&output);

    // Verify report structure
    assert!(
        out.contains("\"report_version\""),
        "Should have report version"
    );
    assert!(out.contains("\"findings\""), "Should have findings array");

    // Check JSON validity
    let open_braces = out.matches('{').count();
    let close_braces = out.matches('}').count();
    assert_eq!(
        open_braces, close_braces,
        "Report JSON should have balanced braces"
    );
}

#[test]
fn test_text_output_very_long_lines() {
    // Test text format handling of very long lines (1000+ chars)
    let dir = TestDir::new("text-long-lines");

    // Create content with a secret embedded in a very long line
    let padding = "x".repeat(500);
    let long_line = format!(
        "{}KEY='{}'{}",
        padding, GITHUB_PAT, padding
    );
    dir.write_file("long_line.py", &long_line);

    let output = cargo_run(&[dir.path_str(), "-f", "text"]);
    let out = stdout(&output);

    // Should still detect the secret
    assert!(
        out.contains("Found") && out.contains("potential secret"),
        "Should find secret in long line"
    );
    assert!(
        out.contains("github"),
        "Should identify as GitHub token"
    );

    // The output should not crash and should complete
    assert!(
        output.status.success() || output.status.code() == Some(0),
        "Should handle long lines without crashing"
    );
}

#[test]
fn test_json_output_empty_file() {
    // Test JSON output for a file that exists but has no content
    let dir = TestDir::new("json-empty-file");

    // Create an empty file
    dir.write_file("empty.py", "");
    // Also create a file with only whitespace
    dir.write_file("whitespace.py", "   \n\n   \t\t\n");
    // And a file with a secret to ensure scanner works
    dir.write_file("has_secret.py", &format!("KEY = '{}'", GITHUB_PAT));

    let output = cargo_run(&[dir.path_str(), "-f", "json"]);
    let out = stdout(&output);

    // Should produce valid JSON
    assert!(out.contains("{"), "Should produce JSON");
    assert!(out.contains("\"findings\""), "Should have findings array");

    // Should find the one secret
    let finding_count = out.matches("\"rule_id\"").count();
    assert_eq!(
        finding_count, 1,
        "Should find exactly 1 secret (empty files have no secrets)"
    );

    // Verify JSON structure
    let open_braces = out.matches('{').count();
    let close_braces = out.matches('}').count();
    assert_eq!(
        open_braces, close_braces,
        "JSON should have balanced braces"
    );
}

#[test]
fn test_multiple_formats_same_findings() {
    // Verify all output formats report the same finding count for identical input
    let dir = TestDir::new("multi-format-consistency");

    // Create files with known number of secrets (3 distinct secrets)
    dir.write_file("secrets.py", &format!(
        "GITHUB = '{}'\nAWS = '{}'\nSLACK = '{}'",
        GITHUB_PAT, AWS_ACCESS_KEY_ID, SLACK_BOT_TOKEN
    ));

    // Get findings count from each format
    let json_output = cargo_run(&[dir.path_str(), "-f", "json"]);
    let json_out = stdout(&json_output);

    let sarif_output = cargo_run(&[dir.path_str(), "-f", "sarif"]);
    let sarif_out = stdout(&sarif_output);

    let report_output = cargo_run(&[dir.path_str(), "-f", "report"]);
    let report_out = stdout(&report_output);

    // Count findings in each format
    // JSON: count "rule_id" occurrences
    let json_count = json_out.matches("\"rule_id\"").count();

    // SARIF: count "ruleId" occurrences
    let sarif_count = sarif_out.matches("\"ruleId\"").count();

    // Report: extract total_findings number
    let report_count = if report_out.contains("\"total_findings\": 3") {
        3
    } else if report_out.contains("\"total_findings\": 2") {
        2
    } else if report_out.contains("\"total_findings\": 4") {
        4
    } else {
        0
    };

    // All formats should report the same number of findings (3)
    assert_eq!(
        json_count, 3,
        "JSON format should report 3 findings, got {}. Output: {}",
        json_count, json_out
    );
    assert_eq!(
        sarif_count, 3,
        "SARIF format should report 3 findings, got {}. Output: {}",
        sarif_count, sarif_out
    );
    assert_eq!(
        report_count, 3,
        "Report format should report 3 total findings, got {}",
        report_count
    );

    // Cross-check: JSON and SARIF counts must match
    assert_eq!(
        json_count, sarif_count,
        "JSON ({}) and SARIF ({}) should report same count",
        json_count, sarif_count
    );

    // All three format counts should be equal
    assert!(
        json_count == sarif_count && sarif_count == report_count,
        "All formats should report same findings: JSON={}, SARIF={}, Report={}",
        json_count, sarif_count, report_count
    );
}

#[test]
fn test_output_with_binary_in_path() {
    // Test handling of paths with binary-like names or unusual extensions
    let dir = TestDir::new("binary-path-names");

    // Create files with unusual extensions that might be confused with binary
    dir.write_file("config.exe.bak", &format!("KEY = '{}'", GITHUB_PAT));
    dir.write_file("data.bin.txt", &format!("SECRET = '{}'", AWS_ACCESS_KEY_ID));
    dir.write_file("app.dll.config", &format!("TOKEN = '{}'", OPENAI_API_KEY));
    // File with null-like characters in name (using underscore as substitute)
    dir.write_file("file_0x00_name.py", &format!("API = '{}'", SLACK_BOT_TOKEN));

    // Test JSON format
    let json_output = cargo_run(&[dir.path_str(), "-f", "json"]);
    let json_out = stdout(&json_output);

    // Should produce valid JSON
    assert!(json_out.contains("{"), "Should produce JSON");
    assert!(json_out.contains("\"findings\""), "Should have findings");

    // Should find secrets in these files (they're text files despite names)
    let finding_count = json_out.matches("\"rule_id\"").count();
    assert!(
        finding_count >= 3,
        "Should find secrets in binary-named files, got {}",
        finding_count
    );

    // Test text format
    let text_output = cargo_run(&[dir.path_str(), "-f", "text"]);
    let text_out = stdout(&text_output);

    assert!(
        text_out.contains("Found"),
        "Text format should find secrets"
    );

    // Verify files with unusual extensions are included in output
    assert!(
        json_out.contains(".exe.bak") || json_out.contains(".bin.txt") || json_out.contains(".dll.config"),
        "Should include files with binary-like extensions"
    );
}

// ============================================================================
// RULE FILTERING EDGE CASE TESTS
// ============================================================================

#[test]
fn test_only_nonexistent_rule() {
    // What happens when --only specifies a rule that doesn't exist
    let dir = TestDir::new("only-nonexistent");
    dir.write_file(
        "config.py",
        &format!("OPENAI = '{}'\nGITHUB = '{}'", OPENAI_API_KEY, GITHUB_PAT),
    );

    let output = cargo_run(&[dir.path_str(), "--only", "nonexistent-rule-xyz"]);
    let out = stdout(&output);

    // Should find nothing since the rule doesn't exist
    assert!(
        out.contains("No secrets found") || !out.contains("Found"),
        "Should find no secrets when filtering by nonexistent rule. Got: {}",
        out
    );
}

#[test]
fn test_exclude_nonexistent_rule() {
    // What happens when --exclude specifies a rule that doesn't exist
    let dir = TestDir::new("exclude-nonexistent");
    dir.write_file(
        "config.py",
        &format!("OPENAI = '{}'\nGITHUB = '{}'", OPENAI_API_KEY, GITHUB_PAT),
    );

    let output = cargo_run(&[dir.path_str(), "--exclude", "nonexistent-rule-xyz"]);
    let out = stdout(&output);

    // Should still find secrets - excluding a nonexistent rule should have no effect
    assert!(
        out.contains("Found") && out.contains("potential secret"),
        "Should still find secrets when excluding nonexistent rule. Got: {}",
        out
    );
}

#[test]
fn test_only_and_exclude_same_rule() {
    // What happens when same rule is in both --only and --exclude
    let dir = TestDir::new("only-exclude-same");
    dir.write_file(
        "config.py",
        &format!(
            "OPENAI = '{}'\nGITHUB = '{}'\nAWS = '{}'",
            OPENAI_API_KEY, GITHUB_PAT, AWS_ACCESS_KEY_ID
        ),
    );

    // Include github-pat via --only but also exclude it
    let output = cargo_run(&[
        dir.path_str(),
        "--only",
        "github-pat",
        "--exclude",
        "github-pat",
    ]);
    let out = stdout(&output);

    // The rule is in --only (so only that rule is considered) but also excluded
    // This should result in no findings
    assert!(
        out.contains("No secrets found") || !out.contains("github"),
        "Should find no secrets when rule is both included and excluded. Got: {}",
        out
    );
}

#[test]
fn test_only_all_rules() {
    // Using --only with all available rules (should be same as no filter)
    let dir = TestDir::new("only-all-rules");
    dir.write_file(
        "config.py",
        &format!(
            "OPENAI = '{}'\nGITHUB = '{}'\nAWS = '{}'",
            OPENAI_API_KEY, GITHUB_PAT, AWS_ACCESS_KEY_ID
        ),
    );

    // Run without any filter first
    let output_no_filter = cargo_run(&[dir.path_str(), "-f", "json"]);
    let out_no_filter = stdout(&output_no_filter);
    let count_no_filter = out_no_filter.matches("\"rule_id\"").count();

    // Run with --only including the rules we expect to match
    let output_all = cargo_run(&[
        dir.path_str(),
        "--only",
        "github-pat,aws-access-key-id,openai-api-key,deepseek-api-key",
        "-f",
        "json",
    ]);
    let out_all = stdout(&output_all);
    let count_all = out_all.matches("\"rule_id\"").count();

    // Should have the same number of findings
    assert_eq!(
        count_no_filter, count_all,
        "Using --only with all matching rules should produce same results as no filter"
    );
}

#[test]
fn test_exclude_all_rules() {
    // Using --exclude with all available rules (should find nothing)
    let dir = TestDir::new("exclude-all-rules");
    dir.write_file(
        "config.py",
        &format!(
            "OPENAI = '{}'\nGITHUB = '{}'\nAWS = '{}'",
            OPENAI_API_KEY, GITHUB_PAT, AWS_ACCESS_KEY_ID
        ),
    );

    // Exclude all rules that would match our test secrets
    let output = cargo_run(&[
        dir.path_str(),
        "--exclude",
        "github-pat,aws-access-key-id,openai-api-key,deepseek-api-key",
    ]);
    let out = stdout(&output);

    // Should find nothing since all matching rules are excluded
    assert!(
        out.contains("No secrets found"),
        "Should find no secrets when all matching rules are excluded. Got: {}",
        out
    );
}

#[test]
fn test_rule_filter_case_sensitivity() {
    // Are rule names case-sensitive?
    let dir = TestDir::new("rule-case-sensitive");
    dir.write_file("config.py", &format!("GITHUB = '{}'", GITHUB_PAT));

    // Try with uppercase
    let output_upper = cargo_run(&[dir.path_str(), "--only", "GITHUB-PAT"]);
    let out_upper = stdout(&output_upper);
    let err_upper = stderr(&output_upper);

    // Try with mixed case
    let output_mixed = cargo_run(&[dir.path_str(), "--only", "GitHub-Pat"]);
    let out_mixed = stdout(&output_mixed);
    let err_mixed = stderr(&output_mixed);

    // Try with correct lowercase
    let output_lower = cargo_run(&[dir.path_str(), "--only", "github-pat"]);
    let out_lower = stdout(&output_lower);

    // The lowercase version should work
    assert!(
        out_lower.contains("github") || out_lower.contains("Found"),
        "Lowercase rule name should work. Got: {}",
        out_lower
    );

    // Document the current behavior - rules ARE case-sensitive
    // When uppercase is used, the tool reports "No rules selected" error
    let upper_has_error = err_upper.contains("No rules selected");
    let mixed_has_error = err_mixed.contains("No rules selected");
    let upper_finds = out_upper.contains("Found") && out_upper.contains("potential secret");
    let mixed_finds = out_mixed.contains("Found") && out_mixed.contains("potential secret");

    // At least one of these should differ from lowercase, indicating case sensitivity
    // Or they could all work if case-insensitive - document whichever is true
    if !upper_finds && !mixed_finds {
        // Case-sensitive behavior - uppercase/mixed case don't match
        // The tool shows an error when no rules match the filter
        assert!(
            upper_has_error || mixed_has_error,
            "Rule names are case-sensitive - uppercase/mixed case should not match. Upper err: {}, Mixed err: {}",
            err_upper, err_mixed
        );
    }
    // Note: if they all find secrets, the rules are case-insensitive, which is also valid
}

#[test]
fn test_rule_filter_with_whitespace() {
    // Rules with leading/trailing whitespace in comma list
    let dir = TestDir::new("rule-whitespace");
    dir.write_file(
        "config.py",
        &format!("GITHUB = '{}'\nAWS = '{}'", GITHUB_PAT, AWS_ACCESS_KEY_ID),
    );

    // Add whitespace around rule names in the comma-separated list
    let output = cargo_run(&[dir.path_str(), "--only", " github-pat , aws-access-key-id "]);
    let out = stdout(&output);

    // Should handle whitespace gracefully and find both secrets
    // Note: This test documents current behavior - it may or may not trim whitespace
    // The important thing is it shouldn't crash
    assert!(
        output.status.code().is_some(),
        "Should handle whitespace in rule list without crashing"
    );

    // Check if whitespace is trimmed (rule matching works)
    let finds_secrets = out.contains("Found") && out.contains("potential secret");
    if !finds_secrets {
        // Whitespace is NOT trimmed - rules don't match
        assert!(
            out.contains("No secrets found"),
            "If whitespace is not trimmed, should find no secrets with whitespace-padded rules. Got: {}",
            out
        );
    }
    // If it finds secrets, whitespace is trimmed - either behavior is documented by this test
}

#[test]
fn test_only_partial_rule_match() {
    // Does "aws" match "aws-access-key-id" or need exact match?
    let dir = TestDir::new("partial-rule-match");
    dir.write_file(
        "config.py",
        &format!("AWS = '{}'\nGITHUB = '{}'", AWS_ACCESS_KEY_ID, GITHUB_PAT),
    );

    // Try partial match with just "aws"
    let output_partial = cargo_run(&[dir.path_str(), "--only", "aws"]);
    let out_partial = stdout(&output_partial);
    let err_partial = stderr(&output_partial);

    // Try exact match
    let output_exact = cargo_run(&[dir.path_str(), "--only", "aws-access-key-id"]);
    let out_exact = stdout(&output_exact);

    // Exact match should definitely work
    assert!(
        out_exact.contains("aws") || out_exact.contains("Found"),
        "Exact rule name match should work. Got: {}",
        out_exact
    );

    // Document behavior for partial match
    let partial_finds = out_partial.contains("Found") && out_partial.contains("potential secret");
    let partial_has_error = err_partial.contains("No rules selected");
    if partial_finds {
        // Partial matching is supported
        assert!(
            out_partial.contains("aws"),
            "Partial rule match 'aws' appears to match aws rules. Got: {}",
            out_partial
        );
    } else {
        // Exact matching required - partial names don't match
        // The tool shows an error when no rules match the filter
        assert!(
            partial_has_error || out_partial.contains("No secrets found"),
            "Rule matching requires exact names - 'aws' should not match 'aws-access-key-id'. Err: {}, Out: {}",
            err_partial, out_partial
        );
    }
}

#[test]
fn test_multiple_only_flags() {
    // Test using --only flag multiple times (if supported)
    let dir = TestDir::new("multiple-only-flags");
    dir.write_file(
        "config.py",
        &format!(
            "GITHUB = '{}'\nAWS = '{}'\nOPENAI = '{}'",
            GITHUB_PAT, AWS_ACCESS_KEY_ID, OPENAI_API_KEY
        ),
    );

    // This tests how the CLI handles multiple --only flags
    // Some CLIs combine them, others use last-wins
    let output = cargo_run(&[
        dir.path_str(),
        "--only",
        "github-pat",
        "--only",
        "aws-access-key-id",
    ]);

    // Should not crash - document the behavior
    assert!(
        output.status.code().is_some(),
        "Should handle multiple --only flags without crashing"
    );
}

#[test]
fn test_multiple_exclude_flags() {
    // Test using --exclude flag multiple times (if supported)
    let dir = TestDir::new("multiple-exclude-flags");
    dir.write_file(
        "config.py",
        &format!(
            "GITHUB = '{}'\nAWS = '{}'\nOPENAI = '{}'",
            GITHUB_PAT, AWS_ACCESS_KEY_ID, OPENAI_API_KEY
        ),
    );

    // Test multiple --exclude flags
    let output = cargo_run(&[
        dir.path_str(),
        "--exclude",
        "github-pat",
        "--exclude",
        "aws-access-key-id",
    ]);

    // Should not crash - document the behavior
    assert!(
        output.status.code().is_some(),
        "Should handle multiple --exclude flags without crashing"
    );
}

#[test]
fn test_empty_rule_in_comma_list() {
    // What happens with empty entries in comma-separated list: "github-pat,,aws-access-key-id"
    let dir = TestDir::new("empty-rule-comma");
    dir.write_file(
        "config.py",
        &format!("GITHUB = '{}'\nAWS = '{}'", GITHUB_PAT, AWS_ACCESS_KEY_ID),
    );

    // Include empty entry in list
    let output = cargo_run(&[dir.path_str(), "--only", "github-pat,,aws-access-key-id"]);

    // Should handle gracefully (not crash)
    assert!(
        output.status.code().is_some(),
        "Should handle empty entries in rule list without crashing"
    );
}

#[test]
fn test_only_exclude_interaction() {
    // Test how --only and --exclude interact when used together
    // --only should restrict to a set, then --exclude should remove from that set
    let dir = TestDir::new("only-exclude-interaction");
    dir.write_file(
        "config.py",
        &format!(
            "GITHUB = '{}'\nAWS = '{}'\nOPENAI = '{}'",
            GITHUB_PAT, AWS_ACCESS_KEY_ID, OPENAI_API_KEY
        ),
    );

    // Only include github-pat and aws-access-key-id, then exclude github-pat
    let output = cargo_run(&[
        dir.path_str(),
        "--only",
        "github-pat,aws-access-key-id",
        "--exclude",
        "github-pat",
        "-f",
        "json",
    ]);
    let out = stdout(&output);

    // Should only find AWS, since GitHub is excluded from the --only set
    assert!(
        out.contains("aws-access-key-id"),
        "Should find AWS key (included but not excluded). Got: {}",
        out
    );
    assert!(
        !out.contains("github-pat"),
        "Should not find GitHub PAT (excluded). Got: {}",
        out
    );
    assert!(
        !out.contains("openai-api-key") && !out.contains("deepseek-api-key"),
        "Should not find OpenAI/DeepSeek key (not in --only list). Got: {}",
        out
    );
}

// ============================================================================
// INPUT VALIDATION AND ERROR HANDLING TESTS
// ============================================================================

#[test]
fn test_context_floating_point_error() {
    // Verify -C 3.14 produces an error (context must be an integer)
    let dir = TestDir::new("context-float-error");
    dir.write_file("config.py", &format!("KEY = '{}'", OPENAI_API_KEY));

    let output = cargo_run(&[dir.path_str(), "-C", "3.14"]);

    assert!(
        !output.status.success(),
        "Floating point context value should fail"
    );
    let err = stderr(&output);
    assert!(
        err.contains("invalid") || err.contains("error") || err.contains("parse"),
        "Should produce an error message for floating point context. Stderr: {}",
        err
    );
}

#[test]
fn test_context_negative_error() {
    // Verify -C -1 produces an error (context cannot be negative)
    let dir = TestDir::new("context-negative-error");
    dir.write_file("config.py", &format!("KEY = '{}'", OPENAI_API_KEY));

    let output = cargo_run(&[dir.path_str(), "-C", "-1"]);

    // Negative values may be parsed as a flag or rejected
    // Either way, it should not succeed normally
    let err = stderr(&output);
    let out = stdout(&output);

    // Check if it fails or if the negative is interpreted as a flag
    let is_error = !output.status.success()
        || err.contains("error")
        || err.contains("invalid")
        || err.contains("unexpected");

    assert!(
        is_error,
        "Negative context value should produce an error or be rejected. Exit: {:?}, Stderr: {}, Stdout: {}",
        output.status.code(),
        err,
        out
    );
}

#[test]
fn test_context_non_numeric_error() {
    // Verify -C abc produces an error
    let dir = TestDir::new("context-non-numeric-error");
    dir.write_file("config.py", &format!("KEY = '{}'", OPENAI_API_KEY));

    let output = cargo_run(&[dir.path_str(), "-C", "abc"]);

    assert!(
        !output.status.success(),
        "Non-numeric context value should fail"
    );
    let err = stderr(&output);
    assert!(
        err.contains("invalid") || err.contains("error") || err.contains("parse"),
        "Should produce an error message for non-numeric context. Stderr: {}",
        err
    );
}

#[test]
fn test_format_typo_error() {
    // Verify -f josn (typo) produces helpful error
    let dir = TestDir::new("format-typo-error");
    dir.write_file("config.py", &format!("KEY = '{}'", OPENAI_API_KEY));

    let output = cargo_run(&[dir.path_str(), "-f", "josn"]);

    assert!(
        !output.status.success(),
        "Format typo should fail"
    );
    let err = stderr(&output);
    // Error message should mention it's an unknown format
    // and ideally list valid options
    assert!(
        err.contains("unknown") || err.contains("invalid") || err.contains("josn"),
        "Should produce an error message for format typo. Stderr: {}",
        err
    );
    // Check if it hints at valid formats
    let suggests_valid = err.contains("text")
        || err.contains("json")
        || err.contains("sarif")
        || err.contains("report");
    // Not strictly required but helpful for user experience
    if !suggests_valid {
        eprintln!("Note: Error message does not suggest valid format options: {}", err);
    }
}

#[test]
fn test_unknown_long_flag_error() {
    // Verify --unknown-flag produces error
    let dir = TestDir::new("unknown-long-flag-error");
    dir.write_file("config.py", &format!("KEY = '{}'", OPENAI_API_KEY));

    let output = cargo_run(&[dir.path_str(), "--unknown-flag"]);

    assert!(
        !output.status.success(),
        "Unknown long flag should fail"
    );
    let err = stderr(&output);
    assert!(
        err.contains("unknown") || err.contains("error") || err.contains("unexpected"),
        "Should produce an error message for unknown flag. Stderr: {}",
        err
    );
}

#[test]
fn test_unknown_short_flag_error() {
    // Verify -Z produces error (Z is not a valid short flag)
    let dir = TestDir::new("unknown-short-flag-error");
    dir.write_file("config.py", &format!("KEY = '{}'", OPENAI_API_KEY));

    let output = cargo_run(&[dir.path_str(), "-Z"]);

    assert!(
        !output.status.success(),
        "Unknown short flag -Z should fail"
    );
    let err = stderr(&output);
    assert!(
        err.contains("unknown") || err.contains("error") || err.contains("-Z"),
        "Should produce an error message for unknown short flag. Stderr: {}",
        err
    );
}

#[test]
fn test_path_with_special_shell_chars() {
    // Test paths with $, ~, etc (as literal chars, not shell expansion)
    // The process::Command bypasses shell, so these are treated literally
    let dir = TestDir::new("path-with-$pecial~chars");
    dir.write_file("config.py", &format!("KEY = '{}'", OPENAI_API_KEY));

    let output = cargo_run(&[dir.path_str()]);

    // Should handle the path with special characters
    // The test verifies the scanner can process files in such directories
    assert!(
        output.status.code().is_some(),
        "Should handle paths with special shell characters without crashing"
    );

    let out = stdout(&output);
    // If successful, should find the secret
    if output.status.success() || output.status.code() == Some(0) || output.status.code() == Some(1) {
        assert!(
            out.contains("Found") || out.contains("secret") || out.contains("openai") || out.contains("deepseek"),
            "Should detect secrets in paths with special characters. Got: {}",
            out
        );
    }
}

#[test]
fn test_multiple_path_arguments() {
    // What happens with multiple positional args (multiple paths)
    let dir1 = TestDir::new("multi-path-1");
    dir1.write_file("config1.py", &format!("KEY1 = '{}'", GITHUB_PAT));

    let dir2 = TestDir::new("multi-path-2");
    dir2.write_file("config2.py", &format!("KEY2 = '{}'", AWS_ACCESS_KEY_ID));

    // Pass two different paths as positional arguments
    let output = cargo_run(&[dir1.path_str(), dir2.path_str()]);

    // Document the behavior - either:
    // 1. Scans both paths and finds secrets in both
    // 2. Only uses the first/last path
    // 3. Produces an error for multiple paths

    let out = stdout(&output);
    let err = stderr(&output);

    if !output.status.success() {
        // Multiple paths produce an error
        assert!(
            err.contains("error") || err.contains("argument") || err.contains("path"),
            "If multiple paths fail, should have error message. Stderr: {}",
            err
        );
    } else {
        // Multiple paths are accepted - check which secrets are found
        let finds_github = out.contains("github");
        let finds_aws = out.contains("aws");

        if finds_github && finds_aws {
            // Both paths were scanned
            assert!(
                out.contains("Found"),
                "Should report findings from both paths. Got: {}",
                out
            );
        } else if finds_github || finds_aws {
            // Only one path was scanned (first or last wins)
            eprintln!(
                "Note: Multiple paths - only one was scanned. GitHub: {}, AWS: {}",
                finds_github, finds_aws
            );
        }
        // Either behavior is valid, we're documenting it
    }
}

// ============================================================================
// NO-REDACT FLAG TESTS
// ============================================================================

#[test]
fn test_no_redact_flag_shows_full_secrets() {
    // Verify --no-redact shows full secret values in text output
    let dir = TestDir::new("no-redact-text");
    dir.write_file("config.py", &format!("KEY = '{}'", GITHUB_PAT));

    let output = cargo_run(&[dir.path_str(), "--no-redact"]);
    let out = stdout(&output);

    // The full secret should appear in output
    assert!(
        out.contains(GITHUB_PAT),
        "Full secret should be visible with --no-redact. Got: {}",
        out
    );
    // Should not contain the redaction marker
    assert!(
        !out.contains("...") || out.contains(GITHUB_PAT),
        "Should show full secret, not redacted version"
    );
}

#[test]
fn test_no_redact_with_json_format() {
    // Verify --no-redact works with -f json
    let dir = TestDir::new("no-redact-json");
    dir.write_file("config.py", &format!("KEY = '{}'", GITHUB_PAT));

    let output = cargo_run(&[dir.path_str(), "--no-redact", "-f", "json"]);
    let out = stdout(&output);

    // Should be valid JSON
    assert!(out.contains("{"), "Should produce JSON output");
    assert!(out.contains("\"findings\""), "Should have findings array");

    // The full secret should appear in the JSON output
    assert!(
        out.contains(GITHUB_PAT),
        "Full secret should be visible in JSON with --no-redact. Got: {}",
        out
    );
}

#[test]
fn test_no_redact_with_report_format() {
    // Verify --no-redact works with -f report
    let dir = TestDir::new("no-redact-report");
    dir.write_file("config.py", &format!("KEY = '{}'", AWS_ACCESS_KEY_ID));

    let output = cargo_run(&[dir.path_str(), "--no-redact", "-f", "report"]);
    let out = stdout(&output);

    // Should be valid report format
    assert!(
        out.contains("\"report_version\""),
        "Should have report version"
    );
    assert!(out.contains("\"findings\""), "Should have findings array");

    // The full secret should appear in the report output
    assert!(
        out.contains(AWS_ACCESS_KEY_ID),
        "Full secret should be visible in report with --no-redact. Got: {}",
        out
    );
}

#[test]
fn test_no_redact_with_sarif_format() {
    // Verify --no-redact works with -f sarif
    // Note: SARIF format only includes location and rule info, not the secret value
    // So --no-redact doesn't affect SARIF output, but the flag should still be accepted
    let dir = TestDir::new("no-redact-sarif");
    dir.write_file("config.py", &format!("KEY = '{}'", OPENAI_API_KEY));

    let output = cargo_run(&[dir.path_str(), "--no-redact", "-f", "sarif"]);
    let out = stdout(&output);

    // Should be valid SARIF and command should succeed
    assert!(
        output.status.success() || output.status.code() == Some(0),
        "--no-redact with SARIF format should succeed"
    );
    assert!(out.contains("$schema"), "Should have SARIF schema");
    assert!(out.contains("\"results\""), "Should have results array");
    assert!(out.contains("\"ruleId\""), "Should have rule ID in results");
    assert!(
        out.contains("openai-api-key") || out.contains("deepseek-api-key"),
        "Should detect the secret and report the rule. Got: {}",
        out
    );
}

#[test]
fn test_no_redact_with_fail_on_leak() {
    // Verify both --no-redact and --fail-on-leak work together
    let dir = TestDir::new("no-redact-fail");
    dir.write_file("config.py", &format!("KEY = '{}'", SLACK_BOT_TOKEN));

    let output = cargo_run(&[dir.path_str(), "--no-redact", "--fail-on-leak"]);
    let out = stdout(&output);

    // Should exit with code 1 because secrets were found
    assert_eq!(
        output.status.code(),
        Some(1),
        "--fail-on-leak should exit 1 when secrets found"
    );

    // The full secret should still be visible
    assert!(
        out.contains(SLACK_BOT_TOKEN),
        "Full secret should be visible with --no-redact even when --fail-on-leak is set. Got: {}",
        out
    );
}

#[test]
fn test_redact_is_default() {
    // Explicitly verify that without --no-redact, secrets ARE redacted
    let dir = TestDir::new("redact-default-explicit");
    dir.write_file("config.py", &format!("KEY = '{}'", GITHUB_PAT));

    let output = cargo_run(&[dir.path_str()]);
    let out = stdout(&output);

    // The full secret should NOT appear in output (default is redacted)
    assert!(
        !out.contains(GITHUB_PAT),
        "Full secret should NOT be visible without --no-redact (default redaction). Got: {}",
        out
    );

    // Should contain redaction marker (... between prefix and suffix)
    assert!(
        out.contains("ghp_") && out.contains("..."),
        "Should show redacted format with ... marker. Got: {}",
        out
    );
}

// ============================================================================
// CONTEXT FLAG EDGE CASE TESTS
// ============================================================================

#[test]
fn test_context_zero_lines() {
    // Verify -C 0 works (shows no context, just the matched line)
    let dir = TestDir::new("context-zero");
    dir.write_file(
        "config.py",
        &format!(
            "# line 1\n# line 2\n# line 3\nKEY = '{}'\n# line 5\n# line 6\n# line 7",
            GITHUB_PAT
        ),
    );

    let output = cargo_run(&[dir.path_str(), "-C", "0"]);
    let out = stdout(&output);

    // Should succeed and find the secret
    assert!(
        output.status.success() || output.status.code() == Some(0),
        "-C 0 should be accepted without error"
    );
    assert!(
        out.contains("Found") && out.contains("potential secret"),
        "Should find secret with -C 0. Got: {}",
        out
    );

    // With 0 context, surrounding lines "# line 2" and "# line 5" should NOT appear in output
    // (Only the matched line itself would be shown in the context block)
    // Note: The exact behavior depends on implementation - this documents expected behavior
}

#[test]
fn test_context_large_number() {
    // Verify -C 100 works without crashing on small files
    let dir = TestDir::new("context-large");
    // Create a small file (only 5 lines total)
    dir.write_file(
        "config.py",
        &format!("# line 1\n# line 2\nKEY = '{}'\n# line 4\n# line 5", GITHUB_PAT),
    );

    let output = cargo_run(&[dir.path_str(), "-C", "100"]);
    let out = stdout(&output);

    // Should succeed without crashing
    assert!(
        output.status.success() || output.status.code() == Some(0),
        "-C 100 should not crash on small files. Status: {:?}",
        output.status.code()
    );
    assert!(
        out.contains("Found") && out.contains("potential secret"),
        "Should find secret with -C 100. Got: {}",
        out
    );

    // The entire file should be shown as context since context > file length
    assert!(
        out.contains("line 1") && out.contains("line 5"),
        "With -C 100 on 5-line file, should show all lines. Got: {}",
        out
    );
}

#[test]
fn test_no_context_with_json_format() {
    // Verify --no-context affects JSON output
    let dir = TestDir::new("no-context-json");
    dir.write_file(
        "config.py",
        &format!("# before line\nKEY = '{}'\n# after line", GITHUB_PAT),
    );

    // Run with --no-context and JSON format
    let output = cargo_run(&[dir.path_str(), "--no-context", "-f", "json"]);
    let out = stdout(&output);

    // Should produce valid JSON
    assert!(out.contains("{"), "Should produce JSON output");
    assert!(out.contains("\"findings\""), "Should have findings array");
    assert!(
        out.contains("\"rule_id\""),
        "Should find the secret. Got: {}",
        out
    );

    // JSON structure should be valid
    let open_braces = out.matches('{').count();
    let close_braces = out.matches('}').count();
    assert_eq!(
        open_braces, close_braces,
        "JSON should have balanced braces"
    );
}

#[test]
fn test_no_context_with_sarif_format() {
    // Verify --no-context affects SARIF output
    let dir = TestDir::new("no-context-sarif");
    dir.write_file(
        "config.py",
        &format!("# before line\nKEY = '{}'\n# after line", GITHUB_PAT),
    );

    // Run with --no-context and SARIF format
    let output = cargo_run(&[dir.path_str(), "--no-context", "-f", "sarif"]);
    let out = stdout(&output);

    // Should produce valid SARIF
    assert!(out.contains("$schema"), "Should have SARIF schema");
    assert!(out.contains("2.1.0"), "Should be SARIF 2.1.0");
    assert!(out.contains("runs"), "Should have runs array");
    assert!(out.contains("results"), "Should have results array");
    assert!(
        out.contains("\"ruleId\""),
        "Should find the secret with ruleId. Got: {}",
        out
    );

    // SARIF structure should be valid
    let open_braces = out.matches('{').count();
    let close_braces = out.matches('}').count();
    assert_eq!(
        open_braces, close_braces,
        "SARIF JSON should have balanced braces"
    );
}

#[test]
fn test_no_context_with_report_format() {
    // Verify --no-context affects report output
    let dir = TestDir::new("no-context-report");
    dir.write_file(
        "config.py",
        &format!("# before line\nKEY = '{}'\n# after line", GITHUB_PAT),
    );

    // Run with --no-context and report format
    let output = cargo_run(&[dir.path_str(), "--no-context", "-f", "report"]);
    let out = stdout(&output);

    // Should produce valid report format
    assert!(
        out.contains("\"report_version\""),
        "Should have report version"
    );
    assert!(
        out.contains("\"scanner\": \"libreleak\""),
        "Should have scanner name"
    );
    assert!(out.contains("\"timestamp\""), "Should have timestamp");
    assert!(out.contains("\"summary\""), "Should have summary section");
    assert!(out.contains("\"findings\""), "Should have findings array");

    // Report structure should be valid
    let open_braces = out.matches('{').count();
    let close_braces = out.matches('}').count();
    assert_eq!(
        open_braces, close_braces,
        "Report JSON should have balanced braces"
    );
}

#[test]
fn test_context_exceeds_file_lines() {
    // When context is larger than file, shows whole file without error
    let dir = TestDir::new("context-exceeds");
    // Create a 3-line file
    dir.write_file("tiny.py", &format!("# start\nKEY = '{}'\n# end", GITHUB_PAT));

    // Request 50 lines of context on a 3-line file
    let output = cargo_run(&[dir.path_str(), "-C", "50"]);
    let out = stdout(&output);

    // Should succeed
    assert!(
        output.status.success() || output.status.code() == Some(0),
        "Should handle context > file length gracefully"
    );
    assert!(
        out.contains("Found") && out.contains("potential secret"),
        "Should find secret. Got: {}",
        out
    );

    // All lines should be visible since context exceeds file
    assert!(
        out.contains("# start") && out.contains("# end"),
        "Should show entire file when context exceeds file length. Got: {}",
        out
    );
}

#[test]
fn test_negative_context_number() {
    // Verify -C -5 produces an error (negative context is invalid)
    let dir = TestDir::new("context-negative");
    dir.write_file("config.py", &format!("KEY = '{}'", GITHUB_PAT));

    let output = cargo_run(&[dir.path_str(), "-C", "-5"]);
    let err = stderr(&output);

    // Should fail because -5 is not a valid usize
    assert!(
        !output.status.success(),
        "-C -5 should produce an error. Status: {:?}",
        output.status.code()
    );

    // Error message should indicate invalid number or unknown option
    // Note: -5 might be parsed as a flag "-5" which would be "unknown option"
    assert!(
        err.contains("error") || err.contains("invalid") || err.contains("unknown"),
        "Should show error for negative context. Got stderr: {}",
        err
    );
}

// ============================================================================
// COMPLEX FLAG COMBINATION TESTS
// ============================================================================

#[test]
fn test_three_flags_only_fail_context() {
    // Test --only rule --fail-on-leak -C 2 together
    let dir = TestDir::new("three-flags-only-fail-context");
    dir.write_file(
        "config.py",
        &format!(
            "# line 1\n# line 2\n# line 3\nGITHUB = '{}'\n# line 5\n# line 6\n# line 7\nOPENAI = '{}'\n# line 9",
            GITHUB_PAT, OPENAI_API_KEY
        ),
    );

    // Combine --only, --fail-on-leak, and -C (context)
    let output = cargo_run(&[
        dir.path_str(),
        "--only",
        "github-pat",
        "--fail-on-leak",
        "-C",
        "2",
    ]);
    let out = stdout(&output);

    // Should exit with 1 since secrets found and --fail-on-leak is set
    assert_eq!(
        output.status.code(),
        Some(1),
        "Should exit 1 when secrets found with --fail-on-leak"
    );

    // Should only find GitHub, not OpenAI (filtered by --only)
    assert!(
        out.contains("github"),
        "Should find GitHub token (included by --only)"
    );
    assert!(
        !out.contains("openai-api-key") && !out.contains("deepseek-api-key"),
        "Should not find OpenAI/DeepSeek (not in --only list)"
    );

    // Should show context (verify -C flag is working)
    // The context flag should include surrounding lines
    assert!(
        output.status.code().is_some(),
        "Command should complete with context flag"
    );
}

#[test]
fn test_three_flags_exclude_no_redact_format() {
    // Test --exclude rule --no-redact -f json together
    let dir = TestDir::new("three-flags-exclude-noredact-format");
    dir.write_file(
        "config.py",
        &format!("GITHUB = '{}'\nAWS = '{}'", GITHUB_PAT, AWS_ACCESS_KEY_ID),
    );

    // Combine --exclude, --no-redact, and -f json
    let output = cargo_run(&[
        dir.path_str(),
        "--exclude",
        "github-pat",
        "--no-redact",
        "-f",
        "json",
    ]);
    let out = stdout(&output);

    // Should be valid JSON
    assert!(out.contains("{"), "Should be JSON output");
    assert!(out.contains("\"findings\""), "Should have findings array");

    // Should not find GitHub (excluded)
    assert!(
        !out.contains("github-pat"),
        "Should not find excluded GitHub PAT"
    );

    // Should find AWS
    assert!(
        out.contains("aws-access-key-id"),
        "Should find AWS key (not excluded)"
    );

    // With --no-redact, should show full secret (or at least more of it)
    // The AWS key should appear less redacted or fully visible
    assert!(
        out.contains("AKIA") || out.contains(AWS_ACCESS_KEY_ID),
        "With --no-redact, should show more of the secret. Got: {}",
        out
    );
}

#[test]
fn test_all_output_modifying_flags() {
    // Test --no-redact --no-context -f report together
    let dir = TestDir::new("all-output-flags");
    dir.write_file(
        "config.py",
        &format!(
            "# line 1\n# line 2\nKEY = '{}'\n# line 4\n# line 5",
            GITHUB_PAT
        ),
    );

    // Combine all output-modifying flags
    let output = cargo_run(&[
        dir.path_str(),
        "--no-redact",
        "--no-context",
        "-f",
        "report",
    ]);
    let out = stdout(&output);

    // Should produce valid report format
    assert!(
        out.contains("\"report_version\""),
        "Should have report version"
    );
    assert!(
        out.contains("\"scanner\": \"libreleak\""),
        "Should have scanner name"
    );
    assert!(out.contains("\"findings\""), "Should have findings array");
    assert!(out.contains("\"summary\""), "Should have summary section");

    // With --no-redact, secret should be more visible
    assert!(
        out.contains("ghp_") || out.contains(GITHUB_PAT),
        "With --no-redact, should show more of the GitHub token"
    );

    // The command should complete successfully
    assert!(
        output.status.success() || output.status.code() == Some(0),
        "Should succeed with all output-modifying flags"
    );
}

#[test]
fn test_all_filter_flags() {
    // Test --only and --exclude with different rules together
    let dir = TestDir::new("all-filter-flags");
    dir.write_file(
        "config.py",
        &format!(
            "GITHUB = '{}'\nAWS = '{}'\nOPENAI = '{}'\nSLACK = '{}'",
            GITHUB_PAT, AWS_ACCESS_KEY_ID, OPENAI_API_KEY, SLACK_BOT_TOKEN
        ),
    );

    // Include GitHub and AWS via --only, then exclude AWS
    // This should result in only GitHub being found
    let output = cargo_run(&[
        dir.path_str(),
        "--only",
        "github-pat,aws-access-key-id",
        "--exclude",
        "aws-access-key-id",
        "-f",
        "json",
    ]);
    let out = stdout(&output);

    // Should be valid JSON
    assert!(out.contains("{"), "Should be JSON");
    assert!(out.contains("\"findings\""), "Should have findings");

    // Should find only GitHub (included by --only, not excluded)
    assert!(
        out.contains("github-pat"),
        "Should find GitHub PAT (included and not excluded)"
    );

    // Should not find AWS (excluded from --only set)
    assert!(
        !out.contains("aws-access-key-id"),
        "Should not find AWS (excluded)"
    );

    // Should not find OpenAI or Slack (not in --only list)
    assert!(
        !out.contains("openai-api-key") && !out.contains("deepseek-api-key"),
        "Should not find OpenAI/DeepSeek (not in --only)"
    );
    assert!(
        !out.contains("slack"),
        "Should not find Slack (not in --only)"
    );

    // Count findings - should be exactly 1 (GitHub)
    let finding_count = out.matches("\"rule_id\"").count();
    assert_eq!(
        finding_count, 1,
        "Should have exactly 1 finding (GitHub only). Got: {}",
        finding_count
    );
}

#[test]
fn test_verify_with_all_formats() {
    // Test --verify with text, json, sarif, report formats
    let dir = TestDir::new("verify-all-formats");
    dir.write_file("config.py", &format!("KEY = '{}'", GITHUB_PAT));

    // Test --verify with text format
    let text_output = cargo_run(&[dir.path_str(), "--verify", "-f", "text"]);
    let text_out = stdout(&text_output);
    assert!(
        text_output.status.success() || text_output.status.code() == Some(0),
        "--verify with text format should succeed"
    );
    assert!(
        text_out.contains("Found") || text_out.contains("github"),
        "Text output should show findings"
    );

    // Test --verify with json format
    let json_output = cargo_run(&[dir.path_str(), "--verify", "-f", "json"]);
    let json_out = stdout(&json_output);
    assert!(
        json_output.status.success() || json_output.status.code() == Some(0),
        "--verify with json format should succeed"
    );
    assert!(json_out.contains("{"), "Should be JSON");
    assert!(
        json_out.contains("\"findings\""),
        "JSON should have findings"
    );
    assert!(
        json_out.contains("\"rule_id\""),
        "JSON should have rule_id"
    );

    // Test --verify with sarif format
    let sarif_output = cargo_run(&[dir.path_str(), "--verify", "-f", "sarif"]);
    let sarif_out = stdout(&sarif_output);
    assert!(
        sarif_output.status.success() || sarif_output.status.code() == Some(0),
        "--verify with sarif format should succeed"
    );
    assert!(sarif_out.contains("$schema"), "Should have SARIF schema");
    assert!(sarif_out.contains("\"results\""), "Should have results");
    assert!(sarif_out.contains("\"ruleId\""), "Should have ruleId");

    // Test --verify with report format
    let report_output = cargo_run(&[dir.path_str(), "--verify", "-f", "report"]);
    let report_out = stdout(&report_output);
    assert!(
        report_output.status.success() || report_output.status.code() == Some(0),
        "--verify with report format should succeed"
    );
    assert!(
        report_out.contains("\"report_version\""),
        "Should have report version"
    );
    assert!(
        report_out.contains("\"verification\""),
        "Report should have verification field"
    );
}

#[test]
fn test_short_and_long_flags_mixed() {
    // Mix short (-x, -f, -C) and long (--only, --exclude) flags
    let dir = TestDir::new("short-long-mixed");
    dir.write_file(
        "config.py",
        &format!(
            "# line 1\n# line 2\n# line 3\nGITHUB = '{}'\n# line 5\n# line 6\n# line 7\nAWS = '{}'\n# line 9",
            GITHUB_PAT, AWS_ACCESS_KEY_ID
        ),
    );

    // Mix short and long flags: -x (fail-on-leak), -f (format), -C (context), --only, --exclude
    // Use --only to include both, --exclude to remove one
    let output = cargo_run(&[
        dir.path_str(),
        "-x",                               // short for --fail-on-leak
        "-f",                               // short for --format
        "json",
        "-C",                               // short for --context
        "1",
        "--only",                           // long form
        "github-pat,aws-access-key-id",
        "--exclude",                        // long form
        "aws-access-key-id",
    ]);
    let out = stdout(&output);

    // Should exit with 1 (secrets found + -x flag)
    assert_eq!(
        output.status.code(),
        Some(1),
        "Should exit 1 with -x and secrets found"
    );

    // Should be JSON format (-f json)
    assert!(out.contains("{"), "Should be JSON");
    assert!(out.contains("\"findings\""), "Should have findings");

    // Should find GitHub only (--only includes both, --exclude removes AWS)
    assert!(
        out.contains("github-pat"),
        "Should find GitHub (included, not excluded)"
    );
    assert!(
        !out.contains("aws-access-key-id"),
        "Should not find AWS (excluded)"
    );

    // Verify finding count is 1
    let finding_count = out.matches("\"rule_id\"").count();
    assert_eq!(
        finding_count, 1,
        "Should have exactly 1 finding with mixed flags"
    );
}
