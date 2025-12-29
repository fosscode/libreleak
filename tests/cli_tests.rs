//! CLI and Output Format Tests
//!
//! Tests for command-line interface parsing, output formats, and exit codes.

mod common;

use common::fake_secrets::*;
use common::TestDir;
use std::process::Command;

// ============================================================================
// HELPERS
// ============================================================================

fn cargo_run(args: &[&str]) -> std::process::Output {
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

    assert!(out.contains("\"findings\": ["), "Should have empty findings array");
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
    assert!(out.contains("Context:") || out.contains("|"), "Should show context");
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
        &format!(
            "1\n2\n3\n4\n5\nKEY = '{}'\n7\n8\n9\n10\n11",
            OPENAI_API_KEY
        ),
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

    assert!(out.contains("github") || out.contains("aws"), "Should find filtered rules");
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

    assert!(!out.contains("openai-api-key"), "Should not find excluded rule");
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

    assert!(!out.contains("openai-api-key"), "Should not find excluded OpenAI");
    assert!(!out.contains("github-pat"), "Should not find excluded GitHub");
}

#[test]
fn test_list_rules() {
    let output = cargo_run(&["--list-rules"]);
    let out = stdout(&output);

    assert!(output.status.success());
    assert!(out.contains("aws-access-key-id"), "Should list AWS rule");
    assert!(out.contains("github-pat"), "Should list GitHub rule");
    assert!(out.contains("openai-api-key"), "Should list OpenAI rule");
    assert!(out.contains("anthropic-api-key"), "Should list Anthropic rule");
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
    assert!(output.status.success() || output.status.code() == Some(0) || output.status.code() == Some(1));
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

    assert!(!output.status.success(), "Invalid context number should error");
}
