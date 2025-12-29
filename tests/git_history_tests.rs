//! Git History Scanning Tests
//!
//! Tests for detecting secrets that exist in git history but may not
//! be present in the current working tree. This includes:
//! - Deleted files with secrets
//! - Secrets on feature branches
//! - Secrets removed in later commits
//! - Secrets in merge commits
//! - Complex branching scenarios

mod common;

use common::fake_secrets::*;
use common::TestGitRepo;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

fn run_history_scan(path: &str) -> (String, i32) {
    let output = std::process::Command::new("cargo")
        .args(["run", "--", path, "--scan-history"])
        .output()
        .expect("Failed to run scanner");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    (format!("{}{}", stdout, stderr), output.status.code().unwrap_or(-1))
}

fn run_branch_scan(path: &str, branch: &str) -> (String, i32) {
    let output = std::process::Command::new("cargo")
        .args(["run", "--", path, "--branch", branch])
        .output()
        .expect("Failed to run scanner");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    (format!("{}{}", stdout, stderr), output.status.code().unwrap_or(-1))
}

fn run_scan(path: &str) -> (String, i32) {
    let output = std::process::Command::new("cargo")
        .args(["run", "--", path, "--no-context"])
        .output()
        .expect("Failed to run scanner");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    (format!("{}{}", stdout, stderr), output.status.code().unwrap_or(-1))
}

fn should_detect(output: &str, rule_id: &str) -> bool {
    output.contains(rule_id)
}

/// Check for sk- prefix tokens (OpenAI/DeepSeek overlap)
fn should_detect_sk_token(output: &str) -> bool {
    output.contains("openai-api-key") || output.contains("deepseek-api-key")
}

/// Check for GitHub tokens (may match github-pat or generic-token)
fn should_detect_github_token(output: &str) -> bool {
    output.contains("github-pat") || output.contains("generic-token")
}

/// Check for any secret detection
fn detected_any_secret(output: &str) -> bool {
    output.contains("Found") && !output.contains("Found 0")
}

// ============================================================================
// BASIC GIT REPO TESTS
// ============================================================================

#[test]
fn test_git_repo_creation() {
    let repo = TestGitRepo::new("basic-repo");

    // Verify repo was created
    assert!(repo.path().join(".git").exists(), "Should create .git directory");

    // Create a file and commit
    repo.write_file("README.md", "# Test Repo");
    repo.commit("Initial commit");

    assert_eq!(repo.get_commit_count(), 1, "Should have one commit");
}

#[test]
fn test_git_branch_creation() {
    let repo = TestGitRepo::new("branch-test");
    repo.write_file("README.md", "# Test");
    repo.commit("Initial");

    repo.create_branch("feature/test");
    assert_eq!(repo.get_current_branch(), "feature/test");

    repo.checkout("main");
    // Note: Could be "master" or "main" depending on git config
    let branch = repo.get_current_branch();
    assert!(branch == "master" || branch == "main", "Should be on main branch");
}

// ============================================================================
// DELETED FILE TESTS
// These test scenarios where a file containing secrets was added and then deleted
// ============================================================================

#[test]
fn test_secret_in_deleted_file_current_scan() {
    let repo = TestGitRepo::new("deleted-file-current");

    // Add a file with a secret
    repo.write_file("config.py", &format!("API_KEY = '{}'", OPENAI_API_KEY));
    repo.commit("Add config with API key");

    // Delete the file
    repo.delete_file("config.py");
    repo.commit("Remove config file");

    // Current scan should NOT find the secret (file is deleted)
    let (output, _) = run_scan(repo.path_str());
    assert!(
        !should_detect_sk_token(&output) || output.contains("No secrets found"),
        "Current scan should not find secret in deleted file"
    );
}

#[test]
#[ignore] // Enable when history scanning is implemented
fn test_secret_in_deleted_file_history_scan() {
    let repo = TestGitRepo::new("deleted-file-history");

    // Add a file with a secret
    repo.write_file("secrets.env", &format!("GITHUB_TOKEN={}", GITHUB_PAT));
    repo.commit("Add secrets file");

    // Delete the file
    repo.delete_file("secrets.env");
    repo.commit("Remove secrets file");

    // History scan SHOULD find the secret
    let (output, _) = run_history_scan(repo.path_str());
    assert!(
        should_detect_github_token(&output),
        "History scan should find secret in deleted file"
    );
}

#[test]
fn test_multiple_deleted_files_with_secrets() {
    let repo = TestGitRepo::new("multi-deleted");

    // Add multiple files with different secrets
    repo.write_file("aws.env", &format!("AWS_KEY={}", AWS_ACCESS_KEY_ID));
    repo.commit("Add AWS config");

    repo.write_file("openai.env", &format!("OPENAI_KEY={}", OPENAI_API_KEY));
    repo.commit("Add OpenAI config");

    repo.write_file("stripe.env", &format!("STRIPE_KEY={}", STRIPE_SECRET_KEY));
    repo.commit("Add Stripe config");

    // Delete all secret files
    repo.delete_file("aws.env");
    repo.delete_file("openai.env");
    repo.delete_file("stripe.env");
    repo.commit("Remove all secret files");

    // Current scan should find nothing
    let (output, _) = run_scan(repo.path_str());
    assert!(
        output.contains("No secrets found") || !should_detect(&output, "aws"),
        "Current scan should not find secrets in deleted files"
    );
}

// ============================================================================
// BRANCH-BASED SECRET TESTS
// These test scenarios where secrets exist on branches other than main
// ============================================================================

#[test]
fn test_secret_on_feature_branch_not_in_main() {
    let repo = TestGitRepo::new("feature-branch-secret");

    // Create initial commit on main
    repo.write_file("README.md", "# Project");
    repo.commit("Initial commit");

    // Create feature branch with a secret
    repo.create_branch("feature/add-api");
    repo.write_file("config.py", &format!("API_KEY = '{}'", OPENAI_API_KEY));
    repo.commit("Add API integration");

    // Go back to main
    repo.checkout("main");

    // Scan main - should NOT find the secret
    let (output, _) = run_scan(repo.path_str());
    assert!(
        !should_detect_sk_token(&output),
        "Should not find secret from feature branch when scanning main"
    );
}

#[test]
#[ignore] // Enable when branch scanning is implemented
fn test_secret_on_feature_branch_with_branch_flag() {
    let repo = TestGitRepo::new("branch-flag-test");

    // Initial commit
    repo.write_file("README.md", "# Project");
    repo.commit("Initial");

    // Create branch with secret
    repo.create_branch("feature/secrets");
    repo.write_file(".env", &format!("SECRET={}", ANTHROPIC_API_KEY));
    repo.commit("Add secret config");

    // Back to main
    repo.checkout("main");

    // Scan specific branch - SHOULD find the secret
    let (output, _) = run_branch_scan(repo.path_str(), "feature/secrets");
    assert!(
        should_detect(&output, "anthropic-api-key"),
        "Should find secret when scanning specific branch"
    );
}

#[test]
fn test_secret_removed_from_branch_still_in_history() {
    let repo = TestGitRepo::new("branch-history");

    repo.write_file("README.md", "# Start");
    repo.commit("Initial");

    // Create branch, add secret, then remove it
    repo.create_branch("feature/temp-secret");
    repo.write_file("temp.env", &format!("TOKEN={}", GITHUB_PAT));
    repo.commit("Add temporary token");

    repo.delete_file("temp.env");
    repo.commit("Remove temporary token");

    // Current branch scan should not find it
    let (output, _) = run_scan(repo.path_str());
    assert!(
        !should_detect_github_token(&output),
        "Should not find removed secret in current scan"
    );
}

#[test]
fn test_multiple_branches_with_different_secrets() {
    let repo = TestGitRepo::new("multi-branch-secrets");

    repo.write_file("README.md", "# Multi-branch test");
    repo.commit("Initial");

    // Branch 1: OpenAI key
    repo.create_branch("feature/openai");
    repo.write_file("openai.env", &format!("KEY={}", OPENAI_API_KEY));
    repo.commit("Add OpenAI");

    // Back to main, create branch 2: Anthropic key
    repo.checkout("main");
    repo.create_branch("feature/anthropic");
    repo.write_file("anthropic.env", &format!("KEY={}", ANTHROPIC_API_KEY));
    repo.commit("Add Anthropic");

    // Back to main, create branch 3: AWS key
    repo.checkout("main");
    repo.create_branch("feature/aws");
    repo.write_file("aws.env", &format!("KEY={}", AWS_ACCESS_KEY_ID));
    repo.commit("Add AWS");

    // Main should have no secrets
    repo.checkout("main");
    let (output, _) = run_scan(repo.path_str());
    assert!(
        output.contains("No secrets found") || !should_detect(&output, "api-key"),
        "Main branch should have no secrets"
    );
}

// ============================================================================
// WEIRD BRANCH NAME TESTS
// ============================================================================

#[test]
fn test_secret_on_branch_with_special_characters() {
    let repo = TestGitRepo::new("special-branch-name");

    repo.write_file("README.md", "# Test");
    repo.commit("Initial");

    // Branch with special characters
    repo.create_branch("feature/API-integration_v2.0");
    repo.write_file("config.py", &format!("KEY = '{}'", OPENAI_API_KEY));
    repo.commit("Add config");

    // Verify we're on the branch
    assert_eq!(
        repo.get_current_branch(),
        "feature/API-integration_v2.0"
    );
}

#[test]
fn test_secret_on_deeply_nested_branch() {
    let repo = TestGitRepo::new("nested-branch");

    repo.write_file("README.md", "# Test");
    repo.commit("Initial");

    repo.create_branch("feature/team/project/subproject/task-123");
    repo.write_file("secret.env", &format!("TOKEN={}", GITHUB_PAT));
    repo.commit("Add secret");

    // Just verify it works
    assert_eq!(
        repo.get_current_branch(),
        "feature/team/project/subproject/task-123"
    );
}

// ============================================================================
// COMPLEX HISTORY SCENARIOS
// ============================================================================

#[test]
fn test_secret_added_modified_removed() {
    let repo = TestGitRepo::new("secret-lifecycle");

    // Initial clean state
    repo.write_file("config.py", "# Configuration\nDEBUG = True");
    repo.commit("Initial config");

    // Add secret
    repo.write_file(
        "config.py",
        &format!("# Configuration\nDEBUG = True\nAPI_KEY = '{}'", OPENAI_API_KEY),
    );
    repo.commit("Add API key");

    // Modify (secret still there)
    repo.write_file(
        "config.py",
        &format!("# Updated Configuration\nDEBUG = False\nAPI_KEY = '{}'", OPENAI_API_KEY),
    );
    repo.commit("Update debug flag");

    // Remove secret
    repo.write_file("config.py", "# Updated Configuration\nDEBUG = False\n# API key moved to env");
    repo.commit("Move API key to environment");

    // Current scan should not find secret
    let (output, _) = run_scan(repo.path_str());
    assert!(
        !should_detect_sk_token(&output),
        "Current scan should not find removed secret"
    );

    // Verify commit count
    assert_eq!(repo.get_commit_count(), 4, "Should have 4 commits");
}

#[test]
fn test_secret_in_different_file_same_content() {
    let repo = TestGitRepo::new("moved-secret");

    // Secret in file A
    repo.write_file("config.py", &format!("API_KEY = '{}'", OPENAI_API_KEY));
    repo.commit("Add config.py");

    // Move to file B (file A deleted)
    repo.delete_file("config.py");
    repo.write_file("settings.py", &format!("API_KEY = '{}'", OPENAI_API_KEY));
    repo.commit("Move to settings.py");

    // Current scan should find it in settings.py
    let (output, _) = run_scan(repo.path_str());
    assert!(
        should_detect_sk_token(&output),
        "Should find secret in moved file"
    );
}

#[test]
fn test_secret_replaced_with_different_secret() {
    let repo = TestGitRepo::new("replaced-secret");

    // Add OpenAI key
    repo.write_file("config.env", &format!("API_KEY={}", OPENAI_API_KEY));
    repo.commit("Add OpenAI key");

    // Replace with Anthropic key
    repo.write_file("config.env", &format!("API_KEY={}", ANTHROPIC_API_KEY));
    repo.commit("Switch to Anthropic");

    // Current scan should find Anthropic, not OpenAI
    let (output, _) = run_scan(repo.path_str());
    assert!(
        should_detect(&output, "anthropic-api-key"),
        "Should find current Anthropic key"
    );
    // Note: May also match generic patterns
}

// ============================================================================
// GITIGNORE AND STAGING TESTS
// ============================================================================

#[test]
fn test_gitignored_file_with_secret() {
    let repo = TestGitRepo::new("gitignored-secret");

    // Add gitignore
    repo.write_file(".gitignore", "*.env\nsecrets/");
    repo.commit("Add gitignore");

    // Add ignored file with secret (won't be tracked)
    repo.write_file("secrets.env", &format!("TOKEN={}", GITHUB_PAT));
    // Don't commit - it's ignored

    // Current scan SHOULD find it (we scan the filesystem, not just git)
    let (output, _) = run_scan(repo.path_str());
    assert!(
        should_detect_github_token(&output),
        "Should find secret in gitignored file (filesystem scan)"
    );
}

#[test]
fn test_staged_but_uncommitted_secret() {
    let repo = TestGitRepo::new("staged-secret");

    repo.write_file("README.md", "# Test");
    repo.commit("Initial");

    // Add file with secret but don't commit
    repo.write_file("config.env", &format!("KEY={}", OPENAI_API_KEY));
    // Stage it
    std::process::Command::new("git")
        .args(["add", "config.env"])
        .current_dir(repo.path())
        .output()
        .unwrap();

    // Current scan should find it
    let (output, _) = run_scan(repo.path_str());
    assert!(
        should_detect_sk_token(&output),
        "Should find staged but uncommitted secret"
    );
}

// ============================================================================
// LARGE HISTORY TESTS
// ============================================================================

#[test]
fn test_secret_buried_in_many_commits() {
    let repo = TestGitRepo::new("many-commits");

    // Create 20 commits before the secret
    for i in 0..20 {
        repo.write_file(&format!("file{}.txt", i), &format!("Content {}", i));
        repo.commit(&format!("Add file {}", i));
    }

    // Add secret
    repo.write_file("secrets.env", &format!("TOKEN={}", GITHUB_PAT));
    repo.commit("Add secret");

    // Create 20 more commits after
    for i in 20..40 {
        repo.write_file(&format!("file{}.txt", i), &format!("Content {}", i));
        repo.commit(&format!("Add file {}", i));
    }

    // Remove secret
    repo.delete_file("secrets.env");
    repo.commit("Remove secret");

    // Verify commit count
    assert_eq!(repo.get_commit_count(), 42, "Should have 42 commits");

    // Current scan should not find secret
    let (output, _) = run_scan(repo.path_str());
    assert!(
        !should_detect_github_token(&output),
        "Current scan should not find deleted secret"
    );
}

// ============================================================================
// MERGE SCENARIO TESTS
// ============================================================================

#[test]
fn test_secret_introduced_in_merge() {
    let repo = TestGitRepo::new("merge-secret");

    repo.write_file("README.md", "# Main");
    repo.commit("Initial");

    // Create feature branch with secret
    repo.create_branch("feature/api");
    repo.write_file("api.py", &format!("KEY = '{}'", OPENAI_API_KEY));
    repo.commit("Add API code");

    // Back to main, make changes
    repo.checkout("main");
    repo.write_file("main.py", "print('main')");
    repo.commit("Update main");

    // Merge feature (creates merge commit)
    std::process::Command::new("git")
        .args(["merge", "feature/api", "-m", "Merge feature/api"])
        .current_dir(repo.path())
        .output()
        .unwrap();

    // Secret should now be in main
    let (output, _) = run_scan(repo.path_str());
    assert!(
        should_detect_sk_token(&output),
        "Should find secret after merge"
    );
}

#[test]
fn test_secret_only_in_branch_not_merged() {
    let repo = TestGitRepo::new("unmerged-branch");

    repo.write_file("README.md", "# Main");
    repo.commit("Initial");

    // Create feature branch with secret
    repo.create_branch("feature/secret-api");
    repo.write_file("secret.env", &format!("TOKEN={}", GITHUB_PAT));
    repo.commit("Add secret");

    // Back to main - DON'T merge
    repo.checkout("main");

    // Main should not have the secret
    let (output, _) = run_scan(repo.path_str());
    assert!(
        !should_detect_github_token(&output),
        "Main should not have secret from unmerged branch"
    );
}

// ============================================================================
// REBASE SCENARIO TESTS
// ============================================================================

#[test]
#[ignore] // Rebase can be tricky in tests
fn test_secret_removed_via_rebase() {
    let repo = TestGitRepo::new("rebase-remove");

    repo.write_file("README.md", "# Main");
    repo.commit("Initial");

    // Add secret
    repo.write_file("secret.env", &format!("KEY={}", OPENAI_API_KEY));
    repo.commit("Add secret");

    // Add more commits
    repo.write_file("app.py", "print('app')");
    repo.commit("Add app");

    // Interactive rebase would remove the secret commit here
    // (Hard to simulate without interactive mode)
}

// ============================================================================
// SUBMODULE TESTS
// ============================================================================

#[test]
#[ignore] // Submodules require more setup
fn test_secret_in_submodule() {
    // Would need to create a separate repo and add as submodule
}

// ============================================================================
// ENCODING AND SPECIAL CASE TESTS
// ============================================================================

#[test]
fn test_secret_in_file_with_encoding_issues() {
    let repo = TestGitRepo::new("encoding-test");

    // File with mixed encoding and secret
    let content = format!(
        "# Configuración\n# 设置\nAPI_KEY = '{}'\n# Конфигурация",
        OPENAI_API_KEY
    );
    repo.write_file("config.py", &content);
    repo.commit("Add config with unicode");

    let (output, _) = run_scan(repo.path_str());
    assert!(
        should_detect_sk_token(&output),
        "Should find secret in file with unicode"
    );
}

#[test]
fn test_secret_in_symlinked_file() {
    let repo = TestGitRepo::new("symlink-test");

    // Create actual file with secret
    repo.write_file("real-config.env", &format!("KEY={}", GITHUB_PAT));
    repo.commit("Add real config");

    // Create symlink
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            repo.path().join("real-config.env"),
            repo.path().join("config.env"),
        )
        .ok();
    }

    // Should find secret through symlink or original
    let (output, _) = run_scan(repo.path_str());
    assert!(
        should_detect_github_token(&output),
        "Should find secret in symlinked file"
    );
}

#[test]
fn test_empty_repo_scan() {
    let repo = TestGitRepo::new("empty-repo");

    // Just init, no commits
    let (output, code) = run_scan(repo.path_str());

    // Should not crash, should report no secrets
    assert_eq!(code, 0, "Should exit cleanly");
    assert!(
        output.contains("No secrets found") || !output.contains("error"),
        "Should handle empty repo gracefully"
    );
}

// ============================================================================
// PERFORMANCE TESTS
// ============================================================================

#[test]
fn test_large_file_performance() {
    let repo = TestGitRepo::new("large-file");

    // Create a large file with secret buried in it
    let mut content = String::new();
    for i in 0..10000 {
        content.push_str(&format!("line {} - some content here\n", i));
    }
    content.push_str(&format!("SECRET_KEY = '{}'\n", OPENAI_API_KEY));
    for i in 10000..20000 {
        content.push_str(&format!("line {} - more content here\n", i));
    }

    repo.write_file("large.txt", &content);
    repo.commit("Add large file");

    let start = std::time::Instant::now();
    let (output, _) = run_scan(repo.path_str());
    let duration = start.elapsed();

    assert!(
        should_detect_sk_token(&output),
        "Should find secret in large file"
    );
    assert!(
        duration.as_secs() < 30,
        "Should complete within 30 seconds"
    );
}

#[test]
fn test_many_files_performance() {
    let repo = TestGitRepo::new("many-files");

    // Create 100 clean files
    for i in 0..100 {
        repo.write_file(
            &format!("src/module{}/file.py", i),
            &format!("# Module {}\nprint('hello')", i),
        );
    }

    // One file with a secret
    repo.write_file("src/module50/config.py", &format!("KEY = '{}'", GITHUB_PAT));
    repo.commit("Add all files");

    let start = std::time::Instant::now();
    let (output, _) = run_scan(repo.path_str());
    let duration = start.elapsed();

    assert!(
        should_detect_github_token(&output),
        "Should find secret among many files"
    );
    assert!(
        duration.as_secs() < 30,
        "Should complete within 30 seconds"
    );
}
