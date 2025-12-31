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
use std::sync::{Mutex, OnceLock};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

static CARGO_RUN_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn run_history_scan(path: &str) -> (String, i32) {
    let lock = CARGO_RUN_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().expect("Failed to lock cargo run mutex");

    let output = std::process::Command::new("cargo")
        .args(["run", "--", path, "--scan-history"])
        .output()
        .expect("Failed to run scanner");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    (
        format!("{}{}", stdout, stderr),
        output.status.code().unwrap_or(-1),
    )
}

fn run_branch_scan(path: &str, branch: &str) -> (String, i32) {
    let lock = CARGO_RUN_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().expect("Failed to lock cargo run mutex");

    let output = std::process::Command::new("cargo")
        .args(["run", "--", path, "--branch", branch])
        .output()
        .expect("Failed to run scanner");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    (
        format!("{}{}", stdout, stderr),
        output.status.code().unwrap_or(-1),
    )
}

fn run_scan(path: &str) -> (String, i32) {
    let lock = CARGO_RUN_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock.lock().expect("Failed to lock cargo run mutex");

    let output = std::process::Command::new("cargo")
        .args(["run", "--", path, "--no-context"])
        .output()
        .expect("Failed to run scanner");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    (
        format!("{}{}", stdout, stderr),
        output.status.code().unwrap_or(-1),
    )
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
    assert!(
        repo.path().join(".git").exists(),
        "Should create .git directory"
    );

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
    assert!(
        branch == "master" || branch == "main",
        "Should be on main branch"
    );
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

/// Test that history scanning finds secrets in deleted files.
///
/// MISSING FEATURE: Requires `--scan-history` CLI flag.
///
/// The `--scan-history` feature should:
/// 1. Walk all commits in the repository
/// 2. Check out each commit's tree (or use git diff-tree)
/// 3. Scan file contents at each historical state
/// 4. Report findings with commit SHA context
///
/// Implementation approach:
/// - Use `git log --all --format=%H` to get all commits
/// - For each commit, use `git diff-tree --no-commit-id --name-only -r <sha>`
/// - Use `git show <sha>:<path>` to get file contents
/// - Track which files were deleted (exist in parent but not child)
#[test]
#[ignore = "requires --scan-history CLI flag (not yet implemented)"]
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

/// Test scanning a specific branch using --branch flag.
///
/// MISSING FEATURE: Requires `--branch <name>` CLI flag.
///
/// The `--branch` feature should:
/// 1. Check out the specified branch to a temporary worktree
/// 2. Scan the files as they exist on that branch
/// 3. Report findings with branch context
///
/// Implementation approach:
/// - Use `git worktree add <temp-path> <branch>` for isolation
/// - Scan the worktree path
/// - Clean up with `git worktree remove`
/// - Alternative: `git archive <branch> | tar -x -C <temp>` for read-only access
#[test]
#[ignore = "requires --branch CLI flag (not yet implemented)"]
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
    assert_eq!(repo.get_current_branch(), "feature/API-integration_v2.0");
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
        &format!(
            "# Configuration\nDEBUG = True\nAPI_KEY = '{}'",
            OPENAI_API_KEY
        ),
    );
    repo.commit("Add API key");

    // Modify (secret still there)
    repo.write_file(
        "config.py",
        &format!(
            "# Updated Configuration\nDEBUG = False\nAPI_KEY = '{}'",
            OPENAI_API_KEY
        ),
    );
    repo.commit("Update debug flag");

    // Remove secret
    repo.write_file(
        "config.py",
        "# Updated Configuration\nDEBUG = False\n# API key moved to env",
    );
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

/// Test that history scanning finds secrets even after they were removed via rebase.
///
/// MISSING FEATURE: Requires `--scan-history` CLI flag.
///
/// This scenario tests when a developer:
/// 1. Accidentally commits a secret
/// 2. Uses `git rebase -i` to remove/squash the commit
/// 3. Force pushes to "remove" the secret from history
///
/// However, the secret may still exist in:
/// - Reflog entries
/// - Unreachable objects (until GC)
/// - Forks/clones made before the rebase
///
/// Note: Testing actual rebase is complex because:
/// - Interactive rebase requires user input
/// - Non-interactive rebase with `--onto` can simulate this
/// - After GC, the secret commit becomes unreachable
///
/// For now, this test demonstrates the scenario but requires
/// history scanning to actually verify secret detection.
#[test]
#[ignore = "requires --scan-history CLI flag (not yet implemented)"]
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

    // Simulate rebase that removes the secret commit
    // In a real scenario, the developer would do:
    //   git rebase -i HEAD~2  (then drop the "Add secret" commit)
    //
    // We can simulate the result by using --onto:
    // This creates a new history without the secret commit
    std::process::Command::new("git")
        .args(["rebase", "--onto", "HEAD~2", "HEAD~1", "HEAD"])
        .current_dir(repo.path())
        .output()
        .ok();

    // Current scan should NOT find the secret (file was never created in new history)
    let (output, _) = run_scan(repo.path_str());
    assert!(
        !should_detect_sk_token(&output),
        "Current scan should not find secret after rebase"
    );

    // History scan SHOULD find the secret in reflog/unreachable objects
    // (This requires --scan-history with reflog support)
    // let (output, _) = run_history_scan(repo.path_str());
    // assert!(should_detect_sk_token(&output), "History scan should find secret in reflog");
}

// ============================================================================
// SUBMODULE TESTS
// ============================================================================

/// Test scanning secrets inside git submodules.
///
/// This test verifies that the scanner can find secrets in submodule directories.
/// By default, `git clone` does not initialize submodules, so scanning behavior
/// depends on whether submodules are initialized.
///
/// Current behavior: Scans submodule directory if it exists (initialized submodule)
/// Expected enhancement: Option to automatically init/update submodules before scanning
#[test]
fn test_secret_in_submodule() {
    let repo = TestGitRepo::new("submodule-test");

    // Create the "submodule" repo first
    let submodule_repo = TestGitRepo::new("submodule-source");
    submodule_repo.write_file("README.md", "# Submodule");
    submodule_repo.write_file("config.env", &format!("API_KEY={}", OPENAI_API_KEY));
    submodule_repo.commit("Add config with secret");

    // Create main repo
    repo.write_file("README.md", "# Main project");
    repo.commit("Initial commit");

    // Add as submodule (using file:// protocol for local path)
    let submodule_path = submodule_repo.path().display().to_string();
    let add_result = std::process::Command::new("git")
        .args(["submodule", "add", &format!("file://{}", submodule_path), "vendor/lib"])
        .current_dir(repo.path())
        .output();

    // Skip test if submodule add fails (git version issues, etc.)
    match add_result {
        Ok(output) if output.status.success() => {
            repo.commit("Add submodule");

            // Scan main repo - should find secret in submodule
            let (output, _) = run_scan(repo.path_str());
            assert!(
                should_detect_sk_token(&output),
                "Should find secret in initialized submodule"
            );
        }
        _ => {
            // Submodule add failed - this can happen in restricted environments
            // Just verify basic scanning still works
            let (output, code) = run_scan(repo.path_str());
            assert_eq!(code, 0, "Scanner should not crash on submodule issues");
            // No secret in main repo, so should find none
            assert!(
                output.contains("No secrets found") || !should_detect_sk_token(&output),
                "Should handle submodule gracefully"
            );
        }
    }
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
    assert!(duration.as_secs() < 30, "Should complete within 30 seconds");
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
    assert!(duration.as_secs() < 30, "Should complete within 30 seconds");
}

// ============================================================================
// RENAMED FILE TESTS
// These test scenarios where a file is renamed but content is preserved
// ============================================================================

#[test]
fn test_secret_in_renamed_file_detected() {
    let repo = TestGitRepo::new("renamed-file");

    // Create file with secret
    repo.write_file("old_config.env", &format!("API_KEY={}", OPENAI_API_KEY));
    repo.commit("Add config with secret");

    // Rename the file using git mv
    std::process::Command::new("git")
        .args(["mv", "old_config.env", "new_config.env"])
        .current_dir(repo.path())
        .output()
        .unwrap();
    repo.commit("Rename config file");

    // Secret should still be detected in renamed file
    let (output, _) = run_scan(repo.path_str());
    assert!(
        should_detect_sk_token(&output),
        "Should find secret in renamed file"
    );
}

#[test]
fn test_secret_in_renamed_file_with_modifications() {
    let repo = TestGitRepo::new("renamed-modified");

    // Create file with secret
    repo.write_file("config.py", &format!("# Config\nAPI_KEY = '{}'", OPENAI_API_KEY));
    repo.commit("Add config");

    // Rename and add content
    std::process::Command::new("git")
        .args(["mv", "config.py", "settings.py"])
        .current_dir(repo.path())
        .output()
        .unwrap();
    repo.write_file(
        "settings.py",
        &format!("# Settings\n# Updated config\nAPI_KEY = '{}'\nDEBUG = True", OPENAI_API_KEY),
    );
    repo.commit("Rename and update config");

    // Should detect secret in renamed file
    let (output, _) = run_scan(repo.path_str());
    assert!(
        should_detect_sk_token(&output),
        "Should find secret in renamed and modified file"
    );
}

#[test]
fn test_secret_removed_during_rename() {
    let repo = TestGitRepo::new("renamed-secret-removed");

    // Create file with secret
    repo.write_file("config.env", &format!("API_KEY={}\nDEBUG=true", OPENAI_API_KEY));
    repo.commit("Add config with secret");

    // Rename and remove secret
    std::process::Command::new("git")
        .args(["mv", "config.env", "config.production.env"])
        .current_dir(repo.path())
        .output()
        .unwrap();
    repo.write_file("config.production.env", "DEBUG=false\n# API key moved to vault");
    repo.commit("Rename and remove secret");

    // Current scan should not find secret
    let (output, _) = run_scan(repo.path_str());
    assert!(
        !should_detect_sk_token(&output),
        "Should not find secret after it was removed during rename"
    );
}

#[test]
fn test_multiple_renames_preserving_secret() {
    let repo = TestGitRepo::new("multiple-renames");

    // Create file with secret
    repo.write_file("a.env", &format!("TOKEN={}", GITHUB_PAT));
    repo.commit("Add a.env");

    // First rename
    std::process::Command::new("git")
        .args(["mv", "a.env", "b.env"])
        .current_dir(repo.path())
        .output()
        .unwrap();
    repo.commit("Rename a.env to b.env");

    // Second rename
    std::process::Command::new("git")
        .args(["mv", "b.env", "c.env"])
        .current_dir(repo.path())
        .output()
        .unwrap();
    repo.commit("Rename b.env to c.env");

    // Third rename
    std::process::Command::new("git")
        .args(["mv", "c.env", "final.env"])
        .current_dir(repo.path())
        .output()
        .unwrap();
    repo.commit("Rename c.env to final.env");

    // Should still detect secret after multiple renames
    let (output, _) = run_scan(repo.path_str());
    assert!(
        should_detect_github_token(&output),
        "Should find secret after multiple renames"
    );
}

// ============================================================================
// FILE MOVED BETWEEN DIRECTORIES TESTS
// These test scenarios where files with secrets are moved between directories
// ============================================================================

#[test]
fn test_secret_in_file_moved_to_subdirectory() {
    let repo = TestGitRepo::new("moved-to-subdir");

    // Create file with secret in root
    repo.write_file("config.env", &format!("KEY={}", OPENAI_API_KEY));
    repo.commit("Add config in root");

    // Create subdirectory and move file
    std::fs::create_dir_all(repo.path().join("config")).unwrap();
    std::process::Command::new("git")
        .args(["mv", "config.env", "config/settings.env"])
        .current_dir(repo.path())
        .output()
        .unwrap();
    repo.commit("Move config to subdirectory");

    // Should detect secret in new location
    let (output, _) = run_scan(repo.path_str());
    assert!(
        should_detect_sk_token(&output),
        "Should find secret in file moved to subdirectory"
    );
}

#[test]
fn test_secret_in_file_moved_from_subdirectory() {
    let repo = TestGitRepo::new("moved-from-subdir");

    // Create file with secret in subdirectory
    repo.write_file("deep/nested/path/secret.env", &format!("TOKEN={}", GITHUB_PAT));
    repo.commit("Add secret in nested directory");

    // Move to root
    std::process::Command::new("git")
        .args(["mv", "deep/nested/path/secret.env", "secret.env"])
        .current_dir(repo.path())
        .output()
        .unwrap();
    repo.commit("Move secret to root");

    // Should detect secret in new location
    let (output, _) = run_scan(repo.path_str());
    assert!(
        should_detect_github_token(&output),
        "Should find secret in file moved from subdirectory"
    );
}

#[test]
fn test_secret_moved_between_nested_directories() {
    let repo = TestGitRepo::new("moved-between-dirs");

    // Create file with secret
    repo.write_file("src/config/api.env", &format!("ANTHROPIC_KEY={}", ANTHROPIC_API_KEY));
    repo.commit("Add API config");

    // Move to different nested location
    std::fs::create_dir_all(repo.path().join("lib/settings")).unwrap();
    std::process::Command::new("git")
        .args(["mv", "src/config/api.env", "lib/settings/api.env"])
        .current_dir(repo.path())
        .output()
        .unwrap();
    repo.commit("Reorganize config files");

    // Should detect secret
    let (output, _) = run_scan(repo.path_str());
    assert!(
        should_detect(&output, "anthropic-api-key"),
        "Should find secret in file moved between directories"
    );
}

#[test]
fn test_secret_removed_after_directory_move() {
    let repo = TestGitRepo::new("removed-after-move");

    // Create file with secret
    repo.write_file("dev/config.env", &format!("SECRET={}", OPENAI_API_KEY));
    repo.commit("Add dev config");

    // Move to prod directory and remove secret
    std::fs::create_dir_all(repo.path().join("prod")).unwrap();
    std::process::Command::new("git")
        .args(["mv", "dev/config.env", "prod/config.env"])
        .current_dir(repo.path())
        .output()
        .unwrap();
    repo.write_file("prod/config.env", "# Production config\n# Secrets managed by vault");
    repo.commit("Move to prod and remove hardcoded secret");

    // Should not detect secret
    let (output, _) = run_scan(repo.path_str());
    assert!(
        !should_detect_sk_token(&output),
        "Should not find secret after it was removed during move"
    );
}

// ============================================================================
// LARGE REPOSITORY WITH MANY BRANCHES TESTS
// ============================================================================

#[test]
fn test_large_repo_many_branches_secret_on_one() {
    let repo = TestGitRepo::new("many-branches");

    repo.write_file("README.md", "# Multi-branch project");
    repo.commit("Initial commit");

    // Create 10 feature branches without secrets
    for i in 0..10 {
        repo.checkout("main");
        repo.create_branch(&format!("feature/clean-{}", i));
        repo.write_file(&format!("feature{}.txt", i), &format!("Feature {} content", i));
        repo.commit(&format!("Add feature {}", i));
    }

    // Create one branch with a secret
    repo.checkout("main");
    repo.create_branch("feature/with-secret");
    repo.write_file("secret.env", &format!("API_KEY={}", OPENAI_API_KEY));
    repo.commit("Add secret on this branch");

    // Create more clean branches
    for i in 10..20 {
        repo.checkout("main");
        repo.create_branch(&format!("feature/clean-{}", i));
        repo.write_file(&format!("feature{}.txt", i), &format!("Feature {} content", i));
        repo.commit(&format!("Add feature {}", i));
    }

    // Go back to main
    repo.checkout("main");

    // Main should not have the secret
    let (output, _) = run_scan(repo.path_str());
    assert!(
        !should_detect_sk_token(&output),
        "Main branch should not have secret from feature branch"
    );

    // Verify we have many branches
    let branches = repo.get_all_branches();
    assert!(branches.len() >= 21, "Should have at least 21 branches");
}

#[test]
fn test_large_repo_with_deep_history_and_branches() {
    let repo = TestGitRepo::new("deep-history-branches");

    // Create initial history on main
    for i in 0..15 {
        repo.write_file(&format!("file{}.txt", i), &format!("Content {}", i));
        repo.commit(&format!("Commit {}", i));
    }

    // Create branches at different points
    repo.create_branch("release/v1.0");
    repo.write_file("version.txt", "1.0.0");
    repo.commit("Release 1.0");

    repo.checkout("main");
    for i in 15..30 {
        repo.write_file(&format!("file{}.txt", i), &format!("Content {}", i));
        repo.commit(&format!("Commit {}", i));
    }

    repo.create_branch("release/v2.0");
    repo.write_file("version.txt", "2.0.0");
    // Add secret on v2.0 release branch
    repo.write_file("config.env", &format!("API_KEY={}", ANTHROPIC_API_KEY));
    repo.commit("Release 2.0 with config");

    repo.checkout("main");

    // Main should not have the secret
    let (output, _) = run_scan(repo.path_str());
    assert!(
        !should_detect(&output, "anthropic-api-key"),
        "Main should not have secret from release branch"
    );
}

#[test]
fn test_parallel_branches_with_different_secrets() {
    let repo = TestGitRepo::new("parallel-branches");

    repo.write_file("README.md", "# Project");
    repo.commit("Initial");

    // Create parallel feature branches from main
    repo.create_branch("feature/openai-integration");
    repo.write_file("openai.py", &format!("KEY = '{}'", OPENAI_API_KEY));
    repo.commit("Add OpenAI integration");

    repo.checkout("main");
    repo.create_branch("feature/anthropic-integration");
    repo.write_file("anthropic.py", &format!("KEY = '{}'", ANTHROPIC_API_KEY));
    repo.commit("Add Anthropic integration");

    repo.checkout("main");
    repo.create_branch("feature/github-integration");
    repo.write_file("github.py", &format!("TOKEN = '{}'", GITHUB_PAT));
    repo.commit("Add GitHub integration");

    // Main has no secrets
    repo.checkout("main");
    let (output, _) = run_scan(repo.path_str());
    assert!(
        !detected_any_secret(&output) || output.contains("No secrets found"),
        "Main should have no secrets"
    );
}

// ============================================================================
// MERGE CONFLICT MARKER TESTS
// These test scenarios with secrets in merge conflict markers
// ============================================================================

#[test]
fn test_secret_in_merge_conflict_markers() {
    let repo = TestGitRepo::new("merge-conflict-secret");

    repo.write_file("config.env", "DEBUG=false");
    repo.commit("Initial config");

    // Create branch with one secret
    repo.create_branch("feature/api-a");
    repo.write_file("config.env", &format!("DEBUG=false\nAPI_KEY={}", OPENAI_API_KEY));
    repo.commit("Add API key A");

    // Go back and create conflicting change
    repo.checkout("main");
    repo.create_branch("feature/api-b");
    repo.write_file("config.env", &format!("DEBUG=true\nAPI_KEY={}", ANTHROPIC_API_KEY));
    repo.commit("Add API key B");

    // Manually create a file with conflict markers (simulating unresolved merge)
    let conflict_content = format!(
        r#"<<<<<<< HEAD
DEBUG=true
API_KEY={}
=======
DEBUG=false
API_KEY={}
>>>>>>> feature/api-a
"#,
        ANTHROPIC_API_KEY, OPENAI_API_KEY
    );
    repo.write_file("config_conflict.env", &conflict_content);
    repo.commit("Add file with conflict markers");

    // Should detect secrets in conflict markers
    let (output, _) = run_scan(repo.path_str());
    assert!(
        should_detect_sk_token(&output) || should_detect(&output, "anthropic-api-key"),
        "Should find secrets in merge conflict markers"
    );
}

#[test]
fn test_multiple_secrets_in_conflict_markers() {
    let repo = TestGitRepo::new("multi-secret-conflict");

    // Create file with multiple conflicts containing different secrets
    let conflict_content = format!(
        r#"# Configuration
<<<<<<< HEAD
OPENAI_KEY={}
GITHUB_TOKEN={}
=======
ANTHROPIC_KEY={}
AWS_KEY={}
>>>>>>> feature
"#,
        OPENAI_API_KEY, GITHUB_PAT, ANTHROPIC_API_KEY, AWS_ACCESS_KEY_ID
    );
    repo.write_file("multi_conflict.env", &conflict_content);
    repo.commit("Add multi-secret conflict file");

    let (output, _) = run_scan(repo.path_str());
    // Should detect at least some of the secrets
    assert!(
        detected_any_secret(&output),
        "Should find secrets in multi-secret conflict markers"
    );
}

#[test]
fn test_nested_conflict_markers_with_secrets() {
    let repo = TestGitRepo::new("nested-conflict");

    // Create deeply nested conflict markers (can happen with rerere or complex merges)
    let nested_conflict = format!(
        r#"# Complex merge
<<<<<<< HEAD
config:
  <<<<<<< HEAD
  key: {}
  =======
  key: placeholder
  >>>>>>> temp
=======
config:
  key: {}
>>>>>>> feature
"#,
        OPENAI_API_KEY, ANTHROPIC_API_KEY
    );
    repo.write_file("nested_conflict.yaml", &nested_conflict);
    repo.commit("Add nested conflict");

    let (output, _) = run_scan(repo.path_str());
    assert!(
        detected_any_secret(&output),
        "Should find secrets in nested conflict markers"
    );
}

// ============================================================================
// .GITATTRIBUTES AND .GITMODULES TESTS
// ============================================================================

#[test]
fn test_secret_in_gitattributes() {
    let repo = TestGitRepo::new("gitattributes-secret");

    // Create .gitattributes with a secret (unusual but possible)
    // Secrets might end up here through copy-paste errors
    let gitattributes_content = format!(
        r#"# Git attributes
*.txt text
*.bin binary
# TODO: remove this test key: {}
*.env filter=clean
"#,
        OPENAI_API_KEY
    );
    repo.write_file(".gitattributes", &gitattributes_content);
    repo.commit("Add gitattributes with accidental secret");

    let (output, _) = run_scan(repo.path_str());
    assert!(
        should_detect_sk_token(&output),
        "Should find secret in .gitattributes"
    );
}

#[test]
fn test_secret_in_gitmodules() {
    let repo = TestGitRepo::new("gitmodules-secret");

    // Create .gitmodules with embedded credentials (bad practice but happens)
    let gitmodules_content = format!(
        r#"[submodule "vendor/lib"]
    path = vendor/lib
    url = https://{}@github.com/example/lib.git
[submodule "vendor/private"]
    path = vendor/private
    url = https://user:{}@gitlab.com/example/private.git
"#,
        GITHUB_PAT, OPENAI_API_KEY
    );
    repo.write_file(".gitmodules", &gitmodules_content);
    repo.commit("Add gitmodules with credentials");

    let (output, _) = run_scan(repo.path_str());
    // Should detect at least one of the embedded credentials
    assert!(
        detected_any_secret(&output),
        "Should find secrets in .gitmodules"
    );
}

#[test]
fn test_secret_in_gitconfig() {
    let repo = TestGitRepo::new("gitconfig-secret");

    // Create a local .gitconfig with credentials
    let gitconfig_content = format!(
        r#"[user]
    name = Test User
    email = test@example.com
[credential]
    helper = store
[http]
    extraHeader = Authorization: Bearer {}
[url "https://{}@github.com"]
    insteadOf = https://github.com
"#,
        GITHUB_PAT, GITHUB_PAT
    );
    repo.write_file(".gitconfig", &gitconfig_content);
    repo.commit("Add gitconfig with credentials");

    let (output, _) = run_scan(repo.path_str());
    assert!(
        should_detect_github_token(&output),
        "Should find secrets in .gitconfig"
    );
}

#[test]
fn test_clean_gitattributes() {
    let repo = TestGitRepo::new("clean-gitattributes");

    // Create clean .gitattributes (no secrets)
    let gitattributes_content = r#"# Git attributes
*.txt text
*.bin binary
*.env filter=clean
*.png binary
"#;
    repo.write_file(".gitattributes", gitattributes_content);
    repo.commit("Add clean gitattributes");

    let (output, _) = run_scan(repo.path_str());
    assert!(
        !detected_any_secret(&output) || output.contains("No secrets found"),
        "Should not find secrets in clean .gitattributes"
    );
}

// ============================================================================
// CONCURRENT MODIFICATIONS TO SAME FILE IN DIFFERENT BRANCHES
// ============================================================================

#[test]
fn test_concurrent_modifications_same_file_different_secrets() {
    let repo = TestGitRepo::new("concurrent-mods");

    // Initial file
    repo.write_file("config.env", "# Configuration\nDEBUG=true");
    repo.commit("Initial config");

    // Branch A adds OpenAI key
    repo.create_branch("feature/openai");
    repo.write_file("config.env", &format!("# Configuration\nDEBUG=true\nOPENAI_KEY={}", OPENAI_API_KEY));
    repo.commit("Add OpenAI key");

    // Branch B (from main) adds Anthropic key
    repo.checkout("main");
    repo.create_branch("feature/anthropic");
    repo.write_file("config.env", &format!("# Configuration\nDEBUG=true\nANTHROPIC_KEY={}", ANTHROPIC_API_KEY));
    repo.commit("Add Anthropic key");

    // Branch C (from main) adds GitHub token
    repo.checkout("main");
    repo.create_branch("feature/github");
    repo.write_file("config.env", &format!("# Configuration\nDEBUG=true\nGITHUB_TOKEN={}", GITHUB_PAT));
    repo.commit("Add GitHub token");

    // Main still has no secrets
    repo.checkout("main");
    let (output, _) = run_scan(repo.path_str());
    assert!(
        !detected_any_secret(&output) || output.contains("No secrets found"),
        "Main should have no secrets from concurrent branches"
    );
}

#[test]
fn test_concurrent_modifications_merged_sequentially() {
    let repo = TestGitRepo::new("concurrent-merged-seq");

    repo.write_file("app.py", "# App\n");
    repo.commit("Initial app");

    // Create and merge first branch
    repo.create_branch("feature/first");
    repo.write_file("app.py", &format!("# App\nKEY1 = '{}'", OPENAI_API_KEY));
    repo.commit("Add first key");
    repo.checkout("main");
    std::process::Command::new("git")
        .args(["merge", "feature/first", "-m", "Merge first"])
        .current_dir(repo.path())
        .output()
        .unwrap();

    // Create second branch from updated main
    repo.create_branch("feature/second");
    repo.write_file("app.py", &format!("# App\nKEY1 = '{}'\nKEY2 = '{}'", OPENAI_API_KEY, ANTHROPIC_API_KEY));
    repo.commit("Add second key");
    repo.checkout("main");
    std::process::Command::new("git")
        .args(["merge", "feature/second", "-m", "Merge second"])
        .current_dir(repo.path())
        .output()
        .unwrap();

    // Main should have both secrets after sequential merges
    let (output, _) = run_scan(repo.path_str());
    assert!(
        should_detect_sk_token(&output) || should_detect(&output, "anthropic-api-key"),
        "Should find secrets after sequential merges"
    );
}

#[test]
fn test_concurrent_modifications_one_branch_removes_secret() {
    let repo = TestGitRepo::new("concurrent-remove");

    // Initial with secret
    repo.write_file("config.py", &format!("KEY = '{}'", OPENAI_API_KEY));
    repo.commit("Initial with secret");

    // Branch A keeps and modifies around secret
    repo.create_branch("feature/keep");
    repo.write_file("config.py", &format!("# Updated\nKEY = '{}'\nDEBUG = True", OPENAI_API_KEY));
    repo.commit("Update with secret");

    // Branch B removes secret
    repo.checkout("main");
    repo.create_branch("feature/remove");
    repo.write_file("config.py", "# Cleaned\nimport os\nKEY = os.environ.get('KEY')");
    repo.commit("Remove hardcoded secret");

    // Main still has original secret
    repo.checkout("main");
    let (output, _) = run_scan(repo.path_str());
    assert!(
        should_detect_sk_token(&output),
        "Main should still have original secret"
    );

    // Check feature/remove branch has no secret
    repo.checkout("feature/remove");
    let (output, _) = run_scan(repo.path_str());
    assert!(
        !should_detect_sk_token(&output),
        "Remove branch should not have secret"
    );
}

#[test]
fn test_concurrent_modifications_race_condition_scenario() {
    let repo = TestGitRepo::new("concurrent-race");

    repo.write_file("settings.yaml", "app:\n  name: test");
    repo.commit("Initial settings");

    // Simulate race: both developers add secrets to same file
    // Developer A
    repo.create_branch("dev-a/add-aws");
    repo.write_file("settings.yaml", &format!("app:\n  name: test\naws:\n  key: {}", AWS_ACCESS_KEY_ID));
    repo.commit("Dev A adds AWS key");

    // Developer B (from same main commit)
    repo.checkout("main");
    repo.create_branch("dev-b/add-stripe");
    repo.write_file("settings.yaml", &format!("app:\n  name: test\nstripe:\n  key: {}", STRIPE_SECRET_KEY));
    repo.commit("Dev B adds Stripe key");

    // Both branches have different secrets
    repo.checkout("dev-a/add-aws");
    let (output_a, _) = run_scan(repo.path_str());
    assert!(
        should_detect(&output_a, "aws"),
        "Dev A branch should have AWS secret"
    );

    repo.checkout("dev-b/add-stripe");
    let (output_b, _) = run_scan(repo.path_str());
    assert!(
        should_detect(&output_b, "stripe"),
        "Dev B branch should have Stripe secret"
    );
}

#[test]
fn test_same_file_modified_in_many_branches() {
    let repo = TestGitRepo::new("many-branch-mods");

    repo.write_file("shared.env", "# Shared config");
    repo.commit("Initial shared config");

    // Create 5 branches, each modifying the same file differently
    let secrets = [
        ("feature/a", "KEY_A", &*OPENAI_API_KEY),
        ("feature/b", "KEY_B", &*ANTHROPIC_API_KEY),
        ("feature/c", "KEY_C", &*GITHUB_PAT),
        ("feature/d", "KEY_D", &*AWS_ACCESS_KEY_ID),
        ("feature/e", "KEY_E", &*STRIPE_SECRET_KEY),
    ];

    for (branch, key_name, secret) in secrets.iter() {
        repo.checkout("main");
        repo.create_branch(branch);
        repo.write_file("shared.env", &format!("# Shared config\n{}={}", key_name, secret));
        repo.commit(&format!("Add {} to shared config", key_name));
    }

    // Main should have no secrets
    repo.checkout("main");
    let (output, _) = run_scan(repo.path_str());
    assert!(
        !detected_any_secret(&output) || output.contains("No secrets found"),
        "Main should have no secrets"
    );

    // Each feature branch should have its own secret
    repo.checkout("feature/a");
    let (output, _) = run_scan(repo.path_str());
    assert!(
        should_detect_sk_token(&output),
        "Feature A should have OpenAI secret"
    );
}
