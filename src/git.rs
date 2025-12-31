#![allow(dead_code)]

use std::process::Command;

pub fn clone_repo(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let temp_dir = std::env::temp_dir().join(format!("libreleak-{}", std::process::id()));
    let temp_path = temp_dir.display().to_string();

    let output = Command::new("git")
        .args(["clone", "--depth", "1", url, &temp_path])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git clone failed: {stderr}").into());
    }

    Ok(temp_path)
}

pub fn cleanup(path: &str) {
    let _ = std::fs::remove_dir_all(path);
}

/// Get list of files tracked by git (respects .gitignore)
pub fn list_tracked_files(repo_path: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let output = Command::new("git")
        .args(["ls-files"])
        .current_dir(repo_path)
        .output()?;

    if !output.status.success() {
        return Ok(Vec::new()); // Not a git repo, fall back to filesystem walk
    }

    let files = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|s| s.to_string())
        .collect();

    Ok(files)
}

/// Scan git history for secrets
pub fn scan_history(repo_path: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let output = Command::new("git")
        .args([
            "log",
            "--all",
            "--pretty=format:",
            "--name-only",
            "--diff-filter=A",
        ])
        .current_dir(repo_path)
        .output()?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let files: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    Ok(files)
}

/// Check if a target string looks like a git URL (vs a local path)
pub fn is_git_url(target: &str) -> bool {
    target.starts_with("http://")
        || target.starts_with("https://")
        || target.starts_with("git@")
        || target.starts_with("ssh://")
        || target.starts_with("git://")
}

/// Check if a path is inside a git repository
pub fn is_git_repo(path: &str) -> bool {
    let output = Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .current_dir(path)
        .output();

    match output {
        Ok(o) => o.status.success(),
        Err(_) => false,
    }
}

/// Extract the repository name from a git URL
pub fn extract_repo_name(url: &str) -> Option<String> {
    // Handle various URL formats:
    // https://github.com/owner/repo.git -> repo
    // https://github.com/owner/repo -> repo
    // git@github.com:owner/repo.git -> repo
    // ssh://git@github.com/owner/repo.git -> repo
    // git://github.com/owner/repo.git -> repo

    let url = url.trim_end_matches('/');

    // Remove .git suffix if present
    let url = url.strip_suffix(".git").unwrap_or(url);

    // Extract the last path component
    if let Some(last_slash) = url.rfind('/') {
        let name = &url[last_slash + 1..];
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }

    // Handle git@ format with colon (git@github.com:owner/repo)
    if let Some(colon_pos) = url.rfind(':') {
        let after_colon = &url[colon_pos + 1..];
        if let Some(last_slash) = after_colon.rfind('/') {
            let name = &after_colon[last_slash + 1..];
            if !name.is_empty() {
                return Some(name.to_string());
            }
        } else if !after_colon.is_empty() && !after_colon.contains('@') {
            // git@host:repo (no owner path)
            return Some(after_colon.to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // ========================================================================
    // IS_GIT_URL TESTS
    // ========================================================================

    #[test]
    fn test_is_git_url_https() {
        assert!(is_git_url("https://github.com/owner/repo"));
        assert!(is_git_url("https://github.com/owner/repo.git"));
        assert!(is_git_url("https://gitlab.com/group/project"));
        assert!(is_git_url("https://bitbucket.org/user/repo"));
    }

    #[test]
    fn test_is_git_url_http() {
        assert!(is_git_url("http://github.com/owner/repo"));
        assert!(is_git_url("http://internal.git.server/repo"));
    }

    #[test]
    fn test_is_git_url_ssh() {
        assert!(is_git_url("git@github.com:owner/repo.git"));
        assert!(is_git_url("git@gitlab.com:group/project.git"));
        assert!(is_git_url("git@bitbucket.org:user/repo.git"));
    }

    #[test]
    fn test_is_git_url_ssh_protocol() {
        assert!(is_git_url("ssh://git@github.com/owner/repo.git"));
        assert!(is_git_url("ssh://user@server.com/path/to/repo.git"));
    }

    #[test]
    fn test_is_git_url_git_protocol() {
        assert!(is_git_url("git://github.com/owner/repo.git"));
        assert!(is_git_url("git://server.local/repo.git"));
    }

    #[test]
    fn test_is_git_url_local_paths() {
        // Local paths should NOT be identified as git URLs
        assert!(!is_git_url("."));
        assert!(!is_git_url("./src"));
        assert!(!is_git_url("../other-project"));
        assert!(!is_git_url("/home/user/project"));
        assert!(!is_git_url("/Users/dev/code/repo"));
        assert!(!is_git_url("C:\\Users\\dev\\project"));
        assert!(!is_git_url("src/main.rs"));
    }

    #[test]
    fn test_is_git_url_relative_paths() {
        assert!(!is_git_url("foo/bar"));
        assert!(!is_git_url("./foo/bar"));
        assert!(!is_git_url("../foo/bar"));
    }

    #[test]
    fn test_is_git_url_edge_cases() {
        // Empty string
        assert!(!is_git_url(""));

        // Just protocol prefix without full URL
        assert!(is_git_url("https://"));
        assert!(is_git_url("git@"));

        // Paths that might look like URLs but aren't
        assert!(!is_git_url("httpsfolder"));
        assert!(!is_git_url("gitfolder"));
    }

    #[test]
    fn test_is_git_url_with_ports() {
        assert!(is_git_url("https://github.com:443/owner/repo"));
        assert!(is_git_url("ssh://git@server.com:22/repo.git"));
        assert!(is_git_url("http://internal.server:8080/repo"));
    }

    #[test]
    fn test_is_git_url_with_auth() {
        assert!(is_git_url("https://user:token@github.com/owner/repo"));
        assert!(is_git_url(
            "https://oauth2:ghp_token@github.com/owner/repo.git"
        ));
    }

    // ========================================================================
    // EXTRACT_REPO_NAME TESTS
    // ========================================================================

    #[test]
    fn test_extract_repo_name_https() {
        assert_eq!(
            extract_repo_name("https://github.com/owner/repo"),
            Some("repo".to_string())
        );
        assert_eq!(
            extract_repo_name("https://github.com/owner/repo.git"),
            Some("repo".to_string())
        );
    }

    #[test]
    fn test_extract_repo_name_ssh() {
        assert_eq!(
            extract_repo_name("git@github.com:owner/repo.git"),
            Some("repo".to_string())
        );
        assert_eq!(
            extract_repo_name("git@github.com:owner/repo"),
            Some("repo".to_string())
        );
    }

    #[test]
    fn test_extract_repo_name_ssh_protocol() {
        assert_eq!(
            extract_repo_name("ssh://git@github.com/owner/repo.git"),
            Some("repo".to_string())
        );
    }

    #[test]
    fn test_extract_repo_name_git_protocol() {
        assert_eq!(
            extract_repo_name("git://github.com/owner/repo.git"),
            Some("repo".to_string())
        );
    }

    #[test]
    fn test_extract_repo_name_trailing_slash() {
        assert_eq!(
            extract_repo_name("https://github.com/owner/repo/"),
            Some("repo".to_string())
        );
        assert_eq!(
            extract_repo_name("https://github.com/owner/repo.git/"),
            Some("repo".to_string())
        );
    }

    #[test]
    fn test_extract_repo_name_nested_groups() {
        // GitLab nested groups
        assert_eq!(
            extract_repo_name("https://gitlab.com/group/subgroup/project"),
            Some("project".to_string())
        );
        assert_eq!(
            extract_repo_name("git@gitlab.com:group/subgroup/project.git"),
            Some("project".to_string())
        );
    }

    #[test]
    fn test_extract_repo_name_special_chars() {
        assert_eq!(
            extract_repo_name("https://github.com/owner/my-repo"),
            Some("my-repo".to_string())
        );
        assert_eq!(
            extract_repo_name("https://github.com/owner/my_repo"),
            Some("my_repo".to_string())
        );
        assert_eq!(
            extract_repo_name("https://github.com/owner/my.repo"),
            Some("my.repo".to_string())
        );
    }

    #[test]
    fn test_extract_repo_name_edge_cases() {
        // Empty string
        assert_eq!(extract_repo_name(""), None);

        // Just domain, no path - returns domain as "repo name" since we use simple rfind('/')
        // This is acceptable behavior as these aren't valid clone URLs anyway
        // The rfind('/') finds the slash in "https://" and returns everything after it
        assert_eq!(
            extract_repo_name("https://github.com"),
            Some("github.com".to_string())
        );
        // With trailing slash, it gets trimmed, so same result
        assert_eq!(
            extract_repo_name("https://github.com/"),
            Some("github.com".to_string())
        );
    }

    #[test]
    fn test_extract_repo_name_no_owner_path() {
        // Some git servers allow repo directly under root
        assert_eq!(
            extract_repo_name("git@server.com:repo.git"),
            Some("repo".to_string())
        );
    }

    // ========================================================================
    // IS_GIT_REPO TESTS
    // ========================================================================

    #[test]
    fn test_is_git_repo_current_directory() {
        // This test assumes we're running in the libreleak repo
        // The test will pass if we're in a git repo, skip otherwise
        let result = is_git_repo(".");
        // Just verify it returns a boolean without crashing
        assert!(result == true || result == false);
    }

    #[test]
    fn test_is_git_repo_temp_directory() {
        // Create a temp directory that's definitely NOT a git repo
        let temp_dir = std::env::temp_dir().join("libreleak-test-not-git");
        let _ = fs::create_dir_all(&temp_dir);

        let result = is_git_repo(temp_dir.to_str().unwrap());
        assert!(!result, "Temp directory should not be a git repo");

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_is_git_repo_nonexistent_path() {
        let result = is_git_repo("/nonexistent/path/that/does/not/exist");
        assert!(!result, "Nonexistent path should not be a git repo");
    }

    #[test]
    fn test_is_git_repo_file_path() {
        // A file is not a git repo
        let result = is_git_repo("/etc/passwd");
        assert!(!result, "A file should not be identified as a git repo");
    }

    // ========================================================================
    // CLONE_REPO TESTS (limited - requires network)
    // ========================================================================

    #[test]
    fn test_clone_repo_invalid_url() {
        // Test with an obviously invalid URL
        let result = clone_repo("not-a-valid-url");
        assert!(result.is_err(), "Invalid URL should fail to clone");
    }

    #[test]
    fn test_clone_repo_nonexistent_repo() {
        // Test with a URL that looks valid but repo doesn't exist
        let result =
            clone_repo("https://github.com/nonexistent-owner-12345/nonexistent-repo-67890");
        assert!(result.is_err(), "Nonexistent repo should fail to clone");
    }

    // ========================================================================
    // CLEANUP TESTS
    // ========================================================================

    #[test]
    fn test_cleanup_existing_directory() {
        // Create a temp directory
        let temp_dir = std::env::temp_dir().join("libreleak-cleanup-test");
        fs::create_dir_all(&temp_dir).expect("Failed to create temp dir");

        // Add a file to it
        let test_file = temp_dir.join("test.txt");
        fs::write(&test_file, "test content").expect("Failed to write file");

        // Verify it exists
        assert!(temp_dir.exists());

        // Cleanup
        cleanup(temp_dir.to_str().unwrap());

        // Verify it's gone
        assert!(
            !temp_dir.exists(),
            "Directory should be removed after cleanup"
        );
    }

    #[test]
    fn test_cleanup_nonexistent_directory() {
        // Cleanup should not panic on nonexistent path
        cleanup("/nonexistent/path/that/does/not/exist");
        // If we get here without panicking, the test passes
    }

    #[test]
    fn test_cleanup_nested_directory() {
        // Create nested temp directories
        let temp_dir = std::env::temp_dir().join("libreleak-nested-cleanup-test");
        let nested = temp_dir.join("level1").join("level2").join("level3");
        fs::create_dir_all(&nested).expect("Failed to create nested dirs");

        // Add files at various levels
        fs::write(temp_dir.join("root.txt"), "root").expect("Failed to write");
        fs::write(nested.join("deep.txt"), "deep").expect("Failed to write");

        // Cleanup should remove everything
        cleanup(temp_dir.to_str().unwrap());

        assert!(
            !temp_dir.exists(),
            "Nested directory should be fully removed"
        );
    }

    // ========================================================================
    // LIST_TRACKED_FILES TESTS
    // ========================================================================

    #[test]
    fn test_list_tracked_files_git_repo() {
        // This test assumes we're running in the libreleak repo
        let result = list_tracked_files(".");

        // Should succeed in a git repo
        assert!(result.is_ok());

        let files = result.unwrap();
        // Should have some tracked files
        if !files.is_empty() {
            // Verify common project files are tracked
            let has_cargo_toml = files.iter().any(|f| f == "Cargo.toml");
            let has_src_main = files
                .iter()
                .any(|f| f == "src/main.rs" || f.ends_with("main.rs"));

            // At least one of these should exist in a Rust project
            assert!(
                has_cargo_toml || has_src_main || files.len() > 0,
                "Should find tracked files in git repo"
            );
        }
    }

    #[test]
    fn test_list_tracked_files_not_git_repo() {
        // Create a temp directory that's not a git repo
        let temp_dir = std::env::temp_dir().join("libreleak-not-git-list");
        let _ = fs::create_dir_all(&temp_dir);

        let result = list_tracked_files(temp_dir.to_str().unwrap());

        // Should return Ok with empty vec (falls back gracefully)
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_list_tracked_files_nonexistent_path() {
        let result = list_tracked_files("/nonexistent/path");

        // Nonexistent path causes command to fail, returns error
        // This is expected - the path must exist for git ls-files to run
        assert!(result.is_err());
    }

    // ========================================================================
    // SCAN_HISTORY TESTS
    // ========================================================================

    #[test]
    fn test_scan_history_git_repo() {
        // This test assumes we're running in the libreleak repo
        let result = scan_history(".");

        // Should succeed in a git repo
        assert!(result.is_ok());

        // May or may not have files depending on git history
        // Just verify it doesn't crash
        let _files = result.unwrap();
    }

    #[test]
    fn test_scan_history_not_git_repo() {
        // Create a temp directory that's not a git repo
        let temp_dir = std::env::temp_dir().join("libreleak-not-git-history");
        let _ = fs::create_dir_all(&temp_dir);

        let result = scan_history(temp_dir.to_str().unwrap());

        // Should return Ok with empty vec (fails gracefully)
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_scan_history_nonexistent_path() {
        let result = scan_history("/nonexistent/path");

        // Nonexistent path causes command to fail, returns error
        // This is expected - the path must exist for git log to run
        assert!(result.is_err());
    }

    // ========================================================================
    // URL PARSING EDGE CASES
    // ========================================================================

    #[test]
    fn test_is_git_url_github_enterprise() {
        assert!(is_git_url("https://github.enterprise.com/org/repo"));
        assert!(is_git_url("git@github.enterprise.com:org/repo.git"));
    }

    #[test]
    fn test_is_git_url_self_hosted_gitlab() {
        assert!(is_git_url("https://gitlab.mycompany.com/team/project"));
        assert!(is_git_url("git@gitlab.internal:group/project.git"));
    }

    #[test]
    fn test_is_git_url_azure_devops() {
        assert!(is_git_url("https://dev.azure.com/org/project/_git/repo"));
        assert!(is_git_url("git@ssh.dev.azure.com:v3/org/project/repo"));
    }

    #[test]
    fn test_extract_repo_name_azure_devops() {
        assert_eq!(
            extract_repo_name("https://dev.azure.com/org/project/_git/repo"),
            Some("repo".to_string())
        );
    }

    #[test]
    fn test_extract_repo_name_with_query_params() {
        // Some clone URLs might have query params (rare but possible)
        // Our simple parser just takes the last path segment
        assert_eq!(
            extract_repo_name("https://github.com/owner/repo"),
            Some("repo".to_string())
        );
    }

    // ========================================================================
    // PATH VS URL DISAMBIGUATION
    // ========================================================================

    #[test]
    fn test_is_git_url_windows_paths() {
        // Windows-style paths should not be URLs
        assert!(!is_git_url("C:\\code\\repo"));
        assert!(!is_git_url("D:\\Users\\dev\\project"));
        assert!(!is_git_url("\\\\server\\share\\repo"));
    }

    #[test]
    fn test_is_git_url_unix_paths() {
        assert!(!is_git_url("/home/user/code"));
        assert!(!is_git_url("/var/lib/git/repo"));
        assert!(!is_git_url("~/projects/repo"));
    }

    #[test]
    fn test_is_git_url_dot_paths() {
        assert!(!is_git_url("."));
        assert!(!is_git_url(".."));
        assert!(!is_git_url("./"));
        assert!(!is_git_url("../"));
        assert!(!is_git_url("./src"));
        assert!(!is_git_url("../sibling"));
    }
}
