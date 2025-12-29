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
