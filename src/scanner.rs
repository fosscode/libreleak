//! Core scanning logic
//!
//! Zero dependencies - hand-rolled pattern matching for full auditability.

use std::fs;
use std::path::Path;

use crate::rules::{Charset, Detector, Rule};

pub struct Scanner {
    rules: Vec<Rule>,
    context_lines: usize,
}

#[derive(Debug)]
pub struct Finding {
    pub rule_id: String,
    pub rule_name: String,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub matched: String,
    pub secret: String,
    pub context: Vec<ContextLine>,
    #[cfg(feature = "verify")]
    pub verification_status: Option<crate::verify::VerificationResult>,
}

#[derive(Debug)]
pub struct ContextLine {
    pub line_num: usize,
    pub content: String,
    pub is_match: bool,
}

impl Scanner {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self {
            rules,
            context_lines: 3, // Show 3 lines before/after
        }
    }

    pub fn with_context(mut self, lines: usize) -> Self {
        self.context_lines = lines;
        self
    }

    pub fn scan_path(&self, path: &str) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
        let path = Path::new(path);
        let mut findings = Vec::new();

        if path.is_file() {
            self.scan_file(path, &mut findings)?;
        } else if path.is_dir() {
            self.scan_directory(path, &mut findings)?;
        }

        Ok(findings)
    }

    pub fn scan_git_repo(&self, url: &str) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
        let temp_dir = crate::git::clone_repo(url)?;
        let findings = self.scan_path(temp_dir.as_str())?;
        crate::git::cleanup(&temp_dir);
        Ok(findings)
    }

    fn scan_directory(
        &self,
        dir: &Path,
        findings: &mut Vec<Finding>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let entries: Vec<_> = fs::read_dir(dir)?.collect();

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if self.should_skip(&path) {
                continue;
            }

            if path.is_dir() {
                self.scan_directory(&path, findings)?;
            } else if path.is_file() {
                self.scan_file(&path, findings)?;
            }
        }
        Ok(())
    }

    fn scan_file(
        &self,
        path: &Path,
        findings: &mut Vec<Finding>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Skip binary files by extension
        if self.is_binary_extension(path) {
            return Ok(());
        }

        // Skip lock files (high false positive rate due to integrity hashes)
        if self.is_lock_file(path) {
            return Ok(());
        }

        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Ok(()), // Skip unreadable files
        };

        let lines: Vec<&str> = content.lines().collect();

        for (line_idx, line) in lines.iter().enumerate() {
            for rule in &self.rules {
                if let Some((matched, column)) = self.detect(&rule.detector, line) {
                    // Extract the actual secret value
                    let secret = self.extract_secret(line, &matched, &rule.detector);

                    // Build context with redacted secret
                    let redacted = redact(&secret);
                    let context = self.build_context(&lines, line_idx, &secret, &redacted);

                    let mut finding = Finding {
                        rule_id: rule.id.to_string(),
                        rule_name: rule.name.to_string(),
                        file: path.display().to_string(),
                        line: line_idx + 1,
                        column: column + 1,
                        matched: redact(&matched),
                        secret: redacted,
                        context,
                        #[cfg(feature = "verify")]
                        verification_status: None,
                    };
                    findings.push(finding);
                }
            }
        }

        Ok(())
    }

    fn detect(&self, detector: &Detector, line: &str) -> Option<(String, usize)> {
        match detector {
            Detector::Prefix {
                prefix,
                min_len,
                charset,
            } => self.detect_prefix(line, prefix, *min_len, *charset),

            Detector::Contains { needle } => {
                line.find(needle).map(|pos| (needle.to_string(), pos))
            }

            Detector::KeyValue { keys, min_value_len } => {
                self.detect_key_value(line, keys, *min_value_len)
            }

            Detector::Endpoint { keys, patterns } => {
                self.detect_endpoint(line, keys, patterns)
            }
        }
    }

    fn detect_prefix(
        &self,
        line: &str,
        prefix: &str,
        min_len: usize,
        charset: Charset,
    ) -> Option<(String, usize)> {
        let mut search_start = 0;

        while let Some(rel_pos) = line[search_start..].find(prefix) {
            let pos = search_start + rel_pos;

            // Ensure prefix is at a word boundary (not preceded by alphanumeric)
            // This prevents matching "rSKxxx" when looking for "SK" prefix
            if pos > 0 {
                let prev_char = line[..pos].chars().last().unwrap_or(' ');
                if prev_char.is_alphanumeric() {
                    search_start = pos + prefix.len();
                    continue;
                }
            }

            let remaining = &line[pos..];

            // Find end of token
            let end = remaining
                .char_indices()
                .skip(prefix.len())
                .find(|(_, c)| !charset.matches(*c))
                .map(|(i, _)| i)
                .unwrap_or(remaining.len());

            if end >= min_len {
                let matched = &remaining[..end];
                // Extract the suffix after the prefix and check for placeholders
                let suffix = &matched[prefix.len()..];
                if !is_placeholder(&suffix.to_lowercase()) {
                    return Some((matched.to_string(), pos));
                }
            }

            search_start = pos + prefix.len();
        }

        None
    }

    fn detect_key_value(
        &self,
        line: &str,
        keys: &[&str],
        min_value_len: usize,
    ) -> Option<(String, usize)> {
        let lower = line.to_lowercase();

        for key in keys.iter() {
            let key_lower = key.to_lowercase();

            // Search for key at word boundaries
            let mut search_pos = 0;
            while let Some(rel_pos) = lower[search_pos..].find(&key_lower) {
                let key_pos = search_pos + rel_pos;

                // Check for word boundary before key (not preceded by alphanumeric or underscore)
                if key_pos > 0 {
                    let prev_char = line.chars().nth(key_pos - 1).unwrap_or(' ');
                    if prev_char.is_alphanumeric() || prev_char == '_' {
                        search_pos = key_pos + key.len();
                        continue;
                    }
                }

                // Check for word boundary after key (not followed by alphanumeric or underscore)
                let after_key_idx = key_pos + key.len();
                if after_key_idx < line.len() {
                    let next_char = line.chars().nth(after_key_idx).unwrap_or(' ');
                    if next_char.is_alphanumeric() || next_char == '_' {
                        search_pos = key_pos + key.len();
                        continue;
                    }
                }

                // Look for = or : after the key
                let after_key = &line[key_pos + key.len()..];
                let trimmed = after_key.trim_start();

                if trimmed.starts_with('=') || trimmed.starts_with(':') {
                    let value_start = &trimmed[1..].trim_start();

                    // Handle quoted values
                    let (value, is_quoted) = if value_start.starts_with('"') {
                        let inner = &value_start[1..];
                        if let Some(end) = inner.find('"') {
                            (&inner[..end], true)
                        } else {
                            search_pos = key_pos + key.len();
                            continue;
                        }
                    } else if value_start.starts_with('\'') {
                        let inner = &value_start[1..];
                        if let Some(end) = inner.find('\'') {
                            (&inner[..end], true)
                        } else {
                            search_pos = key_pos + key.len();
                            continue;
                        }
                    } else {
                        // Unquoted - take until whitespace or end
                        let end = value_start
                            .find(|c: char| c.is_whitespace() || c == ',' || c == ';')
                            .unwrap_or(value_start.len());
                        (&value_start[..end], false)
                    };

                    // Skip common placeholders
                    let value_lower = value.to_lowercase();
                    if is_placeholder(&value_lower) {
                        search_pos = key_pos + key.len();
                        continue;
                    }

                    // Skip method calls and code patterns (not actual secrets)
                    if is_code_pattern(value) {
                        search_pos = key_pos + key.len();
                        continue;
                    }

                    // For unquoted values, be more strict to avoid matching code
                    if !is_quoted && looks_like_code(value) {
                        search_pos = key_pos + key.len();
                        continue;
                    }

                    if value.len() >= min_value_len {
                        return Some((format!("{}={}", key, value), key_pos));
                    }
                }

                search_pos = key_pos + key.len();
            }
        }

        None
    }

    fn detect_endpoint(
        &self,
        line: &str,
        keys: &[&str],
        patterns: &[&str],
    ) -> Option<(String, usize)> {
        let lower = line.to_lowercase();

        // First check for key=value patterns
        for key in keys.iter() {
            let key_lower = key.to_lowercase();
            if let Some(key_pos) = lower.find(&key_lower) {
                let after_key = &line[key_pos + key.len()..];
                let trimmed = after_key.trim_start();

                if trimmed.starts_with('=') || trimmed.starts_with(':') {
                    let value_start = &trimmed[1..].trim_start();

                    // Handle quoted values
                    let value = if value_start.starts_with('"') {
                        let inner = &value_start[1..];
                        inner.find('"').map(|end| &inner[..end])
                    } else if value_start.starts_with('\'') {
                        let inner = &value_start[1..];
                        inner.find('\'').map(|end| &inner[..end])
                    } else {
                        let end = value_start
                            .find(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == '}' || c == ']')
                            .unwrap_or(value_start.len());
                        Some(&value_start[..end])
                    };

                    if let Some(val) = value {
                        // Skip localhost/loopback addresses (not real endpoints)
                        let val_lower = val.to_lowercase();
                        if is_localhost(&val_lower) {
                            continue;
                        }
                        if !val.is_empty() && !is_placeholder(&val_lower) {
                            return Some((format!("{}={}", key, val), key_pos));
                        }
                    }
                }
            }
        }

        // Then check for URL patterns in the line
        for pattern in patterns.iter() {
            if let Some(pos) = line.find(pattern) {
                // Try to extract the full URL
                let start = line[..pos]
                    .rfind(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '=' || c == ':')
                    .map(|i| i + 1)
                    .unwrap_or(0);

                let remaining = &line[start..];
                let end = remaining
                    .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',' || c == ';' || c == '}' || c == ']')
                    .unwrap_or(remaining.len());

                let url = &remaining[..end];

                // Skip localhost/loopback URLs
                if is_localhost(&url.to_lowercase()) {
                    continue;
                }

                if url.len() > pattern.len() {
                    return Some((url.to_string(), start));
                }
            }
        }

        None
    }

    fn extract_secret(&self, line: &str, matched: &str, detector: &Detector) -> String {
        match detector {
            Detector::Prefix { .. } => matched.to_string(),
            Detector::Contains { .. } => {
                // For contains, try to extract more context
                if let Some(pos) = line.find(matched) {
                    // Look for surrounding token
                    let start = line[..pos]
                        .rfind(|c: char| c.is_whitespace())
                        .map(|i| i + 1)
                        .unwrap_or(0);
                    let end = line[pos..]
                        .find(|c: char| c.is_whitespace())
                        .map(|i| pos + i)
                        .unwrap_or(line.len());
                    line[start..end].to_string()
                } else {
                    matched.to_string()
                }
            }
            Detector::KeyValue { .. } | Detector::Endpoint { .. } => {
                // Extract just the value part
                if let Some(eq_pos) = matched.find('=') {
                    matched[eq_pos + 1..].to_string()
                } else {
                    matched.to_string()
                }
            }
        }
    }

    fn build_context(
        &self,
        lines: &[&str],
        match_idx: usize,
        secret: &str,
        redacted: &str,
    ) -> Vec<ContextLine> {
        let start = match_idx.saturating_sub(self.context_lines);
        let end = (match_idx + self.context_lines + 1).min(lines.len());

        (start..end)
            .map(|i| ContextLine {
                line_num: i + 1,
                // Redact the secret in context lines
                content: lines[i].replace(secret, redacted),
                is_match: i == match_idx,
            })
            .collect()
    }

    fn should_skip(&self, path: &Path) -> bool {
        // Check all path components for directories we should skip
        for component in path.components() {
            if let std::path::Component::Normal(name) = component {
                let name_str = name.to_str().unwrap_or("");

                // Skip hidden directories (but .env files are ok since they're files)
                if name_str.starts_with('.') && path.is_dir() {
                    return true;
                }

                // Skip common non-source directories
                if matches!(
                    name_str,
                    "node_modules"
                        | "target"
                        | "vendor"
                        | "dist"
                        | "build"
                        | "__pycache__"
                        | ".git"
                        | ".svn"
                        | ".hg"
                        | "venv"
                        | ".venv"
                        | ".tox"
                        | ".pytest_cache"
                        | ".mypy_cache"
                        | "coverage"
                        | ".coverage"
                ) {
                    return true;
                }
            }
        }
        false
    }

    fn is_binary_extension(&self, path: &Path) -> bool {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        matches!(
            ext.to_lowercase().as_str(),
            "png" | "jpg" | "jpeg" | "gif" | "ico" | "bmp" | "webp" | "svg"
                | "woff" | "woff2" | "ttf" | "eot" | "otf"
                | "mp3" | "mp4" | "avi" | "mov" | "webm" | "ogg" | "wav"
                | "zip" | "tar" | "gz" | "bz2" | "xz" | "7z" | "rar"
                | "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx"
                | "exe" | "dll" | "so" | "dylib" | "o" | "a"
                | "pyc" | "pyo" | "class" | "jar" | "war"
                | "wasm"
                | "db" | "sqlite" | "sqlite3"
        )
    }

    /// Check if file is a lock file (high false positive rate due to integrity hashes)
    fn is_lock_file(&self, path: &Path) -> bool {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        matches!(
            name,
            "package-lock.json"
                | "pnpm-lock.yaml"
                | "yarn.lock"
                | "Cargo.lock"
                | "Gemfile.lock"
                | "composer.lock"
                | "poetry.lock"
                | "Pipfile.lock"
                | "go.sum"
        )
    }
}

fn redact(secret: &str) -> String {
    if secret.len() <= 10 {
        "*".repeat(secret.len())
    } else {
        let visible = 4.min(secret.len() / 4);
        format!(
            "{}...{}",
            &secret[..visible],
            &secret[secret.len() - visible..]
        )
    }
}

/// Check if a URL points to localhost/loopback (not a real leaked endpoint)
fn is_localhost(value: &str) -> bool {
    value.contains("localhost")
        || value.contains("127.0.0.1")
        || value.contains("0.0.0.0")
        || value.contains("[::1]")
        || value.contains("//lo") // Catches //localhost truncated in context
}

/// Check if value looks like a code pattern (method call, function, etc.)
fn is_code_pattern(value: &str) -> bool {
    // Method calls: something.get(), something.value, etc.
    if value.contains(".get(")
        || value.contains(".value")
        || value.contains("->")
        || value.contains("::")
    {
        return true;
    }

    // Function calls or variable access
    if value.starts_with("self.")
        || value.starts_with("this.")
        || value.starts_with("request.")
        || value.starts_with("req.")
        || value.starts_with("config.")
        || value.starts_with("conf.")
        || value.starts_with("settings.")
        || value.starts_with("env.")
        || value.starts_with("data.")
        || value.starts_with("form.")
    {
        return true;
    }

    // Common function patterns
    if value.contains("(") && value.contains(")") {
        return true;
    }

    // Object property access patterns
    if value.contains("['") || value.contains("[\"") {
        return true;
    }

    false
}

/// Check if unquoted value looks like code (for stricter filtering)
fn looks_like_code(value: &str) -> bool {
    // Contains dots (likely object access) unless it's a URL
    if value.contains('.') && !value.starts_with("http") {
        return true;
    }

    // Contains brackets (array access, function calls)
    if value.contains('[') || value.contains('(') {
        return true;
    }

    // Starts with common code patterns
    if value.starts_with("$")
        || value.starts_with("@")
        || value.starts_with("#")
        || value.starts_with("*")
    {
        return true;
    }

    // All lowercase with underscores (likely variable name, not secret)
    if value.chars().all(|c| c.is_lowercase() || c == '_') && value.contains('_') {
        return true;
    }

    false
}

fn is_placeholder(value: &str) -> bool {
    // Exact matches
    if matches!(
        value,
        "xxx"
            | "xxxx"
            | "xxxxx"
            | "your_key"
            | "your_api_key"
            | "your-api-key"
            | "your_secret"
            | "your_token"
            | "changeme"
            | "change_me"
            | "todo"
            | "fixme"
            | "replace_me"
            | "placeholder"
            | "example"
            | "sample"
            | "test"
            | "testing"
            | "dummy"
            | "fake"
            | "none"
            | "null"
            | "undefined"
            | "insert_here"
            | "enter_key_here"
            | "password"
            | "secret"
            | "admin"
            | "root"
    ) {
        return true;
    }

    // Pattern matches
    if value.starts_with("${")
        || value.starts_with("{{")
        || value.starts_with("<")
        || value.contains("...")
        || value.contains("_here")
        || value.contains("-here")
        || value.starts_with("your_")
        || value.starts_with("your-")
        || value.starts_with("my_")
        || value.starts_with("my-")
        || value.ends_with("_example")
        || value.ends_with("-example")
    {
        return true;
    }

    // Environment variable references (not actual secrets)
    if value.starts_with("process.env.")
        || value.starts_with("os.getenv(")
        || value.starts_with("os.environ")
        || value.starts_with("env(")
        || value.starts_with("getenv(")
        || value.contains("process.env")
        || value.contains("os.getenv")
        || value.contains("os.environ")
    {
        return true;
    }

    // All x's pattern (like xxxxxxxxxxxx)
    if value.len() >= 3 && value.chars().all(|c| c == 'x' || c == 'X') {
        return true;
    }

    // Common prefix + all x's pattern (like ghp_xxxxxxxx, sk-xxxxxxxx)
    // Check if value has a known prefix followed by mostly/all x's
    let prefixes = ["ghp_", "gho_", "ghu_", "ghr_", "glpat-", "sk-", "sk_", "npm_", "pypi-", "hf_"];
    for prefix in prefixes {
        if value.starts_with(prefix) {
            let suffix = &value[prefix.len()..];
            if suffix.len() >= 8 && suffix.chars().all(|c| c == 'x' || c == 'X') {
                return true;
            }
        }
    }

    // Database URIs with common placeholder credentials
    // e.g., postgres://user:password@localhost, mongodb://admin:secret@...
    // Only skip when using obvious placeholder passwords
    let placeholder_creds = [
        ":password@", ":secret@", ":pass@", ":passwd@",
        "://user:user@", "://admin:admin@", "://root:root@",
        "@example.com", "@example.org",
    ];
    for cred in placeholder_creds {
        if value.contains(cred) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
use crate::rules::{Charset, Detector, Rule};

    // ========================================================================
    // REDACTION TESTS
    // ========================================================================

    #[test]
    fn test_redact_short() {
        assert_eq!(redact("abc"), "***");
    }

    #[test]
    fn test_redact_exact_boundary() {
        assert_eq!(redact("1234567890"), "**********"); // 10 chars
    }

    #[test]
    fn test_redact_long() {
        let result = redact("ghp_1234567890abcdefghijklmnopqrstuvwxyz");
        assert!(result.starts_with("ghp_"));
        assert!(result.contains("..."));
        assert!(result.len() < 40); // Should be shorter than original
    }

    #[test]
    fn test_redact_preserves_prefix_and_suffix() {
        let secret = "sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let result = redact(secret);
        assert!(result.starts_with("sk-a"), "Should preserve prefix");
        assert!(result.ends_with("xxxx"), "Should preserve suffix");
    }

    // ========================================================================
    // PLACEHOLDER DETECTION TESTS
    // ========================================================================

    #[test]
    fn test_is_placeholder_common_values() {
        assert!(is_placeholder("your_api_key"));
        assert!(is_placeholder("changeme"));
        assert!(is_placeholder("placeholder"));
        assert!(is_placeholder("example"));
        assert!(is_placeholder("test"));
    }

    #[test]
    fn test_is_placeholder_template_syntax() {
        assert!(is_placeholder("${API_KEY}"));
        assert!(is_placeholder("${OPENAI_KEY}"));
        assert!(is_placeholder("{{secret}}"));
        assert!(is_placeholder("{{TOKEN}}"));
        assert!(is_placeholder("<your-key-here>"));
        assert!(is_placeholder("<insert-token>"));
    }

    #[test]
    fn test_is_placeholder_ellipsis() {
        assert!(is_placeholder("sk-..."));
        assert!(is_placeholder("ghp_...xxx"));
    }

    #[test]
    fn test_is_not_placeholder_real_values() {
        assert!(!is_placeholder("sk_live_abc123def456"));
        // Realistic-looking token with mixed chars (not all x's)
        assert!(!is_placeholder("ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"));
        assert!(!is_placeholder("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_is_placeholder_prefixed_xxx() {
        // These are placeholder patterns: known prefix + all x's
        assert!(is_placeholder("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
        assert!(is_placeholder("sk-xxxxxxxxxxxxxxxx"));
        assert!(is_placeholder("npm_xxxxxxxxxxxxxxxx"));
    }

    // ========================================================================
    // PREFIX DETECTOR TESTS
    // ========================================================================

    fn make_test_scanner() -> Scanner {
        Scanner::new(vec![])
    }

    // Realistic-looking fake token for testing (36 chars after prefix = 40 total)
    const FAKE_GHP: &str = "ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8";
    const FAKE_SK: &str = "sk-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4";

    #[test]
    fn test_detect_prefix_github_pat() {
        let scanner = make_test_scanner();
        let line = format!("const token = '{}';", FAKE_GHP);
        let result = scanner.detect_prefix(&line, "ghp_", 40, Charset::AlphaNum);

        assert!(result.is_some());
        let (matched, pos) = result.unwrap();
        assert!(matched.starts_with("ghp_"));
        assert_eq!(matched.len(), 40);
        assert!(pos > 0);
    }

    #[test]
    fn test_detect_prefix_too_short() {
        let scanner = make_test_scanner();
        let line = "token = 'ghp_abc123'"; // Too short
        let result = scanner.detect_prefix(line, "ghp_", 40, Charset::AlphaNum);

        assert!(result.is_none(), "Should not detect token that's too short");
    }

    #[test]
    fn test_detect_prefix_wrong_charset() {
        let scanner = make_test_scanner();
        let line = "key = 'ghp_abc1!@#$def2ghi3jkl4mno5pqr6stu7'"; // Invalid chars
        let result = scanner.detect_prefix(line, "ghp_", 40, Charset::AlphaNum);

        assert!(result.is_none(), "Should not match with invalid characters");
    }

    #[test]
    fn test_detect_prefix_multiple_matches() {
        let scanner = make_test_scanner();
        // First ghp_ is too short, second is valid
        let line = format!("ghp_short {}", FAKE_GHP);
        let result = scanner.detect_prefix(&line, "ghp_", 40, Charset::AlphaNum);

        assert!(result.is_some());
        let (matched, _) = result.unwrap();
        assert_eq!(matched.len(), 40);
    }

    #[test]
    fn test_detect_prefix_at_start() {
        let scanner = make_test_scanner();
        let result = scanner.detect_prefix(FAKE_GHP, "ghp_", 40, Charset::AlphaNum);

        assert!(result.is_some());
        let (_, pos) = result.unwrap();
        assert_eq!(pos, 0);
    }

    #[test]
    fn test_detect_prefix_at_end() {
        let scanner = make_test_scanner();
        let line = format!("token: {}", FAKE_GHP);
        let result = scanner.detect_prefix(&line, "ghp_", 40, Charset::AlphaNum);

        assert!(result.is_some());
    }

    #[test]
    fn test_detect_prefix_openai() {
        let scanner = make_test_scanner();
        let line = format!("OPENAI_KEY={}", FAKE_SK);
        let result = scanner.detect_prefix(&line, "sk-", 48, Charset::AlphaNumDash);

        assert!(result.is_some());
    }

    #[test]
    fn test_detect_prefix_aws() {
        let scanner = make_test_scanner();
        let line = "aws_key = 'AKIAIOSFODNN7EXAMPLE'";
        let result = scanner.detect_prefix(line, "AKIA", 20, Charset::AlphaNum);

        assert!(result.is_some());
        let (matched, _) = result.unwrap();
        assert_eq!(matched.len(), 20);
    }

    // ========================================================================
    // KEY-VALUE DETECTOR TESTS
    // ========================================================================

    // Use realistic-looking fake secrets that won't be caught by placeholder detection
    const FAKE_SECRET: &str = "sk1a2b3c4d5e6f7g8h9i0jklmnopqrstuv";

    #[test]
    fn test_detect_key_value_equals() {
        let scanner = make_test_scanner();
        let line = format!("API_KEY = '{}'", FAKE_SECRET);
        let result = scanner.detect_key_value(&line, &["API_KEY"], 20);

        assert!(result.is_some());
    }

    #[test]
    fn test_detect_key_value_colon() {
        let scanner = make_test_scanner();
        let line = format!("api_key: {}", FAKE_SECRET);
        let result = scanner.detect_key_value(&line, &["api_key"], 20);

        assert!(result.is_some());
    }

    #[test]
    fn test_detect_key_value_double_quotes() {
        let scanner = make_test_scanner();
        let line = format!(r#"API_KEY = "{}""#, FAKE_SECRET);
        let result = scanner.detect_key_value(&line, &["API_KEY"], 20);

        assert!(result.is_some());
    }

    #[test]
    fn test_detect_key_value_single_quotes() {
        let scanner = make_test_scanner();
        let line = format!("API_KEY = '{}'", FAKE_SECRET);
        let result = scanner.detect_key_value(&line, &["API_KEY"], 20);

        assert!(result.is_some());
    }

    #[test]
    fn test_detect_key_value_no_quotes() {
        let scanner = make_test_scanner();
        let line = format!("API_KEY={}", FAKE_SECRET);
        let result = scanner.detect_key_value(&line, &["API_KEY"], 20);

        assert!(result.is_some());
    }

    #[test]
    fn test_detect_key_value_case_insensitive() {
        let scanner = make_test_scanner();
        let line = format!("api_key = {}", FAKE_SECRET);
        let result = scanner.detect_key_value(&line, &["API_KEY"], 20);

        assert!(result.is_some(), "Should match case-insensitively");
    }

    #[test]
    fn test_detect_key_value_placeholder_skipped() {
        let scanner = make_test_scanner();
        let line = "API_KEY = 'your_api_key_here'";
        let result = scanner.detect_key_value(line, &["API_KEY"], 10);

        assert!(result.is_none(), "Should skip placeholder values");
    }

    #[test]
    fn test_detect_key_value_template_skipped() {
        let scanner = make_test_scanner();
        let line = "API_KEY = '${API_KEY}'";
        let result = scanner.detect_key_value(line, &["API_KEY"], 5);

        assert!(result.is_none(), "Should skip template variables");
    }

    #[test]
    fn test_detect_key_value_too_short() {
        let scanner = make_test_scanner();
        let line = "API_KEY = 'short'";
        let result = scanner.detect_key_value(line, &["API_KEY"], 20);

        assert!(result.is_none(), "Should not match short values");
    }

    #[test]
    fn test_detect_key_value_multiple_keys() {
        let scanner = make_test_scanner();
        let line = format!("secret_key = {}", FAKE_SECRET);
        let result = scanner.detect_key_value(&line, &["API_KEY", "SECRET_KEY", "TOKEN"], 20);

        assert!(result.is_some(), "Should match any of the keys");
    }

    // ========================================================================
    // ENDPOINT DETECTOR TESTS
    // ========================================================================

    #[test]
    fn test_detect_endpoint_by_key() {
        let scanner = make_test_scanner();
        // Use non-localhost URL (real external endpoint)
        let line = "OLLAMA_HOST = 'http://my-gpu-server.example.com:11434'";
        let result = scanner.detect_endpoint(
            line,
            &["OLLAMA_HOST", "OLLAMA_BASE_URL"],
            &[":11434"],
        );

        assert!(result.is_some());
    }

    #[test]
    fn test_detect_endpoint_by_pattern() {
        let scanner = make_test_scanner();
        // Use non-localhost URL (real external endpoint)
        let line = "base_url = 'http://ai-server.internal:11434/v1'";
        let result = scanner.detect_endpoint(
            line,
            &["OLLAMA_HOST"],
            &[":11434"],
        );

        assert!(result.is_some());
    }

    #[test]
    fn test_detect_endpoint_lmstudio() {
        let scanner = make_test_scanner();
        // Use non-localhost URL (real external endpoint)
        let line = "LMSTUDIO_URL=http://workstation.local:1234/v1";
        let result = scanner.detect_endpoint(
            line,
            &["LMSTUDIO_URL"],
            &[":1234"],
        );

        assert!(result.is_some());
    }

    #[test]
    fn test_detect_endpoint_skips_localhost() {
        let scanner = make_test_scanner();
        // localhost URLs should be skipped (not real leaked endpoints)
        let line = "OLLAMA_HOST = 'http://localhost:11434'";
        let result = scanner.detect_endpoint(
            line,
            &["OLLAMA_HOST"],
            &[":11434"],
        );

        assert!(result.is_none(), "Should skip localhost URLs");
    }

    #[test]
    fn test_detect_endpoint_skips_127() {
        let scanner = make_test_scanner();
        // 127.0.0.1 URLs should be skipped
        let line = "API_URL=http://127.0.0.1:8080/api";
        let result = scanner.detect_endpoint(
            line,
            &["API_URL"],
            &[":8080"],
        );

        assert!(result.is_none(), "Should skip 127.0.0.1 URLs");
    }

    // ========================================================================
    // FILE SKIP TESTS
    // ========================================================================

    #[test]
    fn test_should_skip_node_modules() {
        let scanner = make_test_scanner();
        let path = Path::new("/project/node_modules/package");
        assert!(scanner.should_skip(path));
    }

    #[test]
    fn test_should_skip_git() {
        let scanner = make_test_scanner();
        let path = Path::new("/project/.git/objects");
        assert!(scanner.should_skip(path));
    }

    #[test]
    fn test_should_skip_vendor() {
        let scanner = make_test_scanner();
        let path = Path::new("/project/vendor/lib");
        assert!(scanner.should_skip(path));
    }

    #[test]
    fn test_should_not_skip_src() {
        let scanner = make_test_scanner();
        let path = Path::new("/project/src/main.rs");
        assert!(!scanner.should_skip(path));
    }

    #[test]
    fn test_should_not_skip_env_file() {
        let scanner = make_test_scanner();
        let path = Path::new("/project/.env");
        assert!(!scanner.should_skip(path), ".env files should NOT be skipped");
    }

    // ========================================================================
    // BINARY EXTENSION TESTS
    // ========================================================================

    #[test]
    fn test_is_binary_images() {
        let scanner = make_test_scanner();
        assert!(scanner.is_binary_extension(Path::new("image.png")));
        assert!(scanner.is_binary_extension(Path::new("photo.jpg")));
        assert!(scanner.is_binary_extension(Path::new("icon.ico")));
    }

    #[test]
    fn test_is_binary_archives() {
        let scanner = make_test_scanner();
        assert!(scanner.is_binary_extension(Path::new("archive.zip")));
        assert!(scanner.is_binary_extension(Path::new("backup.tar")));
        assert!(scanner.is_binary_extension(Path::new("data.gz")));
    }

    #[test]
    fn test_is_binary_executables() {
        let scanner = make_test_scanner();
        assert!(scanner.is_binary_extension(Path::new("program.exe")));
        assert!(scanner.is_binary_extension(Path::new("library.dll")));
        assert!(scanner.is_binary_extension(Path::new("module.so")));
    }

    #[test]
    fn test_is_not_binary_source() {
        let scanner = make_test_scanner();
        assert!(!scanner.is_binary_extension(Path::new("main.rs")));
        assert!(!scanner.is_binary_extension(Path::new("app.py")));
        assert!(!scanner.is_binary_extension(Path::new("index.js")));
        assert!(!scanner.is_binary_extension(Path::new("config.yaml")));
        assert!(!scanner.is_binary_extension(Path::new(".env")));
    }

    // ========================================================================
    // CONTEXT BUILDING TESTS
    // ========================================================================

    #[test]
    fn test_build_context_middle() {
        let scanner = Scanner::new(vec![]).with_context(2);
        let lines = vec!["line1", "line2", "line3", "line4", "line5"];
        let context = scanner.build_context(&lines, 2, "secret", "***"); // Match on line3

        assert_eq!(context.len(), 5); // 2 before + match + 2 after
        assert!(context[2].is_match);
        assert_eq!(context[2].line_num, 3);
    }

    #[test]
    fn test_build_context_start() {
        let scanner = Scanner::new(vec![]).with_context(2);
        let lines = vec!["line1", "line2", "line3", "line4", "line5"];
        let context = scanner.build_context(&lines, 0, "secret", "***"); // Match on line1

        assert_eq!(context.len(), 3); // Match + 2 after
        assert!(context[0].is_match);
    }

    #[test]
    fn test_build_context_end() {
        let scanner = Scanner::new(vec![]).with_context(2);
        let lines = vec!["line1", "line2", "line3", "line4", "line5"];
        let context = scanner.build_context(&lines, 4, "secret", "***"); // Match on line5

        assert_eq!(context.len(), 3); // 2 before + match
        assert!(context[2].is_match);
    }

    // ========================================================================
    // EXTRACT SECRET TESTS
    // ========================================================================

    #[test]
    fn test_extract_secret_prefix() {
        let scanner = make_test_scanner();
        let detector = Detector::Prefix {
            prefix: "ghp_",
            min_len: 40,
            charset: Charset::AlphaNum,
        };
        let line = "token = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'";
        let matched = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

        let secret = scanner.extract_secret(line, matched, &detector);
        assert_eq!(secret, matched);
    }

    #[test]
    fn test_extract_secret_keyvalue() {
        let scanner = make_test_scanner();
        let detector = Detector::KeyValue {
            keys: &["API_KEY"],
            min_value_len: 20,
        };
        let line = "API_KEY=mysecretvalue12345678901234567890";
        let matched = "API_KEY=mysecretvalue12345678901234567890";

        let secret = scanner.extract_secret(line, matched, &detector);
        assert_eq!(secret, "mysecretvalue12345678901234567890");
    }

    // ========================================================================
    // CHARSET TESTS
    // ========================================================================

    #[test]
    fn test_charset_alphanum() {
        assert!(Charset::AlphaNum.matches('a'));
        assert!(Charset::AlphaNum.matches('Z'));
        assert!(Charset::AlphaNum.matches('5'));
        assert!(!Charset::AlphaNum.matches('-'));
        assert!(!Charset::AlphaNum.matches('_'));
    }

    #[test]
    fn test_charset_alphanum_dash() {
        assert!(Charset::AlphaNumDash.matches('a'));
        assert!(Charset::AlphaNumDash.matches('Z'));
        assert!(Charset::AlphaNumDash.matches('5'));
        assert!(Charset::AlphaNumDash.matches('-'));
        assert!(Charset::AlphaNumDash.matches('_'));
        assert!(!Charset::AlphaNumDash.matches('!'));
    }

    #[test]
    fn test_charset_base64() {
        assert!(Charset::Base64.matches('a'));
        assert!(Charset::Base64.matches('Z'));
        assert!(Charset::Base64.matches('+'));
        assert!(Charset::Base64.matches('/'));
        assert!(Charset::Base64.matches('='));
        assert!(!Charset::Base64.matches('-'));
    }

    #[test]
    fn test_charset_hex() {
        assert!(Charset::Hex.matches('0'));
        assert!(Charset::Hex.matches('9'));
        assert!(Charset::Hex.matches('a'));
        assert!(Charset::Hex.matches('f'));
        assert!(Charset::Hex.matches('A'));
        assert!(Charset::Hex.matches('F'));
        assert!(!Charset::Hex.matches('g'));
        assert!(!Charset::Hex.matches('G'));
    }

    #[test]
    fn test_charset_url() {
        assert!(Charset::Url.matches('a'));
        assert!(Charset::Url.matches(':'));
        assert!(Charset::Url.matches('/'));
        assert!(Charset::Url.matches('?'));
        assert!(Charset::Url.matches('='));
        assert!(Charset::Url.matches('%'));
        assert!(!Charset::Url.matches(' '));
    }

    // ========================================================================
    // IS_LOCALHOST TESTS
    // ========================================================================

    #[test]
    fn test_is_localhost_with_localhost() {
        assert!(is_localhost("http://localhost:8080"));
        assert!(is_localhost("localhost:3000"));
        assert!(is_localhost("http://localhost/api"));
    }

    #[test]
    fn test_is_localhost_with_127() {
        assert!(is_localhost("http://127.0.0.1:8080"));
        assert!(is_localhost("127.0.0.1:3000"));
        assert!(is_localhost("http://127.0.0.1/api"));
    }

    #[test]
    fn test_is_localhost_with_0000() {
        assert!(is_localhost("http://0.0.0.0:8080"));
        assert!(is_localhost("0.0.0.0:3000"));
    }

    #[test]
    fn test_is_localhost_with_ipv6_loopback() {
        assert!(is_localhost("http://[::1]:8080"));
        assert!(is_localhost("[::1]:3000"));
    }

    #[test]
    fn test_is_localhost_truncated() {
        // Catches //localhost truncated in context
        assert!(is_localhost("http://lo"));
    }

    #[test]
    fn test_is_localhost_real_host() {
        assert!(!is_localhost("http://example.com:8080"));
        assert!(!is_localhost("http://my-server.local:3000"));
        assert!(!is_localhost("http://192.168.1.100:8080"));
    }

    // ========================================================================
    // IS_CODE_PATTERN TESTS
    // ========================================================================

    #[test]
    fn test_is_code_pattern_method_calls() {
        assert!(is_code_pattern("request.form.get('password')"));
        assert!(is_code_pattern("data.get('token')"));
        assert!(is_code_pattern("config.value"));
        assert!(is_code_pattern("self.api_key"));
    }

    #[test]
    fn test_is_code_pattern_arrow_operators() {
        assert!(is_code_pattern("this->token"));
        assert!(is_code_pattern("obj->get_key()"));
    }

    #[test]
    fn test_is_code_pattern_scope_resolution() {
        assert!(is_code_pattern("std::env::var"));
        assert!(is_code_pattern("Config::get_token()"));
    }

    #[test]
    fn test_is_code_pattern_common_prefixes() {
        assert!(is_code_pattern("self.secret"));
        assert!(is_code_pattern("this.apiKey"));
        assert!(is_code_pattern("request.cookies.get('token')"));
        assert!(is_code_pattern("req.body.password"));
        assert!(is_code_pattern("config.database_password"));
        assert!(is_code_pattern("settings.api_key"));
        assert!(is_code_pattern("env.API_KEY"));
        assert!(is_code_pattern("data['telegram'].get('bot_token')"));
        assert!(is_code_pattern("form.password"));
    }

    #[test]
    fn test_is_code_pattern_function_calls() {
        assert!(is_code_pattern("getenv('API_KEY')"));
        assert!(is_code_pattern("os.getenv('TOKEN')"));
        assert!(is_code_pattern("hash_remember_token(token)"));
        assert!(is_code_pattern("generate_token()"));
    }

    #[test]
    fn test_is_code_pattern_bracket_access() {
        assert!(is_code_pattern("data['token']"));
        assert!(is_code_pattern("config[\"password\"]"));
    }

    #[test]
    fn test_is_code_pattern_real_secrets() {
        // Real secrets should NOT match is_code_pattern
        assert!(!is_code_pattern("sk_live_abc123xyz"));
        assert!(!is_code_pattern("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
        assert!(!is_code_pattern("mysecretpassword123"));
        assert!(!is_code_pattern("AIzaSyB-example-api-key"));
    }

    // ========================================================================
    // LOOKS_LIKE_CODE TESTS
    // ========================================================================

    #[test]
    fn test_looks_like_code_dots() {
        // Dots without http prefix suggest object access
        assert!(looks_like_code("process.env.TOKEN"));
        assert!(looks_like_code("os.environ.get"));
        assert!(looks_like_code("config.secret"));
    }

    #[test]
    fn test_looks_like_code_dots_http_ok() {
        // HTTP URLs with dots are OK
        assert!(!looks_like_code("http://example.com"));
        assert!(!looks_like_code("https://api.service.com/v1"));
    }

    #[test]
    fn test_looks_like_code_brackets() {
        assert!(looks_like_code("data[0]"));
        assert!(looks_like_code("config['key']"));
        assert!(looks_like_code("getPassword()"));
    }

    #[test]
    fn test_looks_like_code_special_prefixes() {
        assert!(looks_like_code("$password"));
        assert!(looks_like_code("@secret"));
        assert!(looks_like_code("#token"));
        assert!(looks_like_code("*pointer"));
    }

    #[test]
    fn test_looks_like_code_snake_case_var() {
        // All lowercase with underscores = variable name
        assert!(looks_like_code("password_input"));
        assert!(looks_like_code("api_key_field"));
        assert!(looks_like_code("user_token"));
    }

    #[test]
    fn test_looks_like_code_real_secrets() {
        // Real secrets should NOT look like code
        assert!(!looks_like_code("MyS3cr3tP@ssw0rd!"));
        assert!(!looks_like_code("ABC123XYZ789"));
        assert!(!looks_like_code("secret-key-value-123"));
    }

    // ========================================================================
    // LOCK FILE TESTS
    // ========================================================================

    #[test]
    fn test_is_lock_file_npm() {
        let scanner = make_test_scanner();
        assert!(scanner.is_lock_file(Path::new("/project/package-lock.json")));
    }

    #[test]
    fn test_is_lock_file_pnpm() {
        let scanner = make_test_scanner();
        assert!(scanner.is_lock_file(Path::new("/project/pnpm-lock.yaml")));
    }

    #[test]
    fn test_is_lock_file_yarn() {
        let scanner = make_test_scanner();
        assert!(scanner.is_lock_file(Path::new("/project/yarn.lock")));
    }

    #[test]
    fn test_is_lock_file_cargo() {
        let scanner = make_test_scanner();
        assert!(scanner.is_lock_file(Path::new("/project/Cargo.lock")));
    }

    #[test]
    fn test_is_lock_file_gemfile() {
        let scanner = make_test_scanner();
        assert!(scanner.is_lock_file(Path::new("/project/Gemfile.lock")));
    }

    #[test]
    fn test_is_lock_file_composer() {
        let scanner = make_test_scanner();
        assert!(scanner.is_lock_file(Path::new("/project/composer.lock")));
    }

    #[test]
    fn test_is_lock_file_poetry() {
        let scanner = make_test_scanner();
        assert!(scanner.is_lock_file(Path::new("/project/poetry.lock")));
    }

    #[test]
    fn test_is_lock_file_pipfile() {
        let scanner = make_test_scanner();
        assert!(scanner.is_lock_file(Path::new("/project/Pipfile.lock")));
    }

    #[test]
    fn test_is_lock_file_go_sum() {
        let scanner = make_test_scanner();
        assert!(scanner.is_lock_file(Path::new("/project/go.sum")));
    }

    #[test]
    fn test_is_not_lock_file_regular() {
        let scanner = make_test_scanner();
        assert!(!scanner.is_lock_file(Path::new("/project/package.json")));
        assert!(!scanner.is_lock_file(Path::new("/project/Cargo.toml")));
        assert!(!scanner.is_lock_file(Path::new("/project/main.rs")));
        assert!(!scanner.is_lock_file(Path::new("/project/.env")));
    }

    // ========================================================================
    // WORD BOUNDARY TESTS FOR DETECT_KEY_VALUE
    // ========================================================================

    #[test]
    fn test_detect_key_value_word_boundary_before() {
        let scanner = make_test_scanner();
        // Should NOT match "bot_token" when searching for "token" key
        let line = format!("bot_token = '{}'", FAKE_SECRET);
        let result = scanner.detect_key_value(&line, &["token"], 20);
        assert!(result.is_none(), "Should not match token when prefixed with bot_");
    }

    #[test]
    fn test_detect_key_value_word_boundary_after() {
        let scanner = make_test_scanner();
        // Should NOT match "password_hash" when searching for "password" key
        let line = format!("password_hash = '{}'", FAKE_SECRET);
        let result = scanner.detect_key_value(&line, &["password"], 20);
        assert!(result.is_none(), "Should not match password when followed by _hash");
    }

    #[test]
    fn test_detect_key_value_word_boundary_exact() {
        let scanner = make_test_scanner();
        // SHOULD match exact "password" key
        let line = format!("password = '{}'", FAKE_SECRET);
        let result = scanner.detect_key_value(&line, &["password"], 20);
        assert!(result.is_some(), "Should match exact password key");
    }

    #[test]
    fn test_detect_key_value_word_boundary_with_prefix() {
        let scanner = make_test_scanner();
        // Should NOT match "remember_token" when searching for "token"
        let line = format!("remember_token = '{}'", FAKE_SECRET);
        let result = scanner.detect_key_value(&line, &["token"], 20);
        assert!(result.is_none(), "Should not match token with prefix");
    }

    #[test]
    fn test_detect_key_value_word_boundary_allows_special_chars() {
        let scanner = make_test_scanner();
        // SHOULD match "token" when preceded by special chars (YAML, env files)
        let line = format!("  token: '{}'", FAKE_SECRET);
        let result = scanner.detect_key_value(&line, &["token"], 20);
        assert!(result.is_some(), "Should match token when preceded by whitespace");

        // Also test with underscore prefix in the KEY list itself
        let line2 = format!("auth_token = '{}'", FAKE_SECRET);
        let result2 = scanner.detect_key_value(&line2, &["auth_token"], 20);
        assert!(result2.is_some(), "Should match auth_token as exact key");
    }

    #[test]
    fn test_detect_key_value_skips_code_patterns() {
        let scanner = make_test_scanner();
        // Should skip when value is a code pattern (function call)
        let line = "password = request.form.get('password')";
        let result = scanner.detect_key_value(line, &["password"], 8);
        assert!(result.is_none(), "Should skip code pattern as value");
    }

    #[test]
    fn test_detect_key_value_skips_method_access() {
        let scanner = make_test_scanner();
        // Should skip when value is method access
        let line = "token = data.get('token')";
        let result = scanner.detect_key_value(line, &["token"], 8);
        assert!(result.is_none(), "Should skip method access as value");
    }

    #[test]
    fn test_detect_key_value_skips_unquoted_code() {
        let scanner = make_test_scanner();
        // Unquoted value that looks like code should be skipped
        let line = "token = password_input";
        let result = scanner.detect_key_value(line, &["token"], 8);
        assert!(result.is_none(), "Should skip unquoted code-like value");
    }
}
