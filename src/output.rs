#![allow(dead_code)]

//! Output formatters
//!
//! Supports text, JSON, SARIF (for GitHub Actions), and report (for database storage) formats.

use crate::cli::OutputFormat;
use crate::scanner::Finding;
use std::collections::HashMap;
use std::io::IsTerminal;
use std::time::{SystemTime, UNIX_EPOCH};

/// Scan metadata for enhanced reporting
#[derive(Default)]
pub struct ScanMetadata {
    pub scan_id: String,
    pub target: String,
    pub target_type: String, // "directory", "git_url", "file"
    pub git_branch: Option<String>,
    pub git_commit: Option<String>,
    pub git_remote: Option<String>,
    pub scan_duration_ms: u64,
}

impl ScanMetadata {
    pub fn new(target: &str) -> Self {
        Self {
            scan_id: generate_scan_id(),
            target: target.to_string(),
            target_type: if target.starts_with("http") || target.starts_with("git@") {
                "git_url".to_string()
            } else if std::path::Path::new(target).is_file() {
                "file".to_string()
            } else {
                "directory".to_string()
            },
            ..Default::default()
        }
    }

    pub fn with_git_info(
        mut self,
        branch: Option<String>,
        commit: Option<String>,
        remote: Option<String>,
    ) -> Self {
        self.git_branch = branch;
        self.git_commit = commit;
        self.git_remote = remote;
        self
    }

    pub fn with_duration(mut self, duration_ms: u64) -> Self {
        self.scan_duration_ms = duration_ms;
        self
    }
}

fn generate_scan_id() -> String {
    // Simple UUID-like ID based on timestamp and random component
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:032x}", timestamp)
}

fn get_timestamp() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    // Format as ISO 8601
    let days_since_epoch = secs / 86400;
    let remaining_secs = secs % 86400;
    let hours = remaining_secs / 3600;
    let minutes = (remaining_secs % 3600) / 60;
    let seconds = remaining_secs % 60;

    // Approximate date calculation (not accounting for leap years perfectly)
    let mut year = 1970;
    let mut days = days_since_epoch;
    loop {
        let days_in_year = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
            366
        } else {
            365
        };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    let days_in_months: [u64; 12] = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1;
    for &dim in &days_in_months {
        if days < dim {
            break;
        }
        days -= dim;
        month += 1;
    }
    let day = days + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

pub fn print_findings(findings: &[Finding], format: OutputFormat, show_context: bool) {
    print_findings_with_metadata(findings, format, show_context, None)
}

pub fn print_findings_with_metadata(
    findings: &[Finding],
    format: OutputFormat,
    show_context: bool,
    metadata: Option<&ScanMetadata>,
) {
    match format {
        OutputFormat::Text => print_text(findings, show_context),
        OutputFormat::Json => print_json(findings),
        OutputFormat::Sarif => print_sarif(findings),
        OutputFormat::Report => print_report(findings, metadata),
    }
}

fn print_text(findings: &[Finding], show_context: bool) {
    if findings.is_empty() {
        println!("No secrets found.");
        return;
    }

    println!("Found {} potential secret(s):\n", findings.len());

    let is_tty = std::io::stdout().is_terminal();
    let max_findings = if is_tty {
        findings.len()
    } else {
        findings.len().min(50)
    };

    for finding in findings.iter().take(max_findings) {
        println!(
            "\x1b[1;31m{}\x1b[0m {}:{}:{}",
            finding.rule_id, finding.file, finding.line, finding.column
        );
        println!("  \x1b[1mRule:\x1b[0m {}", finding.rule_name);
        println!("  \x1b[1mSecret:\x1b[0m {}", finding.secret);

        // Display verification status if available
        #[cfg(feature = "verify")]
        if let Some(ref verification) = finding.verification_status {
            let (status_icon, status_color) = match verification.status {
                crate::verify::VerificationStatus::Active => ("✅", "\x1b[32m"),
                crate::verify::VerificationStatus::Inactive => ("❌", "\x1b[31m"),
                crate::verify::VerificationStatus::Unknown => ("❓", "\x1b[33m"),
                crate::verify::VerificationStatus::NotSupported => ("🚫", "\x1b[90m"),
            };
            println!(
                "  \x1b[1mVerified:\x1b[0m {}{} {}\x1b[0m",
                status_color,
                status_icon,
                verification.message.as_deref().unwrap_or("")
            );
        }

        if show_context && !finding.context.is_empty() {
            println!("  \x1b[1mContext:\x1b[0m");
            for ctx in &finding.context {
                let prefix = if ctx.is_match {
                    "\x1b[33m>\x1b[0m"
                } else {
                    " "
                };
                let line_style = if ctx.is_match { "\x1b[33m" } else { "\x1b[90m" };
                let content = if is_tty {
                    ctx.content.clone()
                } else {
                    truncate_chars(&ctx.content, 500)
                };
                println!(
                    "    {} {:>4} | {}\x1b[0m",
                    prefix,
                    ctx.line_num,
                    line_style.to_owned() + &content
                );
            }
        }
        println!();
    }

    if max_findings < findings.len() {
        println!(
            "Output truncated (showing {} of {} findings). Use `-f json`/`-f report` for full output.",
            max_findings,
            findings.len()
        );
    }
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    let char_count = s.chars().count();
    if char_count <= max_chars {
        return s.to_string();
    }

    if max_chars <= 1 {
        return "…".to_string();
    }

    let head_len = max_chars.saturating_sub(1) / 2;
    let tail_len = max_chars.saturating_sub(1) - head_len;

    let head: String = s.chars().take(head_len).collect();
    let tail: String = s.chars().skip(char_count.saturating_sub(tail_len)).collect();
    format!("{head}…{tail}")
}

fn print_json(findings: &[Finding]) {
    // Hand-rolled JSON - no serde dependency
    println!("{{");
    println!("  \"version\": \"1.0\",");
    println!("  \"scanner\": \"libreleak\",");
    println!("  \"findings\": [");

    for (i, finding) in findings.iter().enumerate() {
        let comma = if i < findings.len() - 1 { "," } else { "" };

        println!("    {{");
        println!("      \"rule_id\": \"{}\",", escape_json(&finding.rule_id));
        println!(
            "      \"rule_name\": \"{}\",",
            escape_json(&finding.rule_name)
        );
        println!("      \"file\": \"{}\",", escape_json(&finding.file));
        println!("      \"line\": {},", finding.line);
        println!("      \"column\": {},", finding.column);
        println!("      \"secret\": \"{}\",", escape_json(&finding.secret));
        println!("      \"context\": [");

        for (j, ctx) in finding.context.iter().enumerate() {
            let ctx_comma = if j < finding.context.len() - 1 {
                ","
            } else {
                ""
            };
            println!(
                "        {{\"line\": {}, \"content\": \"{}\", \"is_match\": {}}}{}",
                ctx.line_num,
                escape_json(&ctx.content),
                ctx.is_match,
                ctx_comma
            );
        }

        println!("      ]");
        println!("    }}{}", comma);
    }

    println!("  ]");
    println!("}}");
}

fn print_sarif(findings: &[Finding]) {
    // SARIF 2.1.0 for GitHub Advanced Security integration
    println!("{{");
    println!(
        "  \"$schema\": \"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json\","
    );
    println!("  \"version\": \"2.1.0\",");
    println!("  \"runs\": [{{");
    println!("    \"tool\": {{");
    println!("      \"driver\": {{");
    println!("        \"name\": \"libreleak\",");
    println!("        \"version\": \"{}\",", env!("CARGO_PKG_VERSION"));
    println!("        \"informationUri\": \"https://github.com/fosscode/libreleak\",");
    println!("        \"rules\": []");
    println!("      }}");
    println!("    }},");
    println!("    \"results\": [");

    for (i, finding) in findings.iter().enumerate() {
        let comma = if i < findings.len() - 1 { "," } else { "" };

        println!("      {{");
        println!("        \"ruleId\": \"{}\",", escape_json(&finding.rule_id));
        println!("        \"level\": \"error\",");
        println!("        \"message\": {{");
        println!(
            "          \"text\": \"Potential {} detected\"",
            escape_json(&finding.rule_name)
        );
        println!("        }},");
        println!("        \"locations\": [{{");
        println!("          \"physicalLocation\": {{");
        println!("            \"artifactLocation\": {{");
        println!("              \"uri\": \"{}\"", escape_json(&finding.file));
        println!("            }},");
        println!("            \"region\": {{");
        println!("              \"startLine\": {},", finding.line);
        println!("              \"startColumn\": {}", finding.column);
        println!("            }}");
        println!("          }}");
        println!("        }}]");
        println!("      }}{}", comma);
    }

    println!("    ]");
    println!("  }}]");
    println!("}}");
}

fn escape_json(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result
}

/// Print findings as a comprehensive report suitable for database storage
/// This format is designed for:
/// - Research papers and security analysis
/// - Bug bounty submissions
/// - Security posture reporting across repositories
/// - Historical trend analysis
fn print_report(findings: &[Finding], metadata: Option<&ScanMetadata>) {
    let timestamp = get_timestamp();

    // Count findings by rule type for summary
    let mut rule_counts: HashMap<String, usize> = HashMap::new();
    for finding in findings {
        *rule_counts.entry(finding.rule_id.clone()).or_insert(0) += 1;
    }

    // Count by category (first part of rule_id before hyphen)
    let mut category_counts: HashMap<String, usize> = HashMap::new();
    for finding in findings {
        let category = finding
            .rule_id
            .split('-')
            .next()
            .unwrap_or("unknown")
            .to_string();
        *category_counts.entry(category).or_insert(0) += 1;
    }

    println!("{{");
    println!("  \"report_version\": \"2.0\",");
    println!("  \"scanner\": \"libreleak\",");
    println!("  \"scanner_version\": \"{}\",", env!("CARGO_PKG_VERSION"));
    println!("  \"timestamp\": \"{}\",", timestamp);

    // Metadata section
    if let Some(meta) = metadata {
        println!("  \"scan_id\": \"{}\",", escape_json(&meta.scan_id));
        println!("  \"target\": {{");
        println!("    \"path\": \"{}\",", escape_json(&meta.target));
        println!("    \"type\": \"{}\",", escape_json(&meta.target_type));
        if let Some(ref branch) = meta.git_branch {
            println!("    \"git_branch\": \"{}\",", escape_json(branch));
        }
        if let Some(ref commit) = meta.git_commit {
            println!("    \"git_commit\": \"{}\",", escape_json(commit));
        }
        if let Some(ref remote) = meta.git_remote {
            println!("    \"git_remote\": \"{}\",", escape_json(remote));
        }
        println!("    \"scan_duration_ms\": {}", meta.scan_duration_ms);
        println!("  }},");
    } else {
        println!("  \"scan_id\": \"{}\",", generate_scan_id());
        println!("  \"target\": null,");
    }

    // Summary section for quick analysis
    println!("  \"summary\": {{");
    println!("    \"total_findings\": {},", findings.len());
    println!("    \"unique_rules_triggered\": {},", rule_counts.len());

    // Rules breakdown
    println!("    \"findings_by_rule\": {{");
    let mut rules: Vec<_> = rule_counts.iter().collect();
    rules.sort_by(|a, b| b.1.cmp(a.1)); // Sort by count descending
    for (i, (rule, count)) in rules.iter().enumerate() {
        let comma = if i < rules.len() - 1 { "," } else { "" };
        println!("      \"{}\": {}{}", escape_json(rule), count, comma);
    }
    println!("    }},");

    // Category breakdown
    println!("    \"findings_by_category\": {{");
    let mut categories: Vec<_> = category_counts.iter().collect();
    categories.sort_by(|a, b| b.1.cmp(a.1));
    for (i, (cat, count)) in categories.iter().enumerate() {
        let comma = if i < categories.len() - 1 { "," } else { "" };
        println!("      \"{}\": {}{}", escape_json(cat), count, comma);
    }
    println!("    }},");

    // Severity assessment (basic heuristic)
    let high_severity = findings
        .iter()
        .filter(|f| {
            f.rule_id.contains("private-key")
                || f.rule_id.contains("aws")
                || f.rule_id.contains("database")
                || f.rule_id.contains("jwt")
        })
        .count();
    let medium_severity = findings
        .iter()
        .filter(|f| {
            f.rule_id.contains("api-key")
                || f.rule_id.contains("token")
                || f.rule_id.contains("secret")
        })
        .count();
    let low_severity = findings
        .len()
        .saturating_sub(high_severity + medium_severity);

    println!("    \"severity_breakdown\": {{");
    println!("      \"high\": {},", high_severity);
    println!("      \"medium\": {},", medium_severity);
    println!("      \"low\": {}", low_severity);
    println!("    }}");
    println!("  }},");

    // Detailed findings
    println!("  \"findings\": [");
    for (i, finding) in findings.iter().enumerate() {
        let comma = if i < findings.len() - 1 { "," } else { "" };

        println!("    {{");
        println!("      \"id\": {},", i + 1);
        println!("      \"rule_id\": \"{}\",", escape_json(&finding.rule_id));
        println!(
            "      \"rule_name\": \"{}\",",
            escape_json(&finding.rule_name)
        );
        println!("      \"location\": {{");
        println!("        \"file\": \"{}\",", escape_json(&finding.file));
        println!("        \"line\": {},", finding.line);
        println!("        \"column\": {}", finding.column);
        println!("      }},");
        println!(
            "      \"secret_preview\": \"{}\",",
            escape_json(&finding.secret)
        );
        println!("      \"context\": [");

        for (j, ctx) in finding.context.iter().enumerate() {
            let ctx_comma = if j < finding.context.len() - 1 {
                ","
            } else {
                ""
            };
            println!(
                "        {{\"line\": {}, \"content\": \"{}\", \"is_match\": {}}}{}",
                ctx.line_num,
                escape_json(&ctx.content),
                ctx.is_match,
                ctx_comma
            );
        }

        println!("      ],");

        // Add verification placeholder
        println!("      \"verification\": {{");
        println!("        \"status\": \"pending\",");
        println!("        \"verified_at\": null,");
        println!("        \"is_active\": null");
        println!("      }}");
        println!("    }}{}", comma);
    }
    println!("  ]");
    println!("}}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{ContextLine, Finding};

    // ========================================================================
    // HELPER FUNCTIONS
    // ========================================================================

    fn create_test_finding(
        rule_id: &str,
        rule_name: &str,
        file: &str,
        line: usize,
        column: usize,
        secret: &str,
    ) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            rule_name: rule_name.to_string(),
            file: file.to_string(),
            line,
            column,
            matched: secret.to_string(),
            secret: secret.to_string(),
            secret_raw: secret.to_string(),
            context: vec![],
            #[cfg(feature = "verify")]
            verification_status: None,
        }
    }

    fn create_test_finding_with_context(
        rule_id: &str,
        rule_name: &str,
        file: &str,
        line: usize,
        column: usize,
        secret: &str,
        context: Vec<ContextLine>,
    ) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            rule_name: rule_name.to_string(),
            file: file.to_string(),
            line,
            column,
            matched: secret.to_string(),
            secret: secret.to_string(),
            secret_raw: secret.to_string(),
            context,
            #[cfg(feature = "verify")]
            verification_status: None,
        }
    }

    // ========================================================================
    // ESCAPE_JSON TESTS
    // ========================================================================

    #[test]
    fn test_escape_json_simple_string() {
        assert_eq!(escape_json("hello world"), "hello world");
    }

    #[test]
    fn test_escape_json_quotes() {
        assert_eq!(escape_json(r#"say "hello""#), r#"say \"hello\""#);
    }

    #[test]
    fn test_escape_json_backslash() {
        assert_eq!(escape_json(r"path\to\file"), r"path\\to\\file");
    }

    #[test]
    fn test_escape_json_newline() {
        assert_eq!(escape_json("line1\nline2"), "line1\\nline2");
    }

    #[test]
    fn test_escape_json_carriage_return() {
        assert_eq!(escape_json("line1\rline2"), "line1\\rline2");
    }

    #[test]
    fn test_escape_json_tab() {
        assert_eq!(escape_json("col1\tcol2"), "col1\\tcol2");
    }

    #[test]
    fn test_escape_json_control_characters() {
        // Test ASCII control character (bell = 0x07)
        assert_eq!(escape_json("\x07"), "\\u0007");
        // Test null character
        assert_eq!(escape_json("\x00"), "\\u0000");
        // Test form feed
        assert_eq!(escape_json("\x0C"), "\\u000c");
    }

    #[test]
    fn test_escape_json_mixed() {
        assert_eq!(
            escape_json("path\\to\\file.txt\nline with \"quotes\""),
            "path\\\\to\\\\file.txt\\nline with \\\"quotes\\\""
        );
    }

    #[test]
    fn test_escape_json_unicode() {
        // Unicode characters should pass through unchanged
        assert_eq!(escape_json("hello"), "hello");
        assert_eq!(escape_json("emoji: 🔒"), "emoji: 🔒");
    }

    #[test]
    fn test_escape_json_empty() {
        assert_eq!(escape_json(""), "");
    }

    // ========================================================================
    // TRUNCATE_CHARS TESTS
    // ========================================================================

    #[test]
    fn test_truncate_chars_short_string() {
        // String shorter than limit - no truncation
        assert_eq!(truncate_chars("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_chars_exact_limit() {
        // String exactly at limit - no truncation
        assert_eq!(truncate_chars("helloworld", 10), "helloworld");
    }

    #[test]
    fn test_truncate_chars_over_limit() {
        // String over limit - should truncate
        let result = truncate_chars("hello world long string", 10);
        assert!(result.contains("…"));
        assert!(result.chars().count() <= 10);
    }

    #[test]
    fn test_truncate_chars_preserves_start_and_end() {
        let result = truncate_chars("0123456789ABCDEFGHIJ", 10);
        // Should have head...tail format
        assert!(result.starts_with("0123"));
        assert!(result.ends_with("GHIJ"));
        assert!(result.contains("…"));
    }

    #[test]
    fn test_truncate_chars_single_char_limit() {
        // Edge case: max_chars = 1
        assert_eq!(truncate_chars("hello", 1), "…");
    }

    #[test]
    fn test_truncate_chars_zero_limit() {
        // Edge case: max_chars = 0
        assert_eq!(truncate_chars("hello", 0), "…");
    }

    #[test]
    fn test_truncate_chars_unicode() {
        // Unicode characters should be handled correctly
        let unicode_str = "hello🔒world🔐test";
        let result = truncate_chars(unicode_str, 10);
        assert!(result.chars().count() <= 10);
    }

    #[test]
    fn test_truncate_chars_empty_string() {
        assert_eq!(truncate_chars("", 10), "");
    }

    // ========================================================================
    // GET_TIMESTAMP TESTS
    // ========================================================================

    #[test]
    fn test_get_timestamp_format() {
        let timestamp = get_timestamp();
        // Should be ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ
        assert!(timestamp.contains("T"));
        assert!(timestamp.ends_with("Z"));
        assert_eq!(timestamp.len(), 20);
    }

    #[test]
    fn test_get_timestamp_valid_year() {
        let timestamp = get_timestamp();
        let year: u32 = timestamp[0..4].parse().unwrap();
        // Should be a reasonable year (between 2020 and 2100)
        assert!(year >= 2020 && year <= 2100);
    }

    #[test]
    fn test_get_timestamp_valid_month() {
        let timestamp = get_timestamp();
        let month: u32 = timestamp[5..7].parse().unwrap();
        assert!(month >= 1 && month <= 12);
    }

    #[test]
    fn test_get_timestamp_valid_day() {
        let timestamp = get_timestamp();
        let day: u32 = timestamp[8..10].parse().unwrap();
        assert!(day >= 1 && day <= 31);
    }

    #[test]
    fn test_get_timestamp_valid_time() {
        let timestamp = get_timestamp();
        let hour: u32 = timestamp[11..13].parse().unwrap();
        let minute: u32 = timestamp[14..16].parse().unwrap();
        let second: u32 = timestamp[17..19].parse().unwrap();
        assert!(hour < 24);
        assert!(minute < 60);
        assert!(second < 60);
    }

    // ========================================================================
    // GENERATE_SCAN_ID TESTS
    // ========================================================================

    #[test]
    fn test_generate_scan_id_length() {
        let id = generate_scan_id();
        assert_eq!(id.len(), 32);
    }

    #[test]
    fn test_generate_scan_id_hex() {
        let id = generate_scan_id();
        // Should be valid hex characters
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_scan_id_unique() {
        let id1 = generate_scan_id();
        // Small delay to ensure different timestamps
        std::thread::sleep(std::time::Duration::from_millis(1));
        let id2 = generate_scan_id();
        // IDs should be different (based on timestamp)
        assert_ne!(id1, id2);
    }

    // ========================================================================
    // SCAN_METADATA TESTS
    // ========================================================================

    #[test]
    fn test_scan_metadata_new_directory() {
        let meta = ScanMetadata::new("/path/to/directory");
        assert_eq!(meta.target, "/path/to/directory");
        assert_eq!(meta.target_type, "directory");
        assert!(!meta.scan_id.is_empty());
    }

    #[test]
    fn test_scan_metadata_new_git_url_https() {
        let meta = ScanMetadata::new("https://github.com/user/repo");
        assert_eq!(meta.target_type, "git_url");
    }

    #[test]
    fn test_scan_metadata_new_git_url_ssh() {
        let meta = ScanMetadata::new("git@github.com:user/repo.git");
        assert_eq!(meta.target_type, "git_url");
    }

    #[test]
    fn test_scan_metadata_with_git_info() {
        let meta = ScanMetadata::new("/path")
            .with_git_info(
                Some("main".to_string()),
                Some("abc123".to_string()),
                Some("origin".to_string()),
            );
        assert_eq!(meta.git_branch, Some("main".to_string()));
        assert_eq!(meta.git_commit, Some("abc123".to_string()));
        assert_eq!(meta.git_remote, Some("origin".to_string()));
    }

    #[test]
    fn test_scan_metadata_with_duration() {
        let meta = ScanMetadata::new("/path")
            .with_duration(1234);
        assert_eq!(meta.scan_duration_ms, 1234);
    }

    #[test]
    fn test_scan_metadata_default() {
        let meta = ScanMetadata::default();
        assert!(meta.scan_id.is_empty());
        assert!(meta.target.is_empty());
        assert!(meta.target_type.is_empty());
        assert!(meta.git_branch.is_none());
        assert!(meta.git_commit.is_none());
        assert!(meta.git_remote.is_none());
        assert_eq!(meta.scan_duration_ms, 0);
    }

    // ========================================================================
    // CONTEXT LINE TESTS
    // ========================================================================

    #[test]
    fn test_context_line_creation() {
        let ctx = ContextLine {
            line_num: 42,
            content: "API_KEY=secret123".to_string(),
            is_match: true,
        };
        assert_eq!(ctx.line_num, 42);
        assert_eq!(ctx.content, "API_KEY=secret123");
        assert!(ctx.is_match);
    }

    #[test]
    fn test_context_line_non_match() {
        let ctx = ContextLine {
            line_num: 41,
            content: "# Configuration".to_string(),
            is_match: false,
        };
        assert!(!ctx.is_match);
    }

    // ========================================================================
    // FINDING STRUCTURE TESTS
    // ========================================================================

    #[test]
    fn test_finding_creation() {
        let finding = create_test_finding(
            "github-pat",
            "GitHub Personal Access Token",
            "src/config.rs",
            10,
            5,
            "ghp_****",
        );
        assert_eq!(finding.rule_id, "github-pat");
        assert_eq!(finding.rule_name, "GitHub Personal Access Token");
        assert_eq!(finding.file, "src/config.rs");
        assert_eq!(finding.line, 10);
        assert_eq!(finding.column, 5);
        assert_eq!(finding.secret, "ghp_****");
    }

    #[test]
    fn test_finding_with_context() {
        let context = vec![
            ContextLine {
                line_num: 9,
                content: "// Config".to_string(),
                is_match: false,
            },
            ContextLine {
                line_num: 10,
                content: "TOKEN=ghp_****".to_string(),
                is_match: true,
            },
            ContextLine {
                line_num: 11,
                content: "// End".to_string(),
                is_match: false,
            },
        ];
        let finding = create_test_finding_with_context(
            "github-pat",
            "GitHub PAT",
            "file.rs",
            10,
            7,
            "ghp_****",
            context,
        );
        assert_eq!(finding.context.len(), 3);
        assert!(finding.context[1].is_match);
    }

    // ========================================================================
    // JSON FORMAT OUTPUT TESTS
    // ========================================================================

    #[test]
    fn test_json_format_escapes_special_chars_in_file() {
        // Test that file paths with special characters are escaped
        let finding = create_test_finding(
            "test-rule",
            "Test Rule",
            r"src\path\to\file.rs",  // Windows-style path
            1,
            1,
            "secret",
        );
        // The escape_json function should handle backslashes
        let escaped_file = escape_json(&finding.file);
        assert_eq!(escaped_file, r"src\\path\\to\\file.rs");
    }

    #[test]
    fn test_json_format_escapes_quotes_in_secret() {
        let finding = create_test_finding(
            "test-rule",
            "Test Rule",
            "file.rs",
            1,
            1,
            r#"secret with "quotes""#,
        );
        let escaped_secret = escape_json(&finding.secret);
        assert_eq!(escaped_secret, r#"secret with \"quotes\""#);
    }

    #[test]
    fn test_json_format_escapes_newlines_in_content() {
        let ctx = ContextLine {
            line_num: 1,
            content: "line1\nline2".to_string(),
            is_match: false,
        };
        let escaped = escape_json(&ctx.content);
        assert_eq!(escaped, "line1\\nline2");
    }

    // ========================================================================
    // SARIF FORMAT TESTS
    // ========================================================================

    #[test]
    fn test_sarif_rule_id_escaped() {
        let finding = create_test_finding(
            "rule-with-\"special\"-chars",
            "Rule Name",
            "file.rs",
            1,
            1,
            "secret",
        );
        let escaped_rule = escape_json(&finding.rule_id);
        assert!(!escaped_rule.contains('"') || escaped_rule.contains("\\\""));
    }

    #[test]
    fn test_sarif_message_escaped() {
        let finding = create_test_finding(
            "test-rule",
            "Rule with \"quotes\" and\nnewlines",
            "file.rs",
            1,
            1,
            "secret",
        );
        let escaped_name = escape_json(&finding.rule_name);
        assert!(escaped_name.contains("\\\""));
        assert!(escaped_name.contains("\\n"));
    }

    // ========================================================================
    // REPORT FORMAT TESTS
    // ========================================================================

    #[test]
    fn test_report_severity_high_private_key() {
        let findings = vec![
            create_test_finding("rsa-private-key", "RSA Private Key", "file.pem", 1, 1, "***"),
        ];
        // High severity should be counted for private-key rule
        let high_count = findings
            .iter()
            .filter(|f| {
                f.rule_id.contains("private-key")
                    || f.rule_id.contains("aws")
                    || f.rule_id.contains("database")
                    || f.rule_id.contains("jwt")
            })
            .count();
        assert_eq!(high_count, 1);
    }

    #[test]
    fn test_report_severity_high_aws() {
        let findings = vec![
            create_test_finding("aws-access-key-id", "AWS Access Key", "config.yml", 1, 1, "AKIA***"),
        ];
        let high_count = findings
            .iter()
            .filter(|f| f.rule_id.contains("aws"))
            .count();
        assert_eq!(high_count, 1);
    }

    #[test]
    fn test_report_severity_medium_api_key() {
        let findings = vec![
            create_test_finding("generic-api-key", "Generic API Key", "file.env", 1, 1, "key***"),
        ];
        let medium_count = findings
            .iter()
            .filter(|f| {
                f.rule_id.contains("api-key")
                    || f.rule_id.contains("token")
                    || f.rule_id.contains("secret")
            })
            .count();
        assert_eq!(medium_count, 1);
    }

    #[test]
    fn test_report_category_extraction() {
        let findings = vec![
            create_test_finding("github-pat", "GitHub PAT", "file.rs", 1, 1, "ghp_***"),
            create_test_finding("github-fine-grained-pat", "GitHub Fine Grained", "file2.rs", 1, 1, "github_pat_***"),
            create_test_finding("aws-access-key-id", "AWS Key", "file3.rs", 1, 1, "AKIA***"),
        ];

        let mut category_counts: HashMap<String, usize> = HashMap::new();
        for finding in &findings {
            let category = finding
                .rule_id
                .split('-')
                .next()
                .unwrap_or("unknown")
                .to_string();
            *category_counts.entry(category).or_insert(0) += 1;
        }

        assert_eq!(category_counts.get("github"), Some(&2));
        assert_eq!(category_counts.get("aws"), Some(&1));
    }

    #[test]
    fn test_report_rule_counts() {
        let findings = vec![
            create_test_finding("github-pat", "GitHub PAT", "file1.rs", 1, 1, "ghp_1"),
            create_test_finding("github-pat", "GitHub PAT", "file2.rs", 2, 1, "ghp_2"),
            create_test_finding("aws-access-key-id", "AWS Key", "file3.rs", 1, 1, "AKIA1"),
        ];

        let mut rule_counts: HashMap<String, usize> = HashMap::new();
        for finding in &findings {
            *rule_counts.entry(finding.rule_id.clone()).or_insert(0) += 1;
        }

        assert_eq!(rule_counts.get("github-pat"), Some(&2));
        assert_eq!(rule_counts.get("aws-access-key-id"), Some(&1));
        assert_eq!(rule_counts.len(), 2);
    }

    // ========================================================================
    // EDGE CASE TESTS
    // ========================================================================

    #[test]
    fn test_empty_findings() {
        let findings: Vec<Finding> = vec![];
        assert!(findings.is_empty());
    }

    #[test]
    fn test_finding_with_empty_context() {
        let finding = create_test_finding(
            "test-rule",
            "Test",
            "file.rs",
            1,
            1,
            "secret",
        );
        assert!(finding.context.is_empty());
    }

    #[test]
    fn test_finding_with_unicode_secret() {
        let finding = create_test_finding(
            "test-rule",
            "Test",
            "file.rs",
            1,
            1,
            "secret_with_unicode_🔒_emoji",
        );
        let escaped = escape_json(&finding.secret);
        assert!(escaped.contains("🔒"));
    }

    #[test]
    fn test_finding_with_long_file_path() {
        let long_path = "a/".repeat(100) + "file.rs";
        let finding = create_test_finding(
            "test-rule",
            "Test",
            &long_path,
            1,
            1,
            "secret",
        );
        assert!(finding.file.len() > 200);
    }

    #[test]
    fn test_finding_at_line_zero() {
        // Edge case: line 0 (unusual but possible)
        let finding = create_test_finding(
            "test-rule",
            "Test",
            "file.rs",
            0,
            1,
            "secret",
        );
        assert_eq!(finding.line, 0);
    }

    #[test]
    fn test_finding_at_column_zero() {
        let finding = create_test_finding(
            "test-rule",
            "Test",
            "file.rs",
            1,
            0,
            "secret",
        );
        assert_eq!(finding.column, 0);
    }

    // ========================================================================
    // SPECIAL CHARACTER HANDLING TESTS
    // ========================================================================

    #[test]
    fn test_escape_json_all_special_chars() {
        let input = "\"\\/\n\r\t";
        let expected = "\\\"\\\\/\\n\\r\\t";
        assert_eq!(escape_json(input), expected);
    }

    #[test]
    fn test_escape_json_backslash_before_quote() {
        // Test that backslash before quote is handled correctly
        let input = r#"\"#;
        let expected = r"\\";
        assert_eq!(escape_json(input), expected);
    }

    #[test]
    fn test_escape_json_multiple_backslashes() {
        let input = r"\\\\";
        let expected = r"\\\\\\\\";
        assert_eq!(escape_json(input), expected);
    }

    #[test]
    fn test_escape_json_crlf() {
        let input = "line1\r\nline2";
        let expected = "line1\\r\\nline2";
        assert_eq!(escape_json(input), expected);
    }

    // ========================================================================
    // REDACTION IN OUTPUT TESTS
    // ========================================================================

    #[test]
    fn test_finding_redacted_secret_format() {
        // Test that redacted secrets follow expected pattern
        let finding = create_test_finding(
            "test-rule",
            "Test",
            "file.rs",
            1,
            1,
            "ghp_...xxxx",  // Typical redacted format
        );
        assert!(finding.secret.contains("..."));
    }

    #[test]
    fn test_context_with_redacted_content() {
        let context = vec![
            ContextLine {
                line_num: 1,
                content: "TOKEN=ghp_...xxxx".to_string(),
                is_match: true,
            },
        ];
        let finding = create_test_finding_with_context(
            "github-pat",
            "GitHub PAT",
            "file.env",
            1,
            7,
            "ghp_...xxxx",
            context,
        );
        assert!(finding.context[0].content.contains("..."));
    }

    // ========================================================================
    // OUTPUT FORMAT ENUM TESTS
    // ========================================================================

    #[test]
    fn test_output_format_text() {
        let format = OutputFormat::Text;
        assert!(matches!(format, OutputFormat::Text));
    }

    #[test]
    fn test_output_format_json() {
        let format = OutputFormat::Json;
        assert!(matches!(format, OutputFormat::Json));
    }

    #[test]
    fn test_output_format_sarif() {
        let format = OutputFormat::Sarif;
        assert!(matches!(format, OutputFormat::Sarif));
    }

    #[test]
    fn test_output_format_report() {
        let format = OutputFormat::Report;
        assert!(matches!(format, OutputFormat::Report));
    }

    #[test]
    fn test_output_format_copy() {
        let format1 = OutputFormat::Json;
        let format2 = format1; // Copy trait
        assert!(matches!(format2, OutputFormat::Json));
    }
}
