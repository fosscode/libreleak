//! Output formatters
//!
//! Supports text, JSON, SARIF (for GitHub Actions), and report (for database storage) formats.

use crate::cli::OutputFormat;
use crate::scanner::Finding;
use std::collections::HashMap;
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

    for finding in findings {
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
                println!(
                    "    {} {:>4} {} {}\x1b[0m",
                    prefix,
                    ctx.line_num,
                    "|",
                    line_style.to_owned() + &ctx.content
                );
            }
        }
        println!();
    }
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
