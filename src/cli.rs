//! Command-line argument parsing
//!
//! Hand-rolled for zero dependencies - full control over behavior.

use std::env;

#[allow(dead_code)]
#[derive(Debug)]
pub struct Args {
    pub target: Target,
    pub format: OutputFormat,
    pub fail_on_leak: bool,
    pub show_context: bool,
    pub context_lines: usize,
    pub no_redact: bool,
    pub rules_only: Vec<String>,
    pub rules_exclude: Vec<String>,
    pub verify_secrets: bool,
}

#[derive(Debug)]
pub enum Target {
    Path(String),
    GitRepo(String),
}

#[derive(Clone, Copy, Debug)]
pub enum OutputFormat {
    Text,
    Json,
    Sarif,
    Report, // Enhanced format for database storage and research
}

pub fn parse_args() -> Args {
    let args: Vec<String> = env::args().collect();

    let mut target = None;
    let mut format = OutputFormat::Text;
    let mut fail_on_leak = false;
    let mut show_context = true;
    let mut context_lines = 3;
    let mut no_redact = false;
    let mut rules_only = Vec::new();
    let mut rules_exclude = Vec::new();
    let mut verify_secrets = false;

    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "-v" | "--version" => {
                println!("libreleak {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "-f" | "--format" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --format requires a value");
                    std::process::exit(1);
                }
                format = match args[i].as_str() {
                    "text" => OutputFormat::Text,
                    "json" => OutputFormat::Json,
                    "sarif" => OutputFormat::Sarif,
                    "report" => OutputFormat::Report,
                    other => {
                        eprintln!("error: unknown format '{other}'");
                        std::process::exit(1);
                    }
                };
            }
            "--fail-on-leak" | "-x" => {
                fail_on_leak = true;
            }
            "--no-context" => {
                show_context = false;
            }
            "-C" | "--context" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --context requires a number");
                    std::process::exit(1);
                }
                context_lines = args[i].parse().unwrap_or_else(|_| {
                    eprintln!("error: --context requires a valid number");
                    std::process::exit(1);
                });
            }
            "--no-redact" => {
                no_redact = true;
            }
            "--verify" | "-V" => {
                verify_secrets = true;
            }
            "--only" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --only requires rule IDs");
                    std::process::exit(1);
                }
                rules_only.extend(args[i].split(',').map(|s| s.trim().to_string()));
            }
            "--exclude" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --exclude requires rule IDs");
                    std::process::exit(1);
                }
                rules_exclude.extend(args[i].split(',').map(|s| s.trim().to_string()));
            }
            "--list-rules" => {
                list_rules();
                std::process::exit(0);
            }
            arg if arg.starts_with('-') => {
                eprintln!("error: unknown option '{arg}'");
                eprintln!("Run 'libreleak --help' for usage");
                std::process::exit(1);
            }
            arg => {
                target = Some(arg.to_string());
            }
        }
        i += 1;
    }

    let target = match target {
        Some(t)
            if t.starts_with("http://")
                || t.starts_with("https://")
                || t.starts_with("git@")
                || t.starts_with("ssh://") =>
        {
            Target::GitRepo(t)
        }
        Some(t) => Target::Path(t),
        None => Target::Path(".".to_string()),
    };

    Args {
        target,
        format,
        fail_on_leak,
        show_context,
        context_lines,
        no_redact,
        rules_only,
        rules_exclude,
        verify_secrets,
    }
}

fn print_help() {
    println!(
        r#"libreleak - fast, offline secret scanner

USAGE:
    libreleak [OPTIONS] [TARGET]

ARGS:
    TARGET    Path or git URL to scan (default: current directory)

OPTIONS:
    -f, --format <FMT>   Output format: text, json, sarif, report [default: text]
                         - text:   Human-readable colored output
                         - json:   Simple JSON for programmatic use
                         - sarif:  GitHub Advanced Security format
                         - report: Enhanced JSON for database storage/research
    -x, --fail-on-leak   Exit with code 1 if secrets found (for CI)
    -C, --context <N>    Lines of context to show [default: 3]
    --no-context         Don't show surrounding lines
    --no-redact          Show full secrets (use with caution!)

    --only <RULES>       Only use specific rules (comma-separated IDs)
    --exclude <RULES>    Exclude specific rules (comma-separated IDs)
    --list-rules         List all available detection rules
    -V, --verify         Verify secrets against provider APIs (requires --features verify)

    -h, --help           Print help
    -v, --version        Print version

EXAMPLES:
    libreleak                          # Scan current directory
    libreleak ./src                    # Scan specific path
    libreleak https://github.com/x/y   # Clone and scan repo
    libreleak -f sarif -x .            # SARIF output, fail on leak (CI)
    libreleak -f report . > scan.json  # Database-ready report
    libreleak --only aws-access-key-id,github-pat .

PRIVACY:
    libreleak is fully offline. No telemetry, no network calls except
    when explicitly cloning a git repository. Your secrets stay local."#
    );
}

fn list_rules() {
    let rules = crate::rules::builtin_rules();
    println!("Available detection rules:\n");
    println!("{:<30} NAME", "ID");
    println!("{}", "-".repeat(60));
    for rule in rules {
        println!("{:<30} {}", rule.id, rule.name);
    }
}

/// Parse arguments from an iterator (for testing)
/// Returns None if help/version/list-rules was requested (they call exit)
#[allow(dead_code)]
pub fn parse_args_from<I, S>(args: I) -> Result<Args, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args: Vec<String> = args.into_iter().map(|s| s.as_ref().to_string()).collect();

    let mut target = None;
    let mut format = OutputFormat::Text;
    let mut fail_on_leak = false;
    let mut show_context = true;
    let mut context_lines = 3;
    let mut no_redact = false;
    let mut rules_only = Vec::new();
    let mut rules_exclude = Vec::new();
    let mut verify_secrets = false;

    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                return Err("help".to_string());
            }
            "-v" | "--version" => {
                return Err("version".to_string());
            }
            "-f" | "--format" => {
                i += 1;
                if i >= args.len() {
                    return Err("error: --format requires a value".to_string());
                }
                format = match args[i].as_str() {
                    "text" => OutputFormat::Text,
                    "json" => OutputFormat::Json,
                    "sarif" => OutputFormat::Sarif,
                    "report" => OutputFormat::Report,
                    other => {
                        return Err(format!("error: unknown format '{other}'"));
                    }
                };
            }
            "--fail-on-leak" | "-x" => {
                fail_on_leak = true;
            }
            "--no-context" => {
                show_context = false;
            }
            "-C" | "--context" => {
                i += 1;
                if i >= args.len() {
                    return Err("error: --context requires a number".to_string());
                }
                context_lines = args[i]
                    .parse()
                    .map_err(|_| "error: --context requires a valid number".to_string())?;
            }
            "--no-redact" => {
                no_redact = true;
            }
            "--verify" | "-V" => {
                verify_secrets = true;
            }
            "--only" => {
                i += 1;
                if i >= args.len() {
                    return Err("error: --only requires rule IDs".to_string());
                }
                rules_only.extend(args[i].split(',').map(|s| s.trim().to_string()));
            }
            "--exclude" => {
                i += 1;
                if i >= args.len() {
                    return Err("error: --exclude requires rule IDs".to_string());
                }
                rules_exclude.extend(args[i].split(',').map(|s| s.trim().to_string()));
            }
            "--list-rules" => {
                return Err("list-rules".to_string());
            }
            arg if arg.starts_with('-') => {
                return Err(format!("error: unknown option '{arg}'"));
            }
            arg => {
                target = Some(arg.to_string());
            }
        }
        i += 1;
    }

    let target = match target {
        Some(t)
            if t.starts_with("http://")
                || t.starts_with("https://")
                || t.starts_with("git@")
                || t.starts_with("ssh://") =>
        {
            Target::GitRepo(t)
        }
        Some(t) => Target::Path(t),
        None => Target::Path(".".to_string()),
    };

    Ok(Args {
        target,
        format,
        fail_on_leak,
        show_context,
        context_lines,
        no_redact,
        rules_only,
        rules_exclude,
        verify_secrets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create args from string slice
    fn parse(args: &[&str]) -> Result<Args, String> {
        parse_args_from(args.iter())
    }

    // =========================================
    // Default argument values
    // =========================================

    #[test]
    fn test_default_values_no_args() {
        let args = parse(&[]).unwrap();
        assert!(matches!(args.target, Target::Path(ref p) if p == "."));
        assert!(matches!(args.format, OutputFormat::Text));
        assert!(!args.fail_on_leak);
        assert!(args.show_context);
        assert_eq!(args.context_lines, 3);
        assert!(!args.no_redact);
        assert!(args.rules_only.is_empty());
        assert!(args.rules_exclude.is_empty());
        assert!(!args.verify_secrets);
    }

    #[test]
    fn test_default_format_is_text() {
        let args = parse(&["./src"]).unwrap();
        assert!(matches!(args.format, OutputFormat::Text));
    }

    #[test]
    fn test_default_context_lines() {
        let args = parse(&[]).unwrap();
        assert_eq!(args.context_lines, 3);
    }

    // =========================================
    // Target parsing
    // =========================================

    #[test]
    fn test_target_path() {
        let args = parse(&["./src/main.rs"]).unwrap();
        assert!(matches!(args.target, Target::Path(ref p) if p == "./src/main.rs"));
    }

    #[test]
    fn test_target_https_git_url() {
        let args = parse(&["https://github.com/user/repo"]).unwrap();
        assert!(
            matches!(args.target, Target::GitRepo(ref u) if u == "https://github.com/user/repo")
        );
    }

    #[test]
    fn test_target_http_git_url() {
        let args = parse(&["http://github.com/user/repo"]).unwrap();
        assert!(
            matches!(args.target, Target::GitRepo(ref u) if u == "http://github.com/user/repo")
        );
    }

    #[test]
    fn test_target_ssh_git_url() {
        let args = parse(&["git@github.com:user/repo.git"]).unwrap();
        assert!(
            matches!(args.target, Target::GitRepo(ref u) if u == "git@github.com:user/repo.git")
        );
    }

    #[test]
    fn test_target_ssh_protocol_url() {
        let args = parse(&["ssh://git@github.com/user/repo.git"]).unwrap();
        assert!(
            matches!(args.target, Target::GitRepo(ref u) if u == "ssh://git@github.com/user/repo.git")
        );
    }

    // =========================================
    // Output format parsing
    // =========================================

    #[test]
    fn test_format_text_short() {
        let args = parse(&["-f", "text"]).unwrap();
        assert!(matches!(args.format, OutputFormat::Text));
    }

    #[test]
    fn test_format_text_long() {
        let args = parse(&["--format", "text"]).unwrap();
        assert!(matches!(args.format, OutputFormat::Text));
    }

    #[test]
    fn test_format_json() {
        let args = parse(&["-f", "json"]).unwrap();
        assert!(matches!(args.format, OutputFormat::Json));
    }

    #[test]
    fn test_format_sarif() {
        let args = parse(&["-f", "sarif"]).unwrap();
        assert!(matches!(args.format, OutputFormat::Sarif));
    }

    #[test]
    fn test_format_report() {
        let args = parse(&["--format", "report"]).unwrap();
        assert!(matches!(args.format, OutputFormat::Report));
    }

    #[test]
    fn test_format_unknown_error() {
        let result = parse(&["-f", "xml"]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown format 'xml'"));
    }

    #[test]
    fn test_format_missing_value() {
        let result = parse(&["-f"]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("--format requires a value"));
    }

    // =========================================
    // Boolean flags
    // =========================================

    #[test]
    fn test_fail_on_leak_short() {
        let args = parse(&["-x"]).unwrap();
        assert!(args.fail_on_leak);
    }

    #[test]
    fn test_fail_on_leak_long() {
        let args = parse(&["--fail-on-leak"]).unwrap();
        assert!(args.fail_on_leak);
    }

    #[test]
    fn test_no_context() {
        let args = parse(&["--no-context"]).unwrap();
        assert!(!args.show_context);
    }

    #[test]
    fn test_no_redact() {
        let args = parse(&["--no-redact"]).unwrap();
        assert!(args.no_redact);
    }

    #[test]
    fn test_verify_short() {
        let args = parse(&["-V"]).unwrap();
        assert!(args.verify_secrets);
    }

    #[test]
    fn test_verify_long() {
        let args = parse(&["--verify"]).unwrap();
        assert!(args.verify_secrets);
    }

    // =========================================
    // Context lines
    // =========================================

    #[test]
    fn test_context_short() {
        let args = parse(&["-C", "5"]).unwrap();
        assert_eq!(args.context_lines, 5);
    }

    #[test]
    fn test_context_long() {
        let args = parse(&["--context", "10"]).unwrap();
        assert_eq!(args.context_lines, 10);
    }

    #[test]
    fn test_context_zero() {
        let args = parse(&["-C", "0"]).unwrap();
        assert_eq!(args.context_lines, 0);
    }

    #[test]
    fn test_context_missing_value() {
        let result = parse(&["-C"]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("--context requires a number"));
    }

    #[test]
    fn test_context_invalid_value() {
        let result = parse(&["-C", "abc"]);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("--context requires a valid number"));
    }

    // =========================================
    // Rule filtering
    // =========================================

    #[test]
    fn test_only_single_rule() {
        let args = parse(&["--only", "aws-access-key-id"]).unwrap();
        assert_eq!(args.rules_only, vec!["aws-access-key-id"]);
    }

    #[test]
    fn test_only_multiple_rules() {
        let args = parse(&["--only", "aws-access-key-id,github-pat,slack-token"]).unwrap();
        assert_eq!(
            args.rules_only,
            vec!["aws-access-key-id", "github-pat", "slack-token"]
        );
    }

    #[test]
    fn test_only_with_spaces() {
        let args = parse(&["--only", "aws-access-key-id, github-pat"]).unwrap();
        assert_eq!(args.rules_only, vec!["aws-access-key-id", "github-pat"]);
    }

    #[test]
    fn test_only_missing_value() {
        let result = parse(&["--only"]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("--only requires rule IDs"));
    }

    #[test]
    fn test_exclude_single_rule() {
        let args = parse(&["--exclude", "generic-api-key"]).unwrap();
        assert_eq!(args.rules_exclude, vec!["generic-api-key"]);
    }

    #[test]
    fn test_exclude_multiple_rules() {
        let args = parse(&["--exclude", "generic-api-key,generic-secret"]).unwrap();
        assert_eq!(
            args.rules_exclude,
            vec!["generic-api-key", "generic-secret"]
        );
    }

    #[test]
    fn test_exclude_missing_value() {
        let result = parse(&["--exclude"]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("--exclude requires rule IDs"));
    }

    // =========================================
    // Special commands (help, version, list-rules)
    // =========================================

    #[test]
    fn test_help_short() {
        let result = parse(&["-h"]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "help");
    }

    #[test]
    fn test_help_long() {
        let result = parse(&["--help"]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "help");
    }

    #[test]
    fn test_version_short() {
        let result = parse(&["-v"]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "version");
    }

    #[test]
    fn test_version_long() {
        let result = parse(&["--version"]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "version");
    }

    #[test]
    fn test_list_rules() {
        let result = parse(&["--list-rules"]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "list-rules");
    }

    // =========================================
    // Unknown options
    // =========================================

    #[test]
    fn test_unknown_option_short() {
        let result = parse(&["-z"]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown option '-z'"));
    }

    #[test]
    fn test_unknown_option_long() {
        let result = parse(&["--unknown-flag"]);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("unknown option '--unknown-flag'"));
    }

    // =========================================
    // Flag combinations
    // =========================================

    #[test]
    fn test_ci_typical_usage() {
        let args = parse(&["-f", "sarif", "-x", "."]).unwrap();
        assert!(matches!(args.format, OutputFormat::Sarif));
        assert!(args.fail_on_leak);
        assert!(matches!(args.target, Target::Path(ref p) if p == "."));
    }

    #[test]
    fn test_multiple_flags_combined() {
        let args = parse(&[
            "--format",
            "json",
            "--fail-on-leak",
            "--no-context",
            "--no-redact",
            "--verify",
            "./src",
        ])
        .unwrap();
        assert!(matches!(args.format, OutputFormat::Json));
        assert!(args.fail_on_leak);
        assert!(!args.show_context);
        assert!(args.no_redact);
        assert!(args.verify_secrets);
        assert!(matches!(args.target, Target::Path(ref p) if p == "./src"));
    }

    #[test]
    fn test_only_and_exclude_together() {
        let args = parse(&["--only", "aws-access-key-id", "--exclude", "generic-secret"]).unwrap();
        assert_eq!(args.rules_only, vec!["aws-access-key-id"]);
        assert_eq!(args.rules_exclude, vec!["generic-secret"]);
    }

    #[test]
    fn test_context_with_no_context_overrides() {
        // Last flag wins - no-context after -C should disable context
        let args = parse(&["-C", "5", "--no-context"]).unwrap();
        assert!(!args.show_context);
        assert_eq!(args.context_lines, 5); // context_lines is still set but show_context is false
    }

    #[test]
    fn test_format_before_target() {
        let args = parse(&["-f", "json", "https://github.com/user/repo"]).unwrap();
        assert!(matches!(args.format, OutputFormat::Json));
        assert!(
            matches!(args.target, Target::GitRepo(ref u) if u == "https://github.com/user/repo")
        );
    }

    #[test]
    fn test_target_between_flags() {
        let args = parse(&["-f", "json", "./src", "-x"]).unwrap();
        assert!(matches!(args.format, OutputFormat::Json));
        assert!(matches!(args.target, Target::Path(ref p) if p == "./src"));
        assert!(args.fail_on_leak);
    }

    // =========================================
    // OutputFormat enum
    // =========================================

    #[test]
    fn test_output_format_is_copy() {
        let format = OutputFormat::Json;
        let copy = format;
        // If this compiles, OutputFormat implements Copy
        assert!(matches!(format, OutputFormat::Json));
        assert!(matches!(copy, OutputFormat::Json));
    }

    #[test]
    fn test_output_format_is_clone() {
        let format = OutputFormat::Sarif;
        let cloned = format.clone();
        assert!(matches!(cloned, OutputFormat::Sarif));
    }

    // =========================================
    // Edge cases
    // =========================================

    #[test]
    fn test_path_starting_with_dash() {
        // Paths starting with dash are treated as unknown options
        let result = parse(&["-path"]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown option"));
    }

    #[test]
    fn test_empty_format_value() {
        let result = parse(&["-f", ""]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown format ''"));
    }

    #[test]
    fn test_multiple_targets_last_wins() {
        let args = parse(&["./first", "./second", "./third"]).unwrap();
        assert!(matches!(args.target, Target::Path(ref p) if p == "./third"));
    }

    #[test]
    fn test_help_takes_precedence() {
        // Help flag should return early even with other args
        let result = parse(&["-f", "json", "--help", "./src"]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "help");
    }
}
