//! Command-line argument parsing
//!
//! Hand-rolled for zero dependencies - full control over behavior.

use std::env;

#[allow(dead_code)]
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

pub enum Target {
    Path(String),
    GitRepo(String),
}

#[derive(Clone, Copy)]
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
