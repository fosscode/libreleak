//! libreleak - fast, offline secret scanner
//!
//! Zero runtime dependencies for full auditability and control.
//! No telemetry, no network calls except when explicitly cloning repos.

mod cli;
mod git;
mod output;
mod rules;
mod scanner;
mod verify;

fn main() {
    let args = cli::parse_args();

    if let Err(e) = run(args) {
        eprintln!("\x1b[1;31merror:\x1b[0m {e}");
        std::process::exit(1);
    }
}

fn run(args: cli::Args) -> Result<(), Box<dyn std::error::Error>> {
    let mut rules = rules::load_rules()?;

    // Filter rules if specified
    if !args.rules_only.is_empty() {
        rules.retain(|r| args.rules_only.iter().any(|id| r.id == id));
    }
    if !args.rules_exclude.is_empty() {
        rules.retain(|r| !args.rules_exclude.iter().any(|id| r.id == id));
    }

    if rules.is_empty() {
        return Err("No rules selected - check your --only/--exclude filters".into());
    }

    let scanner = scanner::Scanner::new(rules).with_context(args.context_lines);

    let mut findings = match &args.target {
        cli::Target::Path(path) => scanner.scan_path(path)?,
        cli::Target::GitRepo(url) => scanner.scan_git_repo(url)?,
    };

    // Verify secrets if requested
    if args.verify_secrets {
        #[cfg(feature = "verify")]
        {
            for finding in &mut findings {
                let result = crate::verify::verify_secret(finding);
                finding.verification_status = Some(result);
            }
        }
        #[cfg(not(feature = "verify"))]
        {
            eprintln!("Warning: --verify requires compiling with --features verify");
        }
    }

    output::print_findings(&findings, args.format, args.show_context);

    if !findings.is_empty() && args.fail_on_leak {
        std::process::exit(1);
    }

    Ok(())
}
