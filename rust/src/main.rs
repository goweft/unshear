// main.rs — CLI entrypoint.
//
// Mirrors the Python CLI exactly:
//   unshear compare <upstream> <fork> [--format human|json] [--no-color] [--min-score N]
//   unshear audit   <target>          [--format human|json] [--no-color]
//   unshear --version
//
// Exit codes:
//   0 — success (score >= min-score, or audit completed)
//   1 — I/O or argument error
//   2 — security score below --min-score threshold

mod engine;
mod output;
mod patterns;
mod report;
mod signals;

use std::io::{self, IsTerminal};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use engine::{audit, Config, ForkGuard};
use output::{format_audit_human, format_audit_json, format_human, format_json};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

#[derive(Parser)]
#[command(
    name = "unshear",
    version = VERSION,
    about = "AI agent fork divergence detector",
    long_about = "Compares a forked AI agent codebase against upstream to detect removed safety \
                  mechanisms, stripped security controls, and weakened guardrails.\n\n\
                  Born from the Claude Code source leak (2026-03-31), where 82,000+ forks \
                  stripped safety mechanisms within hours.",
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Compare fork against upstream
    Compare {
        /// Path to upstream/original codebase
        upstream: String,
        /// Path to forked codebase
        fork: String,
        /// Output format
        #[arg(short, long, value_enum, default_value = "human")]
        format: OutputFormat,
        /// Disable ANSI color output
        #[arg(long)]
        no_color: bool,
        /// Minimum security score to pass (0-100); exit code 2 if below
        #[arg(long, default_value = "50")]
        min_score: i32,
    },
    /// Audit a single codebase for security signal density
    Audit {
        /// Path to codebase to audit
        target: String,
        /// Output format
        #[arg(short, long, value_enum, default_value = "human")]
        format: OutputFormat,
        /// Disable ANSI color output
        #[arg(long)]
        no_color: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        None => {
            // No subcommand — print help (mirrors Python argparse behaviour).
            use clap::CommandFactory;
            Cli::command().print_help().ok();
            println!();
            ExitCode::SUCCESS
        }

        Some(Commands::Compare {
            upstream,
            fork,
            format,
            no_color,
            min_score,
        }) => {
            let config = Config::load_from_dir(std::path::Path::new(&fork));
            let guard = ForkGuard::new(config);
            let report = guard.analyze(&upstream, &fork);

            match format {
                OutputFormat::Json => {
                    println!("{}", format_json(&report));
                }
                OutputFormat::Human => {
                    let use_color = !no_color && io::stdout().is_terminal();
                    print!("{}", format_human(&report, use_color));
                }
            }

            if report.effective_score() < min_score {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            }
        }

        Some(Commands::Audit {
            target,
            format,
            no_color,
        }) => {
            let report = audit(&target);

            match format {
                OutputFormat::Json => {
                    println!("{}", format_audit_json(&report));
                }
                OutputFormat::Human => {
                    let use_color = !no_color && io::stdout().is_terminal();
                    print!("{}", format_audit_human(&report, use_color));
                }
            }

            ExitCode::SUCCESS
        }
    }
}
