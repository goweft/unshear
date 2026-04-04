// output.rs — Human-readable and JSON output formatters.
//
// Mirrors format_human() and format_json() in core.py exactly.
// ANSI escape sequences match the Python constants:
//   RESET = "\033[0m"   → \x1b[0m
//   BOLD  = "\033[1m"   → \x1b[1m   (only on the ═══ header line)
//   DIM   = "\033[2m"   → \x1b[2m   (detail lines, line counts)
//
// The box-drawing characters (┌ │ └ ─) and icons (✖ ⚠ ℹ) are identical
// to the Python output — the demo.svg depends on this.

use crate::report::{AuditReport, DivergenceReport, Severity};

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const SCORE_LOW: &str = "\x1b[92m"; // green  — 80-100
const SCORE_MOD: &str = "\x1b[93m"; // yellow — 50-79
const SCORE_HIGH: &str = "\x1b[91m"; // red    — 20-49 and 0-19

fn col<'a>(code: &'a str, text: &'a str, use_color: bool) -> String {
    if use_color {
        format!("{}{}{}", code, text, RESET)
    } else {
        text.to_string()
    }
}

fn dim(text: &str, use_color: bool) -> String {
    col(DIM, text, use_color)
}

const RULE_LINE: &str = "────────────────────────────────────────────────────────────";

// ── Compare report ────────────────────────────────────────────────────────────

pub fn format_human(report: &DivergenceReport, use_color: bool) -> String {
    let mut lines: Vec<String> = Vec::new();

    lines.push(String::new());
    lines.push(col(BOLD, "═══ unshear divergence report ═══", use_color));
    lines.push(format!("  Upstream: {}", report.upstream_path));
    lines.push(format!("  Fork:     {}", report.fork_path));
    lines.push(format!("  Files upstream: {}", report.total_files_upstream));
    lines.push(format!("  Files in fork:  {}", report.total_files_fork));
    lines.push(format!(
        "  Removed: {}  Added: {}  Modified: {}",
        report.files_removed, report.files_added, report.files_modified
    ));
    lines.push(String::new());

    let score = report.effective_score();
    let (score_color, score_label) = match score {
        80..=100 => (SCORE_LOW, "LOW RISK"),
        50..=79 => (SCORE_MOD, "MODERATE RISK"),
        20..=49 => (SCORE_HIGH, "HIGH RISK"),
        _ => (SCORE_HIGH, "CRITICAL RISK"),
    };
    // CRITICAL RISK: bold + red, same as Python's "\033[91m\033[1m"
    let score_str = format!("  Security Score: {}/100 \u{2014} {}", score, score_label);
    if !use_color {
        lines.push(score_str);
    } else if score < 20 {
        lines.push(format!("{}{}{}{}", score_color, BOLD, score_str, RESET));
    } else {
        lines.push(col(score_color, &score_str, use_color));
    }
    lines.push(String::new());

    if report.findings.is_empty() {
        lines.push(col(
            "\x1b[92m",
            "  \u{2713} No security-relevant divergence detected.",
            use_color,
        ));
        lines.push(String::new());
        return lines.join("\n");
    }

    // Group findings by severity, descending.
    for &sev in Severity::all_descending() {
        let group: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == sev)
            .collect();
        if group.is_empty() {
            continue;
        }
        let sev_color = sev.ansi_color();
        let header = format!("  \u{250c}\u{2500} {} ({})", sev.label(), group.len());
        lines.push(col(sev_color, &header, use_color));

        for f in &group {
            let icon_line = format!("  \u{2502} {} [{}] {}", sev.icon(), f.rule_id, f.file_path);
            lines.push(col(sev_color, &icon_line, use_color));
            lines.push(format!("  \u{2502}   {}", f.message));
            if !f.detail.is_empty() {
                lines.push(dim(&format!("  \u{2502}   {}", f.detail), use_color));
            }
            if f.lines_removed > 0 || f.lines_added > 0 {
                lines.push(dim(
                    &format!(
                        "  \u{2502}   -{} / +{} lines",
                        f.lines_removed, f.lines_added
                    ),
                    use_color,
                ));
            }
        }
        lines.push(format!("  \u{2514}{}", RULE_LINE));
        lines.push(String::new());
    }

    lines.push(String::new());
    lines.join("\n")
}

pub fn format_json(report: &DivergenceReport) -> String {
    serde_json::to_string_pretty(report).expect("DivergenceReport is always serializable")
}

// ── Audit report ──────────────────────────────────────────────────────────────

pub fn format_audit_human(report: &AuditReport, use_color: bool) -> String {
    let mut lines: Vec<String> = Vec::new();

    lines.push(String::new());
    lines.push(col(BOLD, "═══ unshear security audit ═══", use_color));
    lines.push(format!("  Path: {}", report.path));
    lines.push(format!("  Total files: {}", report.total_files));
    lines.push(format!(
        "  Security-relevant files: {}",
        report.security_files.len()
    ));
    lines.push(format!(
        "  Total security signals: {}",
        report.total_security_signals
    ));
    lines.push(String::new());

    if !report.security_files.is_empty() {
        lines.push("  Top security-critical files:".to_string());
        for sf in report.security_files.iter().take(20) {
            let marker = if sf.is_security_filename {
                " [filename match]"
            } else {
                ""
            };
            lines.push(format!(
                "    {:4} signals  {}{}",
                sf.signal_count, sf.path, marker
            ));
        }
    }
    lines.push(String::new());
    lines.join("\n")
}

pub fn format_audit_json(report: &AuditReport) -> String {
    serde_json::to_string_pretty(report).expect("AuditReport is always serializable")
}

// ── Score label helper (used in tests) ───────────────────────────────────────

#[allow(dead_code)]
pub fn score_label(score: i32) -> &'static str {
    match score.clamp(0, 100) {
        80..=100 => "LOW RISK",
        50..=79 => "MODERATE RISK",
        20..=49 => "HIGH RISK",
        _ => "CRITICAL RISK",
    }
}
