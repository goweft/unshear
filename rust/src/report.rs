// report.rs — Data model: Severity, Finding, DivergenceReport, AuditReport
//
// Mirrors the Python dataclasses exactly:
//   class Severity(Enum)
//   @dataclass Finding
//   @dataclass DivergenceReport
//   audit_single() return dict
//
// JSON field names match the Python to_dict() output character-for-character
// so existing CI integrations and tooling remain valid.

use serde::Serialize;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// ── Severity ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    /// ANSI color code — matches Python Severity.color exactly.
    /// CRITICAL and HIGH both use \033[91m (bright red).
    /// MEDIUM uses \033[93m (bright yellow).
    /// LOW uses \033[96m (bright cyan).
    /// INFO uses \033[90m (dark grey).
    pub fn ansi_color(self) -> &'static str {
        match self {
            Severity::Critical | Severity::High => "\x1b[91m",
            Severity::Medium => "\x1b[93m",
            Severity::Low => "\x1b[96m",
            Severity::Info => "\x1b[90m",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }

    /// Icon used in human output: ✖ for CRITICAL/HIGH, ⚠ for MEDIUM, ℹ for rest.
    pub fn icon(self) -> &'static str {
        match self {
            Severity::Critical | Severity::High => "✖",
            Severity::Medium => "⚠",
            _ => "ℹ",
        }
    }

    /// Iteration order for output grouping (highest to lowest).
    pub fn all_descending() -> &'static [Severity] {
        &[
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ]
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

// ── Finding ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub file_path: String,
    pub message: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub detail: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub lines_removed: usize,
    #[serde(skip_serializing_if = "is_zero")]
    pub lines_added: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

impl Finding {
    pub fn new(
        rule_id: &str,
        severity: Severity,
        file_path: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            rule_id: rule_id.to_string(),
            severity,
            file_path: file_path.into(),
            message: message.into(),
            detail: String::new(),
            lines_removed: 0,
            lines_added: 0,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    pub fn with_lines(mut self, removed: usize, added: usize) -> Self {
        self.lines_removed = removed;
        self.lines_added = added;
        self
    }
}

// ── DivergenceReport ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct DivergenceReport {
    pub version: &'static str,
    pub upstream_path: String,
    pub fork_path: String,
    pub total_files_upstream: usize,
    pub total_files_fork: usize,
    pub files_removed: usize,
    pub files_added: usize,
    pub files_modified: usize,
    pub security_score: i32, // starts at 100, decremented; clamped to 0 in output
    pub findings_count: usize,
    pub findings: Vec<Finding>,
}

impl DivergenceReport {
    pub fn new(upstream_path: String, fork_path: String) -> Self {
        Self {
            version: VERSION,
            upstream_path,
            fork_path,
            total_files_upstream: 0,
            total_files_fork: 0,
            files_removed: 0,
            files_added: 0,
            files_modified: 0,
            security_score: 100,
            findings_count: 0,
            findings: Vec::new(),
        }
    }

    pub fn add_finding(&mut self, finding: Finding, score_deduction: i32) {
        self.security_score -= score_deduction;
        self.findings.push(finding);
        self.findings_count += 1;
    }

    /// Score clamped to [0, 100] for display.
    pub fn effective_score(&self) -> i32 {
        self.security_score.clamp(0, 100)
    }
}

// ── AuditReport ──────────────────────────────────────────────────────────────
// Mirrors the dict returned by audit_single() in the Python version.

#[derive(Debug, Serialize)]
pub struct AuditFile {
    pub path: String,
    pub is_security_filename: bool,
    pub signal_count: u32,
    pub signals: SignalSummary,
}

#[derive(Debug, Serialize)]
pub struct SignalSummary {
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub keyword_hits: u32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub code_patterns: Vec<PatternHit>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PatternHit {
    pub category: String,
    pub count: u32,
    pub description: String,
}

fn is_zero_u32(n: &u32) -> bool {
    *n == 0
}

#[derive(Debug, Serialize)]
pub struct AuditReport {
    pub path: String,
    pub total_files: usize,
    pub security_files: Vec<AuditFile>,
    pub total_security_signals: u32,
}
