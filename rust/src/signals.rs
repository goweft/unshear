// signals.rs — Security signal detection on byte content.
//
// Mirrors core.py:
//   count_security_signals(content: bytes) -> dict
//   is_binary(content: bytes) -> bool
//
// Returns structured SignalCount instead of a Python dict, but the
// JSON serialization (via report::SignalSummary) produces identical output.

use crate::patterns;
use crate::report::{PatternHit, SignalSummary};

// ── Binary detection ──────────────────────────────────────────────────────────
// Python: b"\x00" in content[:8192]

pub fn is_binary(content: &[u8]) -> bool {
    content[..content.len().min(8192)].contains(&0u8)
}

// ── Signal counting ───────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct SignalCount {
    pub keyword_hits: u32,
    pub code_patterns: Vec<PatternHit>,
}

impl SignalCount {
    pub fn total(&self) -> u32 {
        self.keyword_hits + self.code_patterns.iter().map(|p| p.count).sum::<u32>()
    }

    pub fn is_empty(&self) -> bool {
        self.keyword_hits == 0 && self.code_patterns.is_empty()
    }

    pub fn has_signals(&self) -> bool {
        self.keyword_hits > 2 || !self.code_patterns.is_empty()
    }

    pub fn to_summary(&self) -> SignalSummary {
        SignalSummary {
            keyword_hits: self.keyword_hits,
            code_patterns: self.code_patterns.clone(),
        }
    }

    /// Produce the summary detail string used in Finding::detail.
    /// Mirrors ForkGuard._summarize_signals() in Python.
    pub fn summarize(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if self.keyword_hits > 0 {
            parts.push(format!("{} security keyword hits", self.keyword_hits));
        }
        if !self.code_patterns.is_empty() {
            let cats: Vec<String> = self
                .code_patterns
                .iter()
                .map(|p| format!("{} ({}x)", p.description, p.count))
                .collect();
            parts.push(cats.join("; "));
        }
        parts.join(". ")
    }
}

/// Count all security signals in raw byte content.
/// Mirrors count_security_signals() in Python exactly.
pub fn count_security_signals(content: &[u8]) -> SignalCount {
    let mut result = SignalCount::default();

    if content.is_empty() {
        return result;
    }

    // Keyword hits — single compiled regex alternation, count all matches.
    result.keyword_hits = patterns::count_keyword_hits(content);

    // Code pattern hits — iterate compiled pattern table.
    for cp in patterns::code_patterns() {
        let count = cp.regex.find_iter(content).count() as u32;
        if count > 0 {
            result.code_patterns.push(PatternHit {
                category: cp.category.to_string(),
                count,
                description: cp.description.to_string(),
            });
        }
    }

    result
}
