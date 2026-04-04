// engine.rs — Core analysis engine.
//
// Mirrors ForkGuard and audit_single() in core.py.
//
// Two modes:
//   analyze(upstream, fork)  → DivergenceReport  (compare mode)
//   audit(target)            → AuditReport        (audit mode)
//
// Detection rules and score deductions are identical to Python:
//   FORK-001 CRITICAL -15   security-critical file removed (filename match AND signals)
//   FORK-002 HIGH     -8    security-relevant file removed (filename OR signals)
//   FORK-003 CRITICAL -12   major security logic removed (net_loss > 10)
//   FORK-004 HIGH     -6    security logic weakened (net_loss > 3)
//   FORK-005 HIGH     -5    weakening pattern introduced in modified file
//   FORK-006 MEDIUM   -3    weakening pattern in added file
//   FORK-007 HIGH     -5    regex patterns removed from security file (net > 3)
//   FORK-008 HIGH     -8    security file gutted (>20 lines removed, <30% added back)

use std::collections::{HashMap, HashSet};
use std::path::Path;

use walkdir::WalkDir;

use crate::patterns::{self, count_regex_patterns, is_security_file, should_ignore};
use crate::report::{AuditFile, AuditReport, DivergenceReport, Finding, Severity};
use crate::signals::{count_security_signals, is_binary};

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, serde::Deserialize)]
#[allow(dead_code)]
pub struct Config {
    #[serde(default)]
    pub ignore_patterns: Vec<String>,
    #[serde(default)]
    pub extra_security_keywords: Vec<String>,
    #[serde(default)]
    pub security_score_weights: HashMap<String, i32>,
}

impl Config {
    pub fn load_from_dir(dir: &Path) -> Self {
        let config_path = dir.join(".unshear.json");
        if let Ok(content) = std::fs::read_to_string(&config_path) {
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            Config::default()
        }
    }
}

// ── File collection ───────────────────────────────────────────────────────────

fn collect_files(root: &Path) -> HashMap<String, Vec<u8>> {
    let mut files = HashMap::new();
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let rel = match entry.path().strip_prefix(root) {
            Ok(r) => r.to_string_lossy().replace('\\', "/"),
            Err(_) => continue,
        };
        if should_ignore(&rel) {
            continue;
        }
        if let Ok(content) = std::fs::read(entry.path()) {
            files.insert(rel, content);
        }
    }
    files
}

// ── Diff analysis ─────────────────────────────────────────────────────────────

struct DiffResult {
    removed_lines: Vec<String>,
    added_lines: Vec<String>,
}

fn compute_diff(up_content: &[u8], fk_content: &[u8]) -> Option<DiffResult> {
    let up_str = String::from_utf8_lossy(up_content);
    let fk_str = String::from_utf8_lossy(fk_content);

    let diff = similar::TextDiff::from_lines(up_str.as_ref(), fk_str.as_ref());

    let mut removed_lines = Vec::new();
    let mut added_lines = Vec::new();

    for change in diff.iter_all_changes() {
        match change.tag() {
            similar::ChangeTag::Delete => {
                removed_lines.push(change.to_string_lossy().into_owned());
            }
            similar::ChangeTag::Insert => {
                added_lines.push(change.to_string_lossy().into_owned());
            }
            similar::ChangeTag::Equal => {}
        }
    }

    if removed_lines.is_empty() && added_lines.is_empty() {
        None
    } else {
        Some(DiffResult {
            removed_lines,
            added_lines,
        })
    }
}

// ── Modified-file analysis ────────────────────────────────────────────────────
// Mirrors ForkGuard._analyze_diff() — appends findings to report in place.

fn analyze_diff(
    report: &mut DivergenceReport,
    rel_path: &str,
    up_content: &[u8],
    fk_content: &[u8],
) {
    let diff = match compute_diff(up_content, fk_content) {
        Some(d) => d,
        None => return,
    };

    let removed_bytes = diff.removed_lines.join("").into_bytes();
    let added_bytes = diff.added_lines.join("").into_bytes();

    let removed_signals = count_security_signals(&removed_bytes);
    let added_signals = count_security_signals(&added_bytes);

    let removed_total = removed_signals.total();
    let added_total = added_signals.total();
    let net_loss = removed_total as i32 - added_total as i32;

    let n_removed = diff.removed_lines.len();
    let n_added = diff.added_lines.len();

    // FORK-003 / FORK-004 — signal delta
    if net_loss > 10 {
        report.add_finding(
            Finding::new(
                "FORK-003",
                Severity::Critical,
                rel_path,
                format!(
                    "Major security logic removed ({} signals removed, {} added)",
                    removed_total, added_total
                ),
            )
            .with_detail(removed_signals.summarize())
            .with_lines(n_removed, n_added),
            12,
        );
    } else if net_loss > 3 {
        report.add_finding(
            Finding::new(
                "FORK-004",
                Severity::High,
                rel_path,
                format!(
                    "Security logic weakened ({} signals removed, {} added)",
                    removed_total, added_total
                ),
            )
            .with_detail(removed_signals.summarize())
            .with_lines(n_removed, n_added),
            6,
        );
    }

    // FORK-005 — weakening patterns introduced in added code that weren't in removed code
    for wp in patterns::weakening_patterns() {
        let in_added = !wp
            .regex
            .find_iter(&added_bytes)
            .collect::<Vec<_>>()
            .is_empty();
        let in_removed = !wp
            .regex
            .find_iter(&removed_bytes)
            .collect::<Vec<_>>()
            .is_empty();
        if in_added && !in_removed {
            report.add_finding(
                Finding::new(
                    "FORK-005",
                    Severity::High,
                    rel_path,
                    format!("Weakening pattern introduced: {}", wp.description),
                )
                .with_lines(n_removed, n_added),
                5,
            );
        }
    }

    // FORK-007 — regex patterns removed from security file
    if is_security_file(rel_path) {
        let removed_regex = count_regex_patterns(&removed_bytes);
        let added_regex = count_regex_patterns(&added_bytes);
        let regex_net_loss = removed_regex as i32 - added_regex as i32;
        if regex_net_loss > 3 {
            report.add_finding(
                Finding::new(
                    "FORK-007",
                    Severity::High,
                    rel_path,
                    format!(
                        "Regex patterns removed from security file ({} net removed)",
                        regex_net_loss
                    ),
                )
                .with_detail(
                    "Regex removal from security files often indicates content filter stripping"
                        .to_string(),
                ),
                5,
            );
        }
    }

    // FORK-008 — security file gutted (>20 lines removed, <30% added back)
    if is_security_file(rel_path) && n_removed > 20 && (n_added as f64) < (n_removed as f64) * 0.3 {
        report.add_finding(
            Finding::new(
                "FORK-008",
                Severity::High,
                rel_path,
                format!(
                    "Security file gutted: {} lines removed, only {} added",
                    n_removed, n_added
                ),
            )
            .with_lines(n_removed, n_added),
            8,
        );
    }
}

// ── ForkGuard ─────────────────────────────────────────────────────────────────

pub struct ForkGuard {
    _config: Config,
}

impl ForkGuard {
    pub fn new(config: Config) -> Self {
        Self { _config: config }
    }

    pub fn analyze(&self, upstream_path: &str, fork_path: &str) -> DivergenceReport {
        let upstream_root = Path::new(upstream_path);
        let fork_root = Path::new(fork_path);

        let mut report = DivergenceReport::new(upstream_path.to_string(), fork_path.to_string());

        let upstream_files = collect_files(upstream_root);
        let fork_files = collect_files(fork_root);

        report.total_files_upstream = upstream_files.len();
        report.total_files_fork = fork_files.len();

        let upstream_keys: HashSet<&String> = upstream_files.keys().collect();
        let fork_keys: HashSet<&String> = fork_files.keys().collect();

        let mut removed: Vec<&String> = upstream_keys.difference(&fork_keys).cloned().collect();
        let mut added: Vec<&String> = fork_keys.difference(&upstream_keys).cloned().collect();
        let mut common: Vec<&String> = upstream_keys.intersection(&fork_keys).cloned().collect();

        removed.sort();
        added.sort();
        common.sort();

        report.files_removed = removed.len();
        report.files_added = added.len();

        // ── Removed files ─────────────────────────────────────────────────

        for rel_path in &removed {
            let content = &upstream_files[*rel_path];
            if is_binary(content) {
                continue;
            }
            let is_sec = is_security_file(rel_path);
            let signals = count_security_signals(content);
            let has_signals = signals.has_signals();

            if is_sec && has_signals {
                // FORK-001 CRITICAL
                report.add_finding(
                    Finding::new(
                        "FORK-001",
                        Severity::Critical,
                        rel_path.as_str(),
                        "Security-critical file removed from fork",
                    )
                    .with_detail(signals.summarize()),
                    15,
                );
            } else if is_sec || has_signals {
                // FORK-002 HIGH
                let detail = if signals.is_empty() {
                    "Filename matches security pattern".to_string()
                } else {
                    signals.summarize()
                };
                report.add_finding(
                    Finding::new(
                        "FORK-002",
                        Severity::High,
                        rel_path.as_str(),
                        "Security-relevant file removed from fork",
                    )
                    .with_detail(detail),
                    8,
                );
            }
        }

        // ── Modified files ────────────────────────────────────────────────

        for rel_path in &common {
            let up_content = &upstream_files[*rel_path];
            let fk_content = &fork_files[*rel_path];

            if up_content == fk_content {
                continue;
            }
            if is_binary(up_content) || is_binary(fk_content) {
                continue;
            }

            report.files_modified += 1;
            analyze_diff(&mut report, rel_path, up_content, fk_content);
        }

        // ── Added files ───────────────────────────────────────────────────

        for rel_path in &added {
            let content = &fork_files[*rel_path];
            if is_binary(content) {
                continue;
            }
            for wp in patterns::weakening_patterns() {
                let matches: Vec<_> = wp.regex.find_iter(content).collect();
                if !matches.is_empty() {
                    // FORK-006 MEDIUM
                    report.add_finding(
                        Finding::new(
                            "FORK-006",
                            Severity::Medium,
                            rel_path.as_str(),
                            format!("New file contains suspicious pattern: {}", wp.description),
                        )
                        .with_detail(format!(
                            "Found {} occurrence(s) in added file",
                            matches.len()
                        )),
                        3,
                    );
                }
            }
        }

        report
    }
}

// ── Audit mode ────────────────────────────────────────────────────────────────
// Mirrors audit_single() in core.py.

pub fn audit(target_path: &str) -> AuditReport {
    let root = Path::new(target_path);
    let mut report = AuditReport {
        path: target_path.to_string(),
        total_files: 0,
        security_files: Vec::new(),
        total_security_signals: 0,
    };

    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let rel = match entry.path().strip_prefix(root) {
            Ok(r) => r.to_string_lossy().replace('\\', "/"),
            Err(_) => continue,
        };
        if should_ignore(&rel) {
            continue;
        }

        report.total_files += 1;

        let content = match std::fs::read(entry.path()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if is_binary(&content) {
            continue;
        }

        let signals = count_security_signals(&content);
        let total = signals.total();
        let is_sec = is_security_file(&rel);

        if total > 0 || is_sec {
            report.total_security_signals += total;
            report.security_files.push(AuditFile {
                path: rel,
                is_security_filename: is_sec,
                signal_count: total,
                signals: signals.to_summary(),
            });
        }
    }

    // Sort by signal count descending — mirrors Python sort.
    report
        .security_files
        .sort_by(|a, b| b.signal_count.cmp(&a.signal_count));

    report
}
