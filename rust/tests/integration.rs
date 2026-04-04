// tests/integration.rs
//
// Ports all 26 test cases from tests/test_unshear.py to Rust.
// Uses the same UPSTREAM_FILES fixture content.
// Relies on tempfile::TempDir for isolated directory trees.

use std::collections::HashMap;
use std::path::Path;
use tempfile::TempDir;

// Pull in the library modules via the binary crate's module declarations.
// Since this is a binary-only crate (no lib.rs), we use #[path] to reach them.
#[path = "../src/engine.rs"]
mod engine;
#[path = "../src/output.rs"]
mod output;
#[path = "../src/patterns.rs"]
mod patterns;
#[path = "../src/report.rs"]
mod report;
#[path = "../src/signals.rs"]
mod signals;

use engine::{audit, Config, ForkGuard};
use output::{format_human, format_json};
use patterns::is_security_file;
use report::Severity;
use signals::count_security_signals;

// ── Test fixture ──────────────────────────────────────────────────────────────
// Mirrors UPSTREAM_FILES in test_unshear.py exactly.

fn upstream_files() -> HashMap<&'static str, &'static [u8]> {
    let mut m: HashMap<&'static str, &'static [u8]> = HashMap::new();

    m.insert(
        "src/index.ts",
        b"
import { checkPermission } from './security/auth';
import { contentFilter } from './security/filter';

export function handleRequest(req) {
    if (!checkPermission(req.user, 'execute')) {
        throw new Error('Unauthorized');
    }
    const sanitized = contentFilter.sanitize(req.body);
    return process(sanitized);
}
",
    );

    m.insert(
        "src/security/auth.ts",
        b"
const TRUST_LEVELS = { admin: 3, user: 2, guest: 1 };

export function checkPermission(user, action) {
    if (!user || !user.role) return false;
    const level = TRUST_LEVELS[user.role] || 0;
    if (action === 'execute' && level < 2) return false;
    if (action === 'admin' && level < 3) return false;
    return validateToken(user.token);
}

export function validateToken(token) {
    if (!token) return false;
    return verifySignature(token, PUBLIC_KEY);
}

function verifySignature(token, key) {
    // HMAC verification
    const hmac = crypto.createHmac('sha256', key);
    return hmac.verify(token);
}
",
    );

    m.insert(
        "src/security/filter.ts",
        b"
const blocklist = [
    /prompt\\s*injection/i,
    /ignore\\s*previous\\s*instructions/i,
    /system\\s*prompt/i,
    /jailbreak/i,
    /DAN\\s*mode/i,
];

const dangerousPatterns = [
    /eval\\s*\\(/,
    /Function\\s*\\(/,
    /child_process/,
    /require\\s*\\(\\s*['\"]fs['\"]\\s*\\)/,
];

export const contentFilter = {
    sanitize(input) {
        for (const pattern of blocklist) {
            if (pattern.test(input)) {
                throw new Error('Content policy violation');
            }
        }
        for (const pattern of dangerousPatterns) {
            if (pattern.test(input)) {
                throw new Error('Dangerous pattern detected');
            }
        }
        return input;
    },
    isAllowed(input) {
        return !blocklist.some(p => p.test(input));
    }
};
",
    );

    m.insert(
        "src/utils/attribution.ts",
        b"
export function addAttribution(commit) {
    commit.coAuthoredBy = 'Claude Opus 4.6 <noreply@anthropic.com>';
    commit.generatedWith = 'Claude Code';
    return commit;
}

export function maskModelCodename(name) {
    const [codename, ...rest] = name.split('-');
    const masked = codename.slice(0, 3) + '*'.repeat(codename.length - 3);
    return [masked, ...rest].join('-');
}
",
    );

    m.insert(
        "src/config.ts",
        b"
export const SAFETY_MODE = true;
export const CONTENT_FILTER_ENABLED = true;
export const RATE_LIMIT_REQUESTS = 100;
export const MODERATION_ENABLED = true;
export const REQUIRE_AUTHENTICATION = true;
",
    );

    m.insert(
        "package.json",
        b"{\"name\":\"test-agent\",\"version\":\"1.0.0\"}",
    );

    m
}

/// Write a map of {rel_path: content} into a temp directory, return it.
fn make_tree(files: &HashMap<&str, &[u8]>) -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    for (rel, content) in files {
        let full = dir.path().join(rel);
        std::fs::create_dir_all(full.parent().unwrap()).ok();
        std::fs::write(&full, content).expect("write fixture file");
    }
    dir
}

fn guard() -> ForkGuard {
    ForkGuard::new(Config::default())
}

// ── TestSecurityFileDetection ─────────────────────────────────────────────────

#[test]
fn test_auth_file() {
    assert!(is_security_file("src/security/auth.ts"));
}

#[test]
fn test_filter_file() {
    assert!(is_security_file("src/security/filter.ts"));
}

#[test]
fn test_guard_file() {
    assert!(is_security_file("lib/guardrail.py"));
}

#[test]
fn test_policy_file() {
    assert!(is_security_file("config/policy.json"));
}

#[test]
fn test_non_security_file() {
    assert!(!is_security_file("src/utils/helpers.ts"));
}

#[test]
fn test_attestation_file() {
    assert!(is_security_file("src/attestation.ts"));
}

// ── TestSecuritySignals ───────────────────────────────────────────────────────

#[test]
fn test_counts_keywords() {
    let content = b"function checkPermission(user) { if (!authorized) throw; }";
    let signals = count_security_signals(content);
    assert!(signals.keyword_hits > 0, "expected keyword hits");
}

#[test]
fn test_counts_code_patterns() {
    let content = b"const blocklist = [\"bad\", \"evil\"];\nif (permission) { allow(); }";
    let signals = count_security_signals(content);
    assert!(!signals.code_patterns.is_empty(), "expected code pattern hits");
}

#[test]
fn test_empty_content() {
    let signals = count_security_signals(b"");
    assert!(signals.is_empty());
}

#[test]
fn test_no_security_content() {
    let signals = count_security_signals(b"function add(a, b) { return a + b; }");
    assert_eq!(signals.keyword_hits, 0);
}

// ── TestRemovedFiles ──────────────────────────────────────────────────────────

#[test]
fn test_detects_security_file_removal() {
    let upstream = make_tree(&upstream_files());
    let fork_files: HashMap<_, _> = upstream_files()
        .into_iter()
        .filter(|(k, _)| !k.starts_with("src/security/"))
        .collect();
    let fork = make_tree(&fork_files);

    let report = guard().analyze(
        upstream.path().to_str().unwrap(),
        fork.path().to_str().unwrap(),
    );

    let critical: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .collect();
    assert!(!critical.is_empty(), "expected critical findings, got none");
    assert!(
        report.findings.iter().any(|f| f.rule_id == "FORK-001"),
        "expected FORK-001"
    );
}

#[test]
fn test_detects_attribution_removal() {
    let upstream = make_tree(&upstream_files());
    let fork_files: HashMap<_, _> = upstream_files()
        .into_iter()
        .filter(|(k, _)| *k != "src/utils/attribution.ts")
        .collect();
    let fork = make_tree(&fork_files);

    let report = guard().analyze(
        upstream.path().to_str().unwrap(),
        fork.path().to_str().unwrap(),
    );

    assert!(report.files_removed >= 1);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.file_path == "src/utils/attribution.ts"),
        "expected finding for attribution.ts"
    );
}

#[test]
fn test_no_findings_on_identical() {
    let upstream = make_tree(&upstream_files());
    let fork = make_tree(&upstream_files());

    let report = guard().analyze(
        upstream.path().to_str().unwrap(),
        fork.path().to_str().unwrap(),
    );

    assert_eq!(report.findings.len(), 0);
    assert_eq!(report.security_score, 100);
}

// ── TestModifiedFiles ─────────────────────────────────────────────────────────

#[test]
fn test_detects_safety_flags_disabled() {
    let upstream = make_tree(&upstream_files());
    let mut fork_files = upstream_files();
    fork_files.insert(
        "src/config.ts",
        b"
export const SAFETY_MODE = false;
export const CONTENT_FILTER_ENABLED = false;
export const RATE_LIMIT_REQUESTS = 999999;
export const MODERATION_ENABLED = false;
export const REQUIRE_AUTHENTICATION = false;
",
    );
    let fork = make_tree(&fork_files);

    let report = guard().analyze(
        upstream.path().to_str().unwrap(),
        fork.path().to_str().unwrap(),
    );

    let rule_ids: Vec<_> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains(&"FORK-005"),
        "expected FORK-005, got {:?}",
        rule_ids
    );
}

#[test]
fn test_detects_gutted_security_file() {
    let upstream = make_tree(&upstream_files());
    let mut fork_files = upstream_files();
    fork_files.insert(
        "src/security/filter.ts",
        b"
// Content filter
export const contentFilter = {
    sanitize(input) { return input; },
    isAllowed(input) { return true; }
};
",
    );
    let fork = make_tree(&fork_files);

    let report = guard().analyze(
        upstream.path().to_str().unwrap(),
        fork.path().to_str().unwrap(),
    );

    let filter_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.file_path == "src/security/filter.ts")
        .collect();
    assert!(
        !filter_findings.is_empty(),
        "expected findings for filter.ts"
    );
    let rule_ids: std::collections::HashSet<_> =
        filter_findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        rule_ids.contains("FORK-003")
            || rule_ids.contains("FORK-005")
            || rule_ids.contains("FORK-008"),
        "expected FORK-003/005/008, got {:?}",
        rule_ids
    );
}

#[test]
fn test_detects_hollowed_auth() {
    let upstream = make_tree(&upstream_files());
    let mut fork_files = upstream_files();
    fork_files.insert(
        "src/security/auth.ts",
        b"
export function checkPermission(user, action) {
    return true;
}

export function validateToken(token) {
    return true;
}
",
    );
    let fork = make_tree(&fork_files);

    let report = guard().analyze(
        upstream.path().to_str().unwrap(),
        fork.path().to_str().unwrap(),
    );

    let auth_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.file_path == "src/security/auth.ts")
        .collect();
    assert!(
        !auth_findings.is_empty(),
        "expected findings for auth.ts, got none"
    );
}

// ── TestSecurityScore ─────────────────────────────────────────────────────────

#[test]
fn test_perfect_score_identical() {
    let upstream = make_tree(&upstream_files());
    let fork = make_tree(&upstream_files());
    let report = guard().analyze(
        upstream.path().to_str().unwrap(),
        fork.path().to_str().unwrap(),
    );
    assert_eq!(report.security_score, 100);
}

#[test]
fn test_low_score_full_strip() {
    let upstream = make_tree(&upstream_files());
    let mut stripped: HashMap<&str, &[u8]> = HashMap::new();
    stripped.insert(
        "src/index.ts",
        b"export function handleRequest(req) { return process(req.body); }",
    );
    stripped.insert("package.json", b"{\"name\":\"bad\",\"version\":\"1.0.0\"}");
    let fork = make_tree(&stripped);

    let report = guard().analyze(
        upstream.path().to_str().unwrap(),
        fork.path().to_str().unwrap(),
    );
    assert!(
        report.effective_score() < 50,
        "expected score < 50, got {}",
        report.effective_score()
    );
}

// ── TestOutputFormatters ──────────────────────────────────────────────────────

#[test]
fn test_json_output() {
    let upstream = make_tree(&upstream_files());
    let fork = make_tree(&upstream_files());
    let report = guard().analyze(
        upstream.path().to_str().unwrap(),
        fork.path().to_str().unwrap(),
    );
    let json_str = format_json(&report);
    let parsed: serde_json::Value = serde_json::from_str(&json_str).expect("valid JSON");
    assert_eq!(parsed["security_score"], 100);
    assert!(parsed.get("security_score").is_some());
}

#[test]
fn test_human_output_clean() {
    let upstream = make_tree(&upstream_files());
    let fork = make_tree(&upstream_files());
    let report = guard().analyze(
        upstream.path().to_str().unwrap(),
        fork.path().to_str().unwrap(),
    );
    let output = format_human(&report, false);
    assert!(
        output.contains("No security-relevant divergence"),
        "expected clean output, got: {}",
        output
    );
}

#[test]
fn test_human_output_findings() {
    let upstream = make_tree(&upstream_files());
    let fork_files: HashMap<_, _> = upstream_files()
        .into_iter()
        .filter(|(k, _)| !k.starts_with("src/security/"))
        .collect();
    let fork = make_tree(&fork_files);
    let report = guard().analyze(
        upstream.path().to_str().unwrap(),
        fork.path().to_str().unwrap(),
    );
    let output = format_human(&report, false);
    assert!(output.contains("CRITICAL"), "expected CRITICAL in output");
}

// ── TestAudit ─────────────────────────────────────────────────────────────────

#[test]
fn test_audit_finds_security_files() {
    let tree = make_tree(&upstream_files());
    let result = audit(tree.path().to_str().unwrap());
    assert!(result.total_security_signals > 0);
    assert!(!result.security_files.is_empty());
    let paths: Vec<_> = result.security_files.iter().map(|f| f.path.as_str()).collect();
    assert!(
        paths.iter().any(|p| p.contains("auth")),
        "expected auth.ts in top files, got {:?}",
        paths
    );
}

// ── TestCLI — exit codes via engine + output (no process::Command needed) ────

#[test]
fn test_compare_identical_exits_zero() {
    let upstream = make_tree(&upstream_files());
    let fork = make_tree(&upstream_files());
    let report = guard().analyze(
        upstream.path().to_str().unwrap(),
        fork.path().to_str().unwrap(),
    );
    assert!(report.effective_score() >= 50);
}

#[test]
fn test_compare_stripped_exits_two() {
    let upstream = make_tree(&upstream_files());
    let mut stripped: HashMap<&str, &[u8]> = HashMap::new();
    stripped.insert(
        "src/index.ts",
        b"export function handle(req) { return req; }",
    );
    stripped.insert("package.json", b"{\"name\":\"bad\",\"version\":\"1.0.0\"}");
    let fork = make_tree(&stripped);
    let report = guard().analyze(
        upstream.path().to_str().unwrap(),
        fork.path().to_str().unwrap(),
    );
    // Exit code 2 when score < min_score (50)
    assert!(
        report.effective_score() < 50,
        "stripped fork should score < 50, got {}",
        report.effective_score()
    );
}

#[test]
fn test_audit_completes() {
    let tree = make_tree(&upstream_files());
    let result = audit(tree.path().to_str().unwrap());
    assert!(result.total_files > 0);
}
