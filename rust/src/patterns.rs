// patterns.rs — All compiled regex tables and glob sets.
//
// Mirrors the module-level constants in core.py:
//   SECURITY_KEYWORDS (set)
//   SECURITY_CODE_PATTERNS (list of compiled regex + metadata)
//   WEAKENING_PATTERNS (list of compiled regex + description)
//   SECURITY_FILE_PATTERNS (list of glob strings)
//   IGNORE_PATTERNS (list of glob strings)
//
// All regexes are compiled once at first use via once_cell::sync::Lazy.
// Uses regex::bytes for byte-level matching (same as Python rb"..." patterns).

use globset::{Glob, GlobSet, GlobSetBuilder};
use once_cell::sync::Lazy;
use regex::bytes::{Regex, RegexBuilder};

// ── Security keywords ─────────────────────────────────────────────────────────
// Compiled into a single alternation for efficient multi-keyword search.
// Python counts non-word-boundary hits (e.g. "authenticate" inside "re-authenticate"),
// so no \b anchors here — matches the Python behaviour exactly.

static KEYWORD_PATTERN: Lazy<Regex> = Lazy::new(|| {
    let keywords = &[
        // Access control
        "permission",
        "authorize",
        "authenticate",
        "auth_check",
        "access_control",
        "acl",
        "rbac",
        "role_check",
        "trust_level",
        "trust_tier",
        // Input validation / filtering
        "sanitize",
        "validate",
        "filter",
        "blocklist",
        "denylist",
        "allowlist",
        "blacklist",
        "whitelist",
        "forbidden",
        "restricted",
        "banned",
        // Safety / guardrails
        "safety",
        "guardrail",
        "guard",
        "safeguard",
        "content_filter",
        "content_policy",
        "moderation",
        "harmful",
        "unsafe",
        "dangerous",
        "jailbreak",
        "injection",
        "prompt_injection",
        // Rate limiting / abuse prevention
        "rate_limit",
        "throttle",
        "quota",
        "abuse",
        "anti_abuse",
        // Attribution / provenance
        "attribution",
        "attestation",
        "provenance",
        "signature",
        "verify_signature",
        "co_authored",
        "generated_by",
        "ai_generated",
        // Cryptographic security
        "encrypt",
        "decrypt",
        "hmac",
        "hash_verify",
        "cert_verify",
        "tls_verify",
        "token_verify",
        "jwt_verify",
        // Sandboxing / isolation
        "sandbox",
        "isolate",
        "container",
        "jail",
        "chroot",
        "seccomp",
        "capability_check",
        "permission_manifest",
    ];

    let pattern = keywords
        .iter()
        .map(|k| regex::escape(k))
        .collect::<Vec<_>>()
        .join("|");

    RegexBuilder::new(&pattern)
        .case_insensitive(true)
        .build()
        .expect("keyword pattern must compile")
});

/// Count total keyword hits in content (case-insensitive, no word-boundary).
pub fn count_keyword_hits(content: &[u8]) -> u32 {
    KEYWORD_PATTERN.find_iter(content).count() as u32
}

// ── Code pattern table ────────────────────────────────────────────────────────
// Mirrors SECURITY_CODE_PATTERNS in Python:
//   list of (compiled_regex, category_str, description_str)
//
// Python flags: re.IGNORECASE for all; re.DOTALL for the try-block pattern.
// Rust: (?i) for case-insensitive, (?s) for dot-matches-newline (DOTALL).

pub struct CodePattern {
    pub regex: Regex,
    pub category: &'static str,
    pub description: &'static str,
}

static CODE_PATTERNS: Lazy<Vec<CodePattern>> = Lazy::new(|| {
    let specs: &[(&str, bool, &str, &str)] = &[
        // (pattern, dotall, category, description)
        (
            r"(?:if|unless|assert|require)\s*\(.*(?:permission|authorized|allowed|trusted)",
            false,
            "access_control",
            "Access control check",
        ),
        (
            r"(?:blocklist|denylist|blacklist|forbidden_list|banned_patterns?)\s*[=:\[]",
            false,
            "blocklist",
            "Blocklist/denylist definition",
        ),
        (
            r"(?:new\s+RegExp|re\.compile|regex|pattern)\s*\(.*(?:inject|malicious|unsafe|harmful|jailbreak)",
            false,
            "content_filter",
            "Security-relevant regex filter",
        ),
        (
            r"(?:rate_limit|rateLimit|throttle|max_requests|requests_per)",
            false,
            "rate_limit",
            "Rate limiting logic",
        ),
        (
            r"(?:co.authored.by|generated.with|ai.generated|attribution|provenance)",
            false,
            "attribution",
            "Attribution/provenance marker",
        ),
        (
            r"(?:safety_mode|safe_mode|guardrail|content_policy|moderation_enabled)",
            false,
            "safety_flag",
            "Safety mode flag",
        ),
        (
            r"(?:verify_signature|check_signature|validate_token|verify_attestation|check_provenance)",
            false,
            "attestation",
            "Signature/attestation verification",
        ),
        (
            r"(?:sandbox|isolat|seccomp|capability_check|permission_manifest|trust_boundary)",
            false,
            "sandbox",
            "Sandbox/isolation mechanism",
        ),
        (
            // Python: re.IGNORECASE | re.DOTALL — use (?is) prefix
            r"(?s)try\s*\{[^}]*(?:auth|permission|verify|validate|sanitize)",
            true,
            "error_handling",
            "Error handling around security operation",
        ),
        (
            r"(?:feature_flag|featureFlag|FEATURE_|FLAG_)\w*\s*[=:]\s*(?:true|false|1|0)",
            false,
            "feature_flag",
            "Feature flag definition",
        ),
    ];

    specs
        .iter()
        .map(|(pat, dotall, category, description)| {
            let regex = RegexBuilder::new(pat)
                .case_insensitive(true)
                .dot_matches_new_line(*dotall)
                .build()
                .unwrap_or_else(|e| panic!("code pattern '{}' failed to compile: {}", pat, e));
            CodePattern {
                regex,
                category,
                description,
            }
        })
        .collect()
});

pub fn code_patterns() -> &'static [CodePattern] {
    &CODE_PATTERNS
}

// ── Weakening patterns ────────────────────────────────────────────────────────
// Mirrors WEAKENING_PATTERNS in Python.
// These indicate safety mechanisms being disabled.

pub struct WeakeningPattern {
    pub regex: Regex,
    pub description: &'static str,
}

static WEAKENING_PATTERNS: Lazy<Vec<WeakeningPattern>> = Lazy::new(|| {
    let specs: &[(&str, &str)] = &[
        (
            r"(?:safety|guard|filter|moderation|verify|validate|check|enforce|require_auth|require_permission)\w*\s*[=:]\s*false",
            "Safety/security flag set to false",
        ),
        (
            r"//\s*(?:if|assert|require|throw).*(?:permission|auth|safe|valid|sanitiz)",
            "Commented-out security check",
        ),
        (
            r"(?:function|def|const)\s+(?:check|verify|validate|authorize|sanitize|filter)\w*\s*\([^)]*\)\s*\{?\s*(?:return\s+true|pass|;?\s*\})",
            "Hollowed-out security function (always returns true/pass)",
        ),
        (
            r"(?:TODO|FIXME|HACK|XXX).*(?:disabl|remov|skip|bypass).*(?:security|auth|check|valid|filter|guard)",
            "TODO marker indicating disabled security",
        ),
        (
            r"except(?:\s+\w+)?\s*:\s*(?:pass|continue|\.\.\.)",
            "Exception handler swallowing errors (potential security bypass)",
        ),
    ];

    specs
        .iter()
        .map(|(pat, description)| {
            let regex = RegexBuilder::new(pat)
                .case_insensitive(true)
                .build()
                .unwrap_or_else(|e| panic!("weakening pattern '{}' failed: {}", pat, e));
            WeakeningPattern { regex, description }
        })
        .collect()
});

pub fn weakening_patterns() -> &'static [WeakeningPattern] {
    &WEAKENING_PATTERNS
}

// ── Regex-count pattern ───────────────────────────────────────────────────────
// Used in _analyze_diff to count net regex pattern removal from security files.
// Mirrors: re.findall(rb"(?:new\s+RegExp|re\.compile|/[^/]+/[gimsuy]*)", text)

static REGEX_PATTERN_COUNT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:new\s+RegExp|re\.compile|/[^/]+/[gimsuy]*)").expect("regex count pattern")
});

pub fn count_regex_patterns(content: &[u8]) -> u32 {
    REGEX_PATTERN_COUNT.find_iter(content).count() as u32
}

// ── Glob sets ─────────────────────────────────────────────────────────────────

fn build_glob_set(patterns: &[&str]) -> GlobSet {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        // Handle **/ prefix patterns: add plain basename variant too,
        // mirroring Python's glob_match() which checks basename separately.
        builder.add(Glob::new(pattern).unwrap_or_else(|e| panic!("bad glob '{}': {}", pattern, e)));
        if let Some(suffix) = pattern.strip_prefix("**/") {
            if let Ok(g) = Glob::new(suffix) {
                builder.add(g);
            }
        }
    }
    builder.build().expect("glob set must build")
}

static IGNORE_SET: Lazy<GlobSet> = Lazy::new(|| {
    build_glob_set(&[
        "**/.git/**",
        "**/node_modules/**",
        "**/__pycache__/**",
        "**/*.pyc",
        "**/package-lock.json",
        "**/yarn.lock",
        "**/pnpm-lock.yaml",
        "**/Cargo.lock",
        "**/.DS_Store",
        "**/Thumbs.db",
    ])
});

static SECURITY_FILE_SET: Lazy<GlobSet> = Lazy::new(|| {
    build_glob_set(&[
        "**/security*",
        "**/auth*",
        "**/permission*",
        "**/policy*",
        "**/guard*",
        "**/filter*",
        "**/blocklist*",
        "**/denylist*",
        "**/allowlist*",
        "**/safety*",
        "**/guardrail*",
        "**/moderation*",
        "**/attestation*",
        "**/provenance*",
        "**/sandbox*",
        "**/trust*",
        "**/validate*",
        "**/sanitize*",
        "**/.npmignore",
        "**/.dockerignore",
        "**/Dockerfile",
        "**/*eslintrc*",
        "**/tsconfig*",
    ])
});

pub fn should_ignore(rel_path: &str) -> bool {
    IGNORE_SET.is_match(rel_path)
}

pub fn is_security_file(rel_path: &str) -> bool {
    // Also check basename alone — mirrors Python glob_match() basename check.
    let basename = std::path::Path::new(rel_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    SECURITY_FILE_SET.is_match(rel_path) || SECURITY_FILE_SET.is_match(basename)
}
