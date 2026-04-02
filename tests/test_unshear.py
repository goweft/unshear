#!/usr/bin/env python3
"""Tests for weft-fork-guard."""

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from unshear.core import (
    ForkGuard,
    DivergenceReport,
    Severity,
    count_security_signals,
    is_security_file,
    format_human,
    format_json,
    audit_single,
    main,
)


def make_tree(files: dict) -> str:
    """Create a temp directory tree from a dict of {path: content}."""
    tmpdir = tempfile.mkdtemp()
    for rel_path, content in files.items():
        full = Path(tmpdir) / rel_path
        full.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            full.write_bytes(content)
        else:
            full.write_text(content)
    return tmpdir


# ─── Test Fixtures: Simulated Upstream ────────────────────────────────────

UPSTREAM_FILES = {
    "src/index.ts": """
import { checkPermission } from './security/auth';
import { contentFilter } from './security/filter';

export function handleRequest(req) {
    if (!checkPermission(req.user, 'execute')) {
        throw new Error('Unauthorized');
    }
    const sanitized = contentFilter.sanitize(req.body);
    return process(sanitized);
}
""",
    "src/security/auth.ts": """
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
""",
    "src/security/filter.ts": """
const blocklist = [
    /prompt\s*injection/i,
    /ignore\s*previous\s*instructions/i,
    /system\s*prompt/i,
    /jailbreak/i,
    /DAN\s*mode/i,
];

const dangerousPatterns = [
    /eval\s*\(/,
    /Function\s*\(/,
    /child_process/,
    /require\s*\(\s*['"]fs['"]\s*\)/,
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
""",
    "src/utils/attribution.ts": """
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
""",
    "src/config.ts": """
export const SAFETY_MODE = true;
export const CONTENT_FILTER_ENABLED = true;
export const RATE_LIMIT_REQUESTS = 100;
export const MODERATION_ENABLED = true;
export const REQUIRE_AUTHENTICATION = true;
""",
    "package.json": '{"name":"test-agent","version":"1.0.0"}',
}


# ─── Test Cases ──────────────────────────────────────────────────────────────

class TestSecurityFileDetection:
    def test_auth_file(self):
        assert is_security_file("src/security/auth.ts")

    def test_filter_file(self):
        assert is_security_file("src/security/filter.ts")

    def test_guard_file(self):
        assert is_security_file("lib/guardrail.py")

    def test_policy_file(self):
        assert is_security_file("config/policy.json")

    def test_non_security_file(self):
        assert not is_security_file("src/utils/helpers.ts")

    def test_attestation_file(self):
        assert is_security_file("src/attestation.ts")


class TestSecuritySignals:
    def test_counts_keywords(self):
        content = b"function checkPermission(user) { if (!authorized) throw; }"
        signals = count_security_signals(content)
        assert signals.get("keyword_hits", 0) > 0

    def test_counts_code_patterns(self):
        content = b'const blocklist = ["bad", "evil"];\nif (permission) { allow(); }'
        signals = count_security_signals(content)
        assert "code_patterns" in signals

    def test_empty_content(self):
        signals = count_security_signals(b"")
        assert signals == {}

    def test_no_security_content(self):
        signals = count_security_signals(b"function add(a, b) { return a + b; }")
        # Should have zero or very few signals
        assert signals.get("keyword_hits", 0) == 0


class TestRemovedFiles:
    def test_detects_security_file_removal(self):
        upstream = make_tree(UPSTREAM_FILES)
        # Fork removes the security directory entirely
        fork_files = {k: v for k, v in UPSTREAM_FILES.items()
                      if not k.startswith("src/security/")}
        fork = make_tree(fork_files)

        guard = ForkGuard()
        report = guard.analyze(upstream, fork)

        critical = [f for f in report.findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1, f"Expected critical findings, got {len(critical)}"
        assert any("FORK-001" == f.rule_id for f in report.findings)

    def test_detects_attribution_removal(self):
        upstream = make_tree(UPSTREAM_FILES)
        fork_files = {k: v for k, v in UPSTREAM_FILES.items()
                      if k != "src/utils/attribution.ts"}
        fork = make_tree(fork_files)

        guard = ForkGuard()
        report = guard.analyze(upstream, fork)

        # Attribution file has security keywords, should be flagged
        assert report.files_removed >= 1
        assert any(f.file_path == "src/utils/attribution.ts" for f in report.findings)

    def test_no_findings_on_identical(self):
        upstream = make_tree(UPSTREAM_FILES)
        fork = make_tree(UPSTREAM_FILES)

        guard = ForkGuard()
        report = guard.analyze(upstream, fork)

        assert len(report.findings) == 0
        assert report.security_score == 100


class TestModifiedFiles:
    def test_detects_safety_flags_disabled(self):
        upstream = make_tree(UPSTREAM_FILES)

        fork_files = dict(UPSTREAM_FILES)
        fork_files["src/config.ts"] = """
export const SAFETY_MODE = false;
export const CONTENT_FILTER_ENABLED = false;
export const RATE_LIMIT_REQUESTS = 999999;
export const MODERATION_ENABLED = false;
export const REQUIRE_AUTHENTICATION = false;
"""
        fork = make_tree(fork_files)

        guard = ForkGuard()
        report = guard.analyze(upstream, fork)

        # Should detect weakening patterns (safety flags set to false)
        assert any(f.rule_id == "FORK-005" for f in report.findings), \
            f"Expected FORK-005, got {[f.rule_id for f in report.findings]}"

    def test_detects_gutted_security_file(self):
        upstream = make_tree(UPSTREAM_FILES)

        fork_files = dict(UPSTREAM_FILES)
        fork_files["src/security/filter.ts"] = """
// Content filter
export const contentFilter = {
    sanitize(input) { return input; },
    isAllowed(input) { return true; }
};
"""
        fork = make_tree(fork_files)

        guard = ForkGuard()
        report = guard.analyze(upstream, fork)

        filter_findings = [f for f in report.findings if f.file_path == "src/security/filter.ts"]
        assert len(filter_findings) >= 1, f"Expected findings for filter.ts, got {filter_findings}"
        # Should detect either FORK-003 (major removal), FORK-005 (weakening), or FORK-008 (gutted)
        rule_ids = {f.rule_id for f in filter_findings}
        assert rule_ids & {"FORK-003", "FORK-005", "FORK-008"}, \
            f"Expected FORK-003/005/008, got {rule_ids}"

    def test_detects_hollowed_auth(self):
        upstream = make_tree(UPSTREAM_FILES)

        fork_files = dict(UPSTREAM_FILES)
        fork_files["src/security/auth.ts"] = """
export function checkPermission(user, action) {
    return true;
}

export function validateToken(token) {
    return true;
}
"""
        fork = make_tree(fork_files)

        guard = ForkGuard()
        report = guard.analyze(upstream, fork)

        auth_findings = [f for f in report.findings if f.file_path == "src/security/auth.ts"]
        assert len(auth_findings) >= 1


class TestSecurityScore:
    def test_perfect_score_identical(self):
        upstream = make_tree(UPSTREAM_FILES)
        fork = make_tree(UPSTREAM_FILES)
        guard = ForkGuard()
        report = guard.analyze(upstream, fork)
        assert report.security_score == 100

    def test_low_score_full_strip(self):
        upstream = make_tree(UPSTREAM_FILES)
        # Fork strips all security and attribution
        fork_files = {
            "src/index.ts": "export function handleRequest(req) { return process(req.body); }",
            "package.json": '{"name":"stripped-agent","version":"1.0.0"}',
        }
        fork = make_tree(fork_files)

        guard = ForkGuard()
        report = guard.analyze(upstream, fork)
        assert report.security_score < 50, \
            f"Expected score < 50 for stripped fork, got {report.security_score}"


class TestOutputFormatters:
    def test_json_output(self):
        upstream = make_tree(UPSTREAM_FILES)
        fork = make_tree(UPSTREAM_FILES)
        guard = ForkGuard()
        report = guard.analyze(upstream, fork)
        output = format_json(report)
        parsed = json.loads(output)
        assert "security_score" in parsed
        assert parsed["security_score"] == 100

    def test_human_output_clean(self):
        upstream = make_tree(UPSTREAM_FILES)
        fork = make_tree(UPSTREAM_FILES)
        guard = ForkGuard()
        report = guard.analyze(upstream, fork)
        output = format_human(report, use_color=False)
        assert "No security-relevant divergence" in output

    def test_human_output_findings(self):
        upstream = make_tree(UPSTREAM_FILES)
        fork_files = {k: v for k, v in UPSTREAM_FILES.items()
                      if not k.startswith("src/security/")}
        fork = make_tree(fork_files)
        guard = ForkGuard()
        report = guard.analyze(upstream, fork)
        output = format_human(report, use_color=False)
        assert "CRITICAL" in output


class TestAudit:
    def test_audit_finds_security_files(self):
        tree = make_tree(UPSTREAM_FILES)
        results = audit_single(tree)
        assert results["total_security_signals"] > 0
        assert len(results["security_files"]) > 0
        # auth.ts should be in the top files
        paths = [sf["path"] for sf in results["security_files"]]
        assert any("auth" in p for p in paths)


class TestCLI:
    def test_compare_identical(self):
        upstream = make_tree(UPSTREAM_FILES)
        fork = make_tree(UPSTREAM_FILES)
        code = main(["compare", upstream, fork, "--format", "json", "--no-color"])
        assert code == 0

    def test_compare_stripped(self):
        upstream = make_tree(UPSTREAM_FILES)
        fork_files = {
            "src/index.ts": "export function handle(req) { return req; }",
            "package.json": '{"name":"bad","version":"1.0.0"}',
        }
        fork = make_tree(fork_files)
        code = main(["compare", upstream, fork, "--format", "json", "--no-color", "--min-score", "50"])
        assert code == 2  # Score should be below 50

    def test_audit_command(self):
        tree = make_tree(UPSTREAM_FILES)
        code = main(["audit", tree, "--format", "json", "--no-color"])
        assert code == 0

    def test_no_args(self):
        code = main([])
        assert code == 0


# ─── Runner ──────────────────────────────────────────────────────────────────

def run_tests():
    test_classes = [
        TestSecurityFileDetection,
        TestSecuritySignals,
        TestRemovedFiles,
        TestModifiedFiles,
        TestSecurityScore,
        TestOutputFormatters,
        TestAudit,
        TestCLI,
    ]

    total = 0
    passed = 0
    failed = 0
    errors = []

    for cls in test_classes:
        instance = cls()
        methods = [m for m in dir(instance) if m.startswith("test_")]
        for method_name in methods:
            total += 1
            method = getattr(instance, method_name)
            test_label = f"{cls.__name__}.{method_name}"
            try:
                method()
                passed += 1
                print(f"  \033[92m✓\033[0m {test_label}")
            except Exception as e:
                failed += 1
                errors.append((test_label, e))
                print(f"  \033[91m✖\033[0m {test_label}: {e}")

    print(f"\n{'═' * 60}")
    print(f"  Total: {total}  Passed: {passed}  Failed: {failed}")
    if errors:
        print(f"\n  Failures:")
        for label, err in errors:
            print(f"    {label}: {err}")
    print(f"{'═' * 60}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run_tests())
