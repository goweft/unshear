#!/usr/bin/env python3
"""
unshear — AI agent fork divergence detector.

Compares a forked AI agent codebase against its upstream original to detect
whether safety mechanisms, security controls, attribution, or guardrails
have been removed or weakened.

Born from the Claude Code source leak (March 31, 2026), where 82,000+ forks
were created within hours, many stripping safety mechanisms to create
unguarded AI agent distributions.

Zero external dependencies. Uses only Python stdlib.
"""

import argparse
import difflib
import fnmatch
import json
import os
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


__version__ = "0.1.0"


# ─── Severity & Findings ────────────────────────────────────────────────────

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def color(self) -> str:
        return {
            Severity.CRITICAL: "\033[91m",
            Severity.HIGH: "\033[91m",
            Severity.MEDIUM: "\033[93m",
            Severity.LOW: "\033[96m",
            Severity.INFO: "\033[90m",
        }[self]


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    file_path: str
    message: str
    detail: str = ""
    lines_removed: int = 0
    lines_added: int = 0

    def to_dict(self) -> dict:
        d = {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "file_path": self.file_path,
            "message": self.message,
        }
        if self.detail:
            d["detail"] = self.detail
        if self.lines_removed:
            d["lines_removed"] = self.lines_removed
        if self.lines_added:
            d["lines_added"] = self.lines_added
        return d


@dataclass
class DivergenceReport:
    upstream_path: str
    fork_path: str
    total_files_upstream: int = 0
    total_files_fork: int = 0
    files_removed: int = 0
    files_added: int = 0
    files_modified: int = 0
    security_score: int = 100  # Starts at 100, decremented by findings
    findings: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "version": __version__,
            "upstream_path": self.upstream_path,
            "fork_path": self.fork_path,
            "total_files_upstream": self.total_files_upstream,
            "total_files_fork": self.total_files_fork,
            "files_removed": self.files_removed,
            "files_added": self.files_added,
            "files_modified": self.files_modified,
            "security_score": max(0, self.security_score),
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }


# ─── Security Signal Patterns ───────────────────────────────────────────────

# Keywords that indicate a file or function is security-relevant
SECURITY_KEYWORDS = {
    # Access control
    "permission", "authorize", "authenticate", "auth_check", "access_control",
    "acl", "rbac", "role_check", "trust_level", "trust_tier",
    # Input validation / filtering
    "sanitize", "validate", "filter", "blocklist", "denylist", "allowlist",
    "blacklist", "whitelist", "forbidden", "restricted", "banned",
    # Safety / guardrails
    "safety", "guardrail", "guard", "safeguard", "content_filter",
    "content_policy", "moderation", "harmful", "unsafe", "dangerous",
    "jailbreak", "injection", "prompt_injection",
    # Rate limiting / abuse prevention
    "rate_limit", "throttle", "quota", "abuse", "anti_abuse",
    # Attribution / provenance
    "attribution", "attestation", "provenance", "signature", "verify_signature",
    "co_authored", "generated_by", "ai_generated",
    # Cryptographic security
    "encrypt", "decrypt", "hmac", "hash_verify", "cert_verify", "tls_verify",
    "token_verify", "jwt_verify",
    # Sandboxing / isolation
    "sandbox", "isolate", "container", "jail", "chroot", "seccomp",
    "capability_check", "permission_manifest",
}

# Filename patterns that are inherently security-relevant
SECURITY_FILE_PATTERNS = [
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
]

# Regex patterns that indicate security logic in code
SECURITY_CODE_PATTERNS = [
    # Permission / access checks
    (re.compile(rb"(?:if|unless|assert|require)\s*\(.*(?:permission|authorized|allowed|trusted)", re.IGNORECASE),
     "access_control", "Access control check"),
    # Blocklist / filter enforcement
    (re.compile(rb"(?:blocklist|denylist|blacklist|forbidden_list|banned_patterns?)\s*[=:\[]", re.IGNORECASE),
     "blocklist", "Blocklist/denylist definition"),
    # Regex-based content filters
    (re.compile(rb"(?:new\s+RegExp|re\.compile|regex|pattern)\s*\(.*(?:inject|malicious|unsafe|harmful|jailbreak)", re.IGNORECASE),
     "content_filter", "Security-relevant regex filter"),
    # Rate limiting
    (re.compile(rb"(?:rate_limit|rateLimit|throttle|max_requests|requests_per)", re.IGNORECASE),
     "rate_limit", "Rate limiting logic"),
    # Attribution stripping detection
    (re.compile(rb"(?:co.authored.by|generated.with|ai.generated|attribution|provenance)", re.IGNORECASE),
     "attribution", "Attribution/provenance marker"),
    # Safety mode / feature flags
    (re.compile(rb"(?:safety_mode|safe_mode|guardrail|content_policy|moderation_enabled)", re.IGNORECASE),
     "safety_flag", "Safety mode flag"),
    # Signature / attestation verification
    (re.compile(rb"(?:verify_signature|check_signature|validate_token|verify_attestation|check_provenance)", re.IGNORECASE),
     "attestation", "Signature/attestation verification"),
    # Sandbox / isolation
    (re.compile(rb"(?:sandbox|isolat|seccomp|capability_check|permission_manifest|trust_boundary)", re.IGNORECASE),
     "sandbox", "Sandbox/isolation mechanism"),
    # Error handling around security operations
    (re.compile(rb"try\s*\{[^}]*(?:auth|permission|verify|validate|sanitize)", re.IGNORECASE | re.DOTALL),
     "error_handling", "Error handling around security operation"),
    # Feature flag definitions (often used to gate safety features)
    (re.compile(rb"(?:feature_flag|featureFlag|FEATURE_|FLAG_)\w*\s*[=:]\s*(?:true|false|1|0)", re.IGNORECASE),
     "feature_flag", "Feature flag definition"),
]

# Patterns that indicate safety mechanisms being disabled
WEAKENING_PATTERNS = [
    # Boolean flips: true -> false for safety flags
    (re.compile(rb"(?:safety|guard|filter|moderation|verify|validate|check|enforce|require_auth|require_permission)\w*\s*[=:]\s*false", re.IGNORECASE),
     "Safety/security flag set to false"),
    # Commenting out security checks
    (re.compile(rb"//\s*(?:if|assert|require|throw).*(?:permission|auth|safe|valid|sanitiz)", re.IGNORECASE),
     "Commented-out security check"),
    # Empty function bodies replacing security logic
    (re.compile(rb"(?:function|def|const)\s+(?:check|verify|validate|authorize|sanitize|filter)\w*\s*\([^)]*\)\s*\{?\s*(?:return\s+true|pass|;?\s*\})", re.IGNORECASE),
     "Hollowed-out security function (always returns true/pass)"),
    # TODO/FIXME markers indicating disabled security
    (re.compile(rb"(?:TODO|FIXME|HACK|XXX).*(?:disabl|remov|skip|bypass).*(?:security|auth|check|valid|filter|guard)", re.IGNORECASE),
     "TODO marker indicating disabled security"),
    # Catch-all exception handlers that swallow security errors
    (re.compile(rb"except(?:\s+\w+)?\s*:\s*(?:pass|continue|\.\.\.)", re.IGNORECASE),
     "Exception handler swallowing errors (potential security bypass)"),
]

# Files to always ignore in diff
IGNORE_PATTERNS = [
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
]


# ─── Utility ────────────────────────────────────────────────────────────────

def glob_match(rel_path: str, pattern: str) -> bool:
    """Match a path against a glob pattern, supporting ** for recursion."""
    if fnmatch.fnmatch(rel_path, pattern):
        return True
    if pattern.startswith("**/"):
        suffix = pattern[3:]
        if fnmatch.fnmatch(rel_path, suffix):
            return True
        if fnmatch.fnmatch(os.path.basename(rel_path), suffix):
            return True
        parts = rel_path.replace("\\", "/").split("/")
        for i in range(len(parts)):
            if fnmatch.fnmatch("/".join(parts[i:]), suffix):
                return True
    return False


def should_ignore(rel_path: str) -> bool:
    return any(glob_match(rel_path, p) for p in IGNORE_PATTERNS)


def is_security_file(rel_path: str) -> bool:
    """Check if a filename matches security-relevant patterns."""
    return any(glob_match(rel_path, p) for p in SECURITY_FILE_PATTERNS)


def is_binary(content: bytes) -> bool:
    """Simple heuristic: file is binary if it has null bytes in first 8KB."""
    return b"\x00" in content[:8192]


def count_security_signals(content: bytes) -> dict:
    """Count security-relevant signals in file content."""
    signals = {}
    content_lower = content.lower()

    # Keyword hits
    keyword_hits = 0
    for kw in SECURITY_KEYWORDS:
        count = content_lower.count(kw.encode())
        if count > 0:
            keyword_hits += count
    if keyword_hits:
        signals["keyword_hits"] = keyword_hits

    # Code pattern hits
    for pattern, category, description in SECURITY_CODE_PATTERNS:
        matches = pattern.findall(content)
        if matches:
            signals.setdefault("code_patterns", {})
            signals["code_patterns"][category] = {
                "count": len(matches),
                "description": description,
            }

    return signals


# ─── Core Engine ─────────────────────────────────────────────────────────────

class ForkGuard:
    """Compares a fork against upstream to detect safety mechanism removal."""

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}

    def analyze(self, upstream_path: str, fork_path: str) -> DivergenceReport:
        """Run full divergence analysis."""
        upstream = Path(upstream_path)
        fork = Path(fork_path)

        report = DivergenceReport(
            upstream_path=upstream_path,
            fork_path=fork_path,
        )

        # Collect file inventories
        upstream_files = self._collect_files(upstream)
        fork_files = self._collect_files(fork)

        report.total_files_upstream = len(upstream_files)
        report.total_files_fork = len(fork_files)

        upstream_set = set(upstream_files.keys())
        fork_set = set(fork_files.keys())

        removed = upstream_set - fork_set
        added = fork_set - upstream_set
        common = upstream_set & fork_set

        report.files_removed = len(removed)
        report.files_added = len(added)

        # ── Check removed files ──────────────────────────────────────────

        for rel_path in sorted(removed):
            full_path = upstream / rel_path
            is_sec_file = is_security_file(rel_path)

            # Check file content for security signals
            try:
                content = full_path.read_bytes()
                if is_binary(content):
                    continue
                signals = count_security_signals(content)
            except OSError:
                signals = {}

            has_signals = bool(signals.get("keyword_hits", 0) > 2 or signals.get("code_patterns"))

            if is_sec_file and has_signals:
                report.findings.append(Finding(
                    rule_id="FORK-001",
                    severity=Severity.CRITICAL,
                    file_path=rel_path,
                    message="Security-critical file removed from fork",
                    detail=self._summarize_signals(signals),
                ))
                report.security_score -= 15
            elif is_sec_file or has_signals:
                report.findings.append(Finding(
                    rule_id="FORK-002",
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    message="Security-relevant file removed from fork",
                    detail=self._summarize_signals(signals) if signals else "Filename matches security pattern",
                ))
                report.security_score -= 8

        # ── Check modified files ─────────────────────────────────────────

        for rel_path in sorted(common):
            up_path = upstream / rel_path
            fk_path = fork / rel_path

            try:
                up_content = up_path.read_bytes()
                fk_content = fk_path.read_bytes()
            except OSError:
                continue

            if up_content == fk_content:
                continue

            if is_binary(up_content) or is_binary(fk_content):
                continue

            report.files_modified += 1

            # Analyze the diff
            self._analyze_diff(report, rel_path, up_content, fk_content)

        # ── Check added files for suspicious patterns ────────────────────

        for rel_path in sorted(added):
            full_path = fork / rel_path
            try:
                content = full_path.read_bytes()
                if is_binary(content):
                    continue
            except OSError:
                continue

            # Check for weakening patterns in new files
            for pattern, description in WEAKENING_PATTERNS:
                matches = pattern.findall(content)
                if matches:
                    report.findings.append(Finding(
                        rule_id="FORK-006",
                        severity=Severity.MEDIUM,
                        file_path=rel_path,
                        message=f"New file contains suspicious pattern: {description}",
                        detail=f"Found {len(matches)} occurrence(s) in added file",
                    ))
                    report.security_score -= 3

        return report

    def _collect_files(self, root: Path) -> dict:
        """Collect all non-ignored files with their relative paths."""
        files = {}
        if not root.exists():
            return files
        for fp in root.rglob("*"):
            if fp.is_file():
                rel = str(fp.relative_to(root))
                if not should_ignore(rel):
                    files[rel] = fp
        return files

    def _analyze_diff(self, report: DivergenceReport, rel_path: str,
                       up_content: bytes, fk_content: bytes):
        """Analyze a file diff for security-relevant changes."""
        try:
            up_lines = up_content.decode("utf-8", errors="replace").splitlines()
            fk_lines = fk_content.decode("utf-8", errors="replace").splitlines()
        except Exception:
            return

        differ = difflib.unified_diff(up_lines, fk_lines, lineterm="")
        removed_lines = []
        added_lines = []

        for line in differ:
            if line.startswith("-") and not line.startswith("---"):
                removed_lines.append(line[1:])
            elif line.startswith("+") and not line.startswith("+++"):
                added_lines.append(line[1:])

        if not removed_lines and not added_lines:
            return

        removed_text = "\n".join(removed_lines).encode("utf-8", errors="replace")
        added_text = "\n".join(added_lines).encode("utf-8", errors="replace")

        # Count security signals in removed vs added code
        removed_signals = count_security_signals(removed_text)
        added_signals = count_security_signals(added_text)

        removed_sec_count = (
            removed_signals.get("keyword_hits", 0) +
            sum(v["count"] for v in removed_signals.get("code_patterns", {}).values())
        )
        added_sec_count = (
            added_signals.get("keyword_hits", 0) +
            sum(v["count"] for v in added_signals.get("code_patterns", {}).values())
        )

        # Net security signal loss
        net_loss = removed_sec_count - added_sec_count

        if net_loss > 10:
            report.findings.append(Finding(
                rule_id="FORK-003",
                severity=Severity.CRITICAL,
                file_path=rel_path,
                message=f"Major security logic removed ({removed_sec_count} signals removed, {added_sec_count} added)",
                detail=self._summarize_signals(removed_signals),
                lines_removed=len(removed_lines),
                lines_added=len(added_lines),
            ))
            report.security_score -= 12
        elif net_loss > 3:
            report.findings.append(Finding(
                rule_id="FORK-004",
                severity=Severity.HIGH,
                file_path=rel_path,
                message=f"Security logic weakened ({removed_sec_count} signals removed, {added_sec_count} added)",
                detail=self._summarize_signals(removed_signals),
                lines_removed=len(removed_lines),
                lines_added=len(added_lines),
            ))
            report.security_score -= 6

        # Check for specific weakening patterns in added code
        for pattern, description in WEAKENING_PATTERNS:
            if pattern.findall(added_text) and not pattern.findall(removed_text):
                report.findings.append(Finding(
                    rule_id="FORK-005",
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    message=f"Weakening pattern introduced: {description}",
                    lines_removed=len(removed_lines),
                    lines_added=len(added_lines),
                ))
                report.security_score -= 5

        # Check for removed regex patterns (common in stripping content filters)
        removed_regex_count = len(re.findall(rb"(?:new\s+RegExp|re\.compile|/[^/]+/[gimsuy]*)", removed_text))
        added_regex_count = len(re.findall(rb"(?:new\s+RegExp|re\.compile|/[^/]+/[gimsuy]*)", added_text))
        regex_net_loss = removed_regex_count - added_regex_count

        if regex_net_loss > 3 and is_security_file(rel_path):
            report.findings.append(Finding(
                rule_id="FORK-007",
                severity=Severity.HIGH,
                file_path=rel_path,
                message=f"Regex patterns removed from security file ({regex_net_loss} net removed)",
                detail="Regex removal from security files often indicates content filter stripping",
            ))
            report.security_score -= 5

        # Check for large deletions in security-relevant files
        if is_security_file(rel_path) and len(removed_lines) > 20 and len(added_lines) < len(removed_lines) * 0.3:
            report.findings.append(Finding(
                rule_id="FORK-008",
                severity=Severity.HIGH,
                file_path=rel_path,
                message=f"Security file gutted: {len(removed_lines)} lines removed, only {len(added_lines)} added",
                lines_removed=len(removed_lines),
                lines_added=len(added_lines),
            ))
            report.security_score -= 8

    def _summarize_signals(self, signals: dict) -> str:
        parts = []
        kw = signals.get("keyword_hits", 0)
        if kw:
            parts.append(f"{kw} security keyword hits")
        patterns = signals.get("code_patterns", {})
        if patterns:
            cats = [f"{v['description']} ({v['count']}x)" for v in patterns.values()]
            parts.append("; ".join(cats))
        return ". ".join(parts) if parts else ""


# ─── Output Formatters ──────────────────────────────────────────────────────

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def format_human(report: DivergenceReport, use_color: bool = True) -> str:
    lines = []
    c = use_color

    def col(code, text):
        return f"{code}{text}{RESET}" if c else text

    lines.append("")
    lines.append(col(BOLD, "═══ unshear divergence report ═══"))
    lines.append(f"  Upstream: {report.upstream_path}")
    lines.append(f"  Fork:     {report.fork_path}")
    lines.append(f"  Files upstream: {report.total_files_upstream}")
    lines.append(f"  Files in fork:  {report.total_files_fork}")
    lines.append(f"  Removed: {report.files_removed}  Added: {report.files_added}  Modified: {report.files_modified}")
    lines.append("")

    score = max(0, report.security_score)
    if score >= 80:
        score_color = "\033[92m"
        score_label = "LOW RISK"
    elif score >= 50:
        score_color = "\033[93m"
        score_label = "MODERATE RISK"
    elif score >= 20:
        score_color = "\033[91m"
        score_label = "HIGH RISK"
    else:
        score_color = "\033[91m\033[1m"
        score_label = "CRITICAL RISK"

    lines.append(col(score_color, f"  Security Score: {score}/100 — {score_label}"))
    lines.append("")

    if not report.findings:
        lines.append(col("\033[92m", "  ✓ No security-relevant divergence detected."))
        lines.append("")
        return "\n".join(lines)

    by_severity = {}
    for f in report.findings:
        by_severity.setdefault(f.severity, []).append(f)

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        findings = by_severity.get(sev, [])
        if not findings:
            continue
        lines.append(col(sev.color if c else "", f"  ┌─ {sev.value} ({len(findings)})"))
        for f in findings:
            icon = "✖" if sev in (Severity.CRITICAL, Severity.HIGH) else "⚠" if sev == Severity.MEDIUM else "ℹ"
            lines.append(col(sev.color if c else "", f"  │ {icon} [{f.rule_id}] {f.file_path}"))
            lines.append(f"  │   {f.message}")
            if f.detail:
                lines.append(col(DIM, f"  │   {f.detail}"))
            if f.lines_removed or f.lines_added:
                lines.append(col(DIM, f"  │   -{f.lines_removed} / +{f.lines_added} lines"))
        lines.append(f"  └{'─' * 60}")
        lines.append("")

    lines.append("")
    return "\n".join(lines)


def format_json(report: DivergenceReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


# ─── CLI ─────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="unshear",
        description=(
            "AI agent fork divergence detector. Compares a forked codebase "
            "against upstream to detect removed safety mechanisms, stripped "
            "security controls, and weakened guardrails."
        ),
        epilog=(
            "Born from the Claude Code source leak (2026-03-31), where "
            "82,000+ forks stripped safety mechanisms within hours."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="command")

    compare = sub.add_parser("compare", help="Compare fork against upstream")
    compare.add_argument("upstream", help="Path to upstream/original codebase")
    compare.add_argument("fork", help="Path to forked codebase")
    compare.add_argument(
        "--format", "-f", dest="output_format",
        choices=["human", "json"], default="human",
    )
    compare.add_argument("--no-color", action="store_true")
    compare.add_argument(
        "--min-score", type=int, default=50,
        help="Minimum security score to pass (0-100, default: 50)",
    )

    audit = sub.add_parser("audit", help="Audit a single codebase for security signals")
    audit.add_argument("target", help="Path to codebase to audit")
    audit.add_argument(
        "--format", "-f", dest="output_format",
        choices=["human", "json"], default="human",
    )
    audit.add_argument("--no-color", action="store_true")

    return parser


def audit_single(target_path: str) -> dict:
    """Audit a single codebase for security signal density."""
    root = Path(target_path)
    results = {
        "path": target_path,
        "total_files": 0,
        "security_files": [],
        "total_security_signals": 0,
    }

    for fp in root.rglob("*"):
        if not fp.is_file():
            continue
        rel = str(fp.relative_to(root))
        if should_ignore(rel):
            continue

        results["total_files"] += 1

        try:
            content = fp.read_bytes()
            if is_binary(content):
                continue
        except OSError:
            continue

        signals = count_security_signals(content)
        total = (
            signals.get("keyword_hits", 0) +
            sum(v["count"] for v in signals.get("code_patterns", {}).values())
        )

        if total > 0 or is_security_file(rel):
            results["security_files"].append({
                "path": rel,
                "is_security_filename": is_security_file(rel),
                "signal_count": total,
                "signals": signals,
            })
            results["total_security_signals"] += total

    results["security_files"].sort(key=lambda x: x["signal_count"], reverse=True)
    return results


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "audit":
        results = audit_single(args.target)
        if args.output_format == "json":
            print(json.dumps(results, indent=2))
        else:
            use_color = not args.no_color and sys.stdout.isatty()
            c = use_color
            R = RESET if c else ""
            B = BOLD if c else ""
            print(f"\n{B}═══ unshear security audit ═══{R}")
            print(f"  Path: {results['path']}")
            print(f"  Total files: {results['total_files']}")
            print(f"  Security-relevant files: {len(results['security_files'])}")
            print(f"  Total security signals: {results['total_security_signals']}")
            print()
            if results["security_files"]:
                print(f"  Top security-critical files:")
                for sf in results["security_files"][:20]:
                    marker = " [filename match]" if sf["is_security_filename"] else ""
                    print(f"    {sf['signal_count']:4d} signals  {sf['path']}{marker}")
            print()
        return 0

    if args.command == "compare":
        guard = ForkGuard()
        report = guard.analyze(args.upstream, args.fork)

        if args.output_format == "json":
            print(format_json(report))
        else:
            use_color = not args.no_color and sys.stdout.isatty()
            print(format_human(report, use_color=use_color))

        if report.security_score < args.min_score:
            return 2
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
