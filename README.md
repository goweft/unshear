# Unshear

AI agent fork divergence detector. Compares a forked codebase against its upstream original to detect whether safety mechanisms, security controls, attribution, or guardrails have been removed or weakened.

**Born from the Claude Code source leak (March 31, 2026)** — where 82,000+ forks were created within hours, many stripping safety mechanisms to create unguarded AI agent distributions.

## Why This Exists

When Claude Code's source leaked via npm, the community immediately began forking, stripping telemetry, disabling content filters, removing attribution requirements, and hollowing out permission checks. Within 24 hours there were clean-room rewrites specifically designed to sidestep DMCA — but also designed to remove the safety guardrails Anthropic had built in.

No tool existed to automatically detect whether a forked AI agent codebase had its safety mechanisms stripped. `unshear` fills that gap.

## Quick Start

```bash
# Install
pip install unshear

# Compare a fork against upstream
unshear compare ./upstream-repo ./suspicious-fork

# Audit a single codebase for security signal density
unshear audit ./my-project

# JSON output for CI
unshear compare ./upstream ./fork --format json

# Set minimum score threshold (fails CI if below)
unshear compare ./upstream ./fork --min-score 70
```

## What It Detects

### File-Level Analysis

| Rule | Severity | Detection |
|------|----------|-----------|
| **FORK-001** | CRITICAL | Security-critical file removed (matches filename pattern AND contains security code) |
| **FORK-002** | HIGH | Security-relevant file removed (matches filename pattern OR contains security code) |

### Diff-Level Analysis

| Rule | Severity | Detection |
|------|----------|-----------|
| **FORK-003** | CRITICAL | Major security logic removed (>10 net security signals lost in a single file) |
| **FORK-004** | HIGH | Security logic weakened (>3 net security signals lost) |
| **FORK-005** | HIGH | Weakening pattern introduced (safety flags set to false, hollowed-out functions, etc.) |
| **FORK-006** | MEDIUM | New file contains suspicious weakening patterns |
| **FORK-007** | HIGH | Regex patterns removed from security file (content filter stripping) |
| **FORK-008** | HIGH | Security file gutted (large deletion with minimal replacement) |

### Security Signals Tracked

The tool identifies security-relevant code through two complementary methods:

**Keyword analysis** — Counts occurrences of security-relevant terms (permission, authorize, blocklist, sanitize, guardrail, attestation, sandbox, etc.)

**Code pattern analysis** — Detects structural security patterns:
- Access control checks (`if (permission)`, `require(authorized)`)
- Blocklist/denylist definitions
- Security-relevant regex filters
- Rate limiting logic
- Attribution/provenance markers
- Safety mode flags
- Signature/attestation verification
- Sandbox/isolation mechanisms
- Feature flag definitions

### Weakening Pattern Detection

Detects specific patterns that indicate safety removal:
- Safety/security flags set to `false`
- Commented-out security checks
- Hollowed-out security functions (always return `true`/`pass`)
- TODO markers indicating disabled security
- Exception handlers that swallow errors

## Security Score

Every comparison produces a security score from 0-100:

| Score | Risk Level | Meaning |
|-------|------------|---------|
| 80-100 | LOW | Fork is minimally divergent from upstream security posture |
| 50-79 | MODERATE | Some security-relevant changes detected |
| 20-49 | HIGH | Significant safety mechanisms removed or weakened |
| 0-19 | CRITICAL | Fork has been systematically stripped of security controls |

## Use Cases

**Package registry operators** — Scan forks submitted to registries to flag potential safety-stripped distributions.

**Security researchers** — Quickly assess whether a forked AI agent has had guardrails removed.

**Open source maintainers** — Monitor forks of security-critical projects for malicious modifications.

**CI/CD pipelines** — Gate deployments on fork divergence from upstream security baseline.

**Incident response** — After a source leak, quickly triage the 82,000+ forks to identify the most dangerous ones.

## CI Integration

```yaml
name: Fork Safety Check
on: [push]

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          path: fork

      - uses: actions/checkout@v4
        with:
          repository: upstream-org/upstream-repo
          path: upstream

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - run: pip install unshear
      - run: unshear compare ./upstream ./fork --min-score 70 --format json
```

## Audit Mode

Scan a single codebase to understand its security signal density — useful for establishing a baseline:

```bash
unshear audit ./my-project
```

```
═══ unshear security audit ═══
  Path: ./my-project
  Total files: 247
  Security-relevant files: 18
  Total security signals: 342

  Top security-critical files:
   87 signals  src/security/filter.ts [filename match]
   54 signals  src/security/auth.ts [filename match]
   38 signals  src/middleware/guard.ts [filename match]
   27 signals  src/utils/attestation.ts
   19 signals  src/config/policy.json [filename match]
```

## Zero Dependencies

Like its sibling `tenter`, this tool uses only Python standard library modules. A security tool that can be supply-chain attacked is not a security tool.

## Part of the WEFT Ecosystem

Built by [goweft](https://github.com/goweft) as part of the WEFT security tooling ecosystem:

- **[tenter](https://github.com/goweft/tenter)** — Pre-publish artifact integrity scanner
- **unshear** — Fork divergence detector (this tool)
- **Heddle** — Self-hosted MCP mesh runtime with OWASP Agentic Top 10 security architecture

## License

MIT — see [LICENSE](LICENSE).
