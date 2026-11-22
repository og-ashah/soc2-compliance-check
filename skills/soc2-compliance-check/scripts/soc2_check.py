#!/usr/bin/env python3
"""SOC 2 readiness checker.

A fast, static, heuristic scan of a repository / project / app folder that
flags common gaps against the AICPA Trust Services Criteria (TSC) that
auditors look for first. It is a *readiness* aid, not an audit and not a
certification. Only the Python 3 standard library is used.

Usage:
    python3 soc2_check.py /path/to/project
    python3 soc2_check.py . --format json --output soc2-report.json
    python3 soc2_check.py . --format markdown --output soc2-report.md --fail-on warn

Exit codes:
    0  no FAIL findings (or --fail-on never)
    1  at least one FAIL finding (or a WARN when --fail-on warn)
    2  usage error (path does not exist, etc.)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Callable, Dict, Iterable, List, Optional, Tuple

__version__ = "0.1.0"

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "venv", ".venv", "env", "__pycache__",
    "dist", "build", "target", ".next", ".nuxt", ".tox", ".mypy_cache",
    ".pytest_cache", "coverage", ".idea", ".vscode",
}
MAX_FILE_BYTES = 1_000_000
SOURCE_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rb", ".java",
    ".kt", ".cs", ".php", ".rs", ".swift", ".sh", ".yml", ".yaml", ".json",
    ".toml", ".ini", ".cfg", ".conf", ".env", ".tf", ".md", ".txt", "",
}
IGNORE_MARKER = "soc2-ignore"  # put this on a line to suppress line-based findings


@dataclass
class Finding:
    id: str
    title: str
    criteria: str          # Trust Services Criteria reference, e.g. "CC6.1"
    status: str            # PASS | WARN | FAIL | INFO
    severity: str          # high | medium | low
    summary: str
    evidence: List[str] = field(default_factory=list)
    recommendation: str = ""


@dataclass
class Context:
    root: str
    files: List[str]                 # relative, posix-style paths
    _cache: Dict[str, Optional[List[str]]] = field(default_factory=dict)

    def has(self, *names: str) -> bool:
        wanted = {n.lower() for n in names}
        return any(os.path.basename(f).lower() in wanted for f in self.files)

    def find(self, pattern: str, flags: int = 0) -> List[str]:
        rx = re.compile(pattern, flags)
        return [f for f in self.files if rx.search(f)]

    def lines(self, rel: str) -> Optional[List[str]]:
        if rel not in self._cache:
            self._cache[rel] = _read_lines(os.path.join(self.root, rel))
        return self._cache[rel]

    def grep(self, pattern: str, files: Optional[Iterable[str]] = None,
             flags: int = 0) -> List[Tuple[str, int, str]]:
        rx = re.compile(pattern, flags)
        hits: List[Tuple[str, int, str]] = []
        for rel in (files if files is not None else self.source_files()):
            lines = self.lines(rel)
            if not lines:
                continue
            for i, line in enumerate(lines, 1):
                if IGNORE_MARKER in line:
                    continue
                if rx.search(line):
                    hits.append((rel, i, line.strip()))
        return hits

    def source_files(self) -> List[str]:
        out = []
        for f in self.files:
            base = os.path.basename(f)
            ext = os.path.splitext(base)[1].lower()
            if ext in SOURCE_EXTS and not base.startswith(".env.example"):
                out.append(f)
        return out

    def workflow_text(self) -> str:
        parts = []
        for f in self.find(r"^\.github/workflows/.+\.ya?ml$|^\.gitlab-ci\.yml$|"
                           r"^\.circleci/config\.yml$|^Jenkinsfile$|"
                           r"^azure-pipelines\.yml$|^bitbucket-pipelines\.yml$"):
            lines = self.lines(f) or []
            parts.append("\n".join(lines))
        return "\n".join(parts).lower()


def _read_lines(path: str) -> Optional[List[str]]:
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, "rb") as fh:
            raw = fh.read()
        if b"\x00" in raw:  # binary
            return None
        return raw.decode("utf-8", errors="replace").splitlines()
    except OSError:
        return None


def collect_files(root: str) -> List[str]:
    files: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                continue
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            files.append(rel)
    files.sort()
    return files


# ---------------------------------------------------------------------------
# Checks. Each returns one Finding. Keep them small and explainable.
# ---------------------------------------------------------------------------

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID"),
    (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "private key block"),
    (r"gh[pousr]_[A-Za-z0-9]{36,}", "GitHub token"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", "Slack token"),
    (r"(?i)(api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*['\"]"
     r"(?!\s*['\"])(?![^'\"]*(example|changeme|your[_-]|placeholder|xxxx|\$\{|<))"
     r"[^'\"\s]{8,}['\"]", "hard-coded credential"),
]


def check_secrets_in_code(ctx: Context) -> Finding:
    hits = []
    for label_rx, label in SECRET_PATTERNS:
        for rel, line_no, line in ctx.grep(label_rx):
            hits.append(f"{rel}:{line_no} ({label})")
    return Finding(
        id="SEC-001", title="No hard-coded secrets in source", criteria="CC6.1",
        status="FAIL" if hits else "PASS", severity="high",
        summary=(f"{len(hits)} possible hard-coded secret(s) found" if hits
                 else "No hard-coded secrets detected"),
        evidence=hits[:20],
        recommendation="Move secrets to environment variables or a secrets manager "
                       "(AWS Secrets Manager, Vault, Doppler), rotate anything that was exposed, "
                       "and purge it from git history.",
    )


def check_env_files(ctx: Context) -> Finding:
    env_files = [f for f in ctx.files
                 if re.search(r"(^|/)\.env(\..+)?$", f)
                 and not re.search(r"\.(example|sample|template|dist)$", f)]
    gi = ctx.lines(".gitignore")
    ignored = bool(gi) and any(re.match(r"^\s*\.env", l) for l in gi)
    evidence = list(env_files)
    if env_files:
        status, summary = "FAIL", f"{len(env_files)} real .env file(s) present in the project"
    elif not gi:
        status, summary = "WARN", "No .gitignore found; secret files could be committed"
    elif not ignored:
        status, summary = "WARN", ".gitignore does not exclude .env files"
    else:
        status, summary = "PASS", ".env files are excluded from version control"
    return Finding(
        id="SEC-002", title="Environment / secret files kept out of version control",
        criteria="CC6.1", status=status, severity="high", summary=summary,
        evidence=evidence,
        recommendation="Add `.env` and `*.pem` / `*.key` to .gitignore, commit a `.env.example` "
                       "with placeholder values instead, and remove committed .env files from history.",
    )


def check_insecure_transport(ctx: Context) -> Finding:
    rx = r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|www\.w3\.org|json-schema\.org|schemas\.)[^\s'\"<>)]+"
    hits = ctx.grep(rx)
    evidence = [f"{r}:{n}" for r, n, _ in hits[:20]]
    return Finding(
        id="NET-001", title="Traffic uses TLS (no plain http:// endpoints)", criteria="CC6.7",
        status="WARN" if hits else "PASS", severity="medium",
        summary=(f"{len(hits)} plain http:// endpoint reference(s) to non-local hosts" if hits
                 else "No plain http:// endpoints to remote hosts found"),
        evidence=evidence,
        recommendation="Use https:// for all external and internal service calls that carry data.",
    )


def check_tls_verification(ctx: Context) -> Finding:
    rx = (r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|"
          r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|InsecureSkipVerify\s*:\s*true|"
          r"_create_unverified_context|CURLOPT_SSL_VERIFYPEER\s*,\s*(0|false)")
    hits = ctx.grep(rx)
    return Finding(
        id="NET-002", title="TLS certificate verification is never disabled", criteria="CC6.7",
        status="FAIL" if hits else "PASS", severity="high",
        summary=(f"TLS verification disabled in {len(hits)} place(s)" if hits
                 else "No disabled TLS verification found"),
        evidence=[f"{r}:{n}" for r, n, _ in hits[:20]],
        recommendation="Remove the override. Trust the system CA bundle, or pin a specific CA "
                       "for internal services.",
    )


def check_weak_crypto(ctx: Context) -> Finding:
    rx = (r"hashlib\.(md5|sha1)\(|createHash\(\s*['\"](md5|sha1)['\"]|"
          r"\bMD5\.|\bDES\b|\bRC4\b|crypto/md5|crypto/sha1|MessageDigest\.getInstance\(\s*['\"](MD5|SHA-?1)['\"]")
    hits = ctx.grep(rx)
    return Finding(
        id="SEC-010", title="No weak hashing or ciphers (MD5, SHA-1, DES, RC4)",
        criteria="CC6.1", status="WARN" if hits else "PASS", severity="medium",
        summary=(f"{len(hits)} use(s) of weak algorithms" if hits
                 else "No weak algorithms detected"),
        evidence=[f"{r}:{n}" for r, n, _ in hits[:20]],
        recommendation="Use SHA-256+ for integrity, bcrypt/argon2/scrypt for passwords, "
                       "and AES-GCM or ChaCha20-Poly1305 for encryption.",
    )


def check_insecure_random(ctx: Context) -> Finding:
    rx = (r"(?i)(token|secret|password|session|otp|nonce|api[_-]?key)"
          r".*(Math\.random\(|random\.(random|randint|choice)\()|"
          r"(Math\.random\(|random\.(random|randint|choice)\().*(?i:token|secret|password|session|otp|nonce)")
    hits = ctx.grep(rx)
    return Finding(
        id="SEC-011", title="Security tokens use a cryptographic random source",
        criteria="CC6.1", status="WARN" if hits else "PASS", severity="medium",
        summary=(f"{len(hits)} token/secret generation(s) use a non-cryptographic RNG" if hits
                 else "No non-cryptographic RNG used for secrets detected"),
        evidence=[f"{r}:{n}" for r, n, _ in hits[:20]],
        recommendation="Use `secrets` (Python), `crypto.randomBytes` / `crypto.randomUUID` (Node), "
                       "or `crypto/rand` (Go).",
    )


def check_dangerous_execution(ctx: Context) -> Finding:
    rx = (r"\beval\(|\bnew Function\(|(?<![\w.])exec\(|os\.system\(|shell\s*=\s*True|"
          r"child_process\.exec\(|dangerouslySetInnerHTML|pickle\.loads?\(|yaml\.load\((?!.*Loader)")
    hits = ctx.grep(rx)
    return Finding(
        id="SEC-020", title="No unsafe code execution or deserialization patterns",
        criteria="CC7.1", status="WARN" if hits else "PASS", severity="medium",
        summary=(f"{len(hits)} potentially unsafe call(s)" if hits
                 else "No unsafe execution patterns detected"),
        evidence=[f"{r}:{n}" for r, n, _ in hits[:20]],
        recommendation="Avoid eval/exec and shell=True with user input; use safe loaders "
                       "(yaml.safe_load, json) and review each remaining use.",
    )


def check_sql_injection(ctx: Context) -> Finding:
    rx = (r"(?i)(execute|query|raw|prepare)\(\s*f?['\"`].*\b(select|insert|update|delete)\b.*"
          r"(\+\s*\w|\$\{|\{[a-zA-Z_]\w*\}|%s\s*['\"`]\s*%|\"\s*\+|'\s*\+)")
    hits = ctx.grep(rx)
    return Finding(
        id="SEC-021", title="Database queries are parameterized", criteria="CC7.1",
        status="WARN" if hits else "PASS", severity="high",
        summary=(f"{len(hits)} query string(s) built by concatenation or interpolation" if hits
                 else "No string-built SQL detected"),
        evidence=[f"{r}:{n}" for r, n, _ in hits[:20]],
        recommendation="Use bound parameters (`?`, `%s`, `$1`) or an ORM query builder.",
    )


def check_lockfile(ctx: Context) -> Finding:
    manifests = ctx.find(r"(^|/)(package\.json|pyproject\.toml|requirements\.txt|Pipfile|"
                         r"Cargo\.toml|go\.mod|Gemfile|composer\.json|pom\.xml|build\.gradle)$")
    lockfiles = ctx.find(r"(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|"
                         r"poetry\.lock|Pipfile\.lock|uv\.lock|Cargo\.lock|go\.sum|Gemfile\.lock|"
                         r"composer\.lock|gradle\.lockfile)$")
    if not manifests:
        status, summary = "INFO", "No dependency manifest found; nothing to lock"
    elif lockfiles:
        status, summary = "PASS", "Dependency lockfile present"
    else:
        status, summary = "WARN", "Dependency manifest present but no lockfile"
    return Finding(
        id="DEP-001", title="Dependencies are pinned with a lockfile", criteria="CC8.1",
        status=status, severity="medium", summary=summary,
        evidence=manifests[:10],
        recommendation="Commit the lockfile produced by your package manager so builds are reproducible.",
    )


def check_dependency_scanning(ctx: Context) -> Finding:
    automated = ctx.has("dependabot.yml", "dependabot.yaml", "renovate.json", "renovate.json5",
                        ".renovaterc", ".renovaterc.json")
    ci = ctx.workflow_text()
    scanners = ["npm audit", "pip-audit", "safety check", "snyk", "trivy", "dependency-review",
                "osv-scanner", "grype", "bundle-audit", "cargo audit", "govulncheck"]
    in_ci = [s for s in scanners if s in ci]
    if automated or in_ci:
        status = "PASS"
        summary = "Automated dependency updates / vulnerability scanning configured"
    else:
        status = "FAIL"
        summary = "No dependency update bot or vulnerability scanner configured"
    evidence = (["dependabot/renovate config" if automated else ""] + in_ci)
    return Finding(
        id="DEP-002", title="Known-vulnerable dependencies are detected automatically",
        criteria="CC7.1", status=status, severity="high", summary=summary,
        evidence=[e for e in evidence if e],
        recommendation="Enable Dependabot or Renovate, and add a scanner (npm audit, pip-audit, "
                       "Trivy, OSV-Scanner or GitHub dependency-review) to CI.",
    )


def check_ci_pipeline(ctx: Context) -> Finding:
    ci_files = ctx.find(r"^\.github/workflows/.+\.ya?ml$|^\.gitlab-ci\.yml$|^\.circleci/config\.yml$|"
                        r"^Jenkinsfile$|^azure-pipelines\.yml$|^bitbucket-pipelines\.yml$")
    return Finding(
        id="CHG-001", title="Automated build pipeline runs on every change", criteria="CC8.1",
        status="PASS" if ci_files else "FAIL", severity="high",
        summary=(f"{len(ci_files)} CI pipeline file(s) found" if ci_files
                 else "No CI pipeline configuration found"),
        evidence=ci_files[:10],
        recommendation="Add a CI workflow (e.g. GitHub Actions) that builds, tests and lints every pull request.",
    )


def check_tests(ctx: Context) -> Finding:
    test_files = ctx.find(r"(^|/)(tests?|__tests__|spec)/|\.(test|spec)\.[a-z]+$|(^|/)test_[^/]+\.py$|"
                          r"_test\.(go|py|rb)$")
    ci = ctx.workflow_text()
    runs_tests = bool(re.search(r"\btest\b|pytest|jest|vitest|mocha|go test|rspec|cargo test|mvn test", ci))
    if test_files and runs_tests:
        status, summary = "PASS", f"{len(test_files)} test file(s), executed by CI"
    elif test_files:
        status, summary = "WARN", f"{len(test_files)} test file(s) found, but CI does not appear to run them"
    else:
        status, summary = "FAIL", "No automated tests found"
    return Finding(
        id="CHG-002", title="Automated tests exist and run in CI", criteria="CC8.1",
        status=status, severity="high", summary=summary, evidence=test_files[:10],
        recommendation="Add unit/integration tests for security-relevant code (auth, authz, input "
                       "validation) and run them in CI.",
    )


def check_code_review_controls(ctx: Context) -> Finding:
    has_owners = ctx.has("CODEOWNERS") or ctx.find(r"^\.github/CODEOWNERS$|^docs/CODEOWNERS$")
    has_pr_template = ctx.find(r"(^|/)\.github/(pull_request_template\.md|PULL_REQUEST_TEMPLATE/.+)$")
    found = bool(has_owners) or bool(has_pr_template)
    evidence = (list(has_owners) if isinstance(has_owners, list) else []) + has_pr_template
    return Finding(
        id="CHG-003", title="Changes are reviewed (ownership and PR template)", criteria="CC8.1",
        status="PASS" if found else "WARN", severity="medium",
        summary=("Review ownership or PR template configured" if found
                 else "No CODEOWNERS or pull request template found"),
        evidence=evidence[:10],
        recommendation="Add a CODEOWNERS file and a PR template. Also enable branch protection that "
                       "requires review (this cannot be verified from files alone).",
    )


def check_static_analysis(ctx: Context) -> Finding:
    ci = ctx.workflow_text()
    tools = ["codeql", "semgrep", "eslint", "ruff", "flake8", "pylint", "bandit", "sonar",
             "golangci", "biome", "rubocop", "clippy", "spotbugs", "gitleaks", "trufflehog", "tflint"]
    found = [t for t in tools if t in ci]
    return Finding(
        id="CHG-004", title="Static analysis / linting runs in CI", criteria="CC7.1",
        status="PASS" if found else "WARN", severity="medium",
        summary=(f"Static analysis in CI: {', '.join(found)}" if found
                 else "No linter or static security analysis detected in CI"),
        evidence=found,
        recommendation="Run a linter plus a SAST tool (CodeQL, Semgrep, Bandit) and a secret scanner "
                       "(gitleaks) on every pull request.",
    )


def check_logging(ctx: Context) -> Finding:
    rx = (r"\bimport logging\b|from logging import|\bwinston\b|\bpino\b|\bstructlog\b|\bloguru\b|"
          r"\blog4j\b|\bslf4j\b|\bzap\.|log/slog|\bsentry\b|@sentry|\bdatadog\b|opentelemetry|"
          r"\bnewrelic\b|aws-xray|cloudwatch|\bbunyan\b|\bconsola\b")
    hits = ctx.grep(rx, flags=re.IGNORECASE)
    files = sorted({r for r, _, _ in hits})
    return Finding(
        id="OPS-001", title="Application logging / monitoring instrumented", criteria="CC7.2",
        status="PASS" if hits else "WARN", severity="medium",
        summary=(f"Logging or monitoring used in {len(files)} file(s)" if hits
                 else "No structured logging or monitoring library detected"),
        evidence=files[:10],
        recommendation="Use a structured logger and an error/APM tool (Sentry, Datadog, CloudWatch, "
                       "OpenTelemetry). Never log secrets or personal data.",
    )


def check_security_policy(ctx: Context) -> Finding:
    found = ctx.find(r"(^|/)(SECURITY|security)\.(md|txt|rst)$")
    return Finding(
        id="GOV-001", title="Security policy and vulnerability disclosure process",
        criteria="CC2.3", status="PASS" if found else "WARN", severity="medium",
        summary="SECURITY policy found" if found else "No SECURITY.md / vulnerability disclosure policy",
        evidence=found,
        recommendation="Add SECURITY.md describing how to report vulnerabilities and expected response times.",
    )


def check_incident_response(ctx: Context) -> Finding:
    by_name = ctx.find(r"(^|/)[^/]*(incident|runbook)[^/]*\.(md|txt|rst|adoc)$", re.IGNORECASE)
    by_text = ctx.grep(r"incident response|incident management|post-?mortem", flags=re.IGNORECASE, files=[
        f for f in ctx.files if f.lower().endswith((".md", ".txt", ".rst"))])
    evidence = sorted(set(by_name) | {r for r, _, _ in by_text})
    return Finding(
        id="GOV-002", title="Incident response plan documented", criteria="CC7.3 / CC7.4",
        status="PASS" if evidence else "WARN", severity="medium",
        summary=("Incident response documentation found" if evidence
                 else "No incident response plan or runbook found"),
        evidence=evidence[:10],
        recommendation="Document detection, triage, escalation, containment, communication and "
                       "post-incident review steps. Test it at least once a year.",
    )


def check_backups(ctx: Context) -> Finding:
    by_name = ctx.find(r"(^|/)[^/]*(backup|restore|disaster|dr-plan)[^/]*$", re.IGNORECASE)
    by_text = ctx.grep(r"\bpg_dump\b|point[_-]in[_-]time[_-]recovery|backup_retention|"
                       r"\bsnapshot_identifier\b|backup_policy|versioning\s*\{|enabled\s*=\s*true.*backup",
                       files=ctx.source_files(), flags=re.IGNORECASE)
    evidence = sorted(set(by_name) | {r for r, _, _ in by_text})
    return Finding(
        id="AVL-001", title="Backups and recovery configured", criteria="A1.2",
        status="PASS" if evidence else "WARN", severity="medium",
        summary=("Backup or recovery configuration found" if evidence
                 else "No backup or disaster recovery configuration found"),
        evidence=evidence[:10],
        recommendation="Enable automated backups with retention, and document/test restores "
                       "(a restore test is evidence auditors ask for).",
    )


def check_container_hardening(ctx: Context) -> Finding:
    dockerfiles = ctx.find(r"(^|/)(Dockerfile|Dockerfile\.[^/]+|Containerfile)$")
    if not dockerfiles:
        return Finding(
            id="INF-001", title="Container images hardened (pinned tags, non-root user)",
            criteria="CC6.1 / CC7.1", status="INFO", severity="low",
            summary="No Dockerfile found", evidence=[],
            recommendation="n/a")
    problems: List[str] = []
    for df in dockerfiles:
        lines = ctx.lines(df) or []
        froms = [l for l in lines if re.match(r"^\s*FROM\s+", l, re.I)]
        for l in froms:
            img = re.split(r"\s+", l.strip())[1] if len(l.split()) > 1 else ""
            if img.endswith(":latest") or (":" not in img and "@" not in img and img.lower() != "scratch"):
                problems.append(f"{df}: unpinned base image '{img}'")
        if not any(re.match(r"^\s*USER\s+(?!root\b|0\b)", l, re.I) for l in lines):
            problems.append(f"{df}: no non-root USER directive")
    return Finding(
        id="INF-001", title="Container images hardened (pinned tags, non-root user)",
        criteria="CC6.1 / CC7.1", status="WARN" if problems else "PASS", severity="medium",
        summary=(f"{len(problems)} container hardening issue(s)" if problems
                 else "Container images pin versions and run as non-root"),
        evidence=problems[:20],
        recommendation="Pin base images to a version or digest, and add `USER` with a non-root uid.",
    )


def check_privacy_docs(ctx: Context) -> Finding:
    found = ctx.find(r"(^|/)(privacy|data[-_ ]?retention|data[-_]?classification)[^/]*\.(md|txt)$", re.IGNORECASE)
    return Finding(
        id="CONF-001", title="Data handling / retention policy documented", criteria="C1.1 / P (privacy)",
        status="PASS" if found else "WARN", severity="low",
        summary="Data retention or privacy documentation found" if found
        else "No data retention or privacy documentation found",
        evidence=found[:10],
        recommendation="Document what data you collect, where it lives, how long you keep it, and how it is deleted.",
    )


CHECKS: List[Callable[[Context], Finding]] = [
    check_secrets_in_code,
    check_env_files,
    check_insecure_transport,
    check_tls_verification,
    check_weak_crypto,
    check_insecure_random,
    check_dangerous_execution,
    check_sql_injection,
    check_lockfile,
    check_dependency_scanning,
    check_ci_pipeline,
    check_tests,
    check_code_review_controls,
    check_static_analysis,
    check_logging,
    check_security_policy,
    check_incident_response,
    check_backups,
    check_container_hardening,
    check_privacy_docs,
]

MANUAL_EVIDENCE = [
    "MFA enforced for all staff and production access (CC6.1, CC6.2)",
    "Quarterly user access reviews with sign-off (CC6.2, CC6.3)",
    "Joiner / mover / leaver (onboarding and offboarding) process with evidence (CC6.2)",
    "Branch protection on the default branch requiring reviews and passing checks (CC8.1)",
    "Encryption at rest for databases, object storage and backups (CC6.1, C1.1)",
    "Annual third-party penetration test and remediation tracking (CC4.1, CC7.1)",
    "Vendor / subprocessor risk assessments (CC9.2)",
    "Written information security policies approved and reviewed annually (CC1.x, CC5.x)",
    "Security awareness training completion records (CC1.4)",
    "Change management tickets linked to deployments (CC8.1)",
    "Restore test evidence for backups (A1.2)",
    "Logs retained and protected from tampering, with alerting (CC7.2)",
]

RANK = {"PASS": 1.0, "INFO": None, "WARN": 0.5, "FAIL": 0.0}


def run_checks(root: str) -> dict:
    files = collect_files(root)
    ctx = Context(root=root, files=files)
    findings = [check(ctx) for check in CHECKS]
    scored = [RANK[f.status] for f in findings if RANK[f.status] is not None]
    score = round(100 * sum(scored) / len(scored)) if scored else 0
    fails = sum(1 for f in findings if f.status == "FAIL")
    warns = sum(1 for f in findings if f.status == "WARN")
    if fails:
        verdict = "NOT READY"
    elif warns:
        verdict = "PARTIALLY READY"
    else:
        verdict = "READY (automated checks)"
    return {
        "tool": "soc2-compliance-check",
        "version": __version__,
        "target": os.path.abspath(root),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "files_scanned": len(files),
        "score": score,
        "verdict": verdict,
        "counts": {s: sum(1 for f in findings if f.status == s) for s in ("PASS", "WARN", "FAIL", "INFO")},
        "findings": [asdict(f) for f in findings],
        "manual_evidence_required": MANUAL_EVIDENCE,
        "disclaimer": ("Heuristic static readiness check. It is not a SOC 2 audit, does not certify "
                       "compliance, and cannot verify policies, people processes or cloud settings."),
    }


def render_text(report: dict) -> str:
    icon = {"PASS": "[PASS]", "WARN": "[WARN]", "FAIL": "[FAIL]", "INFO": "[INFO]"}
    out = [
        "SOC 2 Readiness Check",
        "=" * 60,
        f"Target:      {report['target']}",
        f"Files:       {report['files_scanned']} scanned",
        f"Score:       {report['score']}/100",
        f"Verdict:     {report['verdict']}",
        f"Results:     {report['counts']['PASS']} pass, {report['counts']['WARN']} warn, "
        f"{report['counts']['FAIL']} fail",
        "",
    ]
    for f in report["findings"]:
        out.append(f"{icon[f['status']]} {f['id']}  {f['title']}  ({f['criteria']})")
        out.append(f"        {f['summary']}")
        for ev in f["evidence"][:5]:
            out.append(f"          - {ev}")
        if len(f["evidence"]) > 5:
            out.append(f"          ... and {len(f['evidence']) - 5} more")
        if f["status"] in ("WARN", "FAIL"):
            out.append(f"        Fix: {f['recommendation']}")
        out.append("")
    out.append("Manual evidence auditors will also need (not verifiable from files):")
    out += [f"  [ ] {item}" for item in report["manual_evidence_required"]]
    out += ["", report["disclaimer"]]
    return "\n".join(out)


def render_markdown(report: dict) -> str:
    c = report["counts"]
    out = [
        "# SOC 2 Readiness Report",
        "",
        f"- **Target:** `{report['target']}`",
        f"- **Generated:** {report['generated_at']}",
        f"- **Score:** {report['score']}/100",
        f"- **Verdict:** **{report['verdict']}**",
        f"- **Results:** {c['PASS']} pass · {c['WARN']} warn · {c['FAIL']} fail",
        "",
        "| ID | Check | Criteria | Status | Summary |",
        "|----|-------|----------|--------|---------|",
    ]
    for f in report["findings"]:
        out.append(f"| {f['id']} | {f['title']} | {f['criteria']} | {f['status']} | {f['summary']} |")
    out += ["", "## Details", ""]
    for f in report["findings"]:
        if f["status"] in ("WARN", "FAIL"):
            out.append(f"### {f['id']} {f['title']} — {f['status']}")
            out.append(f"**Fix:** {f['recommendation']}")
            for ev in f["evidence"][:20]:
                out.append(f"- `{ev}`")
            out.append("")
    out += ["## Manual evidence required", ""]
    out += [f"- [ ] {item}" for item in report["manual_evidence_required"]]
    out += ["", f"> {report['disclaimer']}", ""]
    return "\n".join(out)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Quick, heuristic SOC 2 readiness check for a repo, project or app folder.")
    parser.add_argument("path", nargs="?", default=".", help="folder to scan (default: current directory)")
    parser.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    parser.add_argument("--output", "-o", help="write the report to this file instead of stdout")
    parser.add_argument("--fail-on", choices=["fail", "warn", "never"], default="fail",
                        help="exit 1 on FAIL (default), on WARN too, or never")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    if not os.path.isdir(args.path):
        print(f"error: '{args.path}' is not a directory", file=sys.stderr)
        return 2

    report = run_checks(args.path)
    if args.format == "json":
        rendered = json.dumps(report, indent=2)
    elif args.format == "markdown":
        rendered = render_markdown(report)
    else:
        rendered = render_text(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(rendered + "\n")
        print(f"Report written to {args.output} (verdict: {report['verdict']}, score {report['score']}/100)")
    else:
        print(rendered)

    if args.fail_on == "never":
        return 0
    if report["counts"]["FAIL"]:
        return 1
    if args.fail_on == "warn" and report["counts"]["WARN"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
