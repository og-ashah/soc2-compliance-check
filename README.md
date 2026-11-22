# SOC 2 Compliance Readiness Check

[![CI](https://github.com/og-ashah/soc2-compliance-check/actions/workflows/ci.yml/badge.svg)](https://github.com/og-ashah/soc2-compliance-check/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

**Point it at any repo, project or app folder and get a 60-second SOC 2 readiness report.**
It checks the controls auditors look at first (secrets, TLS, access to code, change management,
dependency scanning, logging, incident response, backups) and gives you a prioritized fix list.

It ships as:

- **A Python CLI** (`soc2_check.py`, Python 3.8+): standard library only, no `pip install`, works in CI.
- **A Claude skill** (`skills/soc2-compliance-check/`): ask Claude "is this repo SOC 2 ready?" and it runs the check, verifies the findings and explains the fixes.

> ⚠️ **This is not a SOC 2 audit or certification.** SOC 2 is an attestation performed by a licensed CPA
> firm over time. This tool checks what can be verified from files. It cannot check policies in practice,
> MFA, access reviews, cloud console settings or penetration tests. The report lists those as manual evidence.

## Quick start

```bash
git clone https://github.com/og-ashah/soc2-compliance-check.git
cd soc2-compliance-check
python3 skills/soc2-compliance-check/scripts/soc2_check.py /path/to/your/project
```

Save a report or use it as a CI gate:

```bash
# Markdown report for reviewers
python3 skills/soc2-compliance-check/scripts/soc2_check.py ./my-app --format markdown -o soc2-report.md

# JSON for dashboards; fail the build on any FAIL (default) or on WARN too
python3 skills/soc2-compliance-check/scripts/soc2_check.py ./my-app --format json -o soc2.json --fail-on warn
```

Exit codes: `0` no failures · `1` at least one FAIL (or WARN with `--fail-on warn`) · `2` bad path.

## Sample output

```
SOC 2 Readiness Check
============================================================
Score:       35/100
Verdict:     NOT READY
Results:     0 pass, 14 warn, 6 fail

[FAIL] SEC-001  No hard-coded secrets in source  (CC6.1)
          - src/config.js:1 (hard-coded credential)
        Fix: Move secrets to environment variables or a secrets manager ...
[FAIL] NET-002  TLS certificate verification is never disabled  (CC6.7)
          - src/config.js:6
          - src/report.py:5
...
```

Try it on the included examples:

```bash
python3 skills/soc2-compliance-check/scripts/soc2_check.py examples/compliant-app     # READY, 100/100
python3 skills/soc2-compliance-check/scripts/soc2_check.py examples/noncompliant-app  # NOT READY, 35/100
```

## What it checks

| ID | Check | Trust Services Criteria |
|----|-------|-------------------------|
| SEC-001 | Hard-coded secrets (AWS keys, private keys, GitHub/Slack tokens, `password=`/`api_key=` literals) | CC6.1 |
| SEC-002 | `.env` / secret files kept out of git | CC6.1 |
| NET-001 | No plain `http://` to remote hosts | CC6.7 |
| NET-002 | TLS verification never disabled | CC6.7 |
| SEC-010 | No MD5 / SHA-1 / DES / RC4 | CC6.1 |
| SEC-011 | Tokens generated with a cryptographic RNG | CC6.1 |
| SEC-020 | No `eval`, `exec`, `shell=True`, unsafe YAML/pickle loads | CC7.1 |
| SEC-021 | SQL queries parameterized | CC7.1 |
| DEP-001 | Lockfile committed | CC8.1 |
| DEP-002 | Dependabot/Renovate or a vulnerability scanner configured | CC7.1 |
| CHG-001 | CI pipeline present | CC8.1 |
| CHG-002 | Automated tests present and run in CI | CC8.1 |
| CHG-003 | CODEOWNERS or PR template | CC8.1 |
| CHG-004 | Linter / SAST / secret scanning in CI | CC7.1 |
| OPS-001 | Structured logging or monitoring instrumented | CC7.2 |
| GOV-001 | SECURITY.md / vulnerability disclosure | CC2.3 |
| GOV-002 | Incident response plan documented | CC7.3 / CC7.4 |
| AVL-001 | Backup / recovery configuration or docs | A1.2 |
| INF-001 | Docker images pinned and running as non-root | CC6.1 / CC7.1 |
| CONF-001 | Data retention / privacy documentation | C1.1 / P |

The report also lists the **manual evidence** auditors will ask for: MFA, quarterly access reviews,
joiner/leaver process, branch protection, encryption at rest, pen tests, vendor reviews, policies and training.

## Install as a Claude skill

Copy the skill folder into your Claude skills directory:

```bash
mkdir -p ~/.claude/skills
cp -R skills/soc2-compliance-check ~/.claude/skills/
```

Then ask Claude: *"Check whether this repo follows SOC 2 security practices."*

## Reducing false positives

Heuristics can misfire on test fixtures or docs. Add `soc2-ignore` to a line to skip it:

```python
KEY = "AKIA..."  # soc2-ignore: test fixture
```

Skipped folders: `node_modules`, `.git`, `vendor`, `venv`, `dist`, `build`, `target`, and similar. Files over 1 MB and binary files are skipped.

## Development

```bash
python3 -m unittest discover -s tests -v
```

Each check is a small function in `skills/soc2-compliance-check/scripts/soc2_check.py`. Add one, append it to `CHECKS`, and add a test. Pull requests are welcome.

## Limitations

- Static and heuristic. It can miss things (false negatives) and flag harmless code (false positives).
- It does not read cloud accounts, GitHub settings, identity providers or running systems.
- Scores and verdicts describe automated-check coverage, not audit outcome.

## License

MIT. See [LICENSE](LICENSE).
