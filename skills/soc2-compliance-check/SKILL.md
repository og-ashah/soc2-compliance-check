---
name: soc2-compliance-check
description: Quickly check whether a repository, project or app folder follows SOC 2 (AICPA Trust Services Criteria) security readiness practices. Use when the user asks whether a codebase is SOC 2 compliant or ready, wants a SOC 2 / security-compliance readiness check, asks about audit readiness for CC6/CC7/CC8 controls, or wants to know what to fix before a SOC 2 audit. Runs a bundled static checker and turns the results into a prioritized fix list.
---

# SOC 2 Compliance Readiness Check

This skill runs a fast, static readiness scan of a folder and explains the results in plain language.

> **Important:** SOC 2 is an attestation performed by a licensed CPA firm over a period of time. No script can certify SOC 2 compliance. This skill tells you which *automatically verifiable* controls look good and which look like gaps, and lists the evidence an auditor will still ask for. Always say this to the user.

## When to use

- "Is this repo SOC 2 compliant?" / "Are we audit-ready?"
- "Check this project against SOC 2 / security controls"
- "What do we need to fix before a SOC 2 audit?"

## Steps

1. **Identify the target folder.** Use the folder the user names. If they say "this project" or "this repo", use the current working directory. Do not scan the home directory or system folders.

2. **Run the checker** (read-only; it writes nothing unless `--output` is given):

   ```bash
   python3 "${CLAUDE_SKILL_DIR}/scripts/soc2_check.py" "<target-folder>"
   ```

   If `${CLAUDE_SKILL_DIR}` is not set, use the path to `scripts/soc2_check.py` inside this skill's folder. For a saved report, add `--format markdown --output soc2-report.md` (or `--format json`). The script needs only Python 3.8+ and no packages.

3. **Read the output and group it by severity:**
   - **FAIL** (fix first): hard-coded secrets, committed `.env` files, TLS verification disabled, no CI pipeline, no automated tests, no dependency vulnerability scanning.
   - **WARN** (fix before audit): weak hashing, unsafe RNG for tokens, string-built SQL, missing lockfile, missing linting/SAST, no logging/monitoring, no SECURITY.md, no incident response plan, no backups config, container hardening gaps.
   - **PASS**: say briefly what is already in place.

4. **Verify before you report a finding as real.** Heuristic matches can be false positives. For each FAIL or WARN you plan to call out, open the cited `file:line` and confirm it is real. If a match is a test fixture or placeholder, say so and suggest adding a `soc2-ignore` comment on that line.

5. **Give a prioritized fix list.** Put the highest-risk items first, with the concrete change for each (the script's `Fix:` line is a starting point). Offer to make the fixes if the user wants, but do not change files without being asked.

6. **List the manual evidence.** The report ends with items the script cannot check (MFA, access reviews, penetration tests, policies, training, branch protection, encryption at rest). Tell the user these must be gathered from their identity provider, cloud console, GitHub settings and HR/policy systems.

7. **Report the verdict and score** exactly as the script prints them (`NOT READY`, `PARTIALLY READY`, or `READY (automated checks)`), along with the disclaimer that this is not an audit.

## Output template

```
SOC 2 readiness: <verdict> (<score>/100) for <target>

Fix first (FAIL):
1. <ID> <title> — <file:line> — <concrete fix>

Fix before audit (WARN):
1. ...

Already in place (PASS): <short list>

Still needed from people and systems (manual): <short list>

This is a heuristic readiness check, not a SOC 2 audit or certification.
```

## Notes

- Criteria references (CC6.1, CC7.2, A1.2 and so on) refer to the AICPA 2017 Trust Services Criteria. Use them to point the user to the right control family.
- The checker skips `node_modules`, `.git`, `vendor`, `venv`, `dist`, `build` and binary or very large files.
- Exit code `1` means at least one FAIL (or a WARN with `--fail-on warn`); this makes it usable as a CI gate.
