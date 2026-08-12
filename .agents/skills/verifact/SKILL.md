---
name: verifact
description: Perform an end-to-end, bounded, read-only security assessment of the current Windows computer. Use when the user asks to inspect Windows event activity, endpoint posture, persistence, exposure, permissions, hardening, updates, or local security evidence. Do not use for continuous monitoring, exploitation, remediation, or malware detonation.
license: MIT
---

# Verifact

Own the assessment from invocation to verified report. The user is not the operator.

## Interaction contract

- Run every Verifact command yourself. Never tell the user to initialize, collect, select, normalize, validate, or build.
- Use safe defaults. Do not ask the user to choose routine paths, run IDs, or options.
- Ask only when authorization is unclear, the target is not the current computer, an OS permission prompt needs approval, or a required dependency is missing.
- If authorization is explicit in the request, do not ask again.
- Keep the user informed with short progress updates and return the final report path.
- If a step fails, diagnose and retry safely. Never hide a failed or degraded collection.

## Non-negotiable rules

1. Assess only the authorized, current Windows endpoint.
2. Keep collection read-only. Never change logging, audit policy, Defender, services, tasks, firewall rules, accounts, permissions, or other endpoint state.
3. Treat raw evidence as immutable. Verify selected runs and cited hashes before analysis.
4. Do not use Defender-specific collectors or Defender telemetry for findings. Ignore incidental Defender rows.
5. Separate observed facts from claims. Capability does not prove execution, persistence, exploitation, or compromise.
6. Every validated host claim needs local, hash-bound evidence with a resolvable locator.
7. Keep severity separate from confidence. Keep rejected and inconclusive results.
8. Missing core evidence lowers coverage. It is never a clean result.
9. Prefer a different human or isolated agent for review. If unavailable, use a clearly labeled same-agent adversarial pass. Reviewer identity is self-attested, not cryptographically proven.
10. Never say Verifact proves that a host is secure or uncompromised.
11. Keep endpoint data local and out of external research queries.

## End-to-end workflow

Track these steps and do not stop early:

- [ ] Prepare
- [ ] Collect and normalize
- [ ] Investigate
- [ ] Review
- [ ] Build and verify
- [ ] Deliver

### 1. Prepare

Resolve all paths from this `SKILL.md`. Read `references/METHODOLOGY.md` and `references/CLAIM-CONTRACT.md` before interpreting evidence.

Confirm the runtime is Windows and check PowerShell and Python versions. If a dependency is missing, report the exact blocker; do not silently install software because that would change the endpoint.

Unless the user supplied a path, create a unique assessment path under:

```text
%LOCALAPPDATA%\Verifact\Assessments\<computer>-<UTC timestamp>
```

Use the current computer name as the target label and a 120-day event window unless the user requested a narrower scope.

### 2. Collect and normalize

Run the bundled orchestration script yourself:

```powershell
powershell.exe -NoProfile -File "<skill-root>\scripts\windows\Invoke-VerifactCollection.ps1" -AssessmentPath "<assessment>" -TargetLabel "$env:COMPUTERNAME" -EventDays 120
```

The script initializes the assessment, requests elevation, collects both evidence families, freezes and verifies the runs, and creates normalized analysis views. The user may need to approve the Windows elevation dialog, but must not type commands.

Stop and explain if integrity verification fails. A verified degraded run may continue, but its gaps must remain visible.

### 3. Investigate

Read the selected run paths from `assessment.json`. Start with each derived `summary.json`, then inspect:

- event activity: `derived/triage/events.jsonl`
- posture: `derived/inventory/*.json`
- collection and normalization limits: the manifests, summaries, and `derived/inventory/artifact-status.csv`

For every plausible issue:

1. State one bounded claim.
2. List material conditions as `host-fact` or `external-prerequisite`.
3. Mark each condition `established`, `missing`, or `unknown`.
4. Attach local evidence to every established host fact.
5. Test benign explanations and contradictory evidence.
6. Set severity from impact and exposure; set confidence from evidence quality.
7. Write the result to `findings/<finding-id>.json` using `schemas/finding.schema.json`.

Use `runKind` `events` or `posture`. Use resolvable locators: `line=<n>;channel=<name>;recordId=<id>` for event JSONL, `json-pointer=/...` for JSON, `line=<n>` for other JSONL or text, and `row=<n>` for CSV. Cite normalized evidence, not EVTX directly.

Use authoritative external research only for documented behavior or prerequisites. Research cannot prove what happened on the host.

If the evidence supports no candidate, keep the findings directory empty. Do not invent a clean bill of health.

### 4. Review

For each candidate, create a fresh isolated reviewer context when the host supports subagents, tasks, or subprocesses. Give it the skill path and assessment path, but not the analyst's reasoning beyond the finding and evidence. The reviewer must:

- verify cited files, hashes, and locators;
- challenge missing prerequisites, contradictions, benign alternatives, severity, confidence, and remediation;
- write `reviews/<finding-id>.json` using `schemas/review.schema.json`;
- bind `findingSha256` to the exact final finding bytes;
- use a reviewer identity different from the analyst;
- set `identityAssurance` to `unverified-self-attestation`; never claim the reviewer identity was verified;
- set the finding to `validated`, `rejected`, or `inconclusive` consistently with its decision.

If no isolated reviewer is available, perform a distinct adversarial pass yourself and set `independence` to `same-agent-separated-pass`. Do not call it independent. Finish the workflow without asking the user to run commands.

After review, run validation yourself. Fix contract errors, then validate again:

```powershell
py "<skill-root>\scripts\verifact.py" validate "<assessment>"
```

Use `python` instead of `py` only when the Windows launcher is unavailable.

### 5. Build and verify

Run all three commands yourself:

```powershell
py "<skill-root>\scripts\verifact.py" validate "<assessment>"
py "<skill-root>\scripts\verifact.py" build "<assessment>"
py "<skill-root>\scripts\verifact.py" verify-report "<assessment>"
```

Open candidates block final publication. Fix the assessment rather than bypassing validation.

### 6. Deliver

Open the local report when the host supports it. Return:

- the assessment path;
- `report\index.html`;
- the number of validated, rejected, and inconclusive findings;
- coverage status and its material limits;
- whether declared review separation completed, that reviewer identity remains self-attested, and whether report verification passed.

Use precise language such as “the collected evidence establishes” or “does not establish.”
