# Verifact 👁️

**Evidence-backed Windows security assessment for AI agents.**

Verifact is a skill for AI agents. It performs a bounded, read-only security assessment of one authorized Windows computer.

Verifact checks recorded Windows activity and current system configuration. It creates a local HTML report with findings, supporting evidence, and coverage limits.

Verifact validates a finding only after it checks the supporting evidence and completes a second review.

The report also keeps rejected and inconclusive leads. This shows what Verifact investigated and what the available evidence supports.

## What Verifact checks

Verifact uses evidence that already exists on the computer. It does not enable logging or install additional collectors.

### Windows activity

By default, Verifact reads up to 120 days of available Windows event history.

It can use these Windows logs:

- Security
- System and Application
- PowerShell
- Remote Desktop
- Task Scheduler
- WMI
- WinRM
- Windows Firewall
- AppLocker
- Code Integrity
- Sysmon, when it already exists and is enabled

These logs can show sign-ins, account changes, privilege use, process activity, services, scheduled tasks, remote access, and other security-relevant activity.

If a relevant log is disabled, missing, or inaccessible, Verifact records the problem as a coverage limit.

### Current endpoint configuration

Verifact also checks the current security posture of the computer.

It can examine:

- Local users, local groups, password policy, lockout policy, and user rights
- Audit policy and security-relevant event log configuration
- Services, scheduled tasks, startup folders, startup commands, Run and RunOnce keys, and WMI subscriptions
- Firewall profiles, inbound allow rules, TCP listeners, UDP listeners, Remote Desktop, and WinRM
- SMB shares, share permissions, and permissions on important local paths
- UAC, LSA settings, anonymous access, SMB signing, SMBv1, and PowerShell v2
- Windows version, installed updates, pending restart indicators, and security-relevant installed software

Verifact can use different evidence sources together when a finding needs more than one type of evidence.

## How Verifact works

After you start Verifact, the agent runs the full assessment for you.

### 1. Collect

The agent runs the collection. Windows can request Administrator approval to read protected security data.

Verifact collects Windows events and endpoint configuration without changing the assessed computer.

### 2. Verify

Verifact checks the selected evidence before analysis.

The assessment stops if an evidence integrity check fails.

A verified collection can continue with known gaps. Verifact shows these gaps in the final report.

### 3. Investigate

The agent examines the evidence for security-relevant activity, exposure, persistence, permissions, hardening, updates, and related conditions.

For each possible issue, Verifact defines a specific claim. It then checks the conditions that must support that claim.

Each supported host fact must point to local evidence. The evidence reference identifies the exact record that supports the fact.

### 4. Review

Verifact reviews each candidate finding before final publication.

The review checks missing conditions, contradictory evidence, reasonable benign explanations, severity, confidence, and evidence references.

When possible, Verifact uses a separate reviewer context.

Otherwise, the same agent performs a separate challenge pass. Verifact records this review method in the assessment.

### 5. Build and verify

Verifact validates the completed assessment before it builds the report.

It then creates the local HTML report.

A final check makes sure that the report matches the assessment data used to build it.

## Finding results

Verifact keeps the result of each reviewed lead.

- **Validated:** The evidence supports the finding after review.
- **Rejected:** The available evidence does not support the lead.
- **Inconclusive:** The available evidence cannot resolve the lead.

The report keeps rejected and inconclusive leads. You can see what Verifact investigated and why each lead received its result.

Severity describes the possible security impact and exposure.

Confidence describes the strength and completeness of the supporting evidence.

## Evidence and coverage

Each validated finding includes a reference to the local evidence that supports it.

Verifact also records evidence gaps. Missing core logs lower assessment coverage.

An empty log can still provide useful evidence when Verifact collects it successfully. The report identifies collection failures separately.

Verifact can use authoritative public sources to explain documented Windows behavior or required conditions.

Verifact keeps sensitive endpoint data out of external research queries.

## What you get

Verifact creates a local HTML dashboard for the completed assessment.

The report includes:

- The assessed computer and collection scope
- Validated findings with supporting evidence
- Rejected and inconclusive leads
- Coverage status and important collection limits
- Review information and report verification status

By default, Verifact stores assessments under:

```text
%LOCALAPPDATA%\Verifact\Assessments\<computer>-<UTC timestamp>
```

The final dashboard is:

```text
report\index.html
```

## Install

### Codex

Send this instruction to Codex:

```text
Use $skill-installer to install https://github.com/Rayan-and-beyond/Verifact/tree/main/.agents/skills/verifact
```

Restart Codex if it asks you to.

### Claude Code

Claude Code loads personal skills from:

```text
~/.claude/skills/<skill-name>/SKILL.md
```

Copy the `.agents/skills/verifact` folder to:

```text
~/.claude/skills/verifact
```

Make sure that this file exists:

```text
~/.claude/skills/verifact/SKILL.md
```

If you created the `~/.claude/skills` directory, restart Claude Code.

### Other agent CLIs

Install the `.agents/skills/verifact` folder with the normal skill installation method for your agent.

## Use

Run Verifact on the Windows computer that you want to assess.

### Codex

Tell Codex:

```text
Use $verifact to assess this authorized Windows computer end to end.
```

### Claude Code

Run:

```text
/verifact assess this authorized Windows computer end to end.
```

Verifact uses a 120-day event window by default.

You can request a shorter window when you start the assessment.

For example:

```text
Use $verifact to assess this authorized Windows computer for the last 30 days.
```

## Requirements

- Windows 10 or 11
- PowerShell 5.1 or later
- Python 3.10 or later
- An agent CLI that supports skills and terminal access
- Permission to assess the computer

## Safety and limits

- Verifact assesses only the authorized Windows computer where the agent runs.
- Collection is read-only.
- Verifact does not change logging, audit policy, Defender, services, tasks, firewall rules, accounts, or permissions.
- Verifact checks one Windows computer at a time.
- Verifact does not provide continuous monitoring, antivirus, EDR, malware detonation, exploitation, or remediation.
- Verifact does not use Microsoft Defender-specific collectors or Defender telemetry for findings.
- A Verifact assessment cannot prove that a computer is secure or uncompromised.
- Reports can contain sensitive system data. Keep them private.

Current release: `2.0.0` · MIT License
