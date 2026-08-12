# 👁️ Verifact

Verifact is an Agent Skill that checks a Windows computer for suspicious activity, risky security settings, exposed services, and ways software can start automatically.

When you start an assessment, your AI agent gathers read-only evidence from the computer, investigates it, reviews each potential finding, and creates a local HTML report that explains what it found and why.

## What it checks

- Sign-ins, account changes, privileged activity, and remote sessions
- PowerShell, processes, services, scheduled tasks, WMI, and WinRM activity
- Local users, administrators, password rules, and audit policy
- Startup entries and other persistence locations
- Firewall rules, listening ports, Remote Desktop, WinRM, and SMB shares
- Windows hardening, installed updates, security-relevant software, and risky permissions

Verifact uses the Windows logs and configuration already present on the computer. If evidence is missing or unavailable, the report says so instead of treating that area as safe.

## What you get

- A browser-based report saved on the assessed computer
- Findings with severity, confidence, and exact supporting evidence
- Rejected and inconclusive leads, not only confirmed findings
- A coverage summary showing what Verifact could and could not assess
- Verified local evidence that can be traced back to each finding

Verifact does not change Windows settings, remove threats, or monitor the computer after the assessment.

## Install

### Codex

Start a Codex task and send:

```text
Use $skill-installer to install https://github.com/Rayan-and-beyond/Verifact/tree/main/.agents/skills/verifact
```

Restart Codex if prompted.

### Other compatible agents

Install the `.agents/skills/verifact` folder using your agent's normal skill installation method. You can also download the release ZIP and place the extracted `verifact` folder in your agent's skills directory.

## Run an assessment

On the Windows computer you want to assess, open your agent CLI and send:

```text
Use $verifact to assess this authorized Windows computer end to end.
```

The agent handles the assessment and returns the report. Windows may ask you to approve Administrator access so Verifact can read protected security data.

## Requirements

- Windows 10 or 11
- Windows PowerShell 5.1 or later
- Python 3.10 or later
- An Agent Skills-compatible CLI with terminal access
- Permission to assess the computer

## Important limits

- Verifact assesses one Windows computer at a time.
- It is not antivirus, EDR, continuous monitoring, or a malware sandbox.
- No assessment can prove that a computer is completely secure.
- ⚠️ Reports and evidence may contain sensitive system information. Keep them private.

Current release: `2.0.0` · MIT License
