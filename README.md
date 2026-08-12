# Verifact 👁️

Verifact is a skill for AI agents that performs a bounded, read-only security assessment of one Windows computer. It analyzes events already recorded in the Windows Security log and related Windows event logs, checks local system configuration, reviews possible findings, and creates a local HTML report with supporting evidence and clear coverage limits.

## Evidence Verifact uses

- The Windows Security log for sign-ins, account changes, privilege use, process activity, services, scheduled tasks, and other security events
- Related Windows logs for System, Application, PowerShell, Remote Desktop, Task Scheduler, WMI, WinRM, and Windows Firewall activity
- AppLocker, Code Integrity, and Sysmon logs when they already exist and are enabled
- Local Windows configuration for accounts, persistence, network exposure, sharing, updates, hardening, and permissions

Verifact does not enable logging or install additional collectors. If a relevant log is disabled, missing, or inaccessible, the report records that as a coverage limit.

## What Verifact does

- Analyzes Windows log events to identify security-relevant activity and supporting context
- Checks endpoint posture such as local users and admin groups, password and audit settings, startup and persistence paths, firewall exposure, listening ports, shares, updates, and security-relevant configuration
- Ties every finding to local evidence
- Separates validated findings, rejected leads, and inconclusive leads
- Shows coverage limits when logs, artifacts, or permissions are missing

## What the agent does

When you call Verifact, the agent:

- Collects read-only Windows evidence
- Verifies and analyzes it
- Reviews possible findings
- Builds a local report
- Tells you where the report was saved

Windows may ask for Administrator approval so the agent can read protected security data.

## What you get

- A local HTML dashboard to display findings
- Clear findings tied to supporting local evidence
- Rejected and inconclusive leads too, not just confirmed ones
- Coverage notes showing what was and was not assessable

## Install

### Codex

Send this to Codex:

```text
Use $skill-installer to install https://github.com/Rayan-and-beyond/Verifact/tree/main/.agents/skills/verifact
```

Restart Codex if it asks you to.

### Claude Code

Claude Code loads personal skills from `~/.claude/skills/<skill-name>/SKILL.md`.

Copy the `.agents/skills/verifact` folder to:

```text
~/.claude/skills/verifact
```

The installed entry file should be `~/.claude/skills/verifact/SKILL.md`. If `~/.claude/skills` did not already exist, restart Claude Code after installing the skill.

### Other agent CLIs

Install the `.agents/skills/verifact` folder using your agent's normal skill install method.

## Use

### Codex

On the Windows computer you want to assess, tell Codex:

```text
Use $verifact to assess this authorized Windows computer end to end.
```

### Claude Code

Invoke the installed skill directly:

```text
/verifact assess this authorized Windows computer end to end.
```

## Requirements

- Windows 10 or 11
- PowerShell 5.1 or later
- Python 3.10 or later
- An agent CLI that supports skills and terminal access
- Permission to assess the computer

## Limits

- Verifact checks one Windows computer at a time.
- It is not antivirus, EDR, or continuous monitoring.
- It does not fix problems for you.
- No tool can prove a computer is fully safe.
- Reports may contain sensitive system data. Keep them private.

Current release: `2.0.0` · MIT License
