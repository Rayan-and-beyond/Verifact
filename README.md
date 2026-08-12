# 👁️ Verifact

Verifact is an AI-agent skill that performs a bounded, read-only security assessment of one Windows computer.

## Install

Give your agent's skill installer this folder:

`https://github.com/Rayan-and-beyond/Verifact/tree/main/.agents/skills/verifact`

For Codex, ask:

```text
Use $skill-installer to install https://github.com/Rayan-and-beyond/Verifact/tree/main/.agents/skills/verifact
```

Restart the agent if it asks you to.

Using the release ZIP instead? Extract the complete `verifact` folder into your agent's skills directory.

## Use

On the Windows computer, say:

```text
Use $verifact to assess this authorized Windows computer end to end.
```

That is all. Do not run Verifact scripts yourself.

The agent creates the assessment, collects and verifies evidence, investigates it, reviews any findings, builds the report, and returns its location. Windows may show an Administrator approval prompt during read-only collection.

## Requirements

- Windows 10 or 11
- Windows PowerShell 5.1+
- Python 3.10+
- An Agent Skills-compatible CLI with terminal access
- Permission to assess the computer

## Limits

- Verifact assesses one local Windows computer. It is not continuous monitoring, EDR, SIEM, or a malware sandbox.
- A clean result does not prove the computer is secure.
- Missing evidence is reported as a coverage limit, not treated as clean.
- ⚠️ Assessment files may contain sensitive host data. Keep them private.

Current release: `2.0.0`. MIT licensed.
