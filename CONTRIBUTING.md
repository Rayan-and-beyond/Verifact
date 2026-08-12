# Contributing

Keep collection read-only. Never add code that changes endpoint security settings.

Before opening a pull request:

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest
python3 .agents/skills/verifact/scripts/verifact.py package --output /tmp/verifact-skill.zip
```

Collector or normalizer changes must also pass the Windows CI job. Use only synthetic evidence in tests and public issues.
