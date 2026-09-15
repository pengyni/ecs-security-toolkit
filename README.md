# ECS Security Toolkit

Security kit for **Economy Simulator / Bubbablox** revivals: vulnerability rundown, read-only pentest scanner, compliance gate, and ComRBX-compatible patcher tooling.

## Scan any site (no source code needed)

Requires **Python 3.9+** (Linux, macOS, Windows).

```bash
git clone https://github.com/pengyni/ecs-security-toolkit.git
cd ecs-security-toolkit

# Any public ECS-style revival — bare domain or full URL
python3 ecs-audit.py -u revival.example.com
python3 ecs-audit.py --url https://revival.example.com --json audit.json

# Optional: scan a source tree on disk
python3 ecs-audit.py --source /path/to/ecs --json audit.json
```

Windows: `python ecs-audit.py -u revival.example.com` or `ecs-audit.bat`.

**On ComRBX:** log in and open **Develop → ECS security scan** to run the same checklist in your browser.

## Stay protected on your own host

Harden your deployment with the official patcher (recommended for revival owners):

**https://github.com/pengyni/auto-security-patcher**

This toolkit also ships `patch.py` for the ComRBX integrity / transparency workflow.

## Full workflow (self-hosted)

```bash
python3 ecs-audit.py -u your.domain --json audit.json
python3 patch.py /path/to/ecs --apply --local-log-only
python3 ecs-compliance.py --source /path/to/ecs verify
```

## What's in the box

| Tool | Purpose |
| --- | --- |
| [docs/VULN-RUNDOWN.md](docs/VULN-RUNDOWN.md) | Full ECS/Bubbablox vulnerability list + abuse impact |
| `ecs-audit.py` | Read-only pentest checklist (any public URL + optional source) |
| `ecs-compliance.py` | Official patcher gate, no password-stealer patterns |
| `patch.py` | Hardening patcher + transparency manifest |
| [TRUST.md](TRUST.md) | Why this patcher is not a RAT |
| [docs/COMPLIANCE.md](docs/COMPLIANCE.md) | ComRBX operator + host requirements |

## License

MIT. Only scan infrastructure you own or are allowed to test.
