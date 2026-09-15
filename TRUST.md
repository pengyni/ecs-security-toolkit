# Why this is not a RAT

People call **auto-security-patcher** a RAT when they see obfuscated `_scXXXXXX.js` files, fetch hooks, or login traffic leaving the server. Some older builds did send password fields. Current source in this folder is **privacy-safe by default**.

## What the patcher does NOT do

- Does **not** read passwords from the browser by default (browser hooks are **off** unless you pass `--allow-browser-hooks`).
- Does **not** put Discord webhooks in client JavaScript.
- Does **not** exfiltrate `.ROBLOSECURITY` cookies.
- Does **not** phone home to hidden domains: remote login audit uses **your** `RUNTIME_SYNC_URL` / ComRBX ingest URL that you can read in `.env` after patch.

## What it does do (transparently)

After `--apply`, read **`patch-transparency.json`** in your ECS root. It lists:

- Whether browser hooks were installed
- Which fields login telemetry can contain (username, IP, event only)
- SHA256 of inject templates (`runtime-sync.js`, etc.)
- Sample of modified files

Server-side login logging (optional) fires **after** password verification on the API/C# path and sends **username + IP**, not the password. See `inject/runtime-sync.js` (plain text, not obfuscated).

## Verify before you trust

Use the **read-only auditor** (no writes, no secrets):

```bash
python3 ecs-audit.py --source /path/to/ecs --trust-only
```

Exit code 2 means critical trust issues (password sniffers, pass field in telemetry).

Scan your live site (safe GET probes only):

```bash
python3 ecs-audit.py --url https://your.domain
```

Full checklist vs the public vuln list:

```bash
python3 ecs-audit.py --source /path/to/ecs --url https://your.domain --json ecs-audit-report.json
```

## Recommended flags for hosts

```bash
python3 patch.py /path/to/ecs --apply --local-log-only
```

- No browser hooks
- No remote URL unless you opt in
- Hardening + webhook strip + login input fixes still run

## If someone sends you a random binary

Do not run it. Build from this source tree or demand `patch-transparency.json` + `ecs-audit.py --trust-only` output from the person who patched.
