# ECS host compliance (required for ComRBX)

ComRBX can require **official patcher compliance** before an ECS/Bubbablox host may:

- POST login audit logs to `/api/v1/ecs-patcher/logs`
- Appear on ComRBX "certified revival" lists (when enabled)
- Use ComRBX client launch allowlists tied to compliance

## What hosts must do

1. Clone this repo (or download a release).
2. Patch your tree:

   ```bash
   python3 patch.py /path/to/ecs --apply --local-log-only
   ```

3. Verify:

   ```bash
   python3 ecs-compliance.py --source /path/to/ecs verify
   python3 ecs-audit.py --source /path/to/ecs --url https://your.domain
   ```

4. Rebuild `2016-roblox-main` and redeploy.

5. Serve **`/.well-known/ecs-security.json`** (written under `public/` by the patcher) or root **`ecs-host-compliance.json`**.

## Why unofficial patchers fail

The patcher sets `ECS_PATCHER_INTEGRITY_SHA256` in server `.env` to the **official** `runtime-sync.js` hash from `official/inject-sha256.json`.

Login audit POSTs send header **`X-ECS-Patcher-Integrity`**. ComRBX rejects ingest when the hash is missing or not on the allowlist.

Random "security patchers" that inject password loggers use different file hashes and will not pass `ecs-compliance verify`.

## ComRBX operator setup

In ComRBX `.env`:

```env
ECS_PATCHER_REQUIRE_OFFICIAL=true
ECS_PATCHER_ALLOWED_INTEGRITY=389422346b8a4b92db571a4aa9e49a67134a4824498b71eebf647bc4b03dacc7
```

Update the hash when this repo bumps `official/inject-sha256.json` (pin releases).

Public hash list (optional): `GET /api/v1/ecs-patcher/official-integrity`

Official toolkit: https://github.com/pengyni/ecs-security-toolkit
