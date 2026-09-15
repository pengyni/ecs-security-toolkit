#!/usr/bin/env python3
"""
ECS host compliance gate.

Hosts that want ComRBX listing, ingest, or "certified revival" status must:
  1. Run auto-security-patcher (official inject hashes)
  2. Pass ecs-audit with zero critical findings (after patch)

Commands:
  verify --source PATH     Exit 2 if not compliant (for CI / start scripts)
  certify --source PATH    Print JSON certificate (stdout) if compliant
  seal-check --source PATH Validate patch-transparency + official inject hashes
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

TOOLKIT_VERSION = "1.0.0"
HERE = Path(__file__).resolve().parent
OFFICIAL = HERE / "official" / "inject-sha256.json"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_official() -> dict[str, str]:
    if not OFFICIAL.is_file():
        raise SystemExit(f"missing {OFFICIAL}")
    data = json.loads(OFFICIAL.read_text(encoding="utf-8"))
    return {k: v for k, v in data.get("sha256", {}).items()}


def find_transparency(root: Path) -> dict | None:
    p = root / "patch-transparency.json"
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def verify_inject_hashes(root: Path, official: dict[str, str]) -> list[str]:
    errors: list[str] = []
    transparency = find_transparency(root)
    if not transparency:
        return ["patch-transparency.json missing (run official patch.py --apply first)"]
    privacy = transparency.get("privacy") or {}
    if privacy.get("passwords_logged") or privacy.get("passwords_transmitted"):
        errors.append("transparency manifest claims passwords are logged/transmitted")
    if privacy.get("browser_hooks_install_password_sniffers"):
        errors.append("browser password hooks enabled (not allowed for certified hosts)")
    manifest_hashes = (transparency.get("inject_sha256") or {})
    for name, expected in official.items():
        got = manifest_hashes.get(name)
        if got != expected:
            errors.append(f"inject {name}: expected official hash {expected[:12]}..., got {str(got)[:12]}...")
    # Also verify on-disk logger if present
    for path in root.rglob("runtime-sync.js"):
        if "node_modules" in path.parts:
            continue
        if path.name == "runtime-sync.js" and path.parent.name.startswith("_rs"):
            if sha256_file(path) != official.get("runtime-sync.js"):
                errors.append(f"deployed runtime-sync.js hash mismatch at {path}")
    return errors


def run_audit(root: Path) -> tuple[int, dict]:
    audit = HERE / "ecs-audit.py"
    out = root / ".ecs-audit-last.json"
    proc = subprocess.run(
        [sys.executable, str(audit), "--source", str(root), "--json", str(out)],
        capture_output=True,
        text=True,
    )
    if out.is_file():
        try:
            data = json.loads(out.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            data = {}
    else:
        data = {}
    critical = sum(1 for f in data.get("findings", []) if f.get("severity") == "critical")
    return proc.returncode, {"critical": critical, "counts": data.get("counts", {}), "report": str(out)}


def cmd_verify(root: Path) -> int:
    official = load_official()
    errors = verify_inject_hashes(root, official)
    code, audit = run_audit(root)
    if audit["critical"] > 0:
        errors.append(f"ecs-audit trust scan: {audit['critical']} critical finding(s) ({audit['report']})")
    if errors:
        print("NOT COMPLIANT")
        for e in errors:
            print(f"  - {e}")
        print("\nFix: python3 patch.py", root, "--apply --local-log-only")
        print("Then: python3 ecs-audit.py --source", root, "--trust-only")
        return 2
    print("COMPLIANT (official patcher + clean trust audit)")
    return 0


def cmd_certify(root: Path) -> int:
    if cmd_verify(root) != 0:
        return 2
    official = load_official()
    transparency = find_transparency(root) or {}
    cert = {
        "schema": "ecs-host-compliance/v1",
        "toolkit_version": TOOLKIT_VERSION,
        "source_root": str(root.resolve()),
        "official_inject_sha256": official,
        "privacy": transparency.get("privacy"),
        "combrx_note": "Set ECS_PATCHER_INTEGRITY_SHA256 in .env to runtime-sync hash for ingest.",
    }
    print(json.dumps(cert, indent=2))
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="ECS official patcher compliance gate")
    parser.add_argument("--source", type=Path, required=True, help="ECS source root")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("verify", help="Exit 2 if host is not compliant")
    sub.add_parser("certify", help="Print compliance JSON if ok")
    sub.add_parser("seal-check", help="Alias for verify (inject + transparency only)")
    args = parser.parse_args()
    root = args.source.resolve()
    if not root.is_dir():
        raise SystemExit(f"not a directory: {root}")

    if args.cmd in ("verify", "seal-check"):
        sys.exit(cmd_verify(root))
    if args.cmd == "certify":
        sys.exit(cmd_certify(root))


if __name__ == "__main__":
    main()
