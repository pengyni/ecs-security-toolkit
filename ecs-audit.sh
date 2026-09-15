#!/usr/bin/env bash
# ECS/Bubbablox read-only security audit (Linux/macOS)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$ROOT/ecs-audit.py" "$@"
