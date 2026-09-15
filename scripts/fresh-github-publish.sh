#!/usr/bin/env bash
# Publish with ONLY pengyni on the contributor graph.
# GitHub keeps cursoragent/iceables on a repo if bad commits were ever pushed.
# Fix: delete the repo in GitHub Settings first, then run this script.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

AUTHOR_NAME="${GIT_AUTHOR_NAME:-pengyni}"
AUTHOR_EMAIL="${GIT_AUTHOR_EMAIL:-272656065+pengyni@users.noreply.github.com}"
REPO="${GITHUB_REPO:-pengyni/ecs-security-toolkit}"

export GIT_AUTHOR_NAME="$AUTHOR_NAME"
export GIT_AUTHOR_EMAIL="$AUTHOR_EMAIL"
export GIT_COMMITTER_NAME="$AUTHOR_NAME"
export GIT_COMMITTER_EMAIL="$AUTHOR_EMAIL"

if gh repo view "$REPO" >/dev/null 2>&1; then
  echo "Repo $REPO already exists."
  echo "To reset contributors, delete it first:"
  echo "  https://github.com/$REPO/settings  -> Danger zone -> Delete this repository"
  echo "Then re-run this script."
  exit 1
fi

echo "Creating $REPO ..."
gh repo create "$REPO" --public --description "ECS/Bubbablox security toolkit (audit, compliance, official patcher)"

git init -b main
git add -A
TREE=$(git write-tree)
MSG_FILE="$(mktemp)"
cat >"$MSG_FILE" <<'EOF'
Initial release: ECS audit, compliance gate, and official patcher.

Ships the vulnerability rundown, read-only pentest scanner, ComRBX-compatible
integrity enforcement, and privacy-safe patcher with transparency manifest.
EOF
COMMIT=$(git commit-tree "$TREE" -F "$MSG_FILE")
rm -f "$MSG_FILE"
git update-ref refs/heads/main "$COMMIT"

git remote remove origin 2>/dev/null || true
git remote add origin "https://github.com/$REPO.git"
git push -u origin main

echo "Done: https://github.com/$REPO"
echo "Contributors should show only $AUTHOR_NAME (may take a few minutes)."
