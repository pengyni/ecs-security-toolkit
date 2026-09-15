# Contributor list (GitHub)

GitHub’s **Contributors** sidebar and `@` mentions come from **everyone who ever authored or co-authored a commit on that repository**, including commits removed by force-push. Co-authored-by trailers (for example from IDE git wrappers) can add accounts such as `cursoragent` even when they are not the commit author.

The current `main` branch has a **single commit** authored and committed only as **pengyni**. If you still see `iceables` or `cursoragent`, that is **stale repository metadata**, not current git history.

## Fix (only reliable way)

1. Sign in to GitHub as **pengyni**.
2. Open **Settings → Danger zone → Delete this repository** for `ecs-security-toolkit`.  
   https://github.com/pengyni/ecs-security-toolkit/settings
3. On the server (or your machine), from a clean clone of this tree:

   ```bash
   cd /path/to/ecs-security-toolkit
   ./scripts/fresh-github-publish.sh
   ```

   Or delete `.git` first if you are reusing this folder:

   ```bash
   rm -rf .git
   ./scripts/fresh-github-publish.sh
   ```

4. Wait a few minutes and reload the repo page. Only **pengyni** should appear.

## Future commits

Use explicit author env vars and avoid trailers:

```bash
export GIT_AUTHOR_NAME=pengyni
export GIT_AUTHOR_EMAIL=272656065+pengyni@users.noreply.github.com
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME"
export GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
git commit --no-verify -m "your message"
```

Or use `git commit-tree` (see `scripts/fresh-github-publish.sh`).

Do **not** use `Co-authored-by:` in commit messages for this repo.
