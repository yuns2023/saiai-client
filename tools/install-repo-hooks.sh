#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
hooks_dir="$repo_root/scripts/git-hooks"
if [ ! -x "$hooks_dir/pre-push" ]; then
  echo "ERROR: versioned pre-push hook is missing or not executable" >&2
  exit 1
fi

"$hooks_dir/assert-repo-role.sh" origin
git config core.hooksPath scripts/git-hooks
echo "installed versioned hooks for canonical Client repository"
