#!/usr/bin/env bash
set -euo pipefail

remote_name="${1:-origin}"
remote_url="$(git remote get-url "$remote_name" 2>/dev/null || true)"
case "$remote_url" in
  https://github.com/yuns2023/saiai-client.git|git@github.com:yuns2023/saiai-client.git)
    exit 0
    ;;
  *)
    echo "[repo-role] ERROR: client changes require the canonical saiai-client remote: ${remote_url:-<none>}" >&2
    exit 1
    ;;
esac
