#!/usr/bin/env bash
set -euo pipefail

base_ref="${1:-origin/main}"
mapfile -t changed < <(git diff --name-only "${base_ref}...HEAD")
if ((${#changed[@]} == 0)); then
  echo "No changed files" >&2
  exit 1
fi

handler_dir=""
for file in "${changed[@]}"; do
  if [[ ! "$file" =~ ^handlers/KCML[0-9]{4,}/ ]]; then
    echo "Disallowed onboarding path: $file" >&2
    exit 1
  fi
  candidate="$(cut -d/ -f1-2 <<<"$file")"
  if [[ -n "$handler_dir" && "$candidate" != "$handler_dir" ]]; then
    echo "One onboarding PR may modify only one handler directory" >&2
    exit 1
  fi
  handler_dir="$candidate"
done

if git ls-files -s "$handler_dir" | awk '$1 == "120000" { found=1 } END { exit !found }'; then
  echo "Symlinks are forbidden in handler sources" >&2
  exit 1
fi

printf '%s\n' "$handler_dir"
