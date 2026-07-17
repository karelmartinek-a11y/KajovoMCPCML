#!/usr/bin/env bash
set -euo pipefail
umask 077

artifact="${1:?release artifact required}"
repository="${2:?repository required}"
source_commit="${3:?source commit required}"
run_id="${4:?run id required}"
run_attempt="${5:?run attempt required}"
workflow_trigger="${6:?workflow trigger required}"
case "$repository" in *[!A-Za-z0-9._/-]*) exit 2 ;; esac
[[ "$source_commit" =~ ^[a-f0-9]{40}$ ]] || exit 2
case "$run_id:$run_attempt" in *[!0-9:]*) exit 2 ;; esac
case "$workflow_trigger" in push|workflow_dispatch) ;; *) exit 2 ;; esac
test "$(id -u)" = "0"
test -n "${PASS:-}"

artifact="$(realpath -e "$artifact")"
bundle="$(realpath -e "${artifact}.sigstore.json")"
test -f "$artifact"
test ! -L "$artifact"
test -f "$bundle"
test ! -L "$bundle"
test "$(stat -c '%U' "$artifact")" = "kcml-deploy"
test "$(stat -c '%U' "$bundle")" = "kcml-deploy"
cosign verify-blob \
  --bundle "$bundle" \
  --certificate-identity "https://github.com/${repository}/.github/workflows/ci-deploy.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-github-workflow-repository "$repository" \
  --certificate-github-workflow-ref "refs/heads/main" \
  --certificate-github-workflow-sha "$source_commit" \
  --certificate-github-workflow-trigger "$workflow_trigger" \
  "$artifact" >/dev/null

release_id="${source_commit}-${run_id}-${run_attempt}"
staging="/opt/kcml/releases/.staging-$release_id"
rm -rf "$staging"
install -d -m 0750 -o root -g kcml "$staging"
tar --zstd --extract --file "$artifact" --directory "$staging" --no-same-owner --no-same-permissions
test "$(jq -r .sourceCommit "$staging/release-manifest.json")" = "$source_commit"
test "$(jq -r .repository "$staging/release-manifest.json")" = "$repository"
test "$(jq -r .workflow "$staging/release-manifest.json")" = "$repository/.github/workflows/ci-deploy.yml@refs/heads/main"
exec "$staging/deploy/scripts/install-release.sh" "$staging" "$release_id"
