#!/usr/bin/env bash
set -euo pipefail
umask 077

repository="${1:?repository required}"
repository_key="${2:?repository_key required}"
source_commit="${3:?source commit required}"
image_reference="${4:?image reference required}"
image_digest="${5:?image digest required}"
build_run_id="${6:?build run id required}"
deploy_run_id="${7:?deploy run id required}"
deploy_run_attempt="${8:?deploy run attempt required}"
requested_git_ref="${9:-}"
execution_mode="${10:-REQUEST_RESPONSE}"
single_active_worker="${11:-false}"
graceful_shutdown_seconds="${12:-30}"
receipt_path="${13:?receipt path required}"

case "$repository" in *[!A-Za-z0-9._/-]*) echo "invalid repository" >&2; exit 2 ;; esac
[[ "$repository_key" =~ ^[a-z0-9][a-z0-9-]{2,62}$ ]] || { echo "invalid repository key" >&2; exit 2; }
[[ "$source_commit" =~ ^[a-f0-9]{40}$ ]] || { echo "invalid source commit" >&2; exit 2; }
[[ "$image_reference" =~ ^ghcr\.io/[a-z0-9._-]+/kajovocml-components/${repository_key}:[a-f0-9]{40}$ ]] || { echo "invalid image reference" >&2; exit 2; }
[[ "$image_digest" =~ ^sha256:[a-f0-9]{64}$ ]] || { echo "invalid image digest" >&2; exit 2; }
case "$build_run_id:$deploy_run_id:$deploy_run_attempt" in *[!0-9:]*) echo "invalid run identifiers" >&2; exit 2 ;; esac
case "$execution_mode" in REQUEST_RESPONSE|LONG_RUNNING) ;; *) echo "invalid execution mode" >&2; exit 2 ;; esac
case "$single_active_worker" in true|false) ;; *) echo "invalid single_active_worker" >&2; exit 2 ;; esac
case "$graceful_shutdown_seconds" in *[!0-9]*|'') echo "invalid graceful shutdown" >&2; exit 2 ;; esac
test "$(id -u)" = "0"

set -a
# shellcheck source=/dev/null
. /etc/kcml/kcml.env
set +a

immutable_image="${image_reference%@*}@${image_digest}"
cosign_binary="${COSIGN_BINARY:-cosign}"

"$cosign_binary" verify \
  --certificate-identity "https://github.com/${repository}/.github/workflows/repository-component-deploy.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "$immutable_image" >/dev/null

sbom="$(mktemp)"
provenance="$(mktemp)"
trap 'rm -f "$sbom" "$provenance"' EXIT
"$cosign_binary" verify-attestation \
  --certificate-identity "https://github.com/${repository}/.github/workflows/repository-component-deploy.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --type spdxjson "$immutable_image" > "$sbom"
"$cosign_binary" verify-attestation \
  --certificate-identity "https://github.com/${repository}/.github/workflows/repository-component-deploy.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --type slsaprovenance "$immutable_image" > "$provenance"

test -s "$sbom"
node /opt/kcml/current/scripts/verify-repository-component-attestations.mjs \
  "$sbom" "$provenance" "$image_digest" "$source_commit" "$build_run_id"

install -d -m 0750 -o root -g kcml "$(dirname "$receipt_path")"
exec /usr/local/libexec/kcml-install-repository-component \
  "$repository_key" "$source_commit" "$image_reference" "$image_digest" "$build_run_id" "$deploy_run_id" "$deploy_run_attempt" "$requested_git_ref" "$execution_mode" "$single_active_worker" "$graceful_shutdown_seconds" "$receipt_path"
