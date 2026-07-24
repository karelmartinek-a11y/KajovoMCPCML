#!/usr/bin/env bash
set -euo pipefail
umask 027

repository_key="${1:?repository key required}"
source_commit="${2:?source commit required}"
image_reference="${3:?image reference required}"
image_digest="${4:?image digest required}"
build_run_id="${5:?build run id required}"
deploy_run_id="${6:?deploy run id required}"
deploy_run_attempt="${7:?deploy run attempt required}"
requested_git_ref="${8:-}"
execution_mode_arg="${9:-REQUEST_RESPONSE}"
single_active_worker_arg="${10:-false}"
graceful_shutdown_seconds="${11:-30}"
receipt_path="${12:?receipt path required}"

[[ "$repository_key" =~ ^[a-z0-9][a-z0-9-]{2,62}$ ]] || { echo "invalid repository key" >&2; exit 2; }
[[ "$source_commit" =~ ^[a-f0-9]{40}$ ]] || { echo "invalid source commit" >&2; exit 2; }
[[ "$image_digest" =~ ^sha256:[a-f0-9]{64}$ ]] || { echo "invalid image digest" >&2; exit 2; }
case "$build_run_id:$deploy_run_id:$deploy_run_attempt" in *[!0-9:]*) echo "invalid run identifiers" >&2; exit 2 ;; esac
if [ "${KCML_REQUIRE_ROOT:-1}" = "1" ]; then
  test "$(id -u)" = "0"
fi
env_file="${KCML_ENV_FILE:-/etc/kcml/kcml.env}"
test -f "$env_file"

set -a
# shellcheck source=/dev/null
. "$env_file"
set +a

podman_binary="${PODMAN_BINARY:-podman}"
runuser_binary="${RUNUSER_BINARY:-runuser}"
curl_binary="${CURL_BINARY:-curl}"
jq_binary="${JQ_BINARY:-jq}"
runtime_owner="${KCML_RUNTIME_OWNER:-kcml}"
runtime_group="${KCML_RUNTIME_GROUP:-kcml}"
runtime_root="${KCML_REPOSITORY_COMPONENT_RUNTIME_ROOT:-/var/lib/kcml/repository-components/${repository_key}}"
release_root="${runtime_root}/releases/${source_commit}-${image_digest#sha256:}"
candidate_root="${release_root}/candidate"
live_root="${runtime_root}/live"
previous_root="${runtime_root}/previous-runtime"
data_root="${runtime_root}/data"
health_path="${KCML_REPOSITORY_COMPONENT_HEALTH_PATH:-/tmp/repository-component-health.json}"
ready_path="${KCML_REPOSITORY_COMPONENT_READY_PATH:-/tmp/repository-component-ready.json}"
healthcheck_attempts="${KCML_REPOSITORY_COMPONENT_HEALTHCHECK_ATTEMPTS:-60}"
healthcheck_sleep_seconds="${KCML_REPOSITORY_COMPONENT_HEALTHCHECK_SLEEP_SECONDS:-1}"
container_name="kcml-repository-component-${repository_key}"
candidate_name="${container_name}-candidate"
short_digest="${image_digest#sha256:}"
execution_mode="${KCML_REPOSITORY_COMPONENT_EXECUTION_MODE:-REQUEST_RESPONSE}"
single_active_worker="${KCML_REPOSITORY_COMPONENT_SINGLE_ACTIVE_WORKER:-0}"
case "$execution_mode_arg" in REQUEST_RESPONSE|LONG_RUNNING) execution_mode="$execution_mode_arg" ;; *) echo "invalid execution mode" >&2; exit 2 ;; esac
case "$single_active_worker_arg" in true) single_active_worker="1" ;; false) single_active_worker="0" ;; *) echo "invalid single_active_worker" >&2; exit 2 ;; esac
case "$graceful_shutdown_seconds" in *[!0-9]*|'') echo "invalid graceful shutdown" >&2; exit 2 ;; esac
requested_git_ref_json="null"
if [ -n "$requested_git_ref" ]; then
  requested_git_ref_json="$(printf '%s' "$requested_git_ref" | "$jq_binary" -Rn '$ARGS.positional[0]' --args "$requested_git_ref")"
fi

run_as_kcml() {
  "$runuser_binary" -u "$runtime_owner" -- "$@"
}

container_image_name() {
  run_as_kcml "$podman_binary" container inspect "$1" --format '{{.ImageName}}' 2>/dev/null || true
}

container_image_digest() {
  run_as_kcml "$podman_binary" container inspect "$1" --format '{{index .Config.Labels "cz.hcasc.kcml.image-digest"}}' 2>/dev/null || true
}

wait_for_health() {
  local socket_path="$1"
  local output_path="$2"
  for _attempt in $(seq 1 "$healthcheck_attempts"); do
    if { [ -S "$socket_path" ] || { [ "${KCML_ACCEPT_TEST_SOCKET_FILE:-0}" = "1" ] && [ -f "$socket_path" ]; }; } \
      && "$curl_binary" --fail --silent --show-error --unix-socket "$socket_path" http://localhost/health > "$output_path" 2>/dev/null; then
      return 0
    fi
    sleep "$healthcheck_sleep_seconds"
  done
  return 1
}

wait_for_ready() {
  local socket_path="$1"
  local output_path="$2"
  for _attempt in $(seq 1 "$healthcheck_attempts"); do
    if { [ -S "$socket_path" ] || { [ "${KCML_ACCEPT_TEST_SOCKET_FILE:-0}" = "1" ] && [ -f "$socket_path" ]; }; } \
      && "$curl_binary" --fail --silent --show-error --unix-socket "$socket_path" http://localhost/ready > "$output_path" 2>/dev/null; then
      return 0
    fi
    sleep "$healthcheck_sleep_seconds"
  done
  return 1
}

write_mode() {
  local mount_source="$1"
  local mode="$2"
  printf '{"mode":"%s"}\n' "$mode" > "${mount_source}/runtime-mode.json"
}

start_container() {
  local name="$1"
  local mount_source="$2"
  local data_source="$3"
  local lifecycle_mode="$4"
  local immutable_image="$5"
  local -a podman_args
  local -a extra_mount_args=()
  local -a extra_env_args=()
  write_mode "$mount_source" "$lifecycle_mode"
  if [ -n "${KCML_EGRESS_SOCKET_PATH:-}" ]; then
    local egress_mount_source
    egress_mount_source="$(dirname "$KCML_EGRESS_SOCKET_PATH")"
    extra_mount_args+=(--volume "${egress_mount_source}:/run/kcml-egress:ro,z")
    extra_env_args+=(--env KCML_EGRESS_SOCKET_PATH=/run/kcml-egress/proxy.sock)
  fi
  if [ -n "${KCML_SECRET_BROKER_SOCKET_PATH:-}" ]; then
    local secret_mount_source
    secret_mount_source="$(dirname "$KCML_SECRET_BROKER_SOCKET_PATH")"
    extra_mount_args+=(--volume "${secret_mount_source}:/run/kcml-secret-broker:ro,z")
    extra_env_args+=(--env KCML_SECRET_BROKER_SOCKET_PATH=/run/kcml-secret-broker/proxy.sock)
  fi
  run_as_kcml "$podman_binary" rm --force --ignore "$name" >/dev/null 2>&1 || true
  podman_args=(
    run --detach --replace
    --name "$name"
    --label "cz.hcasc.kcml.repository-component=true"
    --label "cz.hcasc.kcml.repository-key=${repository_key}"
    --label "cz.hcasc.kcml.image-digest=${image_digest}"
    --read-only
    --cap-drop=ALL
    --security-opt=no-new-privileges
    --network none
    --log-driver none
    --pids-limit 256
    --memory 256m
    --cpus 1.0
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m
    --volume "${mount_source}:/run/kcml:rw,z"
    --volume "${data_source}:/var/lib/kcml-data:rw,z"
    --env KCML_SOCKET_PATH=/run/kcml/worker.sock
    --env KCML_SERVER_CODE="repository-${repository_key}"
    --env KCML_IMAGE_DIGEST="${image_digest}"
    --env KCML_RUNTIME_MODE="${lifecycle_mode}"
    --env KCML_RUNTIME_MODE_PATH=/run/kcml/runtime-mode.json
    --env KCML_RUNTIME_EXECUTION_MODE="${execution_mode}"
    --env KCML_RUNTIME_SINGLE_ACTIVE_WORKER="${single_active_worker}"
    --env KCML_RUNTIME_GRACEFUL_SHUTDOWN_SECONDS="${graceful_shutdown_seconds}"
    --env KCML_RUNTIME_LEASE_PATH=/var/lib/kcml-data/worker.lease.json
    --env KCML_DATA_PATH=/var/lib/kcml-data
    --env KCML_EGRESS_CAPABILITY="${KCML_EGRESS_CAPABILITY:-}"
    --env KCML_SECRET_BROKER_CAPABILITY="${KCML_SECRET_BROKER_CAPABILITY:-}"
  )
  if [ "${#extra_mount_args[@]}" -gt 0 ]; then
    podman_args+=("${extra_mount_args[@]}")
  fi
  if [ "${#extra_env_args[@]}" -gt 0 ]; then
    podman_args+=("${extra_env_args[@]}")
  fi
  podman_args+=("$immutable_image")
  run_as_kcml "$podman_binary" "${podman_args[@]}" >/dev/null
}

restore_previous_runtime() {
  local previous_image="$1"
  local previous_digest="$2"
  if [ -n "$previous_image" ] && [ -n "$previous_digest" ] && [ -d "$previous_root" ]; then
    image_digest="$previous_digest"
    ln -sfn "$previous_root" "$live_root"
    start_container "$container_name" "$live_root" "$data_root" "ACTIVE" "${previous_image%@*}@${previous_digest}"
    wait_for_health "${previous_root}/worker.sock" "$health_path" >/dev/null 2>&1 || true
  fi
}

install -d -m 0750 -o "$runtime_owner" -g "$runtime_group" "$runtime_root" "$(dirname "$release_root")" "$data_root"
rm -rf "$candidate_root"
mkdir -p "$candidate_root"
chown -R "$runtime_owner:$runtime_group" "$runtime_root"
chmod 0777 "$candidate_root" "$data_root"

previous_digest="$(container_image_digest "$container_name")"
previous_image_reference="$(container_image_name "$container_name")"
previous_live_target="$(readlink -f "$live_root" 2>/dev/null || true)"
rm -rf "$previous_root"
if [ -n "$previous_live_target" ] && [ -d "$previous_live_target" ]; then
  cp -a "$previous_live_target" "$previous_root"
  chown -R "$runtime_owner:$runtime_group" "$previous_root"
  chmod 0777 "$previous_root"
fi

immutable_image="${image_reference%@*}@${image_digest}"
run_as_kcml "$podman_binary" pull "$immutable_image" >/dev/null
start_container "$candidate_name" "$candidate_root" "$data_root" "PREPARE" "$immutable_image"

if ! wait_for_health "${candidate_root}/worker.sock" "$health_path"; then
  run_as_kcml "$podman_binary" logs "$candidate_name" >/dev/null 2>&1 || true
  run_as_kcml "$podman_binary" rm --force --ignore "$candidate_name" >/dev/null 2>&1 || true
  rm -rf "$release_root"
  echo "candidate runtime failed health check" >&2
  exit 1
fi
if ! wait_for_ready "${candidate_root}/worker.sock" "$ready_path"; then
  run_as_kcml "$podman_binary" rm --force --ignore "$candidate_name" >/dev/null 2>&1 || true
  rm -rf "$release_root"
  echo "candidate runtime failed readiness check" >&2
  exit 1
fi

if [ -n "$previous_live_target" ] && [ -d "$previous_live_target" ]; then
  write_mode "$previous_live_target" "DRAINING"
fi
run_as_kcml "$podman_binary" rm --force --ignore "$container_name" >/dev/null 2>&1 || true
ln -sfn "$candidate_root" "$live_root"
run_as_kcml "$podman_binary" rm --force --ignore "$candidate_name" >/dev/null 2>&1 || true
start_container "$container_name" "$live_root" "$data_root" "ACTIVE" "$immutable_image"

if ! wait_for_health "${live_root}/worker.sock" "$health_path"; then
  run_as_kcml "$podman_binary" logs "$container_name" >/dev/null 2>&1 || true
  run_as_kcml "$podman_binary" rm --force --ignore "$container_name" >/dev/null 2>&1 || true
  rm -f "$live_root"
  if [ -n "$previous_live_target" ]; then
    ln -sfn "$previous_live_target" "$live_root"
  fi
  restore_previous_runtime "$previous_image_reference" "$previous_digest"
  rm -rf "$release_root"
  echo "live runtime failed final verification" >&2
  exit 1
fi
if ! wait_for_ready "${live_root}/worker.sock" "$ready_path"; then
  run_as_kcml "$podman_binary" rm --force --ignore "$container_name" >/dev/null 2>&1 || true
  rm -f "$live_root"
  if [ -n "$previous_live_target" ]; then
    ln -sfn "$previous_live_target" "$live_root"
  fi
  restore_previous_runtime "$previous_image_reference" "$previous_digest"
  rm -rf "$release_root"
  echo "live runtime failed readiness verification" >&2
  exit 1
fi

actual_image_reference="$(container_image_name "$container_name")"
actual_digest="$(container_image_digest "$container_name")"
checked_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
health_body="$(cat "$health_path")"
evidence_digest="$(printf '%s' "$health_body" | sha256sum | awk '{print "sha256:" $1}')"
readiness_body="$(cat "$ready_path")"
readiness_digest="$(printf '%s' "$readiness_body" | sha256sum | awk '{print "sha256:" $1}')"
lease_status="NOT_REQUIRED"
if [ "$single_active_worker" = "1" ]; then
  if [ -f "${data_root}/worker.lease.json" ]; then
    lease_status="SINGLE_ACTIVE_ACQUIRED"
  else
    lease_status="SINGLE_ACTIVE_UNAVAILABLE"
  fi
fi

"$jq_binary" -n \
  --arg repositoryKey "$repository_key" \
  --arg sourceCommit "$source_commit" \
  --arg imageReference "$actual_image_reference" \
  --arg imageDigest "$actual_digest" \
  --arg buildRunId "$build_run_id" \
  --arg deployRunId "$deploy_run_id" \
  --arg deployRunAttempt "$deploy_run_attempt" \
  --arg workflow ".github/workflows/repository-component-deploy.yml" \
  --arg executionMode "$execution_mode" \
  --arg lifecycleMode "ACTIVE" \
  --arg runtimeKind "UDS" \
  --arg runtimeLocation "${live_root}/worker.sock" \
  --arg runtimeIdentifier "$container_name" \
  --arg dataLocation "$data_root" \
  --arg leaseStatus "$lease_status" \
  --arg previousImageDigest "${previous_digest:-}" \
  --arg requestedGitRef "${requested_git_ref}" \
  --arg deployedAt "$checked_at" \
  --arg checkedAt "$checked_at" \
  --arg evidenceDigest "$evidence_digest" \
  --arg readinessCheckedAt "$checked_at" \
  --arg readinessEvidenceDigest "$readiness_digest" \
  '
  {
    schemaVersion: "1.0",
    repositoryKey: $repositoryKey,
    requestedGitRef: ($requestedGitRef | if . == "" then null else . end),
    sourceCommit: $sourceCommit,
    imageReference: $imageReference,
    imageDigest: $imageDigest,
    componentVersion: $sourceCommit,
    buildRunId: $buildRunId,
    deployRunId: $deployRunId,
    deployRunAttempt: $deployRunAttempt,
    workflow: $workflow,
    executionMode: $executionMode,
    lifecycleMode: $lifecycleMode,
    runtimeKind: $runtimeKind,
    runtimeLocation: $runtimeLocation,
    runtimeIdentifier: $runtimeIdentifier,
    dataLocation: $dataLocation,
    leaseStatus: $leaseStatus,
    previousImageDigest: ($previousImageDigest | if . == "" then null else . end),
    deployedAt: $deployedAt,
    readiness: {
      status: "READY",
      checkedAt: $readinessCheckedAt,
      evidenceDigest: $readinessEvidenceDigest
    },
    health: {
      status: "PASS",
      checkedAt: $checkedAt,
      evidenceDigest: $evidenceDigest
    }
  }' > "$receipt_path"
