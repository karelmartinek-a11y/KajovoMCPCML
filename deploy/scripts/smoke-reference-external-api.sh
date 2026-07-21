#!/usr/bin/env bash
set -Eeuo pipefail

release_dir="${1:?release directory required}"
: "${PASS:?PASS is required}"

: "${ADMIN_HOST:?ADMIN_HOST is required}"
: "${AUTH_HOST:?AUTH_HOST is required}"
: "${REGISTER_HOST:?REGISTER_HOST is required}"
: "${PUBLIC_BASE_DOMAIN:?PUBLIC_BASE_DOMAIN is required}"
admin_host="$ADMIN_HOST"
auth_host="$AUTH_HOST"
register_host="$REGISTER_HOST"
public_base_domain="$PUBLIC_BASE_DOMAIN"
port="${PORT:-3010}"
admin_username="${ADMIN_BOOTSTRAP_USERNAME:-owner}"
base_url="http://127.0.0.1:${port}"

tmpdir="$(mktemp -d)"
current_step="init"
step() {
  current_step="$1"
  echo "reference-smoke:$current_step"
}
report_error() {
  local exit_code=$?
  if [ -n "${service_id:-}" ] && [ -n "${admin_cookie_header:-}" ] && [ -n "${base_url:-}" ] && [ ! -s "$tmpdir/managed-service-logs.json" ]; then
    admin_read "$base_url/api/managed-services/$service_id/logs?limit=100" > "$tmpdir/managed-service-logs.json" 2>/dev/null || true
  fi
  echo "reference-smoke-failed:$current_step" >&2
  if [ -s "$tmpdir/onboarding-response.json" ]; then
    echo "reference-smoke:onboarding-response=$(jq -c . "$tmpdir/onboarding-response.json" 2>/dev/null || tr -d '\n' < "$tmpdir/onboarding-response.json")" >&2
  fi
  if [ -s "$tmpdir/onboarding-http-status.txt" ]; then
    echo "reference-smoke:onboarding-http-status=$(tr -d '\n' < "$tmpdir/onboarding-http-status.txt")" >&2
  fi
  if [ -s "$tmpdir/direct-bypass.json" ]; then
    echo "reference-smoke:direct-bypass=$(jq -c . "$tmpdir/direct-bypass.json" 2>/dev/null || tr -d '\n' < "$tmpdir/direct-bypass.json")" >&2
  fi
  if [ -s "$tmpdir/managed-service-state.json" ]; then
    echo "reference-smoke:managed-service-state=$(jq -c . "$tmpdir/managed-service-state.json" 2>/dev/null || tr -d '\n' < "$tmpdir/managed-service-state.json")" >&2
  fi
  if [ -s "$tmpdir/managed-service-logs.json" ]; then
    echo "reference-smoke:managed-service-logs=$(jq -c . "$tmpdir/managed-service-logs.json" 2>/dev/null || tr -d '\n' < "$tmpdir/managed-service-logs.json")" >&2
  fi
  if [ -s "$tmpdir/token-response.json" ]; then
    echo "reference-smoke:token-response=$(jq -c 'if type == "object" then .access_token = "[REDACTED]" | .refresh_token = "[REDACTED]" else . end' "$tmpdir/token-response.json" 2>/dev/null || tr -d '\n' < "$tmpdir/token-response.json")" >&2
  fi
  if [ -s "$tmpdir/token-http-status.txt" ]; then
    echo "reference-smoke:token-http-status=$(tr -d '\n' < "$tmpdir/token-http-status.txt")" >&2
  fi
  if [ -s "$tmpdir/gateway-read.json" ]; then
    echo "reference-smoke:gateway-read=$(jq -c . "$tmpdir/gateway-read.json" 2>/dev/null || tr -d '\n' < "$tmpdir/gateway-read.json")" >&2
  fi
  if [ -s "$tmpdir/gateway-read-status.txt" ]; then
    echo "reference-smoke:gateway-read-status=$(tr -d '\n' < "$tmpdir/gateway-read-status.txt")" >&2
  fi
  exit "$exit_code"
}
cleanup() {
  rm -rf "$tmpdir"
}
trap report_error ERR
trap cleanup EXIT

manifest_file="$tmpdir/reference-manifest.json"
login_headers="$tmpdir/login-headers.txt"
login_body="$tmpdir/login-body.json"

curl_json() {
  curl -fsS "$@"
}

admin_read() {
  curl_json -H "Host: $admin_host" -H "cookie: $admin_cookie_header" "$@"
}

admin_write() {
  curl_json -H "Host: $admin_host" -H "cookie: $admin_cookie_header" -H "x-csrf-token: $csrf_token" "$@"
}

step login
rm -f "$login_headers" "$login_body"
jq -nc --arg username "$admin_username" --arg password "$PASS" '{username:$username,password:$password}' \
  | curl_json -D "$login_headers" -o "$login_body" -H "Host: $admin_host" -H 'content-type: application/json' \
      --data @- "$base_url/api/login"
csrf_token="$(jq -r '.csrfToken' "$login_body")"
test -n "$csrf_token"
test "$csrf_token" != "null"
session_cookie="$(sed -nE 's/^[Ss]et-[Cc]ookie: __Host-kcml_session=([^;]+).*/\1/p' "$login_headers" | tr -d '\r' | tail -n 1)"
csrf_cookie="$(sed -nE 's/^[Ss]et-[Cc]ookie: __Host-kcml_csrf=([^;]+).*/\1/p' "$login_headers" | tr -d '\r' | tail -n 1)"
test -n "$session_cookie"
test "$session_cookie" != "null"
test -n "$csrf_cookie"
test "$csrf_cookie" = "$csrf_token"
admin_cookie_header="__Host-kcml_session=${session_cookie}; __Host-kcml_csrf=${csrf_cookie}"

jq \
  --arg domain "$public_base_domain" \
  --arg revision "reference-api-${BUILD_ID:-release-smoke}" \
  '
    .registrationRevision = $revision
    | .endpoints.baseUrl = ("https://reference-api." + $domain)
    | .endpoints.healthcheckUrl = ("https://reference-api." + $domain + "/health")
    | .endpoints.readinessUrl = ("https://reference-api." + $domain + "/ready")
    | .egressPolicy.allowlist = [("reference-api." + $domain + ":443")]
  ' \
  "$release_dir/docs/service-manifest-external-api-v1.0.example.json" > "$manifest_file"

step discover-service
services_json="$(admin_read "$base_url/api/managed-services")"
service_id="$(jq -r '.services[] | select(.slug == "reference-external-api") | .id' <<<"$services_json" | head -n 1)"

intent_body() {
  jq -nc \
    --arg label "Reference EXTERNAL_API smoke" \
    '{
      label: $label,
      serviceKind: "EXTERNAL_API",
      descriptor: {
        summary: "Reference EXTERNAL_API smoke",
        businessPurpose: "Production smoke validation",
        serviceOwner: "KCML Managed Services",
        technicalOwner: "KCML Managed Services",
        criticality: "HIGH"
      }
    }'
}

step onboard-reference-service
if [ -n "$service_id" ] && [ "$service_id" != "null" ]; then
  step reuse-existing-reference-service
else
  intent_json="$(intent_body)"
  intent_response="$(
    admin_write -H 'content-type: application/json' \
      --data "$intent_json" "$base_url/api/integration-intents"
  )"
  integration_token="$(jq -r '.integrationToken' <<<"$intent_response")"
  onboarding_status="$(
    curl -sS -o "$tmpdir/onboarding-response.json" -w '%{http_code}' \
    -H "Host: $register_host" \
    -H "authorization: Bearer $integration_token" \
    -H "idempotency-key: $(cat /proc/sys/kernel/random/uuid)" \
    -H 'content-type: application/json' \
    --data @"$manifest_file" \
    "$base_url/v1/service-onboardings"
  )"
  printf '%s' "$onboarding_status" > "$tmpdir/onboarding-http-status.txt"
  test "$onboarding_status" = "202"
  service_id="$(jq -r '.job.serviceId' "$tmpdir/onboarding-response.json")"
fi
test -n "$service_id"
test "$service_id" != "null"

step load-managed-service-state
state_ready=false
for _attempt in $(seq 1 15); do
  state_json="$(admin_read "$base_url/api/managed-services/$service_id/state")"
  printf '%s\n' "$state_json" > "$tmpdir/managed-service-state.json"
  lock_version="$(jq -r '.lockVersion' <<<"$state_json")"
  public_hostname="$(jq -r '.publicHostname' <<<"$state_json")"
  resource_uri="$(jq -r '.resourceUri' <<<"$state_json")"
  api_state="$(jq -r '.apiState' <<<"$state_json")"
  enabled_state="$(jq -r '.enabled' <<<"$state_json")"
  if [ -n "$lock_version" ] && [ "$lock_version" != "null" ] && [ "$public_hostname" != "null" ] && [ "$resource_uri" != "null" ]; then
    state_ready=true
    break
  fi
  sleep 1
done
test "$state_ready" = "true"

if [ "$api_state" != "ENABLED" ] || [ "$enabled_state" != "true" ]; then
  step enable-managed-service
  enable_body="$(jq -nc --arg reason "release_smoke_enable_reference_api" --arg password "$PASS" '{reason:$reason,password:$password}')"
  admin_write \
    -H "if-match: \"$lock_version\"" \
    -H 'content-type: application/json' \
    --data "$enable_body" \
    "$base_url/api/managed-services/$service_id/api:enable" >/dev/null
  state_json="$(admin_read "$base_url/api/managed-services/$service_id/state")"
  printf '%s\n' "$state_json" > "$tmpdir/managed-service-state.json"
  lock_version="$(jq -r '.lockVersion' <<<"$state_json")"
  public_hostname="$(jq -r '.publicHostname' <<<"$state_json")"
  resource_uri="$(jq -r '.resourceUri' <<<"$state_json")"
  api_state="$(jq -r '.apiState' <<<"$state_json")"
  enabled_state="$(jq -r '.enabled' <<<"$state_json")"
fi
test "$api_state" = "ENABLED"
test "$enabled_state" = "true"

step create-kaja-credential
kaja_response="$(
  jq -nc --arg label "reference-external-api-smoke-${BUILD_ID:-release-smoke}" '{label:$label}' \
    | admin_write -H 'content-type: application/json' \
        --data @- "$base_url/api/kaja"
)"
client_id="$(jq -r '.publicId' <<<"$kaja_response")"
client_secret="$(jq -r '.clientSecret' <<<"$kaja_response")"
credentials_json="$(admin_read "$base_url/api/kaja")"
credential_id="$(jq -r --arg public_id "$client_id" '.credentials[] | select(.publicId == $public_id) | .id' <<<"$credentials_json" | head -n 1)"
test "$client_id" != "null"
test "$client_secret" != "null"
test -n "$credential_id"
test "$credential_id" != "null"

step grant-managed-service-permissions
permissions_body="$(
  jq -nc \
    --arg managedServiceId "$service_id" \
    '{
      permissions: [
        {
          managedServiceId: $managedServiceId,
          scopeNames: ["reference.shifts.read", "reference.time_off.write"]
        }
      ]
    }'
)"
admin_write \
  -X PUT \
  -H 'content-type: application/json' \
  --data "$permissions_body" \
  "$base_url/api/kaja/$credential_id/managed-service-permissions" >/dev/null

step issue-access-token
client_id_encoded="$(jq -rn --arg value "$client_id" '$value|@uri')"
client_secret_encoded="$(jq -rn --arg value "$client_secret" '$value|@uri')"
basic_auth="$(printf '%s:%s' "$client_id_encoded" "$client_secret_encoded" | base64 | tr -d '\r\n')"
token_http_status="$(
  curl -sS -o "$tmpdir/token-response.json" -w '%{http_code}' \
    -H "Host: $auth_host" \
    -H "authorization: Basic $basic_auth" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=client_credentials' \
    --data-urlencode "resource=$resource_uri" \
    "$base_url/oauth/token"
)"
printf '%s' "$token_http_status" > "$tmpdir/token-http-status.txt"
test "$token_http_status" = "200"
token_json="$(cat "$tmpdir/token-response.json")"
access_token="$(jq -r '.access_token' <<<"$token_json")"
test -n "$access_token"
test "$access_token" != "null"

step verify-direct-bypass-block
direct_status="$(
  curl -sS -o "$tmpdir/direct-bypass.json" -w '%{http_code}' \
    -H "Host: reference-api.$public_base_domain" \
    "$base_url/v1/shifts/release-smoke"
)"
test "$direct_status" = "403"
jq -e '.code == "REFERENCE_DIRECT_BYPASS_BLOCKED"' "$tmpdir/direct-bypass.json" >/dev/null

step exercise-gateway-read
gateway_read_status="$(
  curl -sS -o "$tmpdir/gateway-read.json" -w '%{http_code}' \
    -H "Host: $public_hostname" \
    -H "authorization: Bearer $access_token" \
    "$base_url/v1/shifts/release-smoke"
)"
printf '%s' "$gateway_read_status" > "$tmpdir/gateway-read-status.txt"
test "$gateway_read_status" = "200"
jq -e '.items[0].employeeId == "release-smoke"' "$tmpdir/gateway-read.json" >/dev/null

step exercise-gateway-write
curl_json \
  -X POST \
  -H "Host: $public_hostname" \
  -H "authorization: Bearer $access_token" \
  -H 'content-type: application/json' \
  --data '{"employeeId":"release-smoke","days":1}' \
  "$base_url/v1/time-off" \
  | jq -e '.accepted == true' >/dev/null

step verify-runtime-logs
runtime_logs_ready=false
for _attempt in $(seq 1 15); do
  logs_json="$(admin_read "$base_url/api/managed-services/$service_id/logs?limit=100")"
  printf '%s\n' "$logs_json" > "$tmpdir/managed-service-logs.json"
  if jq -e '.logs | map(select(.eventName == "external_api.gateway.request")) | length > 0' "$tmpdir/managed-service-logs.json" >/dev/null; then
    runtime_logs_ready=true
    break
  fi
  sleep 1
done
test "$runtime_logs_ready" = "true"

step revoke-kaja-credential
admin_write \
  -X POST \
  "$base_url/api/kaja/$credential_id/revoke" >/dev/null
