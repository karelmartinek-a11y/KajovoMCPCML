#!/usr/bin/env bash
set -euo pipefail

release_dir="${1:?release directory required}"
: "${PASS:?PASS is required}"

admin_host="${ADMIN_HOST:-admin.hcasc.cz}"
auth_host="${AUTH_HOST:-auth.hcasc.cz}"
register_host="${REGISTER_HOST:-register.hcasc.cz}"
public_base_domain="${PUBLIC_BASE_DOMAIN:-hcasc.cz}"
port="${PORT:-3010}"
admin_username="${ADMIN_BOOTSTRAP_USERNAME:-karmar78}"
base_url="http://127.0.0.1:${port}"

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

cookiejar="$tmpdir/cookies.txt"
manifest_file="$tmpdir/reference-manifest.json"

curl_json() {
  curl -fsS "$@"
}

csrf_token="$(
  jq -nc --arg username "$admin_username" --arg password "$PASS" '{username:$username,password:$password}' \
    | curl_json -c "$cookiejar" -H "Host: $admin_host" -H 'content-type: application/json' \
        --data @- "$base_url/api/login" \
    | jq -r '.csrfToken'
)"
test -n "$csrf_token"

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

services_json="$(curl_json -b "$cookiejar" -H "Host: $admin_host" "$base_url/api/managed-services")"
service_id="$(jq -r '.services[] | select(.slug == "reference-external-api") | .id' <<<"$services_json" | head -n 1)"
service_code="$(jq -r '.services[] | select(.slug == "reference-external-api") | .code' <<<"$services_json" | head -n 1)"

intent_body() {
  local resume_job_id="${1:-}"
  if [ -n "$resume_job_id" ]; then
    jq -nc \
      --arg label "Reference EXTERNAL_API smoke" \
      --arg resumeJobId "$resume_job_id" \
      '{
        label: $label,
        serviceKind: "EXTERNAL_API",
        resumeJobId: $resumeJobId,
        descriptor: {
          summary: "Reference EXTERNAL_API smoke",
          businessPurpose: "Production smoke validation",
          serviceOwner: "KCML Managed Services",
          technicalOwner: "KCML Managed Services",
          criticality: "HIGH"
        }
      }'
  else
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
  fi
}

if [ -n "$service_id" ]; then
  jobs_json="$(curl_json -b "$cookiejar" -H "Host: $admin_host" "$base_url/api/onboarding-jobs")"
  job_id="$(jq -r --arg code "$service_code" '.jobs[] | select(.code == $code) | .id' <<<"$jobs_json" | head -n 1)"
  job_lock_version="$(jq -r --arg job_id "$job_id" '.jobs[] | select(.id == $job_id) | .lockVersion' <<<"$jobs_json" | head -n 1)"
  test -n "$job_id"
  test -n "$job_lock_version"
  intent_json="$(intent_body "$job_id")"
  intent_response="$(
    curl_json -b "$cookiejar" -H "Host: $admin_host" -H "x-csrf-token: $csrf_token" -H 'content-type: application/json' \
      --data "$intent_json" "$base_url/api/integration-intents"
  )"
  integration_token="$(jq -r '.integrationToken' <<<"$intent_response")"
  curl_json -X PUT \
    -H "Host: $register_host" \
    -H "authorization: Bearer $integration_token" \
    -H "idempotency-key: $(cat /proc/sys/kernel/random/uuid)" \
    -H "if-match: \"$job_lock_version\"" \
    -H 'content-type: application/json' \
    --data @"$manifest_file" \
    "$base_url/v1/service-onboardings/$job_id/revision" > "$tmpdir/onboarding-response.json"
else
  intent_json="$(intent_body)"
  intent_response="$(
    curl_json -b "$cookiejar" -H "Host: $admin_host" -H "x-csrf-token: $csrf_token" -H 'content-type: application/json' \
      --data "$intent_json" "$base_url/api/integration-intents"
  )"
  integration_token="$(jq -r '.integrationToken' <<<"$intent_response")"
  curl_json \
    -H "Host: $register_host" \
    -H "authorization: Bearer $integration_token" \
    -H "idempotency-key: $(cat /proc/sys/kernel/random/uuid)" \
    -H 'content-type: application/json' \
    --data @"$manifest_file" \
    "$base_url/v1/service-onboardings" > "$tmpdir/onboarding-response.json"
  service_id="$(jq -r '.job.serviceId' "$tmpdir/onboarding-response.json")"
fi

test -n "$service_id"
state_json="$(curl_json -b "$cookiejar" -H "Host: $admin_host" "$base_url/api/managed-services/$service_id/state")"
lock_version="$(jq -r '.lockVersion' <<<"$state_json")"
public_hostname="$(jq -r '.publicHostname' <<<"$state_json")"
resource_uri="$(jq -r '.resourceUri' <<<"$state_json")"
api_state="$(jq -r '.apiState' <<<"$state_json")"

if [ "$api_state" != "ENABLED" ]; then
  enable_body="$(jq -nc --arg reason "release_smoke_enable_reference_api" --arg password "$PASS" '{reason:$reason,password:$password}')"
  curl_json \
    -b "$cookiejar" \
    -H "Host: $admin_host" \
    -H "x-csrf-token: $csrf_token" \
    -H "if-match: \"$lock_version\"" \
    -H 'content-type: application/json' \
    --data "$enable_body" \
    "$base_url/api/managed-services/$service_id/api:enable" >/dev/null
fi

kaja_response="$(
  jq -nc --arg label "reference-external-api-smoke-${BUILD_ID:-release-smoke}" '{label:$label}' \
    | curl_json -b "$cookiejar" -H "Host: $admin_host" -H "x-csrf-token: $csrf_token" -H 'content-type: application/json' \
        --data @- "$base_url/api/kaja"
)"
client_id="$(jq -r '.publicId' <<<"$kaja_response")"
client_secret="$(jq -r '.clientSecret' <<<"$kaja_response")"
credentials_json="$(curl_json -b "$cookiejar" -H "Host: $admin_host" "$base_url/api/kaja")"
credential_id="$(jq -r --arg public_id "$client_id" '.credentials[] | select(.publicId == $public_id) | .id' <<<"$credentials_json" | head -n 1)"
test -n "$credential_id"

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
curl_json \
  -X PUT \
  -b "$cookiejar" \
  -H "Host: $admin_host" \
  -H "x-csrf-token: $csrf_token" \
  -H 'content-type: application/json' \
  --data "$permissions_body" \
  "$base_url/api/kaja/$credential_id/managed-service-permissions" >/dev/null

client_id_encoded="$(jq -rn --arg value "$client_id" '$value|@uri')"
client_secret_encoded="$(jq -rn --arg value "$client_secret" '$value|@uri')"
resource_encoded="$(jq -rn --arg value "$resource_uri" '$value|@uri')"
basic_auth="$(printf '%s:%s' "$client_id_encoded" "$client_secret_encoded" | base64)"
token_json="$(
  curl_json -H "Host: $auth_host" \
    -H "authorization: Basic $basic_auth" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data "grant_type=client_credentials&resource=$resource_encoded" \
    "$base_url/oauth/token"
)"
access_token="$(jq -r '.access_token' <<<"$token_json")"
test -n "$access_token"

curl_json \
  -H "Host: $public_hostname" \
  -H "authorization: Bearer $access_token" \
  "$base_url/v1/shifts/release-smoke" \
  | jq -e '.items[0].employeeId == "release-smoke"' >/dev/null

curl_json \
  -X POST \
  -H "Host: $public_hostname" \
  -H "authorization: Bearer $access_token" \
  -H 'content-type: application/json' \
  --data '{"employeeId":"release-smoke","days":1}' \
  "$base_url/v1/time-off" \
  | jq -e '.accepted == true' >/dev/null

direct_status="$(
  curl -sS -o "$tmpdir/direct-bypass.json" -w '%{http_code}' \
    -H "Host: reference-api.$public_base_domain" \
    "$base_url/v1/shifts/release-smoke"
)"
test "$direct_status" = "403"
jq -e '.code == "REFERENCE_DIRECT_BYPASS_BLOCKED"' "$tmpdir/direct-bypass.json" >/dev/null

curl_json -b "$cookiejar" -H "Host: $admin_host" "$base_url/api/managed-services/$service_id/logs?limit=20" \
  | jq -e '.logs | map(select(.eventName == "external_api.gateway.request")) | length > 0' >/dev/null

curl_json \
  -X POST \
  -b "$cookiejar" \
  -H "Host: $admin_host" \
  -H "x-csrf-token: $csrf_token" \
  "$base_url/api/kaja/$credential_id/revoke" >/dev/null
