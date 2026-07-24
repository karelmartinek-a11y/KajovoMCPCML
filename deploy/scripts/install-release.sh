#!/usr/bin/env bash
set -Eeuo pipefail
umask 027

source_dir="${1:?verified release directory required}"
release_id="${2:?release id required}"
case "$release_id" in
  *[!A-Za-z0-9._-]*) echo "invalid release id" >&2; exit 1 ;;
esac
test "$(id -u)" = "0"
test -f "$source_dir/release-manifest.json"
test -f /etc/kcml/kcml.env
: "${PASS:?PASS is required}"

onboarding_catalog="$source_dir/docs/onboarding-catalogs/onboarding-1.1.json"
test -f "$onboarding_catalog"
component_hostname_pattern="$(jq -er '.identityAssignment.hostnamePattern' "$onboarding_catalog")"
component_hostname_suffix="$(printf '%s\n' "$component_hostname_pattern" | sed -n 's/^kcml####\.//p')"
test -n "$component_hostname_suffix"
[[ "$component_hostname_suffix" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]]

set -a
# shellcheck source=/dev/null
. /etc/kcml/kcml.env
set +a
export BUILD_ID="$release_id"
# Older installations predate explicit control-plane host variables. Derive
# only missing values from their configured base domain during the upgrade.
# shellcheck source=/dev/null
. "$source_dir/deploy/scripts/control-plane-hosts.sh"

release_dir="/opt/kcml/releases/$release_id"
previous_release="$(readlink -f /opt/kcml/current 2>/dev/null || true)"
test ! -e "$release_dir"
install -d -m 0755 /opt/kcml/releases
if [ -n "$previous_release" ] && [ -d "$previous_release" ]; then
  previous_release_id="$(basename "$previous_release")"
  bash "$source_dir/deploy/scripts/release-config.sh" snapshot "$previous_release_id"
else
  previous_release_id=""
fi
switched=false
current_step="init"
registry_auth_staged=false
step() {
  current_step="$1"
  echo "release-step:$current_step"
}
cleanup_registry_auth() {
  if [ "$registry_auth_staged" = "true" ]; then
    rm -f /var/lib/kcml/podman/auth.json /var/lib/kcml/podman/.docker/config.json
  fi
}
stage_registry_auth() {
  if [ -z "${GHCR_TOKEN:-}" ]; then
    return 0
  fi
  local ghcr_actor="${GHCR_ACTOR:-${GITHUB_ACTOR:-}}"
  test -n "$ghcr_actor"
  [[ "$ghcr_actor" =~ ^[A-Za-z0-9-]{1,39}$ ]]
  install -d -m 0700 -o kcml -g kcml /var/lib/kcml/podman /var/lib/kcml/podman/.docker
  local encoded_auth
  encoded_auth="$(printf '%s:%s' "$ghcr_actor" "$GHCR_TOKEN" | base64 -w0)"
  printf '{"auths":{"ghcr.io":{"auth":"%s"}}}\n' "$encoded_auth" > /var/lib/kcml/podman/auth.json
  unset encoded_auth
  chown kcml:kcml /var/lib/kcml/podman/auth.json
  chmod 0600 /var/lib/kcml/podman/auth.json
  install -m 0600 -o kcml -g kcml /var/lib/kcml/podman/auth.json /var/lib/kcml/podman/.docker/config.json
  registry_auth_staged=true
}
render_nginx_config() {
  local template="$1" target="$2"
  : "${PUBLIC_BASE_DOMAIN:?PUBLIC_BASE_DOMAIN is required}"
  : "${ADMIN_HOST:?ADMIN_HOST is required}"
  : "${AUTH_HOST:?AUTH_HOST is required}"
  : "${REGISTER_HOST:?REGISTER_HOST is required}"
  local tls_cert_path="${WILDCARD_TLS_CERT_PATH:-/etc/kcml/tls/fullchain.pem}"
  local tls_key_path="${WILDCARD_TLS_KEY_PATH:-${tls_cert_path%/*}/privkey.pem}"
  node "$source_dir/deploy/scripts/render-nginx-config.mjs" \
    "$template" "$target" "$PUBLIC_BASE_DOMAIN" "$component_hostname_suffix" "$ADMIN_HOST" "$AUTH_HOST" "$REGISTER_HOST" "$tls_cert_path" "$tls_key_path"
}
wait_for_sql_equals() {
  local label="$1" expected="$2" query="$3" attempts="${4:-1}" delay="${5:-2}"
  local actual=""
  for _attempt in $(seq 1 "$attempts"); do
    actual="$(psql "$app_database_url" --no-psqlrc --tuples-only --no-align --quiet --command "$query")"
    if [ "$actual" = "$expected" ]; then
      echo "release-check:$label=$actual"
      return 0
    fi
    sleep "$delay"
  done
  echo "release-check-failed:$label expected=$expected actual=$actual" >&2
  return 1
}
effective_admin_username() {
  local fallback="${ADMIN_BOOTSTRAP_USERNAME:-}"
  psql "$app_database_url" --no-psqlrc --tuples-only --no-align --quiet \
    --set fallback="$fallback" <<'SQL'
select coalesce(
  (select value_json #>> '{}' from operational_config_setting where key='adminBootstrapUsername' and value_json is not null),
  (select username from admin_account where role='OWNER' and active=true order by activated_at desc nulls last, created_at desc limit 1),
  nullif(:'fallback','')
)
SQL
}
rollback_on_error() {
  exit_code=$?
  trap - ERR
  echo "release-failed:$current_step" >&2
  cleanup_registry_auth
  if [ -n "$previous_release_id" ] && [ -d "$previous_release" ]; then
    if [ "$switched" = "true" ]; then
      restore_script="$release_dir/deploy/scripts/release-config.sh"
    else
      restore_script="$source_dir/deploy/scripts/release-config.sh"
    fi
    bash "$restore_script" restore "$previous_release_id" "$previous_release" || true
  fi
  exit "$exit_code"
}
trap rollback_on_error ERR

restart_core_services() {
  systemctl restart kcml
  systemctl restart kcml-egress-proxy
  systemctl restart kcml-secret-broker
  systemctl restart kcml-onboarding-worker
  systemctl restart kcml-component-control-worker
  systemctl restart kcml-component-e2e-worker
  systemctl restart kcml-monitor
}

queue_webhook_smoke() {
  test_alert_id="$(psql "$DATABASE_APP_URL" --no-psqlrc --tuples-only --no-align --quiet --set ON_ERROR_STOP=1 \
    --set correlation="$test_correlation" --set release_id="$release_id" <<'SQL' | tail -n 1
begin;
update operational_alert
   set status='CLOSED',closed_at=now(),last_seen_at=now()
 where alert_type='deployment.webhook_test' and status in ('OPEN','ACKNOWLEDGED','SUPPRESSED');
insert into operational_alert(severity,alert_type,title,detail,correlation_id)
values ('CRITICAL','deployment.webhook_test','KCML deployment webhook test',jsonb_build_object('buildId', :'release_id'),:'correlation'::uuid)
returning id \gset
insert into alert_webhook_delivery(alert_id,channel,idempotency_key)
values (:'id','PRIMARY',gen_random_uuid()),(:'id','BACKUP',gen_random_uuid());
select append_audit_event(
  'deployment.webhook_test.opened','deployment',null,'operational_alert',:'id',null,
  jsonb_build_object('buildId', :'release_id'),:'correlation'::uuid
);
commit;
\echo :id
SQL
)"
  [[ "$test_alert_id" =~ ^[0-9a-f-]{36}$ ]]
}

wait_for_runtime_health() {
  local admin_host="$1"
  local healthy=false
  for _attempt in $(seq 1 45); do
    if curl -fsS -H "Host: $admin_host" "http://127.0.0.1:${PORT:-3010}/health" >/dev/null \
      && systemctl is-active --quiet kcml \
      && systemctl is-active --quiet kcml-egress-proxy \
      && systemctl is-active --quiet kcml-secret-broker \
      && systemctl is-active --quiet kcml-onboarding-worker \
      && systemctl is-active --quiet kcml-component-control-worker \
      && systemctl is-active --quiet kcml-component-e2e-worker \
      && systemctl is-active --quiet kcml-monitor \
      && systemctl is-active --quiet kcml-alert-primary \
      && systemctl is-active --quiet kcml-alert-backup \
      && curl -fsS http://127.0.0.1:3011/health >/dev/null \
      && curl -fsS http://127.0.0.1:3012/health >/dev/null \
      && test -S "${EGRESS_PROXY_SOCKET_PATH:-/var/lib/kcml/egress/proxy.sock}" \
      && test -S "${SECRET_BROKER_SOCKET_PATH:-/var/lib/kcml/secret-broker/proxy.sock}"; then
      healthy=true
      break
    fi
    sleep 2
  done

  if [ "$healthy" != "true" ]; then
    systemctl status kcml kcml-egress-proxy kcml-secret-broker kcml-onboarding-worker kcml-component-control-worker kcml-component-e2e-worker kcml-monitor kcml-alert-primary kcml-alert-backup --no-pager -l || true
    for service in kcml kcml-egress-proxy kcml-secret-broker kcml-onboarding-worker kcml-component-control-worker kcml-component-e2e-worker kcml-monitor; do
      echo "==== journal:$service ====" >&2
      journalctl -u "$service" --no-pager -n 80 || true
    done
    return 1
  fi
}

require_stable_runtime_health() {
  local admin_host="$1"
  for _attempt in $(seq 1 13); do
    curl -fsS -H "Host: $admin_host" "http://127.0.0.1:${PORT:-3010}/health" >/dev/null
    systemctl is-active --quiet kcml
    systemctl is-active --quiet kcml-component-control-worker
    systemctl is-active --quiet kcml-component-e2e-worker
    systemctl is-active --quiet kcml-monitor
    sleep 5
  done
}

render_nginx_config "$source_dir/deploy/nginx/kcml.conf" /etc/nginx/sites-available/kcml.conf
ln -sfn /etc/nginx/sites-available/kcml.conf /etc/nginx/sites-enabled/kcml.conf
install -m 0755 "$source_dir/deploy/scripts/kcml-deploy-wrapper.sh" /usr/local/sbin/kcml-deploy-wrapper
install -m 0755 "$source_dir/deploy/scripts/kcml-repository-component-deploy-wrapper.sh" /usr/local/sbin/kcml-repository-component-deploy-wrapper
install -m 0755 "$source_dir/deploy/scripts/kcml-handler-preload-wrapper.sh" /usr/local/sbin/kcml-handler-preload-wrapper
if id kcml-deploy >/dev/null 2>&1 && [ -d /opt/actions-runner/kcml-deploy/_work ]; then
  install -d -m 0755 -o kcml-deploy -g kcml-deploy /opt/actions-runner/kcml-deploy/_work/_temp
  chown -R kcml-deploy:kcml-deploy /opt/actions-runner/kcml-deploy/_work/_temp
fi
cat >/etc/sudoers.d/kcml-deploy-wrappers <<'EOF'
Defaults:kcml-deploy !requiretty
Defaults:kcml-deploy env_keep += "PASS GHCR_TOKEN GHCR_ACTOR KCML_FACTORY_RESET_CONFIRM"
kcml-deploy ALL=(root) NOPASSWD:SETENV: /usr/local/sbin/kcml-deploy-wrapper
kcml-deploy ALL=(root) NOPASSWD:SETENV: /usr/local/sbin/kcml-repository-component-deploy-wrapper
kcml-deploy ALL=(root) NOPASSWD:SETENV: /usr/local/sbin/kcml-handler-preload-wrapper
EOF
chmod 0440 /etc/sudoers.d/kcml-deploy-wrappers
visudo -cf /etc/sudoers.d/kcml-deploy-wrappers
install -d -m 0755 /usr/local/libexec
install -m 0755 "$source_dir/deploy/scripts/install-repository-component.sh" /usr/local/libexec/kcml-install-repository-component
for unit in kcml.service kcml-onboarding-worker.service kcml-component-control-worker.service kcml-component-e2e-worker.service kcml-monitor.service kcml-egress-proxy.service kcml-alert-primary.service kcml-alert-backup.service kcml-secret-broker.service; do
  install -m 0644 "$source_dir/deploy/systemd/$unit" "/etc/systemd/system/$unit"
done
install -d -m 0755 /opt/kcml/alert-sink
install -m 0755 "$source_dir/deploy/alert-sink/receiver.mjs" /opt/kcml/alert-sink/receiver.mjs
install -d -m 0700 -o kcml -g kcml /var/lib/kcml/alert-primary-sink /var/lib/kcml/alert-backup-sink
install -d -m 0750 -o kcml -g kcml /var/lib/kcml/repository-components
install -d -m 0711 -o kcml -g kcml /var/lib/kcml/secret-broker /var/lib/kcml/egress
kcml_uid="$(id -u kcml)"
install -d -m 0755 /etc/systemd/system/kcml-onboarding-worker.service.d
sed "s/@KCML_UID@/${kcml_uid}/g" "$source_dir/deploy/systemd/kcml-onboarding-worker-runtime.conf.in" \
  > /etc/systemd/system/kcml-onboarding-worker.service.d/runtime-user.conf
chmod 0644 /etc/systemd/system/kcml-onboarding-worker.service.d/runtime-user.conf
install -d -m 0755 /etc/systemd/system/kcml-monitor.service.d
sed "s/@KCML_UID@/${kcml_uid}/g" "$source_dir/deploy/systemd/kcml-monitor-runtime.conf.in" \
  > /etc/systemd/system/kcml-monitor.service.d/runtime-user.conf
chmod 0644 /etc/systemd/system/kcml-monitor.service.d/runtime-user.conf

step split-config-initial
DATABASE_APP_URL="${DATABASE_APP_URL:-$DATABASE_URL}" bash "$source_dir/deploy/scripts/split-service-config.sh" "$release_id"
step expose-canonical-tls-challenge
nginx -t
systemctl reload nginx
step ensure-canonical-tls
tls_cert_path="${WILDCARD_TLS_CERT_PATH:-/etc/kcml/tls/fullchain.pem}"
tls_key_path="${WILDCARD_TLS_KEY_PATH:-${tls_cert_path%/*}/privkey.pem}"
bash "$source_dir/deploy/scripts/ensure-canonical-tls.sh" \
  "$PUBLIC_BASE_DOMAIN" "$component_hostname_suffix" "$tls_cert_path" "$tls_key_path"

step preflight
export KCML_COMPONENT_HOST_SUFFIX="$component_hostname_suffix"
KCML_RELEASE_SOURCE="$source_dir" bash "$source_dir/deploy/scripts/preflight.sh"
step backup
bash "$source_dir/deploy/scripts/backup.sh"

step migrate
KCML_PROCESS_ROLE=migrate \
DATABASE_URL_FILE=/etc/kcml/credentials/migrator/database_url \
NODE_ENV=production \
BUILD_ID="$release_id" \
  node "$source_dir/apps/server/dist/cli/migrate.js"

step configure-db-roles
bash "$source_dir/deploy/scripts/configure-db-roles.sh"
DATABASE_APP_URL="$(cat /etc/kcml/database-app.url)"
export DATABASE_APP_URL
step split-config-final
bash "$source_dir/deploy/scripts/split-service-config.sh" "$release_id"
stage_registry_auth

step import-operational-config
KCML_PROCESS_ROLE=admin-sync \
DATABASE_URL_FILE=/etc/kcml/credentials/admin-sync/database_url \
CONFIG_VAULT_MASTER_KEY_BASE64_FILE=/etc/kcml/credentials/config_vault_master_key \
NODE_ENV=production \
BUILD_ID="$release_id" \
  node "$source_dir/apps/server/dist/cli/import-operational-config.js" --refresh-build-id

step migrate-mfa-secrets
KCML_PROCESS_ROLE=admin-sync \
DATABASE_URL_FILE=/etc/kcml/credentials/admin-sync/database_url \
CONFIG_VAULT_MASTER_KEY_BASE64_FILE=/etc/kcml/credentials/config_vault_master_key \
NODE_ENV=production \
BUILD_ID="$release_id" \
  node "$source_dir/apps/server/dist/cli/migrate-mfa-secrets.js"

step forensic-admin-credentials
PASS="$PASS" \
KCML_PROCESS_ROLE=migrate \
DATABASE_URL_FILE=/etc/kcml/credentials/migrator/database_url \
CONFIG_VAULT_MASTER_KEY_BASE64_FILE=/etc/kcml/credentials/config_vault_master_key \
NODE_ENV=production \
BUILD_ID="$release_id" \
  node "$source_dir/apps/server/dist/cli/admin-credential-forensics.js"

step sync-admin-password
admin_sync_result="$(PASS="$PASS" \
KCML_ADMIN_PASSWORD_ROTATION_CONFIRM="${KCML_ADMIN_PASSWORD_ROTATION_CONFIRM:-}" \
KCML_PROCESS_ROLE=admin-sync \
DATABASE_URL_FILE=/etc/kcml/credentials/admin-sync/database_url \
CONFIG_VAULT_MASTER_KEY_BASE64_FILE=/etc/kcml/credentials/config_vault_master_key \
NODE_ENV=production \
BUILD_ID="$release_id" \
  node "$source_dir/apps/server/dist/cli/sync-admin-password.js")"
printf '%s\n' "$admin_sync_result"
admin_password_matches_pass="$(jq -er '.passwordMatchesInput | tostring' <<<"$admin_sync_result")"

step ensure-platform-worker-access
KCML_PROCESS_ROLE=admin-sync \
DATABASE_URL_FILE=/etc/kcml/credentials/admin-sync/database_url \
CONFIG_VAULT_MASTER_KEY_BASE64_FILE=/etc/kcml/credentials/config_vault_master_key \
NODE_ENV=production \
BUILD_ID="$release_id" \
  node "$source_dir/apps/server/dist/cli/ensure-platform-worker-access.js"

mv "$source_dir" "$release_dir"
chown -R root:kcml "$release_dir"
chmod -R g=rX,o= "$release_dir"
ln -sfn "$release_dir" /opt/kcml/current
switched=true

step activate-services
systemctl daemon-reload
systemctl enable kcml kcml-onboarding-worker kcml-component-control-worker kcml-component-e2e-worker kcml-monitor kcml-egress-proxy kcml-secret-broker kcml-alert-primary kcml-alert-backup
systemctl restart kcml-alert-primary
systemctl restart kcml-alert-backup
nginx -t
systemctl reload nginx

test_correlation="$(cat /proc/sys/kernel/random/uuid)"
if [ -z "${KCML_FACTORY_RESET_CONFIRM:-}" ]; then
  step queue-webhook-smoke
  queue_webhook_smoke
fi

restart_core_services

admin_host="${ADMIN_HOST:?ADMIN_HOST is required}"
if [ -z "${KCML_FACTORY_RESET_CONFIRM:-}" ]; then
  step wait-runtime-health
  wait_for_runtime_health "$admin_host"
fi

if [ -n "${KCML_FACTORY_RESET_CONFIRM:-}" ]; then
  step factory-reset
  PASS="$PASS" \
  KCML_PROCESS_ROLE=migrate \
  DATABASE_URL_FILE=/etc/kcml/credentials/migrator/database_url \
  CONFIG_VAULT_MASTER_KEY_BASE64_FILE=/etc/kcml/credentials/config_vault_master_key \
  NODE_ENV=production \
  BUILD_ID="$release_id" \
  KCML_FACTORY_RESET_CONFIRM="${KCML_FACTORY_RESET_CONFIRM}" \
    node "$release_dir/apps/server/dist/cli/factory-reset.js"

  step ensure-platform-worker-access-post-reset
  KCML_PROCESS_ROLE=admin-sync \
  DATABASE_URL_FILE=/etc/kcml/credentials/admin-sync/database_url \
  CONFIG_VAULT_MASTER_KEY_BASE64_FILE=/etc/kcml/credentials/config_vault_master_key \
  NODE_ENV=production \
  BUILD_ID="$release_id" \
    node "$release_dir/apps/server/dist/cli/ensure-platform-worker-access.js"

  step restart-services-post-reset
  restart_core_services

  step wait-runtime-health-post-reset
  wait_for_runtime_health "$admin_host"

  step queue-webhook-smoke-post-reset
  queue_webhook_smoke
fi

app_database_url="$(cat /etc/kcml/database-app.url)"
webhook_delivered=false
step wait-alert-webhooks
for _attempt in $(seq 1 75); do
  if [ "$(psql "$app_database_url" --no-psqlrc --tuples-only --no-align --quiet --command \
    "select count(*) from alert_webhook_delivery where alert_id='$test_alert_id' and state='DELIVERED' and last_http_status=200")" = "2" ]; then
    webhook_delivered=true
    break
  fi
  sleep 2
done
if [ "$webhook_delivered" != "true" ]; then
  psql "$app_database_url" --no-psqlrc --tuples-only --no-align --quiet --command \
    "select channel,state,attempt_count,coalesce(last_http_status::text,''),coalesce(last_error,'') from alert_webhook_delivery where alert_id='$test_alert_id' order by channel" >&2 || true
  false
fi
while IFS='|' read -r channel delivery_id; do
  case "$channel" in
    PRIMARY) test -s "/var/lib/kcml/alert-primary-sink/$delivery_id.json" ;;
    BACKUP) test -s "/var/lib/kcml/alert-backup-sink/$delivery_id.json" ;;
    *) exit 1 ;;
  esac
done < <(psql "$app_database_url" --no-psqlrc --tuples-only --no-align --quiet --command \
  "select channel,idempotency_key from alert_webhook_delivery where alert_id='$test_alert_id' order by channel")

admin_username="$(effective_admin_username)"
export ADMIN_BOOTSTRAP_USERNAME="$admin_username"
step verify-core-hosts
if [ "$admin_password_matches_pass" = "true" ]; then
PASS="$PASS" \
KCML_PROCESS_ROLE=admin-sync \
DATABASE_URL_FILE=/etc/kcml/credentials/admin-sync/database_url \
CONFIG_VAULT_MASTER_KEY_BASE64_FILE=/etc/kcml/credentials/config_vault_master_key \
NODE_ENV=production \
BUILD_ID="$release_id" \
KCML_LOGIN_SMOKE_BASE_URL="http://127.0.0.1:${PORT:-3010}" \
KCML_LOGIN_SMOKE_HOST="$admin_host" \
  node "$release_dir/apps/server/dist/cli/admin-login-smoke.js" | jq -e '.ok == true' >/dev/null
PASS="$PASS" \
KCML_PROCESS_ROLE=admin-sync \
DATABASE_URL_FILE=/etc/kcml/credentials/admin-sync/database_url \
CONFIG_VAULT_MASTER_KEY_BASE64_FILE=/etc/kcml/credentials/config_vault_master_key \
NODE_ENV=production \
BUILD_ID="$release_id" \
KCML_LOGIN_SMOKE_BASE_URL="https://${admin_host}" \
KCML_LOGIN_SMOKE_HOST="$admin_host" \
  node "$release_dir/apps/server/dist/cli/admin-login-smoke.js" | jq -e '.ok == true' >/dev/null
else
  echo "admin-login-smoke:SKIPPED preserved_owner_credential_diverges_from_pass"
fi
curl -fsS -H "Host: ${AUTH_HOST:?AUTH_HOST is required}" \
  "http://127.0.0.1:${PORT:-3010}/.well-known/oauth-authorization-server" \
  | jq -e --arg issuer "https://${AUTH_HOST}" '.issuer == $issuer' >/dev/null
curl -fsS -H "Host: secrets.${PUBLIC_BASE_DOMAIN:?PUBLIC_BASE_DOMAIN is required}" \
  "http://127.0.0.1:${PORT:-3010}/.well-known/kcml-secret-api" \
  | jq -e --arg issuer "https://secrets.${PUBLIC_BASE_DOMAIN}" \
      --arg resolve "https://secrets.${PUBLIC_BASE_DOMAIN}/v1/secrets/resolve" \
      '.issuer == $issuer and .resolveEndpoint == $resolve and (.auth | sort) == ["access_token_bearer", "integration_token_bearer"]' >/dev/null
curl -fsS "https://secrets.${PUBLIC_BASE_DOMAIN}/.well-known/kcml-secret-api" \
  | jq -e --arg issuer "https://secrets.${PUBLIC_BASE_DOMAIN}" \
      --arg resolve "https://secrets.${PUBLIC_BASE_DOMAIN}/v1/secrets/resolve" \
      '.issuer == $issuer and .resolveEndpoint == $resolve and (.auth | sort) == ["access_token_bearer", "integration_token_bearer"]' >/dev/null
curl -fsS "https://secrets.${PUBLIC_BASE_DOMAIN}/health" \
  | jq -e '.status == "ok"' >/dev/null
test "$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: unknown.invalid' \
  "http://127.0.0.1:${PORT:-3010}/health")" = "404"
step smoke-reference-external-api
if [ "$admin_password_matches_pass" = "true" ]; then
  bash "$release_dir/deploy/scripts/smoke-reference-external-api.sh" "$release_dir"
else
  echo "reference-smoke:SKIPPED preserved_owner_credential_diverges_from_pass"
fi

step finalize-webhook-smoke
psql "$app_database_url" --no-psqlrc --quiet --set ON_ERROR_STOP=1 \
  --set alert_id="$test_alert_id" --set correlation="$test_correlation" --set release_id="$release_id" --set admin_username="$admin_username" <<'SQL'
begin;
update operational_alert set status='CLOSED',closed_at=now(),last_seen_at=now() where id=:'alert_id';
update admin_session
   set revoked_at=now()
 where account_id=(select id from admin_account where username=:'admin_username') and revoked_at is null;
select append_audit_event(
  'deployment.webhook_test.closed','deployment',null,'operational_alert',:'alert_id',null,
  jsonb_build_object('buildId', :'release_id'),:'correlation'::uuid
);
commit;
SQL

step verify-final-invariants
wait_for_sql_equals "audit_chain" "t" "select valid from verify_audit_chain()"
wait_for_sql_equals "canonical_component_identity" "0" "select count(*) from component where code <> ('KCML' || lpad(kcml_number::text,4,'0')) or hostname <> (lower(code) || '.${component_hostname_suffix}')" 1 1
wait_for_sql_equals "canonical_managed_service_identity" "0" "select count(*) from managed_service service join component on component.id=service.component_id where service.public_hostname is distinct from component.hostname or service.resource_uri is distinct from case when service.service_kind='MCP' then 'https://' || component.hostname || '/mcp' else 'https://' || component.hostname end" 1 1
wait_for_sql_equals "retired_component_credentials" "0" "select count(*) from component_credential where status='ACTIVE' and revoked_at is null" 1 1
wait_for_sql_equals "integration_secret_grants" "0" "select count(*) from secret_grant where principal_kind='INTEGRATION_TOKEN' and revoked_at is null" 1 1
wait_for_sql_equals "integration_token_lifetime" "0" "select count(*) from integration_token where revoked_at is null and (initial_expires_at <> issued_at + interval '24 hours' or expires_at <> issued_at + interval '24 hours' or max_expires_at <> issued_at + interval '24 hours')" 1 1
canonical_component_hostname="$(psql "$app_database_url" --no-psqlrc --tuples-only --no-align --quiet --command \
  "select component.hostname from component join component_revision revision on revision.id=component.active_revision_id and revision.component_id=component.id where component.deregistered_at is null order by component.kcml_number limit 1")"
if [ -n "$canonical_component_hostname" ]; then
  curl -fsS -H "Host: $canonical_component_hostname" \
    "http://127.0.0.1:${PORT:-3010}/.well-known/oauth-protected-resource/mcp" \
    | jq -e --arg resource "https://${canonical_component_hostname}/mcp" '.resource == $resource' >/dev/null
  curl -fsS "https://${canonical_component_hostname}/.well-known/oauth-protected-resource/mcp" \
    | jq -e --arg resource "https://${canonical_component_hostname}/mcp" '.resource == $resource' >/dev/null
  echo "release-check:canonical_component_metadata=PASS"
else
  echo "release-check:canonical_component_metadata=SKIPPED clean_start_no_registered_component"
fi
wait_for_sql_equals "baseline_migration_row" "1" "select count(*) from schema_migration where version='001_pre_production_baseline.sql'"
wait_for_sql_equals "secret_broker_process_role_migration_row" "1" "select count(*) from schema_migration where version='002_secret_broker_process_role.sql'"
wait_for_sql_equals "component_onboarding_v1_1_migration_row" "1" "select count(*) from schema_migration where version='003_component_onboarding_v1_1.sql'"
wait_for_sql_equals "baseline_migration_count" "3" "select count(*) from schema_migration"

step verify-stable-runtime-health
require_stable_runtime_health "$admin_host"

trap - ERR
cleanup_registry_auth
echo "release-installed:$release_id"
