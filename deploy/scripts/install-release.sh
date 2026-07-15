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

set -a
. /etc/kcml/kcml.env
set +a
export BUILD_ID="$release_id"

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
run_kcml0002_runtime_refresh() {
  local worker_env_args=()
  local key value
  while IFS='=' read -r key value; do
    [ -n "$key" ] || continue
    case "$key" in \#*) continue ;; esac
    worker_env_args+=("$key=$value")
  done < /etc/kcml/worker.env
  runuser -u kcml -- env \
    "${worker_env_args[@]}" \
    KCML_PROCESS_ROLE=worker \
    DATABASE_URL_FILE=/etc/kcml/credentials/worker/database_url \
    EGRESS_CAPABILITY_HMAC_KEY_BASE64_FILE=/etc/kcml/credentials/worker/egress_capability_hmac \
    GITHUB_TOKEN_FILE=/etc/kcml/credentials/worker/github_token \
    GITHUB_APP_PRIVATE_KEY_BASE64_FILE=/etc/kcml/credentials/worker/github_app_private_key \
    HOME=/var/lib/kcml/podman \
    XDG_DATA_HOME=/var/lib/kcml/podman/data \
    XDG_CONFIG_HOME=/var/lib/kcml/podman/config \
    XDG_RUNTIME_DIR=/run/kcml-podman \
    DBUS_SESSION_BUS_ADDRESS=unix:path=/run/kcml-podman/bus \
    REGISTRY_AUTH_FILE=/var/lib/kcml/podman/auth.json \
    DOCKER_CONFIG=/var/lib/kcml/podman/.docker \
    BUILD_ID="$release_id" \
    node "$release_dir/apps/server/dist/cli/release-kcml0002-runtime-refresh.js"
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
rollback_on_error() {
  exit_code=$?
  trap - ERR
  echo "release-failed:$current_step" >&2
  cleanup_registry_auth
  if [ "$switched" = "true" ] && [ -n "$previous_release_id" ] && [ -d "$previous_release" ]; then
    bash "$release_dir/deploy/scripts/release-config.sh" restore "$previous_release_id" "$previous_release" || true
  fi
  exit "$exit_code"
}
trap rollback_on_error ERR

install -m 0644 "$source_dir/deploy/nginx/kcml.conf" /etc/nginx/sites-available/kcml.conf
ln -sfn /etc/nginx/sites-available/kcml.conf /etc/nginx/sites-enabled/kcml.conf
install -m 0755 "$source_dir/deploy/scripts/kcml-deploy-wrapper.sh" /usr/local/sbin/kcml-deploy-wrapper
install -m 0755 "$source_dir/deploy/scripts/kcml-handler-preload-wrapper.sh" /usr/local/sbin/kcml-handler-preload-wrapper
for unit in kcml.service kcml-onboarding-worker.service kcml-monitor.service kcml-egress-proxy.service kcml-alert-primary.service kcml-alert-backup.service; do
  install -m 0644 "$source_dir/deploy/systemd/$unit" "/etc/systemd/system/$unit"
done
install -d -m 0755 /opt/kcml/alert-sink
install -m 0755 "$source_dir/deploy/alert-sink/receiver.mjs" /opt/kcml/alert-sink/receiver.mjs
install -d -m 0700 -o kcml -g kcml /var/lib/kcml/alert-primary-sink /var/lib/kcml/alert-backup-sink
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
step preflight
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
export DATABASE_APP_URL="$(cat /etc/kcml/database-app.url)"
step split-config-final
bash "$source_dir/deploy/scripts/split-service-config.sh" "$release_id"
stage_registry_auth

step sync-admin-password
PASS="$PASS" \
KCML_PROCESS_ROLE=admin-sync \
DATABASE_URL_FILE=/etc/kcml/credentials/admin-sync/database_url \
MFA_ENCRYPTION_KEY_BASE64_FILE=/etc/kcml/credentials/admin-sync/mfa_encryption \
ADMIN_TOTP_SECRET_FILE=/etc/kcml/credentials/admin-sync/admin_totp \
NODE_ENV=production \
BUILD_ID="$release_id" \
  node "$source_dir/apps/server/dist/cli/sync-admin-password.js"

mv "$source_dir" "$release_dir"
chown -R root:kcml "$release_dir"
chmod -R g=rX,o= "$release_dir"
ln -sfn "$release_dir" /opt/kcml/current
switched=true

step activate-services
systemctl daemon-reload
systemctl enable kcml kcml-onboarding-worker kcml-monitor kcml-egress-proxy kcml-alert-primary kcml-alert-backup
systemctl restart kcml-alert-primary
systemctl restart kcml-alert-backup
nginx -t
systemctl reload nginx

test_correlation="$(cat /proc/sys/kernel/random/uuid)"
step queue-webhook-smoke
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

systemctl restart kcml
systemctl restart kcml-egress-proxy
systemctl restart kcml-onboarding-worker
systemctl restart kcml-monitor

admin_host="${ADMIN_HOST:-admin.hcasc.cz}"
healthy=false
step wait-runtime-health
for _attempt in $(seq 1 45); do
  if curl -fsS -H "Host: $admin_host" "http://127.0.0.1:${PORT:-3010}/health" >/dev/null \
    && systemctl is-active --quiet kcml \
    && systemctl is-active --quiet kcml-egress-proxy \
    && systemctl is-active --quiet kcml-onboarding-worker \
    && systemctl is-active --quiet kcml-monitor \
    && systemctl is-active --quiet kcml-alert-primary \
    && systemctl is-active --quiet kcml-alert-backup \
    && curl -fsS http://127.0.0.1:3011/health >/dev/null \
    && curl -fsS http://127.0.0.1:3012/health >/dev/null \
    && test -S "${EGRESS_PROXY_SOCKET_PATH:-/var/lib/kcml/egress/proxy.sock}"; then
    healthy=true
    break
  fi
  sleep 2
done

if [ "$healthy" != "true" ]; then
  systemctl status kcml kcml-egress-proxy kcml-onboarding-worker kcml-monitor kcml-alert-primary kcml-alert-backup --no-pager -l || true
  false
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

admin_username="${ADMIN_BOOTSTRAP_USERNAME:-karmar78}"
step verify-core-hosts
login_payload="$(jq -nc --arg username "$admin_username" --arg password "$PASS" '{username:$username,password:$password}')"
curl -fsS -H "Host: $admin_host" -H 'content-type: application/json' \
  --data "$login_payload" "http://127.0.0.1:${PORT:-3010}/api/login" | jq -e '.ok == true' >/dev/null
unset login_payload
curl -fsS -H "Host: ${AUTH_HOST:-auth.hcasc.cz}" \
  "http://127.0.0.1:${PORT:-3010}/.well-known/oauth-authorization-server" \
  | jq -e --arg issuer "https://${AUTH_HOST:-auth.hcasc.cz}" '.issuer == $issuer' >/dev/null
curl -fsS -H "Host: kcml0002.${PUBLIC_BASE_DOMAIN:-hcasc.cz}" \
  "http://127.0.0.1:${PORT:-3010}/.well-known/oauth-protected-resource/mcp" \
  | jq -e --arg resource "https://kcml0002.${PUBLIC_BASE_DOMAIN:-hcasc.cz}/mcp" '.resource == $resource' >/dev/null
test "$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: unknown.invalid' \
  "http://127.0.0.1:${PORT:-3010}/health")" = "404"
step smoke-reference-external-api
bash "$release_dir/deploy/scripts/smoke-reference-external-api.sh" "$release_dir"

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
kcml0002_server_id="$(psql "$app_database_url" --no-psqlrc --tuples-only --no-align --quiet --command \
  "select id from mcp_server where code='KCML0002'")"
test -n "$kcml0002_server_id"
kcml0002_state="$(psql "$app_database_url" --no-psqlrc --tuples-only --no-align --quiet --command \
  "select registration_state::text || '/' || operational_state::text from mcp_server where code='KCML0002'")"
echo "release-check:mcp_kcml0002_initial_state=$kcml0002_state"
run_kcml0002_runtime_refresh
KCML_PROCESS_ROLE=web \
DATABASE_URL_FILE=/etc/kcml/credentials/web/database_url \
ACCESS_TOKEN_HMAC_KEY_BASE64_FILE=/etc/kcml/credentials/web/access_token_hmac \
INTEGRATION_TOKEN_HMAC_KEY_BASE64_FILE=/etc/kcml/credentials/web/integration_token_hmac \
SESSION_SECRET_BASE64_FILE=/etc/kcml/credentials/web/session_secret \
CSRF_SECRET_BASE64_FILE=/etc/kcml/credentials/web/csrf_secret \
MFA_ENCRYPTION_KEY_BASE64_FILE=/etc/kcml/credentials/web/mfa_encryption \
EGRESS_CAPABILITY_HMAC_KEY_BASE64_FILE=/etc/kcml/credentials/web/egress_capability_hmac \
NODE_ENV=production \
BUILD_ID="$release_id" \
  node "$release_dir/apps/server/dist/cli/release-kcml0002-smoke.js"
if [ "$kcml0002_state" != "ACTIVE/HEALTHY" ] && {
  [ "${kcml0002_state#TRIAL/}" != "$kcml0002_state" ] || [ "${kcml0002_state#REGISTERED_DISABLED/}" != "$kcml0002_state" ];
}; then
  kcml0002_state="$(psql "$app_database_url" --no-psqlrc --tuples-only --no-align --quiet --command \
    "select registration_state::text || '/' || operational_state::text from mcp_server where code='KCML0002'")"
  echo "release-check:mcp_kcml0002_promoted_state=$kcml0002_state"
fi
wait_for_sql_equals "mcp_kcml0002_state" "ACTIVE/HEALTHY" "select registration_state::text || '/' || operational_state::text from mcp_server where code='KCML0002'" 90 2
wait_for_sql_equals "migration_019" "1" "select count(*) from schema_migration where version='019_postgres_http_rate_limiting.sql'"
wait_for_sql_equals "migration_022" "1" "select count(*) from schema_migration where version='022_runtime_egress_capability_backfill.sql'"

trap - ERR
cleanup_registry_auth
echo "release-installed:$release_id"
