#!/usr/bin/env bash
set -euo pipefail

install_script="deploy/scripts/install-release.sh"
monitor_unit="deploy/systemd/kcml-monitor.service"
preflight_script="deploy/scripts/preflight.sh"

test -f "$install_script"
test -f "$monitor_unit"
test -f "$preflight_script"

generic_probe_line="$(grep -n '/.well-known/oauth-protected-resource/mcp' "$install_script" | tail -n 1 | cut -d: -f1)"
test -n "$generic_probe_line"

grep -Fq 'ReadWritePaths=/var/lib/kcml/runtime /var/lib/kcml/podman /var/lib/kcml/audit' "$monitor_unit"
grep -Fq "where key='adminBootstrapUsername'" "$install_script"
grep -Fq 'admin_username="$(effective_admin_username)"' "$install_script"
grep -Fq 'export ADMIN_BOOTSTRAP_USERNAME="$admin_username"' "$install_script"
grep -Fq 'step forensic-admin-credentials' "$install_script"
if grep -Fq 'resumeJobId' deploy/scripts/smoke-reference-external-api.sh; then
  echo "reference smoke must not use resumeJobId" >&2
  exit 1
fi
grep -Fq 'reference-smoke:SKIPPED clean_start_no_reference_service' deploy/scripts/smoke-reference-external-api.sh
grep -Fq 'require_stable_runtime_health "$admin_host"' "$install_script"
grep -Fq 'release-check:canonical_component_metadata=SKIPPED clean_start_no_registered_component' "$install_script"
grep -Fq 'release-check:canonical_component_metadata=PASS' "$install_script"
grep -Fq 'canonical_component_identity' "$install_script"
grep -Fq 'canonical_managed_service_identity' "$install_script"
grep -Fq 'join component_revision revision on revision.id=component.active_revision_id and revision.component_id=component.id' "$install_script"
grep -Fq 'export KCML_COMPONENT_HOST_SUFFIX="$component_hostname_suffix"' "$install_script"
grep -Fq 'curl -fsS "https://${canonical_component_hostname}/.well-known/oauth-protected-resource/mcp"' "$install_script"
grep -Fq 'deploy/scripts/ensure-canonical-tls.sh' "$install_script"
grep -Fq 'status_root="/var/www/letsencrypt/.well-known/acme-challenge"' deploy/scripts/ensure-canonical-tls.sh
grep -Fq 'pid_file="$runtime_dir/canonical-certbot.pid"' deploy/scripts/ensure-canonical-tls.sh
grep -Fq 'command="$(ps -p "$pid" -o args= 2>/dev/null || true)"' deploy/scripts/ensure-canonical-tls.sh
grep -Fq '*certbot*certonly*"--cert-name kcml-wildcards"*' deploy/scripts/ensure-canonical-tls.sh
grep -Fq 'kill -TERM -- "-$certbot_pid"' deploy/scripts/ensure-canonical-tls.sh
grep -Fq 'setsid env' deploy/scripts/ensure-canonical-tls.sh
grep -Fq 'canonical-tls:WAITING_DNS record=$record value=$CERTBOT_VALIDATION' deploy/scripts/ensure-canonical-tls.sh
grep -Fq 'dig +short NS "$KCML_ACME_ZONE"' deploy/scripts/ensure-canonical-tls.sh
grep -Fq 'dig +short TXT "$record" "@$nameserver"' deploy/scripts/ensure-canonical-tls.sh
grep -Fq 'KCML_ACME_ZONE="$base_domain"' deploy/scripts/ensure-canonical-tls.sh
grep -Fq -- '-d "*.${component_suffix}"' deploy/scripts/ensure-canonical-tls.sh
if bash deploy/scripts/ensure-canonical-tls.sh 'hcasc.cz|kajovocml.hcasc.cz' 'kajovocml.hcasc.cz' /missing/cert /missing/key 2>/dev/null; then
  exit 1
fi
challenge_step="$(grep -n 'step expose-canonical-tls-challenge' "$install_script" | cut -d: -f1)"
tls_step="$(grep -n 'step ensure-canonical-tls' "$install_script" | cut -d: -f1)"
test "$challenge_step" -lt "$tls_step"
grep -Fq 'restore_script="$source_dir/deploy/scripts/release-config.sh"' "$install_script"
grep -Fq "component_hostname_pattern=\"\$(jq -er '.identityAssignment.hostnamePattern' \"\$component_catalog\")\"" "$install_script"
grep -Fq "component_hostname_suffix" "$install_script"
grep -Fq 'Defaults:kcml-deploy env_keep += "PASS GHCR_TOKEN GHCR_ACTOR KCML_FACTORY_RESET_CONFIRM"' "$install_script"
grep -Fq 'kcml-deploy ALL=(root) NOPASSWD:SETENV: /usr/local/sbin/kcml-deploy-wrapper' "$install_script"
grep -Fq 'kcml-deploy ALL=(root) NOPASSWD:SETENV: /usr/local/sbin/kcml-handler-preload-wrapper' "$install_script"
if grep -F 'canonical_component_identity' "$install_script" | grep -Fq 'PUBLIC_BASE_DOMAIN'; then
  echo "canonical component identity must come from the versioned onboarding catalog" >&2
  exit 1
fi
grep -Fq 'integration_token_lifetime' "$install_script"
test "$(grep -Ec '^[[:space:]]*step ensure-platform-worker-access$' "$install_script")" = "1"
test "$(grep -Ec '^[[:space:]]*step factory-reset$' "$install_script")" = "1"
test "$(grep -Ec '^[[:space:]]*step ensure-platform-worker-access-post-reset$' "$install_script")" = "1"
test "$(grep -Ec '^[[:space:]]*step restart-services-post-reset$' "$install_script")" = "1"
test "$(grep -Ec '^[[:space:]]*step wait-runtime-health-post-reset$' "$install_script")" = "1"
test "$(grep -Ec '^[[:space:]]*step queue-webhook-smoke-post-reset$' "$install_script")" = "1"
post_reset_health_step="$(grep -n 'step wait-runtime-health-post-reset' "$install_script" | cut -d: -f1)"
post_reset_webhook_step="$(grep -n 'step queue-webhook-smoke-post-reset' "$install_script" | cut -d: -f1)"
test "$post_reset_health_step" -lt "$post_reset_webhook_step"
grep -Fq 'dist/cli/ensure-platform-worker-access.js' "$install_script"
grep -Fq 'dist/cli/factory-reset.js' "$install_script"
grep -Fq 'if [ -z "${KCML_FACTORY_RESET_CONFIRM:-}" ]; then' "$install_script"
grep -Fq 'KCML_FACTORY_RESET_CONFIRM="${KCML_FACTORY_RESET_CONFIRM}"' "$install_script"
grep -Fq 'KCML_PROCESS_ROLE=migrate' "$install_script"
grep -Fq 'DATABASE_URL_FILE=/etc/kcml/credentials/migrator/database_url' "$install_script"
grep -Fq '.auth == ["access_token_bearer"]' "$install_script"
if grep -Eq 'client_secret_basic|integration_token_bearer' "$install_script"; then
  echo "secret API deployment checks must enforce access-token bearer only" >&2
  exit 1
fi
grep -Fq "where version='001_pre_production_baseline.sql'" "$install_script"
grep -Fq "where version='002_secret_broker_process_role.sql'" "$install_script"
grep -Fq 'wait_for_sql_equals "baseline_migration_count" "2" "select count(*) from schema_migration"' "$install_script"
grep -Fq -- "--exclude-table='public.admin_account_manual_fix_backup_*'" deploy/scripts/backup.sh
grep -Fq "grant usage on schema public to %I" deploy/scripts/configure-db-roles.sh
grep -Fq "grant select on all tables in schema public to %I" deploy/scripts/configure-db-roles.sh
if grep -qi 'kcml0002' "$install_script"; then
  echo "release install must not prefer a specific component" >&2
  exit 1
fi
grep -Fq 'dist/cli/admin-login-smoke.js' "$install_script"
grep -Fq 'audit_archive_dir="$(dirname "${AUDIT_ARCHIVE_PATH:-/var/lib/kcml/audit/archive.jsonl}")"' "$preflight_script"
grep -Fq 'runuser -u kcml -- test -w "$audit_archive_dir"' "$preflight_script"
