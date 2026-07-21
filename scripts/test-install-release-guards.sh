#!/usr/bin/env bash
set -euo pipefail

install_script="deploy/scripts/install-release.sh"
monitor_unit="deploy/systemd/kcml-monitor.service"
preflight_script="deploy/scripts/preflight.sh"

test -f "$install_script"
test -f "$monitor_unit"
test -f "$preflight_script"

runtime_refresh_line="$(grep -n 'run_kcml0002_runtime_refresh' "$install_script" | tail -n 1 | cut -d: -f1)"
kcml0002_probe_line="$(grep -n '/.well-known/oauth-protected-resource/mcp' "$install_script" | tail -n 1 | cut -d: -f1)"
kcml0002_smoke_line="$(grep -n 'release-kcml0002-smoke.js' "$install_script" | tail -n 1 | cut -d: -f1)"

test -n "$runtime_refresh_line"
test -n "$kcml0002_probe_line"
test -n "$kcml0002_smoke_line"
test "$runtime_refresh_line" -lt "$kcml0002_probe_line"
test "$kcml0002_smoke_line" -lt "$kcml0002_probe_line"

grep -Fq 'ReadWritePaths=/var/lib/kcml/runtime /var/lib/kcml/podman /var/lib/kcml/audit' "$monitor_unit"
grep -Fq -- '-u CONFIG_VAULT_MASTER_KEY_BASE64_FILE' "$install_script"
grep -Fq 'CONFIG_VAULT_MASTER_KEY_BASE64="$vault_master_key"' "$install_script"
grep -Fq "where key='adminBootstrapUsername'" "$install_script"
grep -Fq 'admin_username="$(effective_admin_username)"' "$install_script"
grep -Fq 'export ADMIN_BOOTSTRAP_USERNAME="$admin_username"' "$install_script"
if grep -Fq 'resumeJobId' deploy/scripts/smoke-reference-external-api.sh; then
  echo "reference smoke must not use resumeJobId" >&2
  exit 1
fi
grep -Fq 'release-check:mcp_kcml0002_state=SKIPPED clean_start_no_registered_server' "$install_script"
grep -Fq "where version='046_drop_stale_component_identity_triggers_20260723.sql'" "$install_script"
grep -Fq -- "--exclude-table='public.admin_account_manual_fix_backup_*'" deploy/scripts/backup.sh
if grep -Fxq 'test -n "$kcml0002_server_id"' "$install_script"; then
  echo "KCML0002 clean-start deploy must not fail before the optional runtime smoke" >&2
  exit 1
fi
grep -Fq '"https://${admin_host}/api/login"' "$install_script"
grep -Fq 'audit_archive_dir="$(dirname "${AUDIT_ARCHIVE_PATH:-/var/lib/kcml/audit/archive.jsonl}")"' "$preflight_script"
grep -Fq 'runuser -u kcml -- test -w "$audit_archive_dir"' "$preflight_script"
