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
if grep -Fq 'resumeJobId' deploy/scripts/smoke-reference-external-api.sh; then
  echo "reference smoke must not use resumeJobId" >&2
  exit 1
fi
grep -Fq 'release-check:canonical_component_metadata=SKIPPED clean_start_no_registered_component' "$install_script"
grep -Fq 'release-check:canonical_component_metadata=PASS' "$install_script"
grep -Fq 'canonical_component_identity' "$install_script"
grep -Fq "component_hostname_pattern=\"\$(jq -er '.identityAssignment.hostnamePattern' \"\$component_catalog\")\"" "$install_script"
grep -Fq "component_hostname_suffix" "$install_script"
if grep -F 'canonical_component_identity' "$install_script" | grep -Fq 'PUBLIC_BASE_DOMAIN'; then
  echo "canonical component identity must come from the versioned onboarding catalog" >&2
  exit 1
fi
grep -Fq 'integration_token_lifetime' "$install_script"
test "$(grep -c '^step ensure-platform-worker-access$' "$install_script")" = "1"
grep -Fq 'dist/cli/ensure-platform-worker-access.js' "$install_script"
grep -Fq '.auth == ["access_token_bearer"]' "$install_script"
if grep -Eq 'client_secret_basic|integration_token_bearer' "$install_script"; then
  echo "secret API deployment checks must enforce access-token bearer only" >&2
  exit 1
fi
grep -Fq "where version='046_drop_stale_component_identity_triggers_20260723.sql'" "$install_script"
grep -Fq -- "--exclude-table='public.admin_account_manual_fix_backup_*'" deploy/scripts/backup.sh
if grep -qi 'kcml0002' "$install_script"; then
  echo "release install must not prefer a specific component" >&2
  exit 1
fi
grep -Fq '"https://${admin_host}/api/login"' "$install_script"
grep -Fq 'audit_archive_dir="$(dirname "${AUDIT_ARCHIVE_PATH:-/var/lib/kcml/audit/archive.jsonl}")"' "$preflight_script"
grep -Fq 'runuser -u kcml -- test -w "$audit_archive_dir"' "$preflight_script"
