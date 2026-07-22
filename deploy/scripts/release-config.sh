#!/usr/bin/env bash
set -euo pipefail
umask 077

action="${1:?snapshot or restore required}"
release_id="${2:?release id required}"
case "$release_id" in *[!A-Za-z0-9._-]*) exit 2 ;; esac
state_dir="/opt/kcml/release-config/$release_id"
managed_paths=(
  etc/nginx/sites-available/kcml.conf
  etc/nginx/sites-enabled/kcml.conf
  etc/systemd/system/kcml.service
  etc/systemd/system/kcml-onboarding-worker.service
  etc/systemd/system/kcml-component-control-worker.service
  etc/systemd/system/kcml-component-e2e-worker.service
  etc/systemd/system/kcml-monitor.service
  etc/systemd/system/kcml-egress-proxy.service
  etc/systemd/system/kcml-alert-primary.service
  etc/systemd/system/kcml-alert-backup.service
  etc/systemd/system/kcml-onboarding-worker.service.d
  etc/systemd/system/kcml-monitor.service.d
)

case "$action" in
  snapshot)
    if [ -s "$state_dir/config.tar" ]; then exit 0; fi
    install -d -m 0700 "$state_dir"
    existing=()
    for path in "${managed_paths[@]}"; do
      if [ -e "/$path" ] || [ -L "/$path" ]; then existing+=("$path"); fi
    done
    test "${#existing[@]}" -gt 0
    tar --create --file "$state_dir/config.tar" --directory / "${existing[@]}"
    chmod 0600 "$state_dir/config.tar"
    ;;
  restore)
    target_release="${3:?target release directory required}"
    test -d "$target_release"
    test -s "$state_dir/config.tar"
    systemctl stop kcml kcml-onboarding-worker kcml-component-control-worker kcml-component-e2e-worker kcml-monitor kcml-egress-proxy kcml-alert-primary kcml-alert-backup 2>/dev/null || true
    for path in "${managed_paths[@]}"; do rm -rf "/${path:?}"; done
    tar --extract --file "$state_dir/config.tar" --directory /
    ln -sfn "$target_release" /opt/kcml/current
    systemctl daemon-reload
    nginx -t
    systemctl reload nginx
    for unit in kcml kcml-onboarding-worker kcml-component-control-worker kcml-component-e2e-worker kcml-monitor kcml-egress-proxy kcml-alert-primary kcml-alert-backup; do
      if systemctl cat "$unit.service" >/dev/null 2>&1; then
        systemctl enable "$unit.service" >/dev/null
        systemctl restart "$unit.service"
      else
        systemctl disable "$unit.service" >/dev/null 2>&1 || true
      fi
    done
    ;;
  *) exit 2 ;;
esac
