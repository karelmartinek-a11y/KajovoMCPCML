#!/usr/bin/env bash
set -euo pipefail
umask 077

backup_dir="${BACKUP_DIR:-/opt/kcml/backups}"
identity_file="${AGE_IDENTITY_FILE:-/etc/kcml/backup.age.key}"
database="kcml_restore_test_$(date -u +%Y%m%d%H%M%S)"
latest="$(find "$backup_dir" -maxdepth 1 -type f -name 'kcml-*.dump.age' -print | sort | tail -n 1)"
database_os_user="${DATABASE_ADMIN_OS_USER:-postgres}"
plain_reader=""

test -n "$latest"
test -r "$identity_file"
test -r "$latest.sha256"
case "$database_os_user" in
  ""|*[!a-zA-Z0-9_-]*) echo "invalid database admin OS user" >&2; exit 1 ;;
esac
if [ -n "${DATABASE_ADMIN_URL:-}" ]; then
  db_admin=(env "PGDATABASE=$DATABASE_ADMIN_URL")
elif [ "$(id -u)" = "0" ] && id "$database_os_user" >/dev/null 2>&1; then
  db_admin=(runuser -u "$database_os_user" --)
  plain_reader="$database_os_user"
else
  db_admin=()
fi
plain="$(mktemp "${TMPDIR:-/tmp}/kcml-restore.XXXXXX.dump")"
cleanup() {
  "${db_admin[@]}" dropdb --if-exists "$database" >/dev/null 2>&1 || true
  rm -f "$plain"
}
trap cleanup EXIT

sha256sum --check "$latest.sha256"
age --decrypt --identity "$identity_file" --output "$plain" "$latest"
chmod 0600 "$plain"
if [ -n "$plain_reader" ]; then
  chown "$plain_reader" "$plain"
fi
"${db_admin[@]}" createdb "$database"
"${db_admin[@]}" pg_restore --exit-on-error --no-owner --no-privileges --dbname "$database" "$plain"
"${db_admin[@]}" psql --dbname "$database" --no-psqlrc --tuples-only --no-align --quiet --command \
  "select case when to_regclass('public.schema_migration') is not null and to_regclass('public.audit_event') is not null then 'restore-ok' else 'restore-invalid' end" \
  | grep -Fx 'restore-ok'
"${db_admin[@]}" psql --dbname "$database" --no-psqlrc --tuples-only --no-align --quiet --command \
  "select valid from verify_audit_chain()" | grep -Fx 't'
echo "restore-test-ok:$latest"
