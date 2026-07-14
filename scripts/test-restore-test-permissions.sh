#!/usr/bin/env bash
set -euo pipefail
umask 077

workdir="$(mktemp -d)"
stub_dir="$workdir/bin"
backup_dir="$workdir/backups"
log="$workdir/commands.log"
mkdir -p "$stub_dir" "$backup_dir"
touch "$backup_dir/kcml-20260714T000000Z.dump.age"
touch "$backup_dir/kcml-20260714T000000Z.dump.age.sha256"
touch "$workdir/identity"
cleanup() { rm -rf "$workdir"; }
trap cleanup EXIT

cat > "$stub_dir/dispatcher" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail

case "$(basename "$0")" in
  id)
    if [ "${1:-}" = "-u" ]; then printf '0\n'; exit 0; fi
    test "${1:-}" = "postgres"
    ;;
  sha256sum)
    printf '%s: OK\n' "${2:-checksum}"
    ;;
  age)
    output=""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "--output" ]; then output="$2"; shift 2; else shift; fi
    done
    test -n "$output"
    printf 'test dump' > "$output"
    ;;
  chown)
    printf 'chown:%s\n' "$*" >> "$KCML_RESTORE_TEST_LOG"
    test "$1" = "postgres"
    ;;
  runuser)
    printf 'runuser:%s\n' "$*" >> "$KCML_RESTORE_TEST_LOG"
    test "$1" = "-u"
    test "$2" = "postgres"
    test "$3" = "--"
    shift 3
    operation="$1"
    shift
    case "$operation" in
      createdb|dropdb) ;;
      pg_restore)
        plain="${!#}"
        if mode="$(stat -c '%a' "$plain" 2>/dev/null)"; then
          :
        else
          mode="$(stat -f '%Lp' "$plain")"
        fi
        printf 'pg_restore-mode:%s\n' "$mode" >> "$KCML_RESTORE_TEST_LOG"
        test "$mode" = "600"
        ;;
      psql)
        if printf '%s\n' "$*" | grep -q 'verify_audit_chain'; then
          printf 't\n'
        else
          printf 'restore-ok\n'
        fi
        ;;
      *) exit 1 ;;
    esac
    ;;
  *) exit 1 ;;
esac
STUB
chmod 0700 "$stub_dir/dispatcher"
for command in age chown id runuser sha256sum; do
  ln -s dispatcher "$stub_dir/$command"
done

KCML_RESTORE_TEST_LOG="$log" \
BACKUP_DIR="$backup_dir" \
AGE_IDENTITY_FILE="$workdir/identity" \
PATH="$stub_dir:$PATH" \
  bash deploy/scripts/restore-test.sh > "$workdir/output"

grep -Fx 'pg_restore-mode:600' "$log" >/dev/null
chown_line="$(grep -n '^chown:postgres ' "$log" | cut -d: -f1)"
restore_line="$(grep -n '^runuser:-u postgres -- pg_restore ' "$log" | cut -d: -f1)"
test "$chown_line" -lt "$restore_line"
grep -F 'restore-test-ok:' "$workdir/output" >/dev/null
echo "restore-test-permissions-ok"
