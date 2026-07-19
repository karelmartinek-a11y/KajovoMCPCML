#!/usr/bin/env bash
set -euo pipefail
umask 077

password_file="$(mktemp)"
url_file="$(mktemp)"
rm -f "$password_file" "$url_file"
trap 'rm -f "$password_file" "$url_file"' EXIT

KCML_APP_DB_PASSWORD_FILE="$password_file" \
KCML_APP_DB_URL_FILE="$url_file" \
  bash deploy/scripts/configure-db-roles.sh >/dev/null
app_url="$(cat "$url_file")"

test "$(psql "$app_url" --no-psqlrc --tuples-only --no-align --quiet --command 'select current_user')" = "kcml_app"
psql "$app_url" --no-psqlrc --set ON_ERROR_STOP=1 --quiet <<'SQL'
begin;
insert into http_rate_bucket(bucket_key,window_started_at,request_count,updated_at)
values (decode(repeat('09',32),'hex'),clock_timestamp(),1,clock_timestamp())
on conflict (bucket_key) do update set request_count=http_rate_bucket.request_count+1,updated_at=clock_timestamp();
rollback;
SQL
psql "$app_url" --no-psqlrc --set ON_ERROR_STOP=1 --quiet --command \
  "select append_audit_event('role.isolation.test','system',null,null,null,'null','null',gen_random_uuid())" >/dev/null
if psql "$app_url" --no-psqlrc --set ON_ERROR_STOP=1 --quiet --command \
  "update audit_event set event_type='forbidden' where false" >/dev/null 2>&1; then
  echo "application role can update audit_event" >&2
  exit 1
fi
if psql "$app_url" --no-psqlrc --set ON_ERROR_STOP=1 --quiet --command \
  "select * from audit_head" >/dev/null 2>&1; then
  echo "application role can read audit_head" >&2
  exit 1
fi
if psql "$app_url" --no-psqlrc --set ON_ERROR_STOP=1 --quiet --command \
  "update component_audit_event set event_type='forbidden' where false" >/dev/null 2>&1; then
  echo "application role can update component_audit_event" >&2
  exit 1
fi
if psql "$app_url" --no-psqlrc --set ON_ERROR_STOP=1 --quiet --command \
  "delete from component_audit_event where false" >/dev/null 2>&1; then
  echo "application role can delete component_audit_event" >&2
  exit 1
fi
test "$(psql "$app_url" --no-psqlrc --tuples-only --no-align --quiet --command 'select valid from verify_audit_chain()')" = "t"
echo "database-role-isolation-ok"
