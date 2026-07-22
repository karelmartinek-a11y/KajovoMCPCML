#!/usr/bin/env bash
set -euo pipefail
umask 077

: "${DATABASE_URL:?migrator DATABASE_URL is required}"
password_file="${KCML_APP_DB_PASSWORD_FILE:-/etc/kcml/database-app.password}"
url_file="${KCML_APP_DB_URL_FILE:-/etc/kcml/database-app.url}"
mkdir -p "$(dirname "$password_file")"
if [ ! -s "$password_file" ]; then
  openssl rand -base64 48 | tr -d '=+/\n' | head -c 56 > "$password_file"
fi
chmod 0600 "$password_file"
app_password="$(cat "$password_file")"

database_name="$(node - "$DATABASE_URL" <<'NODE'
const raw = process.argv[2];
const url = new URL(raw);
const database = decodeURIComponent(url.pathname.slice(1));
if (!/^[A-Za-z0-9_]+$/.test(database)) throw new Error("invalid_database_name");
process.stdout.write(database);
NODE
)"

migrator_role="$(node - "$DATABASE_URL" <<'NODE'
const raw = process.argv[2];
const url = new URL(raw);
const username = decodeURIComponent(url.username);
if (!/^[A-Za-z0-9_]+$/.test(username)) throw new Error("invalid_database_username");
process.stdout.write(username);
NODE
)"

if [ -n "${DATABASE_ADMIN_URL:-}" ]; then
  admin_psql=(psql "$DATABASE_ADMIN_URL")
elif [ "$(id -u)" = "0" ] && id postgres >/dev/null 2>&1; then
  admin_psql=(runuser -u postgres -- psql --dbname "$database_name")
else
  admin_psql=(psql "$DATABASE_URL")
fi

"${admin_psql[@]}" --no-psqlrc --set ON_ERROR_STOP=1 --set app_password="$app_password" --set migrator_role="$migrator_role" <<'SQL'
do $$
begin
  if not exists (select 1 from pg_roles where rolname='kcml_app') then
    create role kcml_app login nosuperuser nocreatedb nocreaterole noinherit;
  end if;
end $$;
alter role kcml_app password :'app_password';
select format('grant connect on database %I to kcml_app', current_database()) \gexec
grant usage on schema public to kcml_app;
grant select,insert,update,delete on all tables in schema public to kcml_app;
grant usage,select on all sequences in schema public to kcml_app;
select format('grant usage on schema public to %I', :'migrator_role') \gexec
select format('grant select on all tables in schema public to %I', :'migrator_role') \gexec
revoke all on table audit_event,audit_head from kcml_app;
revoke all on function public.kcml_factory_reset_truncate(text[]) from public;
revoke all on function public.kcml_factory_reset_truncate(text[]) from kcml_app;
grant select on table audit_event to kcml_app;
grant update (id) on table audit_event to kcml_app;
do $$
begin
  if pg_catalog.to_regclass('public.component_audit_event') is not null then
    revoke all on table component_audit_event from kcml_app;
    grant select,insert on table component_audit_event to kcml_app;
  end if;
end $$;
grant execute on function append_audit_event(text,text,text,text,text,jsonb,jsonb,uuid) to kcml_app;
grant execute on function verify_audit_chain() to kcml_app;
select format('grant execute on function public.kcml_factory_reset_truncate(text[]) to %I', :'migrator_role') \gexec
do $$
declare
  writer_owner name;
  reset_executor_owner name;
begin
  select pg_catalog.pg_get_userbyid(procedure.proowner)
    into writer_owner
    from pg_catalog.pg_proc procedure
   where procedure.oid = 'public.append_audit_event(text,text,text,text,text,jsonb,jsonb,uuid)'::pg_catalog.regprocedure;
  if writer_owner is null then
    raise exception 'audit_writer_owner_missing';
  end if;
  if writer_owner = 'kcml_app' then
    raise exception 'audit_writer_must_not_be_owned_by_application_role';
  end if;
  alter function public.append_audit_event(text,text,text,text,text,jsonb,jsonb,uuid) security definer;
  alter function public.append_audit_event(text,text,text,text,text,jsonb,jsonb,uuid)
    set search_path = pg_catalog, public;
  execute pg_catalog.format('grant insert on table public.audit_event to %I', writer_owner);
  execute pg_catalog.format('grant select (id) on table public.audit_event to %I', writer_owner);
  execute pg_catalog.format('grant select, update on table public.audit_head to %I', writer_owner);
  if pg_catalog.to_regclass('public.audit_event_id_seq') is not null then
    execute pg_catalog.format('grant usage, select on sequence public.audit_event_id_seq to %I', writer_owner);
  end if;

  select pg_catalog.pg_get_userbyid(procedure.proowner)
    into reset_executor_owner
    from pg_catalog.pg_proc procedure
   where procedure.oid = 'public.kcml_factory_reset_truncate(text[])'::pg_catalog.regprocedure;
  if reset_executor_owner is null then
    raise exception 'factory_reset_executor_owner_missing';
  end if;
  if reset_executor_owner = 'kcml_app' then
    raise exception 'factory_reset_executor_must_not_be_owned_by_application_role';
  end if;
  alter function public.kcml_factory_reset_truncate(text[]) security definer;
  alter function public.kcml_factory_reset_truncate(text[])
    set search_path = pg_catalog, public;
  execute pg_catalog.format('grant truncate on all tables in schema public to %I', reset_executor_owner);
  execute pg_catalog.format('grant usage, select, update on all sequences in schema public to %I', reset_executor_owner);
end $$;
SQL

app_url="$(node - "$DATABASE_URL" "$app_password" <<'NODE'
const [raw, password] = process.argv.slice(2);
const url = new URL(raw);
if (!url.hostname) url.hostname = "127.0.0.1";
url.username = "kcml_app";
url.password = password;
process.stdout.write(url.toString());
NODE
)"
mkdir -p "$(dirname "$url_file")"
printf '%s' "$app_url" > "$url_file"
chmod 0600 "$url_file"
echo "database-role-configured:kcml_app"
