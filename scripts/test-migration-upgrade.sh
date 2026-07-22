#!/usr/bin/env bash
set -euo pipefail

test -n "${KCML_UPGRADE_DATABASE_URL:-}"
test -n "${DATABASE_URL:-}"

upgrade_database_name="${KCML_UPGRADE_DATABASE_NAME:-kcml_upgrade_test}"
case "$upgrade_database_name" in
  *[!a-zA-Z0-9_]*) echo "invalid upgrade database name" >&2; exit 1 ;;
esac

release_version="$(node --input-type=module -e "import('./apps/server/src/domain/release.ts').then(({KCML_RELEASE}) => process.stdout.write(KCML_RELEASE.catalogVersion))")"

run_migrations() {
  if [[ -x apps/server/node_modules/.bin/tsx ]]; then
    KCML_PROCESS_ROLE=migrate DATABASE_URL="$KCML_UPGRADE_DATABASE_URL" \
      apps/server/node_modules/.bin/tsx apps/server/src/cli/migrate.ts
  else
    KCML_PROCESS_ROLE=migrate DATABASE_URL="$KCML_UPGRADE_DATABASE_URL" pnpm db:migrate
  fi
}

reset_database() {
  psql "$DATABASE_URL" --no-psqlrc --set ON_ERROR_STOP=1 --command "drop database if exists \"$upgrade_database_name\" with (force)" >/dev/null
  psql "$DATABASE_URL" --no-psqlrc --set ON_ERROR_STOP=1 --command "create database \"$upgrade_database_name\"" >/dev/null
}

reset_database
run_migrations
run_migrations

psql "$KCML_UPGRADE_DATABASE_URL" --no-psqlrc --set ON_ERROR_STOP=1 --tuples-only --no-align <<SQL | grep -Fx 'baseline-clean-install-ok'
select case when
  (select count(*) from schema_migration) = 1
  and exists (
    select 1
      from schema_migration
     where version='001_pre_production_baseline.sql'
       and sequence_number=1
       and checksum_sha256 ~ '^[0-9a-f]{64}$'
  )
  and (select count(*) from release_epoch) = 1
  and exists (
    select 1
      from release_epoch
     where release_version='${release_version}'
       and blueprint_version='${release_version}'
       and catalog_version='${release_version}'
       and manifest_schema_version='${release_version}'
       and pulse_envelope_version='${release_version}'
  )
  and (select count(*) from release_wave) = 0
  and (select count(*) from release_wave_component) = 0
  and exists (
    select 1
      from admin_account
     where username='karmar78'
       and role='ADMIN'
       and active=false
       and password_hash is null
  )
  and exists (
    select 1
      from admin_bootstrap_state
     where singleton is true
       and completed is false
  )
  and exists (
    select 1
      from principal
     where public_id='KCML-PLATFORM-WORKER'
       and kind='PLATFORM'
       and status='ACTIVE'
  )
  and exists (
    select 1
      from platform_worker_access_identity identity
      join principal on principal.id=identity.principal_id
     where identity.singleton is true
       and principal.public_id='KCML-PLATFORM-WORKER'
       and identity.access_token_id is null
  )
  and (select count(*) from audit_head where singleton is true and last_sequence=0 and event_hash is null) = 1
then 'baseline-clean-install-ok' else 'baseline-clean-install-failed' end;
SQL

psql "$KCML_UPGRADE_DATABASE_URL" --no-psqlrc --set ON_ERROR_STOP=1 <<'SQL'
delete from schema_migration;
insert into schema_migration(version, applied_at, sequence_number, checksum_sha256) values
  ('001_initial.sql', now(), null, null),
  ('055_release_epoch_20260724.sql', now(), null, null),
  ('088_canonical_managed_service_identity.sql', now(), null, null);
SQL

run_migrations
run_migrations

psql "$KCML_UPGRADE_DATABASE_URL" --no-psqlrc --set ON_ERROR_STOP=1 --tuples-only --no-align <<SQL | grep -Fx 'baseline-compaction-ok'
select case when
  (select count(*) from schema_migration) = 1
  and exists (
    select 1
      from schema_migration
     where version='001_pre_production_baseline.sql'
       and sequence_number=1
       and checksum_sha256 ~ '^[0-9a-f]{64}$'
  )
  and (select count(*) from release_epoch) = 1
  and exists (select 1 from principal where public_id='KCML-PLATFORM-WORKER' and kind='PLATFORM')
  and exists (select 1 from admin_account where username='karmar78')
  and (select valid from verify_audit_chain()) is true
then 'baseline-compaction-ok' else 'baseline-compaction-failed' end;
SQL
