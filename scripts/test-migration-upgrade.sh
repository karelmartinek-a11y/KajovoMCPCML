#!/usr/bin/env bash
set -euo pipefail

test -n "${KCML_UPGRADE_DATABASE_URL:-}"
upgrade_database_name="${KCML_UPGRADE_DATABASE_NAME:-kcml_upgrade_test}"
case "$upgrade_database_name" in
  *[!a-zA-Z0-9_]*) echo "invalid upgrade database name" >&2; exit 1 ;;
esac
migrations="apps/server/src/migrations"

psql "$DATABASE_URL" --no-psqlrc --set ON_ERROR_STOP=1 --command "drop database if exists \"$upgrade_database_name\" with (force)" >/dev/null
psql "$DATABASE_URL" --no-psqlrc --set ON_ERROR_STOP=1 --command "create database \"$upgrade_database_name\"" >/dev/null

for migration in \
  001_initial.sql \
  002_kaja_labels.sql \
  003_kaja_lifecycle_permissions.sql \
  004_permission_access_level.sql \
  005_automated_onboarding.sql \
  005_fix_mcp_hostname_constraint.sql \
  006_invocation_latency_metrics.sql
do
  psql "$KCML_UPGRADE_DATABASE_URL" --no-psqlrc --set ON_ERROR_STOP=1 --file "$migrations/$migration" >/dev/null
done

psql "$KCML_UPGRADE_DATABASE_URL" --no-psqlrc --set ON_ERROR_STOP=1 <<'SQL'
create table schema_migration(version text primary key, applied_at timestamptz not null default now());
insert into schema_migration(version) values
  ('001_initial.sql'),
  ('002_kaja_labels.sql'),
  ('003_kaja_lifecycle_permissions.sql'),
  ('004_permission_access_level.sql'),
  ('005_automated_onboarding.sql'),
  ('005_fix_mcp_hostname_constraint.sql'),
  ('006_invocation_latency_metrics.sql'),
  ('007_auth_hardening.sql'),
  ('008_mcp_runtime_policies.sql'),
  ('009_permission_and_tool_scope.sql'),
  ('010_audit_hash_chain.sql'),
  ('011_admin_bootstrap_recovery.sql'),
  ('011_integration_token_descriptor.sql'),
  ('012_operational_config.sql'),
  ('013_rate_bucket_per_client.sql'),
  ('014_mcp_idempotency.sql');

insert into mcp_server(
  id,kcml_number,code,hostname,tool_name,display_name,description,enabled,
  registration_state,operational_state,input_schema,output_schema,handler_key,
  handler_version,contract_version,artifact_digest,manifest_digest,created_at
) values (
  '00000000-0000-0000-0000-000000000002',2,'KCML0002','kcml0002.hcasc.cz','home_assistant_inventory',
  'Home Assistant inventory','Production compatibility fixture',true,'ACTIVE','HEALTHY',
  '{"type":"object","additionalProperties":false}'::jsonb,
  '{"type":"object","additionalProperties":false}'::jsonb,
  'home-assistant-inventory','1.0.0','prod-1',
  'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  '2026-01-13T00:00:00Z'
);

insert into registration_revision(
  id,server_id,revision,state,manifest,manifest_digest,artifact_digest,evidence,created_at
) values (
  '10000000-0000-0000-0000-000000000002',
  '00000000-0000-0000-0000-000000000002',
  'prod-1','ACTIVE',
  $manifest${
    "schemaVersion":"1.4",
    "registrationRevision":"prod-1",
    "environment":"production",
    "handlerKey":"home-assistant-inventory",
    "handlerVersion":"1.0.0",
    "displayName":"Home Assistant inventory",
    "businessPurpose":"Read approved Home Assistant inventory for production operations.",
    "owners":{"service":"KCML Service","technical":"KCML Platform","security":"KCML Security","operations":"KCML Operations"},
    "source":{"runtime":"nodejs24-typescript","entrypoint":"src/index.ts","testCommand":"pnpm test"},
    "runtime":{"memoryMb":128,"cpuCores":0.5,"pidsLimit":32,"egressAllowlist":[]},
    "tool":{"title":"Home Assistant inventory","description":"Return the approved production Home Assistant inventory.","inputSchema":{"type":"object","additionalProperties":false},"outputSchema":{"type":"object","additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false,"taskSupport":"forbidden"}},
    "behavior":{"effectClass":"READ_ONLY","timeoutMs":10000,"maxConcurrency":1,"requestMaxBytes":65536,"responseMaxBytes":262144,"rateLimit":{"windowSeconds":60,"maxRequests":30},"shutdownPolicy":"COMPLETE_IN_FLIGHT","idempotencyPolicy":"Read only and safe to repeat.","retryPolicy":{"automaticRetry":false}},
    "testContract":{"safeInput":{},"expectedResult":{},"cleanupOrCompensation":"No cleanup required."},
    "protocol":{"protocolVersion":"2025-11-25","transport":"streamable-http","capabilities":["tools"],"errorCatalog":[{"code":"INTERNAL_ERROR","description":"The operation did not complete."}]},
    "dependencies":{"runtime":[{"name":"nodejs24","version":"24.0.0"}],"externalServices":[],"secretRefs":[],"networkPolicy":{"outboundAllowlist":[],"dnsPolicy":"strict","databaseRole":"kcml_reader","filesystemPolicy":"read-only"},"dataClassification":{"input":"internal","output":"internal","containsPersonalData":false,"loggingPolicy":"redacted","redactionFields":[],"retentionPolicy":"365 days"}},
    "monitoringProfile":{"sloTargets":{"availability":99.9},"probeIntervals":{"readiness":"60s"},"alertRules":[{"severity":"critical"}],"runbookRef":"docs/runbooks/kcml0002.md","primaryAlertChannel":"primary","backupAlertChannel":"backup"},
    "errorCatalog":[{"code":"INTERNAL_ERROR","description":"The operation did not complete."}],
    "change":{"changeClass":"INITIAL","migrationRef":"migrations/production.sql","rollbackRef":"docs/rollback.md","decommissionRef":"docs/decommission.md","previousApprovedRevision":null,"reviewDueAt":"2027-01-13T00:00:00.000Z"}
  }$manifest$::jsonb,
  'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  '{}'::jsonb,
  '2026-04-17T11:37:00Z'
);

insert into monitoring_profile(server_id,profile,enabled) values (
  '00000000-0000-0000-0000-000000000002',
  '{"sloTargets":{"availability":99.9},"probeIntervals":{"readiness":"60s"},"alertRules":[{"severity":"critical"}],"runbookRef":"docs/runbooks/kcml0002.md","primaryAlertChannel":"primary","backupAlertChannel":"backup"}'::jsonb,
  true
);

insert into integration_token(
  id,label,lookup_digest,key_id,fingerprint,created_by,initial_expires_at,expires_at,max_expires_at
) select
  '20000000-0000-0000-0000-000000000002','Legacy production integration token',digest('legacy-token','sha256'),'v1','legacy0000000000',id,
  now()+interval '1 hour',now()+interval '1 hour',now()+interval '24 hours'
-- The upgrade fixture intentionally anchors to the historical seed username from
-- 001_initial.sql so the compatibility path exercises real production-shape data.
from admin_account where username='karmar78';

insert into onboarding_job(
  id,token_id,server_id,kcml_number,code,hostname,tool_name,state,correlation_id,manifest
) values (
  '40000000-0000-0000-0000-000000000002',
  '20000000-0000-0000-0000-000000000002',
  '00000000-0000-0000-0000-000000000002',
  2,'KCML0002','kcml0002.hcasc.cz','home_assistant_inventory','ACTIVE',
  '50000000-0000-0000-0000-000000000002',
  '{}'::jsonb
);

insert into egress_capability(
  lookup_digest,fingerprint,job_id,server_id,allowlist,issued_at,expires_at
) values (
  digest('legacy-egress-capability','sha256'),
  'legacy-egress',
  '40000000-0000-0000-0000-000000000002',
  '00000000-0000-0000-0000-000000000002',
  '[]'::jsonb,
  '2026-04-17T11:37:00Z'::timestamptz,
  '2026-05-17T11:37:00Z'::timestamptz
);

insert into kaja_credential(id,public_id,secret_hash,secret_fingerprint,label)
values ('30000000-0000-0000-0000-000000000002','Kaja0002','legacy-hash','legacy0000000000','Legacy production credential');
insert into kaja_permission(credential_id,server_id,access_level)
values ('30000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000002','EXECUTE');
insert into access_token(
  lookup_digest,key_id,fingerprint,credential_id,server_id,audience,expires_at,
  credential_revocation_epoch,server_revocation_epoch
) select digest('legacy-access-token','sha256'),'v1','legacyaccess0000',credential.id,server.id,
         'https://kcml0002.hcasc.cz/mcp',now()+interval '1 hour',credential.revocation_epoch,server.revocation_epoch
    from kaja_credential credential,mcp_server server
   where credential.id='30000000-0000-0000-0000-000000000002'
     and server.id='00000000-0000-0000-0000-000000000002';

insert into audit_event(event_type,actor_type,object_type,object_id,correlation_id,created_at)
select 'legacy.production.event','system','migration_fixture',series::text,
       ('00000000-0000-0000-0000-' || lpad(series::text,12,'0'))::uuid,
       '2026-04-17T11:37:00Z'::timestamptz + series * interval '1 second'
  from generate_series(1,1165) as series;

create table if not exists operational_config_setting (
  key text primary key,
  value_json jsonb,
  value_ciphertext text,
  updated_by uuid references admin_account(id),
  updated_at timestamptz not null default now()
);
alter table operational_config_setting add column if not exists value_ciphertext text;
alter table operational_config_setting drop constraint if exists operational_config_setting_check;
alter table operational_config_setting
  add constraint operational_config_setting_check
  check (
    ((value_json is not null) and (value_ciphertext is null))
    or ((value_json is null) and (value_ciphertext is not null))
  );
SQL

run_migrations() {
  if [[ -x apps/server/node_modules/.bin/tsx ]]; then
    KCML_PROCESS_ROLE=migrate DATABASE_URL="$KCML_UPGRADE_DATABASE_URL" \
      apps/server/node_modules/.bin/tsx apps/server/src/cli/migrate.ts
  else
    KCML_PROCESS_ROLE=migrate DATABASE_URL="$KCML_UPGRADE_DATABASE_URL" pnpm db:migrate
  fi
}

run_migrations
run_migrations

psql "$KCML_UPGRADE_DATABASE_URL" --no-psqlrc --set ON_ERROR_STOP=1 <<'SQL'
begin;
insert into managed_service(
  code, slug, display_name, description, service_kind, lifecycle_state, operational_state, enabled,
  public_hostname, base_url, resource_uri, auth_mode, api_state, criticality, owners, contacts, governance,
  monitoring_enabled, monitoring_profile_digest, review_approved_at, review_due_at, review_interval_days, environment
) values (
  'KCML999999','reference-external-api-upgrade-fixture',
  'Reference External API upgrade fixture',
  'Rolled-back upgrade fixture proving the current managed-service component bridge is authoritative.',
  'EXTERNAL_API','REGISTERED_DISABLED','HEALTHY',false,
  'kcml999999.hcasc.cz','https://reference-api.hcasc.cz','https://kcml999999.hcasc.cz',
  'NONE','DISABLED','HIGH',
  '{"service":"KCML Managed Services","technical":"KCML Managed Services","security":"KCML Security","operations":"KCML Operations"}'::jsonb,
  '{"serviceEmail":"service@hcasc.cz","technicalEmail":"platform@hcasc.cz","securityEmail":"security@hcasc.cz","operationsOnCall":"KCML Operations"}'::jsonb,
  '{"criticality":"HIGH","classification":"CONFIDENTIAL","containsPersonalData":true,"exportAllowed":false,"retentionDays":365,"loggingPolicy":"Redact secrets before storing runtime evidence.","redactionFields":["authorization"]}'::jsonb,
  true,'sha256:upgrade-fixture','2026-07-15T00:00:00Z','2026-10-13T00:00:00Z',90,'production'
);
do $$
begin
  if exists (
    select 1
      from pg_trigger
     where tgname in ('legacy_mcp_server_component_adapter_trigger','legacy_managed_service_component_adapter_trigger')
       and not tgisinternal
  ) then
    raise exception 'stale_component_identity_trigger_present';
  end if;
  if not exists (
    select 1
      from managed_service service
      join component component on component.id=service.component_id
     where service.slug='reference-external-api-upgrade-fixture'
       and component.release_version='2026.07.23'
  ) then
    raise exception 'managed_service_component_bridge_not_current';
  end if;
end $$;
rollback;
SQL

psql "$KCML_UPGRADE_DATABASE_URL" --no-psqlrc --set ON_ERROR_STOP=1 <<'SQL'
do $$
begin
  if not exists (select 1 from pg_roles where rolname='kcml_audit_writer_fixture') then
    create role kcml_audit_writer_fixture nologin;
  end if;
  if not exists (select 1 from pg_roles where rolname='kcml_audit_caller_fixture') then
    create role kcml_audit_caller_fixture nologin;
  end if;
end $$;
grant usage,create on schema public to kcml_audit_writer_fixture;
alter function append_audit_event(text,text,text,text,text,jsonb,jsonb,uuid) owner to kcml_audit_writer_fixture;
alter function append_audit_event(text,text,text,text,text,jsonb,jsonb,uuid) security invoker;
revoke create on schema public from kcml_audit_writer_fixture;
revoke all on table audit_event,audit_head from kcml_audit_writer_fixture;
revoke all on sequence audit_event_id_seq from kcml_audit_writer_fixture;
grant usage on schema public to kcml_audit_caller_fixture;
grant execute on function append_audit_event(text,text,text,text,text,jsonb,jsonb,uuid) to kcml_audit_caller_fixture;
grant update (id) on table audit_event to kcml_audit_caller_fixture;
SQL
psql "$KCML_UPGRADE_DATABASE_URL" --no-psqlrc --set ON_ERROR_STOP=1 --file "$migrations/034_audit_writer_owner_privileges.sql" >/dev/null
psql "$KCML_UPGRADE_DATABASE_URL" --no-psqlrc --set ON_ERROR_STOP=1 --file "$migrations/035_audit_writer_returning_privilege.sql" >/dev/null
psql "$KCML_UPGRADE_DATABASE_URL" --no-psqlrc --set ON_ERROR_STOP=1 --file "$migrations/036_audit_writer_security_contract.sql" >/dev/null
psql "$KCML_UPGRADE_DATABASE_URL" --no-psqlrc --set ON_ERROR_STOP=1 <<'SQL'
begin;
set local role kcml_audit_caller_fixture;
select append_audit_event('migration.role_split.test','system',null,null,null,'null','null',gen_random_uuid());
rollback;
SQL

psql "$KCML_UPGRADE_DATABASE_URL" --no-psqlrc --set ON_ERROR_STOP=1 <<'SQL'
insert into operational_config_setting(key, value_json, secret_ciphertext, is_secret, version)
values ('githubToken', null, 'vault:v1:upgrade-fixture', true, 1)
on conflict (key) do update
  set value_json = excluded.value_json,
      secret_ciphertext = excluded.secret_ciphertext,
      is_secret = excluded.is_secret,
      version = excluded.version,
      updated_at = now();
SQL

psql "$KCML_UPGRADE_DATABASE_URL" --no-psqlrc --set ON_ERROR_STOP=1 --tuples-only --no-align <<'SQL' | grep -Fx 'upgrade-ok'
select case when
  (select count(*) from schema_migration) = 47
  and (select count(*) from legacy_schema_migration) = 9
  and (select count(*) from audit_event) = 1165
  and (select valid from verify_audit_chain()) is true
  and (
    select pg_get_userbyid(proowner) <> 'kcml_app'
       and prosecdef
       and has_table_privilege(pg_get_userbyid(proowner), 'public.audit_event', 'INSERT')
       and has_column_privilege(pg_get_userbyid(proowner), 'public.audit_event', 'id', 'SELECT')
      from pg_proc
     where oid='public.append_audit_event(text,text,text,text,text,jsonb,jsonb,uuid)'::regprocedure
  )
  and exists (
    select 1
      from mcp_server server
      join registration_revision revision on revision.id=server.active_revision_id
      join monitoring_profile profile on profile.server_id=server.id and profile.registration_revision_id=revision.id
     where server.code='KCML0002'
       and server.registration_state='ACTIVE'
       and server.operational_state='HEALTHY'
       and server.enabled=true
       and revision.schema_version='1.4'
       and revision.validation_state='VALID'
       and revision.review_due_at='2027-01-13T00:00:00Z'
       and revision.approved_at='2026-01-13T00:00:00Z'
       and revision.review_interval_days=365
       and profile.enabled=true
       and profile.profile_digest like 'sha256:%'
  )
  and exists (
    select 1 from integration_token
     where id='20000000-0000-0000-0000-000000000002'
       and legacy_backfill=true
       and descriptor->>'summary'='Legacy production integration token'
  )
  and exists (
    select 1 from access_token
     where credential_id='30000000-0000-0000-0000-000000000002'
       and revoked_at is null
       and component_id='00000000-0000-0000-0000-000000000002'
  )
  and exists (
    select 1
      from component component
      join mcp_server server on server.component_id=component.id
      join managed_service service on service.component_id=component.id
     where component.id='00000000-0000-0000-0000-000000000002'
       and component.code='KCML0002'
       and component.hostname='kcml0002.hcasc.cz'
       and component.enabled=true
       and component.lifecycle_state='ACTIVE'
       and component.activation_state='ACTIVE'
       and component.revocation_epoch=server.revocation_epoch
       and service.legacy_mcp_server_id=server.id
  )
  and exists (
    select 1
      from managed_service service
      join managed_service_revision revision on revision.id=service.active_revision_id
      join managed_service_scope scope on scope.managed_service_id=service.id and scope.scope_name='mcp.invoke'
      join managed_service_permission permission on permission.managed_service_id=service.id and permission.scope_id=scope.id
      join managed_service_access_token token on token.managed_service_id=service.id and token.credential_id=permission.credential_id
     where service.legacy_mcp_server_id='00000000-0000-0000-0000-000000000002'
       and service.code='KCML0002'
       and service.service_kind='MCP'
       and service.lifecycle_state='ACTIVE'
       and service.operational_state='HEALTHY'
       and service.enabled=true
       and service.api_state='ENABLED'
       and revision.schema_version='1.4'
       and revision.active=true
       and permission.revoked_at is null
       and token.revoked_at is null
       and token.service_revocation_epoch=service.revocation_epoch
  )
  and exists (
    select 1
      from egress_capability capability
     where capability.server_id='00000000-0000-0000-0000-000000000002'
       and capability.revoked_at is null
       and capability.allowlist='["ha-inventory.hcasc.cz:443"]'::jsonb
       and capability.expires_at > now() + interval '3000 days'
  )
  and not exists (
    select 1
      from pg_constraint
     where conrelid = 'operational_config_setting'::regclass
       and conname = 'operational_config_setting_check'
  )
  and exists (
    select 1 from operational_config_setting
     where key = 'githubToken'
       and is_secret = true
       and value_json is null
       and secret_ciphertext = 'vault:v1:upgrade-fixture'
  )
  then 'upgrade-ok' else 'upgrade-failed' end;
SQL
