alter table release_epoch drop constraint if exists release_epoch_release_version_check;
alter table release_epoch add constraint release_epoch_release_version_check
  check (release_version ~ '^[0-9]{4}[.][0-9]{2}[.][0-9]{2}(-[a-z0-9]+([.][a-z0-9]+)*)?$');

insert into release_epoch(
  release_version,blueprint_version,catalog_version,manifest_schema_version,
  pulse_envelope_version,policy_baseline,mcp_protocol_version,sealed_previous_epoch_hash
) values (
  '2026.07.22-compliance.1','2026.07.22-compliance.1','2026.07.22-compliance.1','2026.07.22-compliance.1',
  '2026.07.22-compliance.1',date '2026-07-22','2025-11-25',
  encode(sha256(coalesce((select event_hash::text from audit_head where singleton is true),'')::bytea),'hex')
) on conflict (release_version) do nothing;

alter table component alter column release_version set default '2026.07.22-compliance.1';
alter table component_revision alter column schema_version set default '2026.07.22-compliance.1';
alter table component_revision alter column catalog_version set default '2026.07.22-compliance.1';
alter table component_onboarding_job alter column release_version set default '2026.07.22-compliance.1';

alter table component_documentation_evidence add column if not exists content bytea;
alter table component_documentation_evidence add column if not exists content_verified_at timestamptz;

alter table component_e2e_run add column if not exists lease_owner text;
alter table component_e2e_run add column if not exists lease_until timestamptz;
alter table component_e2e_run add column if not exists deadline_at timestamptz not null default now()+interval '15 minutes';
alter table component_e2e_run add column if not exists cancellation_requested_at timestamptz;
alter table component_e2e_run add column if not exists worker_heartbeat_at timestamptz;
alter table component_e2e_run add column if not exists attempt_count integer not null default 0;
alter table component_e2e_run add column if not exists final_error_code text;
alter table component_e2e_run add column if not exists created_at timestamptz not null default now();

alter table component_e2e_fixture add column if not exists invocation_kind text;
alter table component_e2e_fixture add column if not exists invocation_name text;
alter table component_e2e_fixture add column if not exists timeout_ms integer not null default 30000;
alter table component_e2e_fixture add column if not exists cleanup_contract jsonb not null default '{"required":false}'::jsonb;

create index if not exists component_e2e_run_worker_idx
  on component_e2e_run(status,deadline_at,created_at)
  where status in ('QUEUED','RUNNING');
