do $$ begin
  create type integration_token_kind as enum ('SINGLE_COMPONENT','BLUEPRINT_RELEASE');
exception when duplicate_object then null; end $$;

create table if not exists release_epoch (
  release_version text primary key,
  blueprint_version text not null,
  catalog_version text not null,
  manifest_schema_version text not null,
  pulse_envelope_version text not null,
  policy_baseline date not null,
  mcp_protocol_version text not null,
  sealed_previous_epoch_hash text,
  created_at timestamptz not null default now(),
  check (release_version ~ '^[0-9]{4}[.][0-9]{2}[.][0-9]{2}$')
);

insert into release_epoch(
  release_version, blueprint_version, catalog_version, manifest_schema_version,
  pulse_envelope_version, policy_baseline, mcp_protocol_version, sealed_previous_epoch_hash
)
values (
  '2026.07.20', '2026.07.20', '2026.07.20', '2026.07.20',
  '2026.07.20', date '2026-07-20', '2025-11-25',
  encode(sha256(coalesce((select event_hash::text from audit_head where singleton is true), '')::bytea), 'hex')
)
on conflict (release_version) do nothing;

alter table integration_token
  drop constraint if exists integration_token_check,
  drop constraint if exists integration_token_check1,
  drop constraint if exists integration_token_check2;

alter table integration_token
  add constraint integration_token_max_expires_release_20260720_check
  check (max_expires_at <= issued_at + interval '30 days');

alter table integration_token
  add column if not exists token_kind integration_token_kind not null default 'SINGLE_COMPONENT',
  add column if not exists release_version text not null default '2026.07.20' references release_epoch(release_version),
  add column if not exists max_child_jobs integer not null default 1 check (max_child_jobs between 1 and 20),
  add column if not exists auto_activate_after_pass boolean not null default false,
  add column if not exists manual_approval_required_after_issuance boolean not null default true;

create table if not exists integration_token_allowed_component (
  id uuid primary key default gen_random_uuid(),
  token_id uuid not null references integration_token(id) on delete cascade,
  blueprint_component_id text not null,
  registration_type text not null check (registration_type in ('KAJA_CLIENT','MCP_SERVER','MANAGED_PLATFORM_SERVICE')),
  release_version text not null default '2026.07.20' references release_epoch(release_version),
  created_at timestamptz not null default now(),
  unique(token_id, blueprint_component_id)
);

create table if not exists integration_token_child_job (
  id uuid primary key default gen_random_uuid(),
  token_id uuid not null references integration_token(id) on delete cascade,
  onboarding_job_id uuid references onboarding_job(id) on delete cascade,
  blueprint_component_id text not null,
  registration_type text not null check (registration_type in ('KAJA_CLIENT','MCP_SERVER','MANAGED_PLATFORM_SERVICE')),
  release_version text not null default '2026.07.20' references release_epoch(release_version),
  authorization_snapshot jsonb not null,
  created_at timestamptz not null default now(),
  unique(token_id, blueprint_component_id),
  unique(onboarding_job_id)
);

alter table onboarding_job
  add column if not exists release_version text not null default '2026.07.20' references release_epoch(release_version),
  add column if not exists blueprint_component_id text,
  add column if not exists registration_type text check (registration_type is null or registration_type in ('KAJA_CLIENT','MCP_SERVER','MANAGED_PLATFORM_SERVICE')),
  add column if not exists archived_at timestamptz,
  add column if not exists archive_reason text;

alter table mcp_server
  add column if not exists release_version text not null default '2026.07.20' references release_epoch(release_version),
  add column if not exists blueprint_component_id text,
  add column if not exists archived_at timestamptz,
  add column if not exists archive_reason text;

update integration_token
   set revoked_at=coalesce(revoked_at, now()),
       release_version='2026.07.20',
       lock_version=lock_version+1
 where revoked_at is null
   and (created_at < timestamp with time zone '2026-07-20 00:00:00+00'
        or onboarding_job_id is not null);

update onboarding_job
   set archived_at=coalesce(archived_at, now()),
       archive_reason='release_2026_07_20_boundary',
       runtime_stopped_at=coalesce(runtime_stopped_at, now()),
       state=case when state in ('ACTIVE','REGISTERED_DISABLED','TRIAL_TESTING') then 'CANCELLED'::onboarding_job_state else state end,
       lock_version=lock_version+1
 where release_version='2026.07.20'
   and created_at < timestamp with time zone '2026-07-20 00:00:00+00'
   and archived_at is null;

update mcp_server
   set enabled=false,
       registration_state=case when registration_state in ('ACTIVE','TRIAL','REGISTERED_DISABLED') then 'RETIRED'::registration_state else registration_state end,
       operational_state=case when operational_state in ('HEALTHY','DEGRADED','UNKNOWN') then 'RETIRED'::operational_state else operational_state end,
       archived_at=coalesce(archived_at, now()),
       archive_reason='release_2026_07_20_boundary',
       retired_at=coalesce(retired_at, now()),
       lock_version=lock_version+1
 where archived_at is null
   and created_at < timestamp with time zone '2026-07-20 00:00:00+00'
   and not (
     enabled is true
     and registration_state='ACTIVE'::registration_state
     and operational_state='HEALTHY'::operational_state
     and active_revision_id is not null
   );

update access_token
   set revoked_at=coalesce(revoked_at, now())
 where revoked_at is null
   and server_id in (select id from mcp_server where archived_at is not null);

update egress_capability
   set revoked_at=coalesce(revoked_at, now())
 where revoked_at is null
   and server_id in (select id from mcp_server where archived_at is not null);

create index if not exists integration_token_release_active_idx
  on integration_token(release_version, token_kind, issued_at desc)
  where revoked_at is null and deleted_at is null;

create index if not exists onboarding_job_release_active_idx
  on onboarding_job(release_version, blueprint_component_id, state)
  where archived_at is null;

create index if not exists mcp_server_release_active_idx
  on mcp_server(release_version, blueprint_component_id, registration_state)
  where archived_at is null;
