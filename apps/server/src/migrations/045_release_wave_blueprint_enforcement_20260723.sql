insert into release_epoch(
  release_version, blueprint_version, catalog_version, manifest_schema_version,
  pulse_envelope_version, policy_baseline, mcp_protocol_version, sealed_previous_epoch_hash
)
values (
  '2026.07.23', '2026.07.23', '2026.07.23', '2026.07.23',
  '2026.07.23', date '2026-07-23', '2025-11-25',
  encode(sha256(coalesce((select event_hash::text from audit_head where singleton is true), '')::bytea), 'hex')
)
on conflict (release_version) do nothing;

create table if not exists release_wave (
  release_version text not null references release_epoch(release_version),
  wave_key text not null,
  display_name text not null,
  description text not null default '',
  baseline boolean not null default false,
  created_at timestamptz not null default now(),
  primary key (release_version, wave_key)
);

create table if not exists release_wave_component (
  release_version text not null,
  wave_key text not null,
  blueprint_component_id text not null,
  category text not null check (category in ('AI_AGENT','MCP_SERVER','PLATFORM_SERVICE')),
  registration_type text not null check (registration_type in ('KAJA_CLIENT','MCP_SERVER','MANAGED_PLATFORM_SERVICE')),
  component_role text not null check (component_role in ('AGENT','SERVICE','PLATFORM')),
  required_in_baseline boolean not null default true,
  display_order integer not null,
  created_at timestamptz not null default now(),
  primary key (release_version, wave_key, blueprint_component_id),
  foreign key (release_version, wave_key) references release_wave(release_version, wave_key) on delete cascade
);

insert into release_wave(release_version, wave_key, display_name, description, baseline)
values (
  '2026.07.23',
  'baseline-2026-07-23',
  'Prvni release vlna 9 AI / 11 MCP / 5 managed',
  'Baseline release wave for the first production rollout. It is not a final system ceiling.',
  true
)
on conflict (release_version, wave_key) do update
  set display_name=excluded.display_name,
      description=excluded.description,
      baseline=excluded.baseline;

insert into release_wave_component(release_version, wave_key, blueprint_component_id, category, registration_type, component_role, display_order)
values
  ('2026.07.23','baseline-2026-07-23','AI-CLS-001','AI_AGENT','KAJA_CLIENT','AGENT',1),
  ('2026.07.23','baseline-2026-07-23','AI-QRP-002','AI_AGENT','KAJA_CLIENT','AGENT',2),
  ('2026.07.23','baseline-2026-07-23','AI-LYL-003','AI_AGENT','KAJA_CLIENT','AGENT',3),
  ('2026.07.23','baseline-2026-07-23','AI-GRP-004','AI_AGENT','KAJA_CLIENT','AGENT',4),
  ('2026.07.23','baseline-2026-07-23','AI-BIZ-005','AI_AGENT','KAJA_CLIENT','AGENT',5),
  ('2026.07.23','baseline-2026-07-23','AI-IND-006','AI_AGENT','KAJA_CLIENT','AGENT',6),
  ('2026.07.23','baseline-2026-07-23','AI-HIS-007','AI_AGENT','KAJA_CLIENT','AGENT',7),
  ('2026.07.23','baseline-2026-07-23','AI-BRD-008','AI_AGENT','KAJA_CLIENT','AGENT',8),
  ('2026.07.23','baseline-2026-07-23','AI-QA-009','AI_AGENT','KAJA_CLIENT','AGENT',9),
  ('2026.07.23','baseline-2026-07-23','MCP-RX-WA-001','MCP_SERVER','MCP_SERVER','SERVICE',10),
  ('2026.07.23','baseline-2026-07-23','MCP-RX-MS-002','MCP_SERVER','MCP_SERVER','SERVICE',11),
  ('2026.07.23','baseline-2026-07-23','MCP-RX-EM-003','MCP_SERVER','MCP_SERVER','SERVICE',12),
  ('2026.07.23','baseline-2026-07-23','MCP-RX-BC-004','MCP_SERVER','MCP_SERVER','SERVICE',13),
  ('2026.07.23','baseline-2026-07-23','MCP-PMS-RO-005','MCP_SERVER','MCP_SERVER','SERVICE',14),
  ('2026.07.23','baseline-2026-07-23','MCP-PMS-RW-006','MCP_SERVER','MCP_SERVER','SERVICE',15),
  ('2026.07.23','baseline-2026-07-23','MCP-TX-WA-007','MCP_SERVER','MCP_SERVER','SERVICE',16),
  ('2026.07.23','baseline-2026-07-23','MCP-TX-MS-008','MCP_SERVER','MCP_SERVER','SERVICE',17),
  ('2026.07.23','baseline-2026-07-23','MCP-TX-EM-009','MCP_SERVER','MCP_SERVER','SERVICE',18),
  ('2026.07.23','baseline-2026-07-23','MCP-TX-BC-010','MCP_SERVER','MCP_SERVER','SERVICE',19),
  ('2026.07.23','baseline-2026-07-23','MCP-WFC-011','MCP_SERVER','MCP_SERVER','SERVICE',20),
  ('2026.07.23','baseline-2026-07-23','KCML-AUTH-001','PLATFORM_SERVICE','MANAGED_PLATFORM_SERVICE','PLATFORM',21),
  ('2026.07.23','baseline-2026-07-23','KCML-CTL-002','PLATFORM_SERVICE','MANAGED_PLATFORM_SERVICE','PLATFORM',22),
  ('2026.07.23','baseline-2026-07-23','KCML-MON-003','PLATFORM_SERVICE','MANAGED_PLATFORM_SERVICE','PLATFORM',23),
  ('2026.07.23','baseline-2026-07-23','KCML-AUD-004','PLATFORM_SERVICE','MANAGED_PLATFORM_SERVICE','PLATFORM',24),
  ('2026.07.23','baseline-2026-07-23','KCML-SEC-005','PLATFORM_SERVICE','MANAGED_PLATFORM_SERVICE','PLATFORM',25)
on conflict (release_version, wave_key, blueprint_component_id) do update
  set category=excluded.category,
      registration_type=excluded.registration_type,
      component_role=excluded.component_role,
      display_order=excluded.display_order;

alter table integration_token
  drop constraint if exists integration_token_max_child_jobs_check;

alter table integration_token
  add constraint integration_token_max_child_jobs_check
  check (max_child_jobs between 1 and 200);

alter table integration_token
  alter column release_version set default '2026.07.23',
  add column if not exists release_wave_key text,
  add column if not exists blueprint_release_version text;

update integration_token
   set release_wave_key=coalesce(release_wave_key, 'baseline-2026-07-23'),
       blueprint_release_version=coalesce(blueprint_release_version, release_version)
 where release_version='2026.07.23';

alter table integration_token_allowed_component
  add column if not exists release_wave_key text;

update integration_token_allowed_component
   set release_wave_key=coalesce(release_wave_key, 'baseline-2026-07-23')
 where release_version='2026.07.23';

alter table integration_token_child_job
  add column if not exists release_wave_key text,
  add column if not exists component_onboarding_job_id uuid references component_onboarding_job(id) on delete cascade;

update integration_token_child_job
   set release_wave_key=coalesce(release_wave_key, 'baseline-2026-07-23')
 where release_version='2026.07.23';

alter table component
  alter column release_version set default '2026.07.23',
  add column if not exists release_wave_key text,
  add column if not exists blueprint_component_id text;

alter table component_revision
  alter column schema_version set default '2026.07.23',
  alter column catalog_version set default '2026.07.23';

alter table component_onboarding_job
  alter column release_version set default '2026.07.23',
  add column if not exists release_wave_key text,
  add column if not exists blueprint_component_id text,
  add column if not exists authorization_snapshot jsonb not null default '{}'::jsonb;

alter table onboarding_job
  alter column release_version set default '2026.07.23',
  add column if not exists release_wave_key text,
  add column if not exists authorization_snapshot jsonb not null default '{}'::jsonb;

alter table mcp_server
  alter column release_version set default '2026.07.23',
  add column if not exists release_wave_key text;

create unique index if not exists component_release_wave_blueprint_live_uidx
  on component(release_version, release_wave_key, blueprint_component_id)
  where blueprint_component_id is not null and lifecycle_state <> 'DEREGISTERED';

create unique index if not exists component_onboarding_token_blueprint_live_uidx
  on component_onboarding_job(integration_token_id, blueprint_component_id)
  where blueprint_component_id is not null and state not in ('CANCELLED','FAILED');

create unique index if not exists integration_token_child_component_onboarding_job_uidx
  on integration_token_child_job(component_onboarding_job_id)
  where component_onboarding_job_id is not null;

create table if not exists component_onboarding_revision_request (
  job_id uuid not null references component_onboarding_job(id) on delete cascade,
  idempotency_key text not null,
  request_digest text not null,
  created_at timestamptz not null default now(),
  primary key (job_id, idempotency_key)
);

alter table operational_config_setting
  drop constraint if exists operational_config_setting_updated_by_fkey;

alter table operational_config_setting
  add constraint operational_config_setting_updated_by_fkey
  foreign key (updated_by) references admin_account(id) on delete set null;

create or replace function kcml_factory_reset_truncate(table_names text[]) returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  candidate_table_name text;
  qualified_tables text := '';
begin
  if array_length(table_names, 1) is null then
    return;
  end if;

  foreach candidate_table_name in array table_names loop
    if candidate_table_name in ('schema_migration','operational_config_setting','operational_config_applied') then
      raise exception 'factory_reset_table_not_allowed:%', candidate_table_name;
    end if;
    if not exists (
      select 1
        from information_schema.tables
       where table_schema = 'public'
         and table_type = 'BASE TABLE'
         and information_schema.tables.table_name = candidate_table_name
    ) then
      raise exception 'factory_reset_table_not_found:%', candidate_table_name;
    end if;
    qualified_tables := qualified_tables || case when qualified_tables = '' then '' else ', ' end || format('public.%I', candidate_table_name);
  end loop;

  execute 'truncate table ' || qualified_tables || ' restart identity cascade';
end;
$$;

revoke all on function kcml_factory_reset_truncate(text[]) from public;
grant execute on function kcml_factory_reset_truncate(text[]) to current_user;
