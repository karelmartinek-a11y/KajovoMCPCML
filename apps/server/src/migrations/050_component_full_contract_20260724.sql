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

alter table release_wave_component
  drop constraint if exists release_wave_component_registration_type_check;

alter table release_wave_component
  add constraint release_wave_component_registration_type_check
  check (registration_type in ('KCML_ACCESS_CLIENT','KAJA_CLIENT','MCP_SERVER','MANAGED_PLATFORM_SERVICE'));

update release_wave_component
   set registration_type='KCML_ACCESS_CLIENT'
 where registration_type='KAJA_CLIENT';

alter table integration_token_allowed_component
  drop constraint if exists integration_token_allowed_component_registration_type_check;

alter table integration_token_allowed_component
  add constraint integration_token_allowed_component_registration_type_check
  check (registration_type in ('KCML_ACCESS_CLIENT','KAJA_CLIENT','MCP_SERVER','MANAGED_PLATFORM_SERVICE'));

update integration_token_allowed_component
   set registration_type='KCML_ACCESS_CLIENT'
 where registration_type='KAJA_CLIENT';

alter table integration_token_child_job
  drop constraint if exists integration_token_child_job_registration_type_check;

alter table integration_token_child_job
  add constraint integration_token_child_job_registration_type_check
  check (registration_type in ('KCML_ACCESS_CLIENT','KAJA_CLIENT','MCP_SERVER','MANAGED_PLATFORM_SERVICE'));

update integration_token_child_job
   set registration_type='KCML_ACCESS_CLIENT'
 where registration_type='KAJA_CLIENT';

alter table onboarding_job
  drop constraint if exists onboarding_job_registration_type_check;

alter table onboarding_job
  add constraint onboarding_job_registration_type_check
  check (registration_type is null or registration_type in ('KCML_ACCESS_CLIENT','KAJA_CLIENT','MCP_SERVER','MANAGED_PLATFORM_SERVICE'));

update onboarding_job
   set registration_type='KCML_ACCESS_CLIENT'
 where registration_type='KAJA_CLIENT';

create or replace function kcml_enforce_blueprint_release_generated_scope() returns trigger
language plpgsql
as $$
begin
  if exists (
    select 1
      from release_wave_component
     where release_version = new.release_version
       and wave_key = new.release_wave_key
       and blueprint_component_id = new.blueprint_component_id
  ) then
    return new;
  end if;

  raise exception 'unknown_blueprint_component:%', new.blueprint_component_id
    using errcode = '23514';
end;
$$;

create or replace function kcml_enforce_blueprint_release_child_job_scope() returns trigger
language plpgsql
as $$
begin
  if exists (
    select 1
      from release_wave_component
     where release_version = new.release_version
       and wave_key = new.release_wave_key
       and blueprint_component_id = new.blueprint_component_id
  ) then
    return new;
  end if;

  raise exception 'unknown_blueprint_child_job_component:%', new.blueprint_component_id
    using errcode = '23514';
end;
$$;

alter table component_onboarding_job
  drop constraint if exists component_onboarding_job_registration_type_check;

alter table component
  drop constraint if exists component_hostname_kajovocml_suffix_check;

alter table component
  add constraint component_hostname_kajovocml_suffix_check
  check (
    blueprint_component_id is null
    or release_wave_key is null
    or lifecycle_state='DEREGISTERED'
    or hostname ~* ('^' || lower(code::text) || '[.]kajovocml[.]hcasc[.]cz$')
  ) not valid;

create table if not exists component_state_contract (
  id uuid primary key default gen_random_uuid(),
  component_id uuid not null references component(id) on delete cascade,
  revision_id uuid not null references component_revision(id) on delete cascade,
  state_key text not null,
  category text not null default 'OPERATIONAL',
  state_schema jsonb not null,
  terminal boolean not null default false,
  created_at timestamptz not null default now(),
  unique(component_id, revision_id, state_key),
  check (state_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{1,159}$'),
  check (jsonb_typeof(state_schema)='object')
);

create table if not exists component_state_transition (
  id uuid primary key default gen_random_uuid(),
  component_id uuid not null references component(id) on delete cascade,
  revision_id uuid not null references component_revision(id) on delete cascade,
  from_state_key text not null,
  to_state_key text not null,
  trigger_mask text not null,
  created_at timestamptz not null default now(),
  unique(component_id, revision_id, from_state_key, to_state_key, trigger_mask)
);

create table if not exists component_state_observation (
  id uuid primary key default gen_random_uuid(),
  component_id uuid not null references component(id) on delete cascade,
  state_key text not null,
  observed_at timestamptz not null,
  correlation_id uuid not null,
  state_payload jsonb not null,
  validation_state text not null check (validation_state in ('ACCEPTED','REJECTED')),
  rejection_reason text,
  received_at timestamptz not null default now()
);

create index if not exists component_state_observation_component_idx
  on component_state_observation(component_id, observed_at desc);

create table if not exists component_pulse_mask (
  id uuid primary key default gen_random_uuid(),
  component_id uuid not null references component(id) on delete cascade,
  revision_id uuid not null references component_revision(id) on delete cascade,
  pulse_type text not null,
  direction text not null check (direction in ('INCOMING','OUTGOING')),
  route_acl text[] not null default '{}',
  scopes text[] not null default '{}',
  envelope_schema jsonb not null,
  execution_mode text not null,
  idempotency text not null,
  token_required boolean not null default true,
  created_at timestamptz not null default now(),
  unique(component_id, revision_id, pulse_type, direction),
  check (jsonb_typeof(envelope_schema)='object')
);

create index if not exists component_pulse_mask_lookup_idx
  on component_pulse_mask(component_id, pulse_type, direction);

create table if not exists component_call_mask (
  id uuid primary key default gen_random_uuid(),
  component_id uuid not null references component(id) on delete cascade,
  revision_id uuid not null references component_revision(id) on delete cascade,
  mask_key text not null,
  direction text not null check (direction in ('INBOUND','OUTBOUND','CONTROL','E2E')),
  route_pattern text not null,
  scope_name text not null,
  request_schema jsonb not null,
  response_schema jsonb not null,
  created_at timestamptz not null default now(),
  unique(component_id, revision_id, mask_key),
  check (jsonb_typeof(request_schema)='object'),
  check (jsonb_typeof(response_schema)='object')
);

create table if not exists component_endpoint_contract (
  id uuid primary key default gen_random_uuid(),
  component_id uuid not null references component(id) on delete cascade,
  revision_id uuid not null references component_revision(id) on delete cascade,
  endpoint_id text not null,
  public_hostname citext not null,
  path text not null,
  methods text[] not null,
  auth_mode text not null,
  request_schema jsonb not null,
  response_schema jsonb not null,
  created_at timestamptz not null default now(),
  unique(component_id, revision_id, endpoint_id),
  check (public_hostname ~* '^kcml[0-9]{4,}[.]kajovocml[.]hcasc[.]cz$')
);

create table if not exists component_attribute_contract (
  id uuid primary key default gen_random_uuid(),
  component_id uuid not null references component(id) on delete cascade,
  revision_id uuid not null references component_revision(id) on delete cascade,
  contract_kind text not null,
  mask_key text not null,
  attribute_path text not null,
  required boolean not null default false,
  attribute_schema jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  unique(component_id, revision_id, contract_kind, mask_key, attribute_path)
);

create table if not exists component_e2e_scenario (
  id uuid primary key default gen_random_uuid(),
  component_id uuid not null references component(id) on delete cascade,
  revision_id uuid not null references component_revision(id) on delete cascade,
  scenario_key text not null,
  variant text not null,
  input_ref text not null,
  input_digest text not null,
  expected_output_ref text not null,
  expected_output_digest text not null,
  expected_output jsonb not null,
  test_commands text[] not null,
  created_at timestamptz not null default now(),
  unique(component_id, revision_id, scenario_key),
  check (jsonb_typeof(expected_output) in ('object','array'))
);

create table if not exists component_e2e_result (
  id uuid primary key default gen_random_uuid(),
  component_id uuid not null references component(id) on delete cascade,
  revision_id uuid not null references component_revision(id) on delete cascade,
  scenario_id uuid not null references component_e2e_scenario(id) on delete cascade,
  status text not null check (status in ('PASS','FAIL')),
  generated_output_digest text not null,
  generated_output jsonb not null,
  correlation_id uuid not null,
  received_at timestamptz not null default now()
);

create index if not exists component_e2e_result_latest_idx
  on component_e2e_result(scenario_id, received_at desc);

create table if not exists component_documentation_evidence (
  id uuid primary key default gen_random_uuid(),
  component_id uuid not null references component(id) on delete cascade,
  revision_id uuid not null references component_revision(id) on delete cascade,
  evidence_key text not null,
  evidence_ref text not null,
  evidence_digest text,
  media_type text,
  required boolean not null default true,
  created_at timestamptz not null default now(),
  unique(component_id, revision_id, evidence_key)
);

create table if not exists component_operation_event (
  id uuid primary key default gen_random_uuid(),
  component_id uuid not null references component(id) on delete cascade,
  pulse_type text,
  direction text,
  operation_key text not null,
  input_digest text not null,
  input_payload jsonb not null,
  process_trace jsonb not null,
  output_digest text not null,
  output_payload jsonb not null,
  success boolean not null,
  correlation_id uuid not null,
  causation_id uuid,
  trace_id text,
  access_token_fingerprint text,
  occurred_at timestamptz not null,
  received_at timestamptz not null default now()
);

create index if not exists component_operation_event_component_idx
  on component_operation_event(component_id, occurred_at desc);

create table if not exists component_heartbeat (
  id uuid primary key default gen_random_uuid(),
  component_id uuid not null references component(id) on delete cascade,
  heartbeat_at timestamptz not null,
  policy_epoch bigint not null,
  operational_state text not null,
  state_digest text,
  correlation_id uuid not null,
  payload jsonb not null default '{}'::jsonb,
  received_at timestamptz not null default now()
);

create index if not exists component_heartbeat_component_idx
  on component_heartbeat(component_id, heartbeat_at desc);

create table if not exists component_control_command (
  id uuid primary key default gen_random_uuid(),
  component_id uuid not null references component(id) on delete cascade,
  revision_id uuid references component_revision(id) on delete cascade,
  command_key text not null,
  command_type text not null check (command_type in ('enable','disable','state','heartbeat')),
  endpoint_path text not null,
  request_schema jsonb not null,
  response_schema jsonb not null,
  status text not null default 'DECLARED' check (status in ('DECLARED','SENT','ACKED','FAILED')),
  ack_payload jsonb,
  acknowledged_at timestamptz,
  created_at timestamptz not null default now(),
  unique(component_id, revision_id, command_type)
);

create table if not exists component_external_principal (
  id uuid primary key default gen_random_uuid(),
  public_id citext not null unique,
  display_name text not null,
  description text not null default '',
  token_fingerprint text,
  status text not null default 'ACTIVE' check (status in ('ACTIVE','DISABLED','REVOKED')),
  created_at timestamptz not null default now(),
  revoked_at timestamptz
);

create table if not exists component_external_target (
  id uuid primary key default gen_random_uuid(),
  target_key text not null unique,
  display_name text not null,
  base_url text not null,
  audit_required boolean not null default true,
  status text not null default 'ACTIVE' check (status in ('ACTIVE','DISABLED','REVOKED')),
  created_at timestamptz not null default now(),
  revoked_at timestamptz
);

create table if not exists component_external_permission (
  id uuid primary key default gen_random_uuid(),
  component_id uuid references component(id) on delete cascade,
  external_principal_id uuid references component_external_principal(id) on delete cascade,
  external_target_id uuid not null references component_external_target(id) on delete cascade,
  route_pattern text not null,
  scope_name text not null,
  granted_at timestamptz not null default now(),
  revoked_at timestamptz,
  check (component_id is not null or external_principal_id is not null),
  unique(component_id, external_principal_id, external_target_id, route_pattern, scope_name)
);

create table if not exists component_secret_policy (
  component_id uuid not null references component(id) on delete cascade,
  revision_id uuid not null references component_revision(id) on delete cascade,
  policy_mode text not null check (policy_mode in ('GRANTED_SECRETS','ALL_SECRETS')),
  all_secrets_requires_grant boolean not null default true,
  audit_level text not null default 'FULL',
  created_at timestamptz not null default now(),
  primary key(component_id, revision_id)
);

alter table secret_grant
  add column if not exists all_secrets boolean not null default false;

drop index if exists secret_grant_current_identity_idx;

create unique index if not exists secret_grant_current_identity_idx
  on secret_grant(secret_id, principal_kind, coalesce(principal_id::text, ''), coalesce(principal_public_id::text, ''), all_secrets)
  where revoked_at is null;

create unique index if not exists secret_grant_current_all_secrets_identity_idx
  on secret_grant(principal_kind, coalesce(principal_id::text, ''), coalesce(principal_public_id::text, ''))
  where revoked_at is null and all_secrets is true;

create or replace view access_token_credential as
select * from kaja_credential;

create or replace view access_token_permission as
select * from kaja_permission;

update component c
   set lifecycle_state='REVIEW',
       activation_state='BLOCKED',
       operational_state='DISABLED',
       enabled=false,
       ingress_enabled=false,
       pulse_enabled=false,
       egress_enabled=false,
       policy_epoch=policy_epoch+1,
       updated_at=now()
 where c.lifecycle_state in ('APPROVED','ACTIVE')
   and not exists (
     select 1
       from component_state_contract s
      where s.component_id=c.id
   );
