insert into release_epoch(
  release_version, blueprint_version, catalog_version, manifest_schema_version,
  pulse_envelope_version, policy_baseline, mcp_protocol_version, sealed_previous_epoch_hash
)
values (
  '2026.07.21', '2026.07.21', '2026.07.21', '2026.07.21',
  '2026.07.21', date '2026-07-21', '2025-11-25',
  encode(sha256(coalesce((select event_hash::text from audit_head where singleton is true), '')::bytea), 'hex')
)
on conflict (release_version) do nothing;

create table component (
  id uuid primary key default gen_random_uuid(),
  kcml_number bigint not null unique,
  code citext not null unique,
  hostname citext not null unique,
  display_name text not null,
  description text not null default '',
  category text not null check (category in ('AI_CLIENT','AI_AGENT','MCP_SERVER','MANAGED_RUNTIME','EXTERNAL_SERVICE','PLATFORM_SERVICE')),
  registration_type text not null,
  component_role text not null default 'SERVICE' check (component_role in ('CLIENT','AGENT','SERVICE','RUNTIME','PLATFORM')),
  owners jsonb not null default '{}'::jsonb,
  contacts jsonb not null default '{}'::jsonb,
  lifecycle_state text not null default 'DRAFT' check (lifecycle_state in ('DRAFT','REVIEW','APPROVED','ACTIVE','SUSPENDED','QUARANTINED','RETIRED','DEREGISTERED')),
  activation_state text not null default 'INACTIVE' check (activation_state in ('INACTIVE','READY','ACTIVE','BLOCKED')),
  operational_state text not null default 'UNKNOWN' check (operational_state in ('UNKNOWN','DISABLED','HEALTHY','DEGRADED','UNHEALTHY','MAINTENANCE','QUARANTINED','RETIRED')),
  monitoring_state text not null default 'NOT_CONFIGURED' check (monitoring_state in ('NOT_CONFIGURED','PENDING','HEALTHY','DEGRADED','FAILED')),
  recertification_state text not null default 'NOT_DUE' check (recertification_state in ('NOT_DUE','DUE','OVERDUE','IN_REVIEW','PASSED','FAILED')),
  enabled boolean not null default false,
  ingress_enabled boolean not null default false,
  pulse_enabled boolean not null default false,
  egress_enabled boolean not null default false,
  active_revision_id uuid,
  revocation_epoch uuid not null default gen_random_uuid(),
  policy_epoch bigint not null default 0 check (policy_epoch >= 0),
  release_version text not null default '2026.07.21' references release_epoch(release_version),
  lock_version bigint not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  retired_at timestamptz,
  deregistered_at timestamptz,
  check (code ~* '^KCML[0-9]{4,}$'),
  check (hostname ~* ('^' || lower(code::text) || '[.][a-z0-9][a-z0-9.-]*[a-z0-9]$')),
  check (enabled is false or activation_state='ACTIVE'),
  check (lifecycle_state not in ('RETIRED','DEREGISTERED') or enabled is false)
);

alter table component alter column kcml_number set default nextval('kcml_number_seq');
alter sequence kcml_number_seq owned by component.kcml_number;

create table component_revision (
  id uuid primary key default gen_random_uuid(),
  component_id uuid not null references component(id) on delete cascade,
  revision text not null,
  schema_version text not null default '2026.07.21',
  catalog_version text not null default '2026.07.21',
  validation_state text not null default 'PENDING' check (validation_state in ('PENDING','APPROVED','REJECTED','SUPERSEDED')),
  manifest jsonb not null,
  manifest_digest text not null,
  artifact_digest text,
  capabilities text[] not null default '{}',
  protocols text[] not null default '{}',
  transports text[] not null default '{}',
  derived_gates jsonb not null default '[]'::jsonb,
  evidence jsonb not null default '{}'::jsonb,
  approved_at timestamptz,
  created_at timestamptz not null default now(),
  unique(component_id, revision)
);

alter table component
  add constraint component_active_revision_id_fkey
  foreign key (active_revision_id) references component_revision(id)
  deferrable initially deferred;

create table component_credential (
  id uuid primary key default gen_random_uuid(),
  component_id uuid not null references component(id) on delete cascade,
  public_id citext not null unique,
  key_id text not null,
  secret_digest bytea not null unique,
  secret_fingerprint text not null,
  status text not null default 'ACTIVE' check (status in ('ACTIVE','ROTATING','REVOKED','EXPIRED')),
  issued_at timestamptz not null default now(),
  expires_at timestamptz,
  last_used_at timestamptz,
  revoked_at timestamptz,
  rotated_at timestamptz,
  revocation_epoch uuid not null default gen_random_uuid(),
  metadata jsonb not null default '{}'::jsonb,
  check (public_id ~* '^KCML[0-9]{4,}[-]C[0-9]{2,}$'),
  check ((status='REVOKED') = (revoked_at is not null))
);

create table component_access_token (
  lookup_digest bytea primary key,
  key_id text not null,
  fingerprint text not null,
  credential_id uuid not null references component_credential(id) on delete cascade,
  source_component_id uuid not null references component(id) on delete cascade,
  target_component_id uuid not null references component(id) on delete cascade,
  audience text not null,
  scope_names text[] not null default '{}',
  issued_at timestamptz not null default now(),
  expires_at timestamptz not null,
  revoked_at timestamptz,
  last_used_at timestamptz,
  credential_revocation_epoch uuid not null,
  target_revocation_epoch uuid not null,
  policy_epoch_at_issue bigint not null
);

create index component_access_token_target_expires_idx
  on component_access_token(target_component_id, expires_at desc)
  where revoked_at is null;

create table component_onboarding_job (
  id uuid primary key default gen_random_uuid(),
  integration_token_id uuid not null references integration_token(id),
  component_id uuid references component(id),
  idempotency_key text not null,
  request_digest text not null,
  category text not null,
  registration_type text not null,
  state text not null default 'SUBMITTED' check (state in ('SUBMITTED','IN_REVIEW','GATES_PENDING','READY','ACTIVE','CANCELLED','FAILED')),
  manifest jsonb not null,
  manifest_digest text not null,
  gate_results jsonb not null default '[]'::jsonb,
  credential_id uuid references component_credential(id),
  credential_claim_digest bytea unique,
  credential_claim_expires_at timestamptz,
  credential_claimed_at timestamptz,
  failure_code text,
  release_version text not null default '2026.07.21' references release_epoch(release_version),
  lock_version bigint not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  cancelled_at timestamptz,
  unique(integration_token_id, idempotency_key)
);

create index component_onboarding_job_state_idx on component_onboarding_job(state, created_at);

create table component_permission (
  id uuid primary key default gen_random_uuid(),
  source_component_id uuid not null references component(id) on delete cascade,
  target_component_id uuid not null references component(id) on delete cascade,
  route_pattern text not null,
  scope_name text not null,
  access_level text not null default 'INVOKE' check (access_level in ('DISCOVER','MONITOR','INVOKE','READ','WRITE','ADMIN')),
  constraints_json jsonb not null default '{}'::jsonb,
  granted_at timestamptz not null default now(),
  granted_by_type text not null default 'system',
  granted_by_id text,
  revoked_at timestamptz,
  unique(source_component_id, target_component_id, route_pattern, scope_name)
);

create index component_permission_current_route_idx
  on component_permission(source_component_id, target_component_id, scope_name, route_pattern)
  where revoked_at is null;

create table component_audit_stream (
  id uuid primary key default gen_random_uuid(),
  component_id uuid not null unique references component(id) on delete cascade,
  expected_next_sequence bigint not null default 1 check (expected_next_sequence > 0),
  highest_received_sequence bigint not null default 0 check (highest_received_sequence >= 0),
  highest_acknowledged_sequence bigint not null default 0 check (highest_acknowledged_sequence >= 0),
  gap_state text not null default 'CONTIGUOUS' check (gap_state in ('CONTIGUOUS','GAP_DETECTED','REPLAY_REQUESTED','REPLAYING','UNAVAILABLE')),
  gap_from_sequence bigint,
  gap_to_sequence bigint,
  replay_requested_at timestamptz,
  last_event_at timestamptz,
  last_acknowledged_at timestamptz,
  lock_version bigint not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check ((gap_from_sequence is null) = (gap_to_sequence is null)),
  check (gap_from_sequence is null or gap_from_sequence <= gap_to_sequence)
);

create table component_audit_event (
  stream_id uuid not null references component_audit_stream(id) on delete cascade,
  sequence_number bigint not null check (sequence_number > 0),
  event_type text not null,
  workflow text,
  workflow_step text,
  initiated_by_type text not null,
  initiated_by_id text,
  occurred_at timestamptz not null,
  model_name text,
  tool_name text,
  service_name text,
  input_classification text,
  output_classification text,
  input_summary jsonb,
  output_summary jsonb,
  principal_id text,
  principal_fingerprint text,
  scope_name text,
  route text,
  authorization_decision text,
  authorization_reason text,
  protocol_result text,
  http_status integer check (http_status is null or http_status between 100 and 599),
  retry_count integer not null default 0 check (retry_count >= 0),
  idempotency_key text,
  correlation_id uuid not null,
  causation_id uuid,
  trace_id text,
  span_id text,
  state_change jsonb,
  catalog_version text not null,
  payload jsonb not null default '{}'::jsonb,
  received_at timestamptz not null default now(),
  acknowledged_at timestamptz,
  primary key(stream_id, sequence_number)
);

create index component_audit_event_correlation_idx on component_audit_event(correlation_id);
create index component_audit_event_trace_idx on component_audit_event(trace_id) where trace_id is not null;

alter table mcp_server add column component_id uuid;
alter table managed_service add column component_id uuid;
alter table onboarding_job add column component_id uuid;
alter table access_token add column component_id uuid;
alter table managed_service_access_token add column component_id uuid;

create or replace function legacy_mcp_server_component_adapter() returns trigger language plpgsql as $$
begin
  if new.component_id is null then
    insert into component(
      id,kcml_number,code,hostname,display_name,description,category,registration_type,component_role,
      lifecycle_state,activation_state,operational_state,monitoring_state,
      enabled,ingress_enabled,pulse_enabled,egress_enabled,revocation_epoch,release_version
    ) values (
      new.id,new.kcml_number,new.code,new.hostname,new.display_name,new.description,'MCP_SERVER','MCP_SERVER','SERVICE',
      case new.registration_state::text
        when 'ACTIVE' then 'ACTIVE' when 'TRIAL' then 'ACTIVE' when 'QUARANTINED' then 'QUARANTINED'
        when 'RETIRED' then 'RETIRED' when 'SUSPENDED' then 'SUSPENDED' when 'APPROVED' then 'APPROVED' else 'DRAFT' end,
      case when new.enabled then 'ACTIVE' when new.registration_state::text in ('APPROVED','REGISTERED_DISABLED') then 'READY' else 'INACTIVE' end,
      new.operational_state::text,'NOT_CONFIGURED',new.enabled,new.enabled,new.enabled,new.enabled,
      new.revocation_epoch,coalesce(new.release_version,'2026.07.21')
    ) on conflict (id) do nothing;
    new.component_id := new.id;
  end if;
  return new;
end $$;

create trigger legacy_mcp_server_component_adapter_trigger
before insert on mcp_server for each row execute function legacy_mcp_server_component_adapter();

create or replace function legacy_managed_service_component_adapter() returns trigger language plpgsql as $$
begin
  if new.component_id is null and new.legacy_mcp_server_id is not null then
    select component_id into new.component_id from mcp_server where id=new.legacy_mcp_server_id;
    if new.component_id is null then raise exception 'legacy_mcp_component_missing'; end if;
  elsif new.component_id is null then
    insert into component(
      id,kcml_number,code,hostname,display_name,description,category,registration_type,component_role,
      owners,contacts,lifecycle_state,activation_state,operational_state,monitoring_state,
      enabled,ingress_enabled,pulse_enabled,egress_enabled,revocation_epoch,release_version
    ) values (
      new.id,regexp_replace(new.code::text,'[^0-9]','','g')::bigint,new.code,
      coalesce(new.public_hostname,(lower(new.code::text)||'.hcasc.cz')::citext),new.display_name,new.description,
      case when new.service_kind='MCP' then 'MCP_SERVER' else 'EXTERNAL_SERVICE' end,
      case when new.service_kind='MCP' then 'MCP_SERVER' else 'MANAGED_PLATFORM_SERVICE' end,'SERVICE',new.owners,new.contacts,
      case new.lifecycle_state::text
        when 'ACTIVE' then 'ACTIVE' when 'TRIAL' then 'ACTIVE' when 'QUARANTINED' then 'QUARANTINED'
        when 'RETIRED' then 'RETIRED' when 'SUSPENDED' then 'SUSPENDED' else 'DRAFT' end,
      case when new.enabled then 'ACTIVE' when new.lifecycle_state::text='REGISTERED_DISABLED' then 'READY' else 'INACTIVE' end,
      new.operational_state::text,case when new.monitoring_enabled then 'PENDING' else 'NOT_CONFIGURED' end,
      new.enabled,new.enabled and new.api_state='ENABLED',new.enabled,new.enabled,new.revocation_epoch,'2026.07.21'
    ) on conflict (id) do nothing;
    new.component_id := new.id;
  end if;
  return new;
end $$;

create trigger legacy_managed_service_component_adapter_trigger
before insert on managed_service for each row execute function legacy_managed_service_component_adapter();

insert into component(
  id, kcml_number, code, hostname, display_name, description, category, registration_type, component_role,
  owners, contacts, lifecycle_state, activation_state, operational_state, monitoring_state,
  recertification_state, enabled, ingress_enabled, pulse_enabled, egress_enabled,
  revocation_epoch, release_version, lock_version, created_at, updated_at, retired_at
)
select s.id, s.kcml_number, s.code, s.hostname, s.display_name, s.description, 'MCP_SERVER', 'MCP_SERVER', 'SERVICE',
       coalesce(ms.owners, '{}'::jsonb), coalesce(ms.contacts, '{}'::jsonb),
       case s.registration_state::text
         when 'ACTIVE' then 'ACTIVE' when 'TRIAL' then 'ACTIVE' when 'QUARANTINED' then 'QUARANTINED'
         when 'RETIRED' then 'RETIRED' when 'SUSPENDED' then 'SUSPENDED' when 'APPROVED' then 'APPROVED' else 'DRAFT' end,
       case when s.enabled then 'ACTIVE' when s.registration_state::text in ('APPROVED','REGISTERED_DISABLED') then 'READY' else 'INACTIVE' end,
       s.operational_state::text,
       case when coalesce(ms.monitoring_enabled, false) then
         case when s.operational_state::text='HEALTHY' then 'HEALTHY' when s.operational_state::text in ('DEGRADED','UNHEALTHY') then 'DEGRADED' else 'PENDING' end
       else 'NOT_CONFIGURED' end,
       case when ms.review_due_at is not null and ms.review_due_at < now() then 'OVERDUE' else 'NOT_DUE' end,
       s.enabled, s.enabled, s.enabled, s.enabled, s.revocation_epoch, s.release_version, s.lock_version,
       s.created_at, s.updated_at, s.retired_at
  from mcp_server s
  left join managed_service ms on ms.legacy_mcp_server_id=s.id;

insert into component(
  id, kcml_number, code, hostname, display_name, description, category, registration_type, component_role,
  owners, contacts, lifecycle_state, activation_state, operational_state, monitoring_state,
  recertification_state, enabled, ingress_enabled, pulse_enabled, egress_enabled,
  revocation_epoch, release_version, lock_version, created_at, updated_at, retired_at
)
select ms.id,
       regexp_replace(ms.code::text, '[^0-9]', '', 'g')::bigint,
       ms.code,
       coalesce(ms.public_hostname, (lower(ms.code::text) || '.hcasc.cz')::citext),
       ms.display_name, ms.description,
       case when ms.service_kind='MCP' then 'MCP_SERVER' else 'EXTERNAL_SERVICE' end,
       case when ms.service_kind='MCP' then 'MCP_SERVER' else 'MANAGED_PLATFORM_SERVICE' end,
       'SERVICE', ms.owners, ms.contacts,
       case ms.lifecycle_state::text when 'ACTIVE' then 'ACTIVE' when 'TRIAL' then 'ACTIVE' when 'QUARANTINED' then 'QUARANTINED' when 'RETIRED' then 'RETIRED' when 'SUSPENDED' then 'SUSPENDED' else 'DRAFT' end,
       case when ms.enabled then 'ACTIVE' when ms.lifecycle_state::text='REGISTERED_DISABLED' then 'READY' else 'INACTIVE' end,
       ms.operational_state::text,
       case when ms.monitoring_enabled then case when ms.operational_state::text='HEALTHY' then 'HEALTHY' when ms.operational_state::text in ('DEGRADED','UNHEALTHY') then 'DEGRADED' else 'PENDING' end else 'NOT_CONFIGURED' end,
       case when ms.review_due_at is not null and ms.review_due_at < now() then 'OVERDUE' else 'NOT_DUE' end,
       ms.enabled, ms.enabled and ms.api_state='ENABLED', ms.enabled, ms.enabled,
       ms.revocation_epoch, '2026.07.21', ms.lock_version, ms.created_at, ms.updated_at, ms.retired_at
  from managed_service ms
 where ms.legacy_mcp_server_id is null;

update mcp_server set component_id=id;
update managed_service set component_id=coalesce(legacy_mcp_server_id, id);
update onboarding_job j set component_id=s.component_id from mcp_server s where j.server_id=s.id;
update access_token t set component_id=s.component_id from mcp_server s where t.server_id=s.id;
update managed_service_access_token t set component_id=s.component_id from managed_service s where t.managed_service_id=s.id;

select setval(
  'kcml_number_seq',
  greatest((select last_value from kcml_number_seq), coalesce((select max(kcml_number) from component), 1)),
  true
);

alter table mcp_server alter column component_id set not null;
alter table managed_service alter column component_id set not null;
alter table mcp_server add constraint mcp_server_component_id_fkey foreign key(component_id) references component(id);
alter table managed_service add constraint managed_service_component_id_fkey foreign key(component_id) references component(id);
alter table onboarding_job add constraint onboarding_job_component_id_fkey foreign key(component_id) references component(id);
alter table access_token add constraint access_token_component_id_fkey foreign key(component_id) references component(id);
alter table managed_service_access_token add constraint managed_service_access_token_component_id_fkey foreign key(component_id) references component(id);

create unique index mcp_server_component_unique_idx on mcp_server(component_id);
create unique index managed_service_component_unique_idx on managed_service(component_id);
create index onboarding_job_component_idx on onboarding_job(component_id, state) where archived_at is null;

insert into component_revision(
  id, component_id, revision, schema_version, catalog_version, validation_state, manifest, manifest_digest,
  artifact_digest, capabilities, protocols, transports, derived_gates, evidence, approved_at, created_at
)
select r.id, r.server_id, r.revision, '2026.07.21', '2026.07.21',
       case when r.state::text in ('ACTIVE','TRIAL','APPROVED') then 'APPROVED' else 'PENDING' end,
       r.manifest, r.manifest_digest, r.artifact_digest,
       array['mcp.initialize','mcp.notifications.initialized','mcp.tools.list','mcp.tools.call']::text[],
       array['MCP']::text[], array['HTTPS']::text[],
       '["AUTHORIZATION","PUBLIC_ENDPOINT","TECHNICAL_DISABLE","MONITORING","AUDIT_CONTINUITY"]'::jsonb,
       r.evidence,
       case when r.state::text in ('ACTIVE','TRIAL','APPROVED') then r.created_at else null end,
       r.created_at
  from registration_revision r
on conflict (component_id, revision) do nothing;

insert into component_revision(
  id, component_id, revision, schema_version, catalog_version, validation_state, manifest, manifest_digest,
  artifact_digest, capabilities, protocols, transports, derived_gates, evidence, approved_at, created_at
)
select r.id, s.component_id, r.revision, r.schema_version, '2026.07.21',
       case when r.validation_state='APPROVED' then 'APPROVED' else 'PENDING' end,
       r.manifest, r.manifest_digest, r.artifact_digest,
       case when s.service_kind='MCP' then array['mcp.initialize','mcp.notifications.initialized','mcp.tools.list','mcp.tools.call']::text[] else array['service.invoke']::text[] end,
       case when s.service_kind='MCP' then array['MCP']::text[] else array['HTTP']::text[] end,
       array['HTTPS']::text[],
       '["AUTHORIZATION","PUBLIC_ENDPOINT","TECHNICAL_DISABLE","MONITORING","AUDIT_CONTINUITY"]'::jsonb,
       r.evidence, r.approved_at, r.created_at
  from managed_service_revision r
  join managed_service s on s.id=r.managed_service_id
 where s.legacy_mcp_server_id is null
on conflict (component_id, revision) do nothing;

update component c
   set active_revision_id=coalesce(
     (select r.id from registration_revision r where r.id=s.active_revision_id),
     (select cr.id from component_revision cr where cr.component_id=c.id order by cr.approved_at desc nulls last, cr.created_at desc limit 1)
   )
  from mcp_server s
 where s.component_id=c.id;

update component c
   set active_revision_id=coalesce(
     (select r.id from managed_service_revision r where r.id=s.active_revision_id),
     (select cr.id from component_revision cr where cr.component_id=c.id order by cr.approved_at desc nulls last, cr.created_at desc limit 1)
   )
  from managed_service s
 where s.component_id=c.id and s.legacy_mcp_server_id is null;

insert into component_audit_stream(component_id)
select id from component
on conflict (component_id) do nothing;

create or replace function component_policy_epoch_sync() returns trigger language plpgsql as $$
begin
  if (new.enabled, new.ingress_enabled, new.pulse_enabled, new.egress_enabled, new.activation_state,
      new.operational_state, new.monitoring_state, new.lifecycle_state)
     is distinct from
     (old.enabled, old.ingress_enabled, old.pulse_enabled, old.egress_enabled, old.activation_state,
      old.operational_state, old.monitoring_state, old.lifecycle_state) then
    new.policy_epoch := old.policy_epoch + 1;
  end if;
  new.updated_at := now();
  return new;
end $$;

create trigger component_policy_epoch_sync_trigger
before update on component for each row execute function component_policy_epoch_sync();

create or replace function component_audit_event_no_update_delete() returns trigger language plpgsql as $$
begin
  raise exception 'component_audit_event is append-only';
end $$;

create trigger component_audit_event_append_only
before update or delete on component_audit_event
for each row execute function component_audit_event_no_update_delete();
