alter table kaja_credential
  add column if not exists principal_token_epoch uuid not null default gen_random_uuid();

alter table managed_service
  add column if not exists environment text not null default 'production',
  add column if not exists service_token_epoch uuid not null default gen_random_uuid(),
  add column if not exists permission_epoch uuid not null default gen_random_uuid(),
  add column if not exists active_revision_epoch bigint not null default 0,
  add column if not exists last_policy_invalidation_at timestamptz;

alter table managed_service_permission
  add column if not exists state text not null default 'GRANTED',
  add column if not exists valid_from timestamptz not null default now(),
  add column if not exists valid_to timestamptz,
  add column if not exists permission_version bigint not null default 0,
  add column if not exists audit_metadata jsonb not null default '{}'::jsonb;

alter table managed_service_access_token
  add column if not exists environment text not null default 'production',
  add column if not exists principal_token_epoch uuid,
  add column if not exists service_token_epoch uuid,
  add column if not exists permission_epoch_snapshot uuid,
  add column if not exists active_revision_epoch_snapshot bigint not null default 0;

update managed_service_access_token token
   set principal_token_epoch = kc.principal_token_epoch,
       service_token_epoch = ms.service_token_epoch,
       permission_epoch_snapshot = ms.permission_epoch,
       active_revision_epoch_snapshot = ms.active_revision_epoch,
       environment = ms.environment
  from kaja_credential kc,
       managed_service ms
 where kc.id = token.credential_id
   and ms.id = token.managed_service_id
   and (
     token.principal_token_epoch is null
     or token.service_token_epoch is null
     or token.permission_epoch_snapshot is null
   );

alter table managed_service_access_token
  alter column principal_token_epoch set not null,
  alter column service_token_epoch set not null,
  alter column permission_epoch_snapshot set not null;

alter table integration_token
  add column if not exists service_kind managed_service_kind not null default 'MCP',
  add column if not exists allowed_pipeline service_pipeline_kind not null default 'MCP_ONBOARDING',
  add column if not exists usage_count integer not null default 0;

alter table onboarding_job
  add column if not exists service_kind managed_service_kind not null default 'MCP';

create table if not exists managed_service_api_status_history (
  id bigserial primary key,
  managed_service_id uuid not null references managed_service(id) on delete cascade,
  previous_state managed_service_api_state,
  current_state managed_service_api_state not null,
  reason text,
  actor_type text not null,
  actor_id text,
  lock_version bigint not null,
  correlation_id uuid,
  decision_id uuid not null,
  created_at timestamptz not null default now()
);

create index if not exists managed_service_api_status_history_service_created_idx
  on managed_service_api_status_history(managed_service_id, created_at desc);

create table if not exists managed_service_policy_event (
  id bigserial primary key,
  managed_service_id uuid not null references managed_service(id) on delete cascade,
  event_type text not null,
  correlation_id uuid not null,
  detail jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists managed_service_policy_event_service_created_idx
  on managed_service_policy_event(managed_service_id, created_at desc);
