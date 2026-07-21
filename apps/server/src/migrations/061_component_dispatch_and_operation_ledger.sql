create table if not exists component_operation_lease (
  id uuid primary key default gen_random_uuid(),
  source_principal_id uuid not null references principal(id),
  target_component_id uuid not null references component(id),
  operation_kind text not null check (operation_kind in ('TOOL','PULSE','ENDPOINT','CONTROL','E2E')),
  operation_name text not null, input_payload jsonb not null, input_digest text not null,
  output_payload jsonb, output_digest text, process_trace jsonb,
  success boolean, started_at timestamptz not null default now(), finished_at timestamptz,
  expires_at timestamptz not null, correlation_id uuid not null, causation_id uuid, trace_id text,
  token_fingerprint text not null, permission_epoch bigint not null,
  check (input_digest='sha256:' || encode(sha256(convert_to(input_payload::text, 'utf8')), 'hex'))
);
create index if not exists component_operation_lease_target_idx on component_operation_lease(target_component_id, started_at desc);

alter table component_control_dispatch add column if not exists lease_owner text;
alter table component_control_dispatch add column if not exists lease_until timestamptz;
alter table component_control_dispatch add column if not exists next_attempt_at timestamptz not null default now();
alter table component_control_dispatch drop constraint if exists component_control_dispatch_state_check;
alter table component_control_dispatch add constraint component_control_dispatch_state_check check (state in ('QUEUED','CLAIMED','SENT','ACK_PENDING','ACKED','STATE_CONFIRMED','HEARTBEAT_CONFIRMED','SUCCEEDED','FAILED','EXPIRED','PENDING','COMPLETED'));
update component_control_dispatch set state='QUEUED' where state='PENDING';

alter table component_control_dispatch_attempt add column if not exists transport_status text;
alter table component_control_dispatch_attempt add column if not exists request_digest text;
