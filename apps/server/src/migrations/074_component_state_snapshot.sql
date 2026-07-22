create table if not exists component_state_snapshot (
  id uuid primary key default gen_random_uuid(),
  component_id uuid not null references component(id) on delete cascade,
  revision_id uuid not null references component_revision(id) on delete cascade,
  query_run_id uuid references component_state_query_run(id) on delete set null,
  observed_at timestamptz not null,
  states jsonb not null check (jsonb_typeof(states)='object'),
  state_digest text not null,
  validation_state text not null check (validation_state in ('ACCEPTED','REJECTED')),
  rejection_reason text,
  correlation_id uuid not null,
  received_at timestamptz not null default now()
);
create index if not exists component_state_snapshot_component_idx
  on component_state_snapshot(component_id,observed_at desc);
