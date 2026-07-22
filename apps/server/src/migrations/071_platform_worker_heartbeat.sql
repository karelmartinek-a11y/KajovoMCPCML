create table if not exists platform_worker_heartbeat (
  worker_kind text primary key check (worker_kind in ('COMPONENT_CONTROL','COMPONENT_E2E')),
  worker_id text not null,
  build_id text not null,
  started_at timestamptz not null,
  last_heartbeat_at timestamptz not null,
  last_completed_at timestamptz,
  last_error text,
  updated_at timestamptz not null default now()
);

revoke all on platform_worker_heartbeat from public;
