alter table component_external_target
  add column if not exists circuit_state text not null default 'CLOSED' check (circuit_state in ('CLOSED','OPEN','HALF_OPEN')),
  add column if not exists circuit_failure_count integer not null default 0 check (circuit_failure_count >= 0),
  add column if not exists circuit_failure_threshold integer not null default 5 check (circuit_failure_threshold between 1 and 100),
  add column if not exists circuit_open_seconds integer not null default 60 check (circuit_open_seconds between 1 and 3600),
  add column if not exists circuit_opened_at timestamptz,
  add column if not exists circuit_probe_in_flight boolean not null default false;
