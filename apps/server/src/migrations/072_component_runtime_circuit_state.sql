alter table component_runtime_target
  add column if not exists circuit_failure_count integer not null default 0 check (circuit_failure_count>=0),
  add column if not exists circuit_open_until timestamptz,
  add column if not exists last_dispatch_error text;
