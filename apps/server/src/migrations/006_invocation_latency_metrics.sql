create table if not exists mcp_invocation_metric (
  id bigserial primary key,
  server_id uuid not null references mcp_server(id),
  success boolean not null,
  latency_ms integer not null check (latency_ms >= 0),
  classification text,
  correlation_id uuid not null,
  created_at timestamptz not null default now()
);

create index if not exists mcp_invocation_metric_server_created_idx
  on mcp_invocation_metric(server_id, created_at desc);
