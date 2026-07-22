-- Generic contracts are intentionally independent of component kind and runtime language.
create table if not exists component_tool_contract (
  id uuid primary key default gen_random_uuid(),
  component_id uuid not null references component(id) on delete cascade,
  revision_id uuid not null references component_revision(id) on delete cascade,
  name text not null, title text not null, description text not null,
  input_schema jsonb not null, output_schema jsonb not null,
  annotations jsonb not null default '{}'::jsonb, scope_name text not null,
  timeout_ms integer not null check (timeout_ms between 1 and 60000),
  limits jsonb not null default '{}'::jsonb, idempotency jsonb not null default '{}'::jsonb,
  variants jsonb not null default '[]'::jsonb,
  unique(component_id, revision_id, name),
  check (jsonb_typeof(input_schema)='object' and jsonb_typeof(output_schema)='object')
);

create table if not exists component_runtime_target (
  id uuid primary key default gen_random_uuid(),
  component_id uuid not null references component(id) on delete cascade,
  revision_id uuid not null references component_revision(id) on delete cascade,
  transport text not null check (transport in ('UDS','HTTPS')),
  upstream text not null, expected_tls_identity text, socket_path text,
  status text not null default 'PENDING' check (status in ('PENDING','HEALTHY','UNHEALTHY','DISABLED')),
  last_probe_at timestamptz, runtime_digest text not null,
  unique(component_id, revision_id),
  check ((transport='UDS' and socket_path is not null and expected_tls_identity is null)
      or (transport='HTTPS' and expected_tls_identity is not null and socket_path is null))
);

create table if not exists component_document_blob (
  id uuid primary key default gen_random_uuid(),
  component_id uuid not null references component(id) on delete cascade,
  revision_id uuid not null references component_revision(id) on delete cascade,
  evidence_key text not null, media_type text not null, content bytea not null,
  digest text not null, size_bytes integer not null check (size_bytes >= 0),
  created_at timestamptz not null default now(),
  unique(component_id, revision_id, evidence_key), unique(revision_id, digest),
  check (digest='sha256:' || encode(sha256(content), 'hex')),
  check (size_bytes=octet_length(content))
);
