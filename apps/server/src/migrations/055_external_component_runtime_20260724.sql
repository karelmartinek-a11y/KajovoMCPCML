create table if not exists component_external_principal_credential (
  id uuid primary key default gen_random_uuid(),
  external_principal_id uuid not null references component_external_principal(id) on delete cascade,
  public_id citext not null unique,
  key_id text not null,
  secret_digest bytea not null,
  secret_fingerprint text not null,
  status text not null default 'ACTIVE' check (status in ('ACTIVE','REVOKED')),
  revocation_epoch uuid not null default gen_random_uuid(),
  issued_at timestamptz not null default now(),
  expires_at timestamptz,
  last_used_at timestamptz,
  revoked_at timestamptz
);

create index if not exists component_external_principal_credential_principal_idx
  on component_external_principal_credential(external_principal_id, issued_at desc);

create table if not exists component_external_access_token (
  id uuid primary key default gen_random_uuid(),
  lookup_digest bytea not null unique,
  key_id text not null,
  fingerprint text not null,
  credential_id uuid not null references component_external_principal_credential(id) on delete cascade,
  external_principal_id uuid not null references component_external_principal(id) on delete cascade,
  external_target_id uuid not null references component_external_target(id) on delete cascade,
  audience text not null,
  scope_names text[] not null,
  expires_at timestamptz not null,
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  last_used_at timestamptz
);

create table if not exists component_external_gateway_call (
  id uuid primary key default gen_random_uuid(),
  source_component_id uuid not null references component(id) on delete restrict,
  external_target_id uuid not null references component_external_target(id) on delete restrict,
  external_permission_id uuid not null references component_external_permission(id) on delete restrict,
  route_path text not null,
  scope_name text not null,
  correlation_id uuid not null,
  request_digest text not null,
  response_digest text,
  request_payload jsonb not null,
  response_payload jsonb,
  status text not null check (status in ('PENDING','SUCCEEDED','FAILED','BLOCKED')),
  http_status integer,
  error_code text,
  attempt_count integer not null default 0,
  created_at timestamptz not null default now(),
  completed_at timestamptz
);

create index if not exists component_external_gateway_call_target_idx
  on component_external_gateway_call(external_target_id, created_at desc);

alter table component_external_target
  add column if not exists allowed_path_prefixes text[] not null default '{/}',
  add column if not exists connect_timeout_ms integer not null default 5000 check (connect_timeout_ms between 100 and 30000),
  add column if not exists request_timeout_ms integer not null default 15000 check (request_timeout_ms between 100 and 60000),
  add column if not exists max_retries integer not null default 1 check (max_retries between 0 and 3),
  add column if not exists tls_required boolean not null default true;
