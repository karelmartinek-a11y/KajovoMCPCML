create table if not exists component_e2e_fixture (
  id uuid primary key default gen_random_uuid(),
  revision_id uuid not null references component_revision(id) on delete cascade,
  scenario_key text not null, variant_key text not null, input_content bytea not null,
  input_media_type text not null, input_digest text not null,
  expected_content bytea not null, expected_media_type text not null, expected_digest text not null,
  unique(revision_id, scenario_key, variant_key),
  check (input_digest='sha256:' || encode(sha256(input_content), 'hex')),
  check (expected_digest='sha256:' || encode(sha256(expected_content), 'hex'))
);
create table if not exists component_e2e_run (
  id uuid primary key default gen_random_uuid(), component_id uuid not null references component(id),
  revision_id uuid not null references component_revision(id), runtime_digest text not null,
  requested_by_principal_id uuid references principal(id), status text not null default 'QUEUED' check (status in ('QUEUED','RUNNING','PASS','FAIL','CANCELLED')),
  started_at timestamptz, completed_at timestamptz, correlation_id uuid not null default gen_random_uuid()
);
create table if not exists component_e2e_result (
  id uuid primary key default gen_random_uuid(), run_id uuid not null references component_e2e_run(id) on delete cascade,
  fixture_id uuid not null references component_e2e_fixture(id), response_content bytea, response_digest text,
  exact_match boolean not null default false, status text not null check (status in ('PASS','FAIL','ERROR')),
  error_code text, started_at timestamptz not null default now(), completed_at timestamptz
);
