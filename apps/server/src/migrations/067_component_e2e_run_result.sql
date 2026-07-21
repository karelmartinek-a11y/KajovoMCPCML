-- The historical component_e2e_result table is scenario-oriented. Keep it
-- immutable and add the canonical KCML-executed result ledger without a name
-- collision.
create table if not exists component_e2e_run_result (
  id uuid primary key default gen_random_uuid(),
  run_id uuid not null references component_e2e_run(id) on delete cascade,
  fixture_id uuid not null references component_e2e_fixture(id),
  response_content bytea,
  response_digest text,
  exact_match boolean not null default false,
  status text not null check (status in ('PASS','FAIL','ERROR')),
  error_code text,
  started_at timestamptz not null default now(),
  completed_at timestamptz,
  unique(run_id, fixture_id)
);

create index if not exists component_e2e_run_result_run_idx
  on component_e2e_run_result(run_id, started_at);
