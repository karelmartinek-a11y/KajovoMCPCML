create table if not exists component_readiness_gate_evidence (
  id uuid primary key default gen_random_uuid(),
  component_id uuid not null references component(id) on delete cascade,
  revision_id uuid not null references component_revision(id) on delete cascade,
  gate_key text not null,
  evaluator_version text not null,
  status text not null check (status in ('PASS','FAIL')),
  reason_code text not null,
  evidence jsonb not null default '{}'::jsonb,
  evidence_digest text not null,
  correlation_id uuid not null,
  executed_at timestamptz not null default now(),
  expires_at timestamptz,
  unique(component_id, revision_id, gate_key, correlation_id)
);

create index if not exists component_readiness_gate_evidence_component_idx
  on component_readiness_gate_evidence(component_id, executed_at desc);

create table if not exists component_e2e_execution_run (
  id uuid primary key default gen_random_uuid(),
  component_id uuid not null references component(id) on delete cascade,
  revision_id uuid not null references component_revision(id) on delete cascade,
  scenario_id uuid not null references component_e2e_scenario(id) on delete cascade,
  onboarding_job_id uuid references component_onboarding_job(id) on delete set null,
  executor_kind text not null default 'component.report' check (executor_kind in ('component.report','kcml.executor')),
  caller_generated_output_digest text,
  computed_output_digest text not null,
  expected_output_digest text not null,
  canonical_output_match boolean not null,
  digest_match boolean not null,
  generated_output jsonb not null,
  correlation_id uuid not null,
  stdout_text text,
  stderr_text text,
  exit_code integer,
  created_at timestamptz not null default now()
);

create index if not exists component_e2e_execution_run_component_idx
  on component_e2e_execution_run(component_id, created_at desc);

create table if not exists component_control_dispatch (
  id uuid primary key default gen_random_uuid(),
  component_id uuid not null references component(id) on delete cascade,
  revision_id uuid not null references component_revision(id) on delete cascade,
  command_contract_id uuid not null references component_control_command(id) on delete cascade,
  command_type text not null check (command_type in ('enable','disable','state','heartbeat')),
  target_hostname citext not null,
  endpoint_path text not null,
  request_body jsonb not null,
  request_digest text not null,
  requested_policy_epoch bigint not null,
  expected_state_key text,
  correlation_id uuid not null,
  causation_id uuid,
  deadline_at timestamptz not null,
  retry_policy jsonb not null default '{}'::jsonb,
  state text not null default 'PENDING' check (state in ('PENDING','SENT','ACK_PENDING','ACKED','STATE_CONFIRMED','HEARTBEAT_CONFIRMED','COMPLETED','FAILED')),
  final_result jsonb,
  final_error_code text,
  attempt_count integer not null default 0 check (attempt_count >= 0),
  last_attempt_at timestamptz,
  ack_digest text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists component_control_dispatch_component_idx
  on component_control_dispatch(component_id, created_at desc);

create index if not exists component_control_dispatch_pending_idx
  on component_control_dispatch(state, deadline_at)
  where state in ('PENDING','SENT','ACK_PENDING','ACKED','STATE_CONFIRMED');

create table if not exists component_control_dispatch_attempt (
  id uuid primary key default gen_random_uuid(),
  dispatch_id uuid not null references component_control_dispatch(id) on delete cascade,
  attempt_number integer not null check (attempt_number > 0),
  status text not null check (status in ('SENT','FAILED','ACKED')),
  request_body jsonb not null,
  response_body jsonb,
  response_digest text,
  error_code text,
  correlation_id uuid not null,
  attempted_at timestamptz not null default now(),
  unique(dispatch_id, attempt_number)
);

create table if not exists component_state_query_run (
  id uuid primary key default gen_random_uuid(),
  component_id uuid not null references component(id) on delete cascade,
  revision_id uuid not null references component_revision(id) on delete cascade,
  dispatch_id uuid references component_control_dispatch(id) on delete cascade,
  requested_state_keys text[] not null default '{}',
  challenge_nonce text not null,
  requested_policy_epoch bigint not null,
  correlation_id uuid not null,
  status text not null default 'PENDING' check (status in ('PENDING','RESPONDED','FAILED')),
  response_state_key text,
  response_digest text,
  response_payload jsonb,
  observed_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists component_state_query_run_component_idx
  on component_state_query_run(component_id, created_at desc);

create table if not exists component_heartbeat_challenge (
  id uuid primary key default gen_random_uuid(),
  component_id uuid not null references component(id) on delete cascade,
  revision_id uuid not null references component_revision(id) on delete cascade,
  dispatch_id uuid references component_control_dispatch(id) on delete cascade,
  challenge_nonce text not null,
  requested_policy_epoch bigint not null,
  correlation_id uuid not null,
  status text not null default 'PENDING' check (status in ('PENDING','RESPONDED','FAILED')),
  response_digest text,
  responded_at timestamptz,
  response_payload jsonb,
  created_at timestamptz not null default now(),
  unique(component_id, challenge_nonce)
);

create index if not exists component_heartbeat_challenge_component_idx
  on component_heartbeat_challenge(component_id, created_at desc);

alter table component_state_observation
  add column if not exists query_run_id uuid references component_state_query_run(id) on delete set null,
  add column if not exists declared_client_id text,
  add column if not exists declared_component_code text,
  add column if not exists policy_epoch bigint;

alter table component_heartbeat
  add column if not exists challenge_id uuid references component_heartbeat_challenge(id) on delete set null,
  add column if not exists challenge_nonce text,
  add column if not exists declared_client_id text,
  add column if not exists declared_component_code text,
  add column if not exists validation_state text not null default 'ACCEPTED' check (validation_state in ('ACCEPTED','REJECTED')),
  add column if not exists rejection_reason text;
