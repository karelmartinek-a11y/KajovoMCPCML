do $$ begin
  create type onboarding_job_state as enum (
    'CREATED','SOURCE_UPLOADED','PR_CREATED','CI_RUNNING','AWAITING_REVISION',
    'MERGED','ARTIFACT_BUILDING','DEPLOYING','REGISTERED_DISABLED',
    'TRIAL_TESTING','ACTIVE','FAILED','QUARANTINED','CANCELLED'
  );
exception when duplicate_object then null; end $$;

create table if not exists integration_token (
  id uuid primary key default gen_random_uuid(),
  label text not null check (char_length(label) between 1 and 120),
  lookup_digest bytea not null unique,
  key_id text not null,
  fingerprint text not null,
  created_by uuid not null references admin_account(id),
  onboarding_job_id uuid,
  issued_at timestamptz not null default now(),
  initial_expires_at timestamptz not null,
  expires_at timestamptz not null,
  max_expires_at timestamptz not null,
  revoked_at timestamptz,
  deleted_at timestamptz,
  last_used_at timestamptz,
  lock_version bigint not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (initial_expires_at <= expires_at),
  check (expires_at <= max_expires_at),
  check (max_expires_at <= issued_at + interval '24 hours')
);

create table if not exists onboarding_job (
  id uuid primary key default gen_random_uuid(),
  token_id uuid not null unique references integration_token(id),
  server_id uuid unique references mcp_server(id),
  kcml_number bigint unique,
  code citext unique,
  hostname citext unique,
  tool_name citext unique,
  state onboarding_job_state not null default 'CREATED',
  correlation_id uuid not null,
  manifest jsonb,
  manifest_digest text,
  source_digest text,
  source_archive_path text,
  source_revision integer not null default 0 check (source_revision >= 0),
  github_branch text,
  github_pr_number bigint,
  github_pr_url text,
  source_commit text,
  build_id text,
  image_reference text,
  image_digest text,
  sbom_digest text,
  provenance_digest text,
  blocking_error_code text,
  blocking_error_detail text,
  lease_owner text,
  lease_expires_at timestamptz,
  heartbeat_at timestamptz,
  token_extended_at timestamptz,
  next_run_at timestamptz not null default now(),
  lock_version bigint not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  completed_at timestamptz,
  runtime_stopped_at timestamptz,
  check (code is null or code ~* '^KCML[0-9]{4,}$'),
  check (hostname is null or hostname ~* '^kcml[0-9]{4,}\.hcasc\.cz$')
);

alter table integration_token
  drop constraint if exists integration_token_onboarding_job_id_fkey;
alter table onboarding_job
  add column if not exists runtime_stopped_at timestamptz;
alter table integration_token
  add constraint integration_token_onboarding_job_id_fkey
  foreign key (onboarding_job_id) references onboarding_job(id);

create index if not exists integration_token_job_idx
  on integration_token(onboarding_job_id, issued_at desc) where onboarding_job_id is not null;
create index if not exists integration_token_created_by_idx on integration_token(created_by, issued_at desc);
create index if not exists integration_token_active_lookup_idx
  on integration_token(lookup_digest, expires_at)
  where revoked_at is null and deleted_at is null;
create index if not exists onboarding_job_runnable_idx
  on onboarding_job(next_run_at, created_at)
  where state not in ('ACTIVE','FAILED','QUARANTINED','CANCELLED');
create index if not exists onboarding_job_server_idx on onboarding_job(server_id);

create table if not exists onboarding_source_revision (
  id uuid primary key default gen_random_uuid(),
  job_id uuid not null references onboarding_job(id) on delete cascade,
  revision integer not null check (revision > 0),
  idempotency_key text not null,
  request_digest text not null,
  source_digest text not null,
  archive_path text not null,
  manifest jsonb not null,
  manifest_digest text not null,
  validation_evidence jsonb not null default '{}',
  created_at timestamptz not null default now(),
  unique(job_id, revision),
  unique(job_id, idempotency_key)
);

create table if not exists onboarding_gate (
  id uuid primary key default gen_random_uuid(),
  job_id uuid not null references onboarding_job(id) on delete cascade,
  gate_name text not null,
  stage text not null,
  status text not null check (status in ('PENDING','RUNNING','PASS','FAIL','QUARANTINED','SKIPPED')),
  evidence jsonb not null default '{}',
  correlation_id uuid not null,
  started_at timestamptz,
  completed_at timestamptz,
  updated_at timestamptz not null default now(),
  unique(job_id, gate_name)
);
create index if not exists onboarding_gate_job_stage_idx on onboarding_gate(job_id, stage, gate_name);

create table if not exists onboarding_event (
  id bigserial primary key,
  job_id uuid not null references onboarding_job(id) on delete cascade,
  from_state onboarding_job_state,
  to_state onboarding_job_state not null,
  event_type text not null,
  detail jsonb not null default '{}',
  correlation_id uuid not null,
  created_at timestamptz not null default now()
);
create index if not exists onboarding_event_job_created_idx on onboarding_event(job_id, created_at, id);

create table if not exists monitoring_profile (
  server_id uuid primary key references mcp_server(id) on delete cascade,
  profile jsonb not null,
  enabled boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists monitoring_probe_result (
  id bigserial primary key,
  server_id uuid not null references mcp_server(id) on delete cascade,
  probe_type text not null,
  status text not null check (status in ('PASS','FAIL','STALE')),
  latency_ms integer,
  evidence jsonb not null default '{}',
  correlation_id uuid not null,
  checked_at timestamptz not null default now()
);
create index if not exists monitoring_probe_server_checked_idx
  on monitoring_probe_result(server_id, probe_type, checked_at desc);

create table if not exists runtime_log_event (
  id bigserial primary key,
  server_id uuid not null references mcp_server(id) on delete cascade,
  level text not null check (level in ('info','warn','error')),
  event_name text not null,
  fields jsonb not null default '{}',
  correlation_id uuid not null,
  image_digest text,
  created_at timestamptz not null default now()
);
create index if not exists runtime_log_server_created_idx on runtime_log_event(server_id, created_at desc);
create index if not exists runtime_log_correlation_idx on runtime_log_event(correlation_id);

create table if not exists function_rate_bucket (
  server_id uuid primary key references mcp_server(id) on delete cascade,
  window_started_at timestamptz not null,
  request_count integer not null check (request_count >= 0)
);

create table if not exists egress_capability (
  lookup_digest bytea primary key,
  fingerprint text not null,
  job_id uuid not null references onboarding_job(id) on delete cascade,
  server_id uuid references mcp_server(id) on delete cascade,
  allowlist jsonb not null,
  issued_at timestamptz not null default now(),
  expires_at timestamptz not null,
  revoked_at timestamptz,
  last_used_at timestamptz
);
create index if not exists egress_capability_job_idx on egress_capability(job_id, expires_at) where revoked_at is null;
create index if not exists egress_capability_server_idx on egress_capability(server_id) where server_id is not null and revoked_at is null;

alter table mcp_server
  add column if not exists image_reference text,
  add column if not exists image_digest text,
  add column if not exists sbom_digest text,
  add column if not exists provenance_digest text,
  add column if not exists runtime_socket text,
  add column if not exists timeout_ms integer not null default 30000 check (timeout_ms between 100 and 60000),
  add column if not exists max_concurrency integer not null default 1 check (max_concurrency between 1 and 32),
  add column if not exists request_max_bytes integer not null default 1048576 check (request_max_bytes between 1 and 1048576),
  add column if not exists response_max_bytes integer not null default 5242880 check (response_max_bytes between 1 and 5242880);
alter table mcp_server
  add column if not exists rate_window_seconds integer not null default 60 check (rate_window_seconds between 1 and 86400),
  add column if not exists rate_max_requests integer not null default 60 check (rate_max_requests between 1 and 100000);

drop trigger if exists integration_token_updated_at on integration_token;
create trigger integration_token_updated_at before update on integration_token
for each row execute function set_updated_at();

drop trigger if exists onboarding_job_updated_at on onboarding_job;
create trigger onboarding_job_updated_at before update on onboarding_job
for each row execute function set_updated_at();

drop trigger if exists monitoring_profile_updated_at on monitoring_profile;
create trigger monitoring_profile_updated_at before update on monitoring_profile
for each row execute function set_updated_at();
