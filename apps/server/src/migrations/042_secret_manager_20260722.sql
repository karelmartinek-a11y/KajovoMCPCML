insert into release_epoch(
  release_version, blueprint_version, catalog_version, manifest_schema_version,
  pulse_envelope_version, policy_baseline, mcp_protocol_version, sealed_previous_epoch_hash
)
values (
  '2026.07.22', '2026.07.22', '2026.07.22', '2026.07.22',
  '2026.07.22', date '2026-07-22', '2025-11-25',
  encode(sha256(coalesce((select event_hash::text from audit_head where singleton is true), '')::bytea), 'hex')
)
on conflict (release_version) do nothing;

create table secret_record (
  id uuid primary key default gen_random_uuid(),
  stable_name citext not null unique,
  display_name text not null,
  description text not null default '',
  owner_kind text not null default 'PLATFORM' check (owner_kind in ('PLATFORM','COMPONENT','MANAGED_SERVICE','KAJA')),
  owner_id uuid,
  status text not null default 'ACTIVE' check (status in ('ACTIVE','DISABLED','DELETED')),
  active_version_id uuid,
  lock_version bigint not null default 0 check (lock_version >= 0),
  created_by uuid references admin_account(id) on delete set null,
  updated_by uuid references admin_account(id) on delete set null,
  deleted_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (stable_name ~ '^[A-Z][A-Z0-9_]{2,127}$'),
  check ((status='DELETED') = (deleted_at is not null))
);

create table secret_version (
  id uuid primary key default gen_random_uuid(),
  secret_id uuid not null references secret_record(id) on delete cascade,
  version_number integer not null check (version_number > 0),
  ciphertext text not null,
  key_id text not null,
  algorithm text not null default 'AES-256-GCM',
  fingerprint text not null,
  created_by uuid references admin_account(id) on delete set null,
  created_at timestamptz not null default now(),
  activated_at timestamptz,
  retired_at timestamptz,
  unique(secret_id, version_number)
);

alter table secret_record
  add constraint secret_record_active_version_fkey
  foreign key (active_version_id) references secret_version(id)
  deferrable initially deferred;

create table secret_grant (
  id uuid primary key default gen_random_uuid(),
  secret_id uuid not null references secret_record(id) on delete cascade,
  principal_kind text not null check (principal_kind in ('KAJA','COMPONENT','INTEGRATION_TOKEN')),
  principal_id uuid,
  principal_public_id citext,
  granted_at timestamptz not null default now(),
  granted_by uuid references admin_account(id) on delete set null,
  revoked_at timestamptz,
  revoked_by uuid references admin_account(id) on delete set null,
  metadata jsonb not null default '{}'::jsonb,
  check (principal_id is not null or principal_public_id is not null)
);

create unique index secret_grant_current_identity_idx
  on secret_grant(secret_id, principal_kind, coalesce(principal_id::text, ''), coalesce(principal_public_id::text, ''))
  where revoked_at is null;

create table secret_admin_reveal_grant (
  id uuid primary key default gen_random_uuid(),
  secret_version_id uuid not null references secret_version(id) on delete cascade,
  admin_account_id uuid not null references admin_account(id) on delete cascade,
  correlation_id uuid not null,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now(),
  check (expires_at > created_at)
);

create index secret_admin_reveal_grant_live_idx
  on secret_admin_reveal_grant(admin_account_id, secret_version_id, expires_at)
  where consumed_at is null;

create table secret_api_rate_limit (
  bucket_key bytea primary key,
  window_started_at timestamptz not null,
  request_count integer not null check (request_count >= 0),
  updated_at timestamptz not null default now()
);

create table secret_resolve_idempotency (
  principal_kind text not null,
  principal_identity text not null,
  idempotency_key text not null,
  request_digest text not null,
  response_digest text not null,
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  primary key(principal_kind, principal_identity, idempotency_key)
);

create index secret_record_status_idx on secret_record(status, updated_at desc);
create index secret_version_secret_created_idx on secret_version(secret_id, created_at desc);
create index secret_grant_principal_idx on secret_grant(principal_kind, principal_id, principal_public_id) where revoked_at is null;
