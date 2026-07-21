-- Canonical principal namespace.  Legacy credential tables remain readable only
-- during the compatibility period; new runtime authorization is principal based.
create table if not exists principal (
  id uuid primary key default gen_random_uuid(),
  kind text not null check (kind in ('COMPONENT','EXTERNAL','PLATFORM','ADMIN_AUTOMATION')),
  public_id citext not null unique,
  status text not null default 'ACTIVE' check (status in ('ACTIVE','SUSPENDED','QUARANTINED','REVOKED')),
  policy_epoch bigint not null default 1 check (policy_epoch > 0),
  revocation_epoch bigint not null default 1 check (revocation_epoch > 0),
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table component add column if not exists principal_id uuid references principal(id);
alter table component add column if not exists kind_metadata text not null default 'generic';

insert into principal(kind, public_id, status, policy_epoch, metadata)
select 'COMPONENT', c.code,
       case when c.lifecycle_state='QUARANTINED' then 'QUARANTINED'
            when c.enabled then 'ACTIVE' else 'SUSPENDED' end,
       greatest(c.policy_epoch, 1), jsonb_build_object('componentId', c.id, 'legacyCategory', c.category)
  from component c
on conflict (public_id) do nothing;

update component c
   set principal_id=p.id
  from principal p
 where p.kind='COMPONENT' and p.public_id=c.code and c.principal_id is null;

alter table component alter column principal_id set not null;
create unique index if not exists component_principal_unique_idx on component(principal_id);

create table if not exists principal_credential (
  id uuid primary key default gen_random_uuid(),
  principal_id uuid not null references principal(id) on delete cascade,
  public_id citext not null unique,
  secret_digest bytea not null unique,
  fingerprint text not null,
  issued_at timestamptz not null default now(),
  expires_at timestamptz,
  revoked_at timestamptz,
  revocation_epoch bigint not null default 1 check (revocation_epoch > 0),
  metadata jsonb not null default '{}'::jsonb
);

insert into principal_credential(principal_id, public_id, secret_digest, fingerprint, issued_at, expires_at, revoked_at, metadata)
select c.principal_id, credential.public_id, credential.secret_digest, credential.secret_fingerprint,
       credential.issued_at, credential.expires_at, credential.revoked_at,
       jsonb_build_object('legacyCredentialId', credential.id, 'keyId', credential.key_id)
  from component_credential credential join component c on c.id=credential.component_id
on conflict (public_id) do nothing;

create table if not exists principal_access_token (
  lookup_digest bytea primary key,
  fingerprint text not null,
  source_principal_id uuid not null references principal(id) on delete cascade,
  target_component_id uuid not null references component(id) on delete cascade,
  audience text not null,
  scope_names text[] not null default '{}',
  issued_policy_epoch bigint not null,
  issued_revocation_epoch bigint not null,
  expires_at timestamptz not null,
  revoked_at timestamptz,
  last_used_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists principal_access_token_target_active_idx on principal_access_token(target_component_id, expires_at desc) where revoked_at is null;
