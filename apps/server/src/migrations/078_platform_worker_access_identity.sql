insert into principal(kind,public_id,status,policy_epoch,revocation_epoch,metadata)
values ('PLATFORM','KCML-PLATFORM-WORKER','ACTIVE',1,1,'{"managedBy":"KCML","purpose":"control-and-e2e-workers"}'::jsonb)
on conflict (public_id) do update set kind='PLATFORM',status='ACTIVE',updated_at=now();

create table if not exists platform_worker_access_identity (
  singleton boolean primary key default true check (singleton),
  principal_id uuid not null unique references principal(id),
  access_token_id uuid references principal_access_token(id),
  token_ciphertext text,
  key_id text,
  fingerprint text,
  rotated_by uuid references admin_account(id),
  rotated_at timestamptz,
  updated_at timestamptz not null default now(),
  check ((access_token_id is null and token_ciphertext is null and key_id is null and fingerprint is null)
      or (access_token_id is not null and token_ciphertext is not null and key_id is not null and fingerprint is not null))
);

insert into platform_worker_access_identity(singleton,principal_id)
select true,id from principal where public_id='KCML-PLATFORM-WORKER'
on conflict (singleton) do nothing;

create index if not exists platform_worker_access_token_idx
  on platform_worker_access_identity(access_token_id) where access_token_id is not null;
