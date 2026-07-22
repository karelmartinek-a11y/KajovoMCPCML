alter table principal_access_token
  add column if not exists key_id text not null default 'v1';
