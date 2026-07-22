-- Give long-lived access tokens a stable administrative identifier without
-- exposing their lookup digest. Token material remains one-way HMAC protected.
alter table principal_access_token
  add column if not exists id uuid default gen_random_uuid();

update principal_access_token set id=gen_random_uuid() where id is null;

alter table principal_access_token alter column id set not null;
create unique index if not exists principal_access_token_id_uidx on principal_access_token(id);
