alter table kaja_credential
  add column if not exists expires_at timestamptz,
  add column if not exists updated_at timestamptz not null default now();

update kaja_credential
   set updated_at = coalesce(updated_at, created_at, now());

create or replace function set_updated_at() returns trigger language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end $$;

drop trigger if exists kaja_credential_updated_at on kaja_credential;
create trigger kaja_credential_updated_at
before update on kaja_credential
for each row execute function set_updated_at();
