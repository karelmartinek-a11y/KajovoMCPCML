alter table kaja_credential
  add column if not exists label text not null default 'Bez označení';

alter table kaja_credential
  add column if not exists updated_at timestamptz not null default now();

update kaja_credential
set label = public_id
where label = 'Bez označení';
