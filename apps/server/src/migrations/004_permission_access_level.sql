alter table kaja_permission
  add column if not exists access_level text not null default 'EXECUTE';

alter table kaja_permission
  drop constraint if exists kaja_permission_access_level_check;

alter table kaja_permission
  add constraint kaja_permission_access_level_check
  check (access_level in ('READ','EXECUTE','MANAGE'));
