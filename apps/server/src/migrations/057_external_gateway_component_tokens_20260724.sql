alter table component_external_access_token
  alter column credential_id drop not null,
  alter column external_principal_id drop not null,
  add column if not exists source_component_id uuid references component(id) on delete cascade;

alter table component_external_access_token
  drop constraint if exists component_external_access_token_subject_check;

alter table component_external_access_token
  add constraint component_external_access_token_subject_check
  check ((external_principal_id is not null and source_component_id is null) or (external_principal_id is null and source_component_id is not null));

create index if not exists component_external_access_token_component_idx
  on component_external_access_token(source_component_id, external_target_id, expires_at desc)
  where source_component_id is not null;
