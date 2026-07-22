alter table component_external_principal add column if not exists principal_id uuid references principal(id);

insert into principal(kind,public_id,status,metadata)
select 'EXTERNAL',external.public_id,
       case external.status when 'ACTIVE' then 'ACTIVE' when 'REVOKED' then 'REVOKED' else 'SUSPENDED' end,
       jsonb_build_object('externalPrincipalId',external.id)
  from component_external_principal external
on conflict (public_id) do nothing;

update component_external_principal external set principal_id=principal.id
  from principal where principal.public_id=external.public_id and principal.kind='EXTERNAL' and external.principal_id is null;
alter table component_external_principal alter column principal_id set not null;
create unique index if not exists component_external_principal_canonical_uidx on component_external_principal(principal_id);

create table if not exists principal_component_permission (
  id uuid primary key default gen_random_uuid(),
  source_principal_id uuid not null references principal(id) on delete cascade,
  target_component_id uuid not null references component(id) on delete cascade,
  route_pattern text not null,
  scope_name text not null,
  granted_at timestamptz not null default now(),
  revoked_at timestamptz,
  unique(source_principal_id,target_component_id,route_pattern,scope_name)
);

update component_external_principal_credential set status='REVOKED',revoked_at=coalesce(revoked_at,now()) where status='ACTIVE';
update component_external_access_token set revoked_at=coalesce(revoked_at,now()) where revoked_at is null;
