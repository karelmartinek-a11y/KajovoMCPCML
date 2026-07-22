-- E2E probes execute the same internal runtime routes as production dispatch.
-- Replace the retired private E2E endpoint grant with the constrained runtime route family.
update principal_component_permission
   set revoked_at=coalesce(revoked_at,now())
 where scope_name='platform.e2e.execute'
   and route_pattern='/v1/kcml/runtime/e2e';

insert into principal_component_permission(source_principal_id,target_component_id,route_pattern,scope_name)
select permission.source_principal_id,permission.target_component_id,'/v1/kcml/runtime/*',permission.scope_name
  from principal_component_permission permission
 where permission.scope_name='platform.e2e.execute'
on conflict (source_principal_id,target_component_id,route_pattern,scope_name)
do update set revoked_at=null;
