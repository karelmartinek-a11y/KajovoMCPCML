update component_permission
   set revoked_at=coalesce(revoked_at,now())
 where scope_name='mcp.tools.call' and route_pattern='/mcp' and revoked_at is null;

insert into component_permission(source_component_id,target_component_id,route_pattern,scope_name,access_level,granted_by_type)
select source_component_id,target_component_id,'/mcp/*',scope_name,access_level,granted_by_type
  from component_permission
 where scope_name='mcp.tools.call' and route_pattern='/mcp'
on conflict (source_component_id,target_component_id,route_pattern,scope_name)
do update set revoked_at=null;
