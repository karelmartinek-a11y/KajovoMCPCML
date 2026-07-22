insert into component_tool_contract(
  component_id,revision_id,name,title,description,input_schema,output_schema,annotations,scope_name,
  timeout_ms,limits,idempotency,variants
)
select c.id,c.active_revision_id,s.tool_name,s.display_name,s.description,s.input_schema,s.output_schema,
       jsonb_build_object(
         'readOnlyHint',s.read_only_hint,'destructiveHint',s.destructive_hint,
         'idempotentHint',s.idempotent_hint,'openWorldHint',s.open_world_hint
       ),
       'mcp.tools.call',s.timeout_ms,
       jsonb_build_object('requestMaxBytes',s.request_max_bytes,'responseMaxBytes',s.response_max_bytes,'maxConcurrency',s.max_concurrency),
       jsonb_build_object('effectClass',s.effect_class,'policy',s.idempotency_policy),
       '[]'::jsonb
  from mcp_server s
  join component c on c.id=s.component_id
 where c.active_revision_id is not null
on conflict (component_id,revision_id,name) do nothing;

insert into component_runtime_target(component_id,revision_id,transport,upstream,socket_path,status,runtime_digest)
select c.id,c.active_revision_id,'UDS',s.runtime_socket,s.runtime_socket,
       case when c.enabled then 'HEALTHY' else 'PENDING' end,
       coalesce(s.image_digest,s.artifact_digest,s.manifest_digest)
  from mcp_server s
  join component c on c.id=s.component_id
 where c.active_revision_id is not null and s.runtime_socket is not null
on conflict (component_id,revision_id) do nothing;

insert into component_permission(source_component_id,target_component_id,route_pattern,scope_name,access_level,granted_by_type)
select c.id,c.id,'/mcp',scope_name,'INVOKE','migration'
  from component c
  cross join unnest(array['mcp.initialize','mcp.notifications.initialized','mcp.tools.list']) scope_name
 where c.active_revision_id is not null
on conflict (source_component_id,target_component_id,route_pattern,scope_name) do update set revoked_at=null;

insert into component_permission(source_component_id,target_component_id,route_pattern,scope_name,access_level,granted_by_type)
select contract.component_id,contract.component_id,'/mcp/tools/'||contract.name,'mcp.tools.call','INVOKE','migration'
  from component_tool_contract contract
on conflict (source_component_id,target_component_id,route_pattern,scope_name) do update set revoked_at=null;
