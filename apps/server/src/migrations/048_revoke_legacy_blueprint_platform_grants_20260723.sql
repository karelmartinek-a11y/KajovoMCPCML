create temporary table kcml_invalid_blueprint_release_token as
select distinct token.id
  from integration_token token
  join (
    select token_id, blueprint_component_id, release_version, release_wave_key
      from integration_token_allowed_component
    union all
    select token_id, blueprint_component_id, release_version, release_wave_key
      from integration_token_child_job
  ) grant_row on grant_row.token_id = token.id
  left join release_wave_component component
    on component.release_version = grant_row.release_version
   and component.wave_key = grant_row.release_wave_key
   and component.blueprint_component_id = grant_row.blueprint_component_id
 where token.token_kind = 'BLUEPRINT_RELEASE'::integration_token_kind
   and component.category is distinct from 'AI_AGENT'
   and component.category is distinct from 'MCP_SERVER';

update integration_token token
   set revoked_at = coalesce(token.revoked_at, now()),
       lock_version = token.lock_version + case when token.revoked_at is null then 1 else 0 end
 where token.id in (select id from kcml_invalid_blueprint_release_token)
   and token.revoked_at is null;

delete from integration_token_allowed_component grant_row
 using integration_token token
 where token.id = grant_row.token_id
   and token.token_kind = 'BLUEPRINT_RELEASE'::integration_token_kind
   and not exists (
     select 1
       from release_wave_component component
      where component.release_version = grant_row.release_version
        and component.wave_key = grant_row.release_wave_key
        and component.blueprint_component_id = grant_row.blueprint_component_id
        and component.category in ('AI_AGENT', 'MCP_SERVER')
   );

drop table kcml_invalid_blueprint_release_token;

