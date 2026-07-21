-- New writes use component/principal contracts.  Keep legacy tables readable for
-- upgrade rollback, but remove their write-time identity bridges and allowlists.
drop trigger if exists mcp_server_component_identity_bridge on mcp_server;
drop trigger if exists managed_service_component_identity_bridge on managed_service;
drop trigger if exists integration_token_allowed_component_generated_scope_tg on integration_token_allowed_component;
drop trigger if exists integration_token_child_job_generated_scope_tg on integration_token_child_job;
drop trigger if exists integration_token_allowed_component_release_scope on integration_token_allowed_component;
drop trigger if exists integration_token_child_job_release_scope on integration_token_child_job;
drop function if exists ensure_mcp_server_component_identity();
drop function if exists ensure_managed_service_component_identity();
drop function if exists kcml_enforce_blueprint_release_generated_scope();
drop function if exists kcml_enforce_blueprint_release_child_job_scope();

alter table component drop constraint if exists component_hostname_kajovocml_suffix_check;
alter table component add constraint component_hostname_kajovocml_suffix_check
  check (hostname ~* ('^' || lower(code::text) || '[.]kajovocml[.]hcasc[.]cz$')) not valid;

create or replace view legacy_component_runtime_adapter as
select c.id as component_id, c.code, c.hostname, c.active_revision_id, c.enabled,
       p.status as principal_status
  from component c join principal p on p.id=c.principal_id;
