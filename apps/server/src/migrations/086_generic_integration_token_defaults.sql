alter table integration_token alter column service_kind set default 'COMPONENT';
alter table integration_token alter column allowed_pipeline set default 'COMPONENT_ONBOARDING';

update integration_token
   set service_kind='COMPONENT', allowed_pipeline='COMPONENT_ONBOARDING'
 where service_kind='MCP'
   and revoked_at is null
   and deleted_at is null;
