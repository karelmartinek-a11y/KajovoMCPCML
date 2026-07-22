-- Managed API and compatibility MCP records share the component-assigned
-- identity.  Reconcile pre-catalog hostnames without preserving tokens whose
-- audience was issued for the retired resource.
do $$
declare
  affected record;
  canonical_resource text;
  correlation uuid;
begin
  for affected in
    select service.id,service.component_id,service.code,service.service_kind,
           service.public_hostname,service.resource_uri,component.hostname as canonical_hostname
      from managed_service service
      join component on component.id=service.component_id
     where service.public_hostname is distinct from component.hostname
        or service.resource_uri is distinct from case
             when service.service_kind='MCP' then 'https://' || component.hostname || '/mcp'
             else 'https://' || component.hostname
           end
     order by service.code
     for update of service
  loop
    canonical_resource := case
      when affected.service_kind='MCP' then 'https://' || affected.canonical_hostname || '/mcp'
      else 'https://' || affected.canonical_hostname
    end;
    correlation := gen_random_uuid();

    update access_token legacy
       set revoked_at=coalesce(legacy.revoked_at,now())
     where legacy.revoked_at is null
       and legacy.lookup_digest in (
         select token.legacy_access_token_digest
           from managed_service_access_token token
          where token.managed_service_id=affected.id
            and token.legacy_access_token_digest is not null
       );

    update managed_service_access_token
       set revoked_at=coalesce(revoked_at,now())
     where managed_service_id=affected.id and revoked_at is null;

    update principal_access_token
       set revoked_at=coalesce(revoked_at,now()),
           rotation_reason=coalesce(rotation_reason,'CANONICAL_RESOURCE_MIGRATION')
     where target_component_id=affected.component_id
       and revoked_at is null
       and audience in (
         coalesce(affected.resource_uri,''),
         'https://' || coalesce(affected.public_hostname::text,''),
         'https://' || coalesce(affected.public_hostname::text,'') || '/mcp'
       );

    update managed_service
       set public_hostname=affected.canonical_hostname,
           resource_uri=canonical_resource,
           service_token_epoch=gen_random_uuid(),
           permission_epoch=gen_random_uuid(),
           last_policy_invalidation_at=now(),
           lock_version=lock_version+1,
           updated_at=now()
     where id=affected.id;

    perform append_audit_event(
      'managed_service.identity.canonicalized','migration',null,'managed_service',affected.id::text,
      jsonb_build_object(
        'code',affected.code,
        'publicHostname',affected.public_hostname,
        'resourceUri',affected.resource_uri
      ),
      jsonb_build_object(
        'code',affected.code,
        'publicHostname',affected.canonical_hostname,
        'resourceUri',canonical_resource,
        'priorAudienceTokensRevoked',true
      ),
      correlation
    );
  end loop;
end $$;
