create or replace function ensure_mcp_server_component_identity()
returns trigger
language plpgsql
as $$
declare
  existing_component_id uuid;
begin
  if new.component_id is null then
    select id into existing_component_id
      from component
     where code=new.code or kcml_number=new.kcml_number
     order by case when code=new.code then 0 else 1 end
     limit 1;
    new.component_id := coalesce(existing_component_id, new.id);
  end if;

  insert into component(
    id, kcml_number, code, hostname, display_name, description, category, registration_type, component_role,
    lifecycle_state, activation_state, operational_state, monitoring_state,
    enabled, ingress_enabled, pulse_enabled, egress_enabled, revocation_epoch, release_version, lock_version
  )
  values (
    new.component_id,
    new.kcml_number,
    new.code,
    new.hostname,
    new.display_name,
    coalesce(new.description, ''),
    'MCP_SERVER',
    'MCP_SERVER',
    'SERVICE',
    case new.registration_state::text
      when 'ACTIVE' then 'ACTIVE'
      when 'TRIAL' then 'ACTIVE'
      when 'QUARANTINED' then 'QUARANTINED'
      when 'RETIRED' then 'RETIRED'
      when 'SUSPENDED' then 'SUSPENDED'
      when 'APPROVED' then 'APPROVED'
      else 'DRAFT'
    end,
    case when new.enabled then 'ACTIVE' when new.registration_state::text in ('APPROVED','REGISTERED_DISABLED') then 'READY' else 'INACTIVE' end,
    coalesce(new.operational_state::text, 'UNKNOWN'),
    'NOT_CONFIGURED',
    new.enabled,
    new.enabled,
    new.enabled,
    new.enabled,
    coalesce(new.revocation_epoch, gen_random_uuid()),
    coalesce(new.release_version, '2026.07.22'),
    coalesce(new.lock_version, 0)
  )
  on conflict (id) do nothing;

  return new;
end;
$$;

drop trigger if exists mcp_server_component_identity_bridge on mcp_server;
create trigger mcp_server_component_identity_bridge
before insert on mcp_server
for each row
execute function ensure_mcp_server_component_identity();

create or replace function ensure_managed_service_component_identity()
returns trigger
language plpgsql
as $$
declare
  resolved_component_id uuid;
  resolved_kcml_number bigint;
begin
  if new.component_id is null and new.legacy_mcp_server_id is not null then
    select component_id into resolved_component_id
      from mcp_server
     where id=new.legacy_mcp_server_id;
  end if;

  if new.component_id is null and new.legacy_mcp_server_id is null then
    select id into resolved_component_id
      from component
     where code=new.code
        or kcml_number=nullif(regexp_replace(new.code::text, '[^0-9]', '', 'g'), '')::bigint
     order by case when code=new.code then 0 else 1 end
     limit 1;
  end if;
  resolved_component_id := coalesce(new.component_id, resolved_component_id, new.legacy_mcp_server_id, new.id);
  new.component_id := resolved_component_id;

  if not exists (select 1 from component where id=resolved_component_id) then
    resolved_kcml_number := nullif(regexp_replace(new.code::text, '[^0-9]', '', 'g'), '')::bigint;
    if resolved_kcml_number is null then
      resolved_kcml_number := nextval('kcml_number_seq');
    end if;

    insert into component(
      id, kcml_number, code, hostname, display_name, description, category, registration_type, component_role,
      owners, contacts, lifecycle_state, activation_state, operational_state, monitoring_state,
      enabled, ingress_enabled, pulse_enabled, egress_enabled, revocation_epoch, release_version, lock_version
    )
    values (
      resolved_component_id,
      resolved_kcml_number,
      new.code,
      coalesce(new.public_hostname, (lower(new.code::text) || '.hcasc.cz')::citext),
      new.display_name,
      coalesce(new.description, ''),
      case when new.service_kind='MCP' then 'MCP_SERVER' else 'EXTERNAL_SERVICE' end,
      case when new.service_kind='MCP' then 'MCP_SERVER' else 'MANAGED_PLATFORM_SERVICE' end,
      'SERVICE',
      coalesce(new.owners, '{}'::jsonb),
      coalesce(new.contacts, '{}'::jsonb),
      case new.lifecycle_state::text
        when 'ACTIVE' then 'ACTIVE'
        when 'TRIAL' then 'ACTIVE'
        when 'QUARANTINED' then 'QUARANTINED'
        when 'RETIRED' then 'RETIRED'
        when 'SUSPENDED' then 'SUSPENDED'
        else 'DRAFT'
      end,
      case when new.enabled then 'ACTIVE' when new.lifecycle_state::text='REGISTERED_DISABLED' then 'READY' else 'INACTIVE' end,
      coalesce(new.operational_state::text, 'UNKNOWN'),
      case when coalesce(new.monitoring_enabled, false) then 'PENDING' else 'NOT_CONFIGURED' end,
      new.enabled,
      new.enabled and coalesce(new.api_state::text, 'DISABLED')='ENABLED',
      new.enabled,
      new.enabled,
      coalesce(new.revocation_epoch, gen_random_uuid()),
      '2026.07.22',
      coalesce(new.lock_version, 0)
    )
    on conflict (id) do nothing;
  end if;

  return new;
end;
$$;

drop trigger if exists managed_service_component_identity_bridge on managed_service;
create trigger managed_service_component_identity_bridge
before insert on managed_service
for each row
execute function ensure_managed_service_component_identity();
