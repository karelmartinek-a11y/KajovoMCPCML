alter table integration_token
  drop constraint if exists integration_token_max_child_jobs_check;

update integration_token
   set max_child_jobs = 20,
       revoked_at = case
         when token_kind = 'BLUEPRINT_RELEASE'::integration_token_kind
          and onboarding_job_id is not null
          and revoked_at is null
         then now()
         else revoked_at
       end,
       lock_version = lock_version + 1
 where token_kind = 'BLUEPRINT_RELEASE'::integration_token_kind
   and max_child_jobs > 20;

alter table integration_token
  add constraint integration_token_max_child_jobs_check
  check (
    max_child_jobs between 1 and 200
    and (
      token_kind <> 'BLUEPRINT_RELEASE'::integration_token_kind
      or max_child_jobs between 1 and 20
    )
  );

create or replace function kcml_enforce_blueprint_release_generated_scope() returns trigger
language plpgsql
as $$
declare
  parent_token_kind text;
  component_category text;
begin
  select token_kind::text
    into parent_token_kind
    from integration_token
   where id = new.token_id;

  if parent_token_kind <> 'BLUEPRINT_RELEASE' then
    return new;
  end if;

  select category
    into component_category
    from release_wave_component
   where release_version = new.release_version
     and wave_key = new.release_wave_key
     and blueprint_component_id = new.blueprint_component_id;

  if component_category is distinct from 'AI_AGENT' and component_category is distinct from 'MCP_SERVER' then
    raise exception 'platform_prerequisite_not_allowed:%', new.blueprint_component_id
      using errcode = '23514';
  end if;

  return new;
end;
$$;

drop trigger if exists integration_token_allowed_component_generated_scope_tg on integration_token_allowed_component;
create trigger integration_token_allowed_component_generated_scope_tg
before insert or update on integration_token_allowed_component
for each row execute function kcml_enforce_blueprint_release_generated_scope();

create or replace function kcml_enforce_blueprint_release_child_job_scope() returns trigger
language plpgsql
as $$
declare
  parent_token_kind text;
  component_category text;
begin
  select token_kind::text
    into parent_token_kind
    from integration_token
   where id = new.token_id;

  if parent_token_kind <> 'BLUEPRINT_RELEASE' then
    return new;
  end if;

  select category
    into component_category
    from release_wave_component
   where release_version = new.release_version
     and wave_key = new.release_wave_key
     and blueprint_component_id = new.blueprint_component_id;

  if component_category is distinct from 'AI_AGENT' and component_category is distinct from 'MCP_SERVER' then
    raise exception 'platform_prerequisite_child_job_not_allowed:%', new.blueprint_component_id
      using errcode = '23514';
  end if;

  return new;
end;
$$;

drop trigger if exists integration_token_child_job_generated_scope_tg on integration_token_child_job;
create trigger integration_token_child_job_generated_scope_tg
before insert or update on integration_token_child_job
for each row execute function kcml_enforce_blueprint_release_child_job_scope();
