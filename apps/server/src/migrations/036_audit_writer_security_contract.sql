do $$
declare
  writer_owner name;
begin
  select pg_catalog.pg_get_userbyid(procedure.proowner)
    into writer_owner
    from pg_catalog.pg_proc procedure
   where procedure.oid = 'public.append_audit_event(text,text,text,text,text,jsonb,jsonb,uuid)'::pg_catalog.regprocedure;

  if writer_owner is null then
    raise exception 'audit_writer_owner_missing';
  end if;
  if writer_owner = 'kcml_app' then
    raise exception 'audit_writer_must_not_be_owned_by_application_role';
  end if;

  alter function public.append_audit_event(text,text,text,text,text,jsonb,jsonb,uuid) security definer;
  alter function public.append_audit_event(text,text,text,text,text,jsonb,jsonb,uuid)
    set search_path = pg_catalog, public;
  revoke all on function public.append_audit_event(text,text,text,text,text,jsonb,jsonb,uuid) from public;

  execute pg_catalog.format('grant usage on schema public to %I', writer_owner);
  execute pg_catalog.format('grant insert on table public.audit_event to %I', writer_owner);
  execute pg_catalog.format('grant select (id) on table public.audit_event to %I', writer_owner);
  execute pg_catalog.format('grant select, update on table public.audit_head to %I', writer_owner);
  if pg_catalog.to_regclass('public.audit_event_id_seq') is not null then
    execute pg_catalog.format('grant usage, select on sequence public.audit_event_id_seq to %I', writer_owner);
  end if;
end $$;
