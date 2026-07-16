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

  -- INSERT ... RETURNING id requires SELECT on the returned column.
  execute pg_catalog.format('grant select (id) on table public.audit_event to %I', writer_owner);
end $$;
