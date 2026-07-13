alter table mcp_server
  drop constraint if exists mcp_server_hostname_check;

alter table mcp_server
  add constraint mcp_server_hostname_check
  check (hostname ~* '^kcml[0-9]{4,}[.]hcasc[.]cz$');

do $$
begin
  if not exists (select 1 from mcp_server) then
    perform setval('kcml_number_seq', 1, false);
  end if;
end $$;
