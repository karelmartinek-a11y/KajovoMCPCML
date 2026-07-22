alter table component add column if not exists activated_at timestamptz;
update component set activated_at=coalesce(activated_at,updated_at,created_at)
 where lifecycle_state='ACTIVE' and enabled=true
   and hostname ~* ('^' || lower(code::text) || '[.]kajovocml[.]hcasc[.]cz$');
