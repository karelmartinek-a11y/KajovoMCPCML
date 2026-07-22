-- Integration tokens exist only to drive one onboarding registration. They
-- must never become a durable runtime identity or receive managed secrets.
update secret_grant
   set revoked_at=coalesce(revoked_at, now())
 where principal_kind='INTEGRATION_TOKEN'
   and revoked_at is null;

alter table secret_grant
  drop constraint if exists secret_grant_principal_kind_check;

alter table secret_grant
  add constraint secret_grant_principal_kind_check
  check (principal_kind in ('KAJA','COMPONENT')) not valid;

alter table secret_grant
  validate constraint secret_grant_principal_kind_check;
