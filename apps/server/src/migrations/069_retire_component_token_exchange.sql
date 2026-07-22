-- Component access is handed off once by successful onboarding and remains
-- valid until explicit rotation/revocation. Retire the former short-lived
-- client-secret exchange without deleting its rollback-era ledger.
update component_access_token set revoked_at=coalesce(revoked_at,now()) where revoked_at is null;
update component_credential set status='REVOKED',revoked_at=coalesce(revoked_at,now()) where status='ACTIVE';

alter table principal_access_token drop constraint if exists principal_access_token_long_lived_check;
alter table principal_access_token add constraint principal_access_token_long_lived_check
  check (expires_at='infinity'::timestamptz) not valid;
alter table principal_access_token validate constraint principal_access_token_long_lived_check;
