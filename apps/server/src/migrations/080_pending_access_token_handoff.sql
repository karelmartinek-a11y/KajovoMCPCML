alter table component_onboarding_job
  add column if not exists principal_access_token_ciphertext text,
  add column if not exists principal_access_token_key_id text;

alter table component_onboarding_job
  drop constraint if exists component_onboarding_access_token_handoff_check;
alter table component_onboarding_job
  add constraint component_onboarding_access_token_handoff_check check (
    principal_access_token_handed_off_at is null
    or principal_access_token_ciphertext is null
  ) not valid;
alter table component_onboarding_job validate constraint component_onboarding_access_token_handoff_check;
