-- KCML exposes exactly two bearer-token classes: a 24-hour integration token
-- and a long-lived principal access token.  Access authorization is resolved
-- from current permissions at use time, so a token is not audience-bound.
alter table principal_access_token
  alter column target_component_id drop not null;

alter table component_onboarding_job
  add column if not exists principal_access_token_digest bytea,
  add column if not exists principal_access_token_fingerprint text,
  add column if not exists principal_access_token_handed_off_at timestamptz;

create unique index if not exists component_onboarding_principal_access_token_digest_uidx
  on component_onboarding_job(principal_access_token_digest)
  where principal_access_token_digest is not null;

alter table principal_access_token
  add column if not exists handed_off_at timestamptz not null default now(),
  add column if not exists rotated_at timestamptz,
  add column if not exists rotation_reason text;
