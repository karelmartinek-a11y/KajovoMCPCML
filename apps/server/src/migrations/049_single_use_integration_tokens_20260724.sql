alter table integration_token
  drop constraint if exists integration_token_max_expires_release_20260720_check;

alter table integration_token
  drop constraint if exists integration_token_single_use_24h_check;

update integration_token
   set initial_expires_at = least(initial_expires_at, issued_at + interval '24 hours'),
       expires_at = least(expires_at, issued_at + interval '24 hours'),
       max_expires_at = least(max_expires_at, issued_at + interval '24 hours'),
       max_child_jobs = 1,
       lock_version = lock_version + 1
 where max_expires_at > issued_at + interval '24 hours'
    or expires_at > issued_at + interval '24 hours'
    or initial_expires_at > issued_at + interval '24 hours'
    or max_child_jobs <> 1;

update integration_token token
   set revoked_at = coalesce(token.revoked_at, now()),
       lock_version = token.lock_version + 1
 where token.revoked_at is null
   and (
     exists (
       select 1
         from component_onboarding_job job
        where job.integration_token_id = token.id
          and job.credential_id is not null
     )
     or exists (
       select 1
         from onboarding_job job
        where job.token_id = token.id
          and job.state = 'ACTIVE'::onboarding_job_state
     )
   );

update component_credential credential
   set status = 'REVOKED',
       revoked_at = coalesce(credential.revoked_at, now()),
       revocation_epoch = gen_random_uuid()
  from component_onboarding_job job
  join integration_token token on token.id = job.integration_token_id
 where credential.component_id = job.component_id
   and token.expires_at <= now()
   and job.credential_id is null
   and credential.status <> 'REVOKED';

update component component_row
   set enabled = false,
       ingress_enabled = false,
       pulse_enabled = false,
       egress_enabled = false,
       lifecycle_state = 'DEREGISTERED',
       activation_state = 'INACTIVE',
       operational_state = 'RETIRED',
       deregistered_at = coalesce(component_row.deregistered_at, now()),
       lock_version = component_row.lock_version + 1
  from component_onboarding_job job
  join integration_token token on token.id = job.integration_token_id
 where component_row.id = job.component_id
   and token.expires_at <= now()
   and job.credential_id is null;

update component_onboarding_job job
   set state = 'CANCELLED',
       cancelled_at = coalesce(job.cancelled_at, now()),
       credential_claim_digest = null,
       credential_claim_expires_at = null,
       lock_version = job.lock_version + 1,
       updated_at = now()
  from integration_token token
 where token.id = job.integration_token_id
   and token.expires_at <= now()
   and job.credential_id is null
   and job.state not in ('CANCELLED','FAILED');

delete from integration_token_child_job child
 using component_onboarding_job job
 join integration_token token on token.id = job.integration_token_id
 where child.component_onboarding_job_id = job.id
   and token.expires_at <= now()
   and job.credential_id is null;

update onboarding_job job
   set state = 'CANCELLED'::onboarding_job_state,
       completed_at = now(),
       archived_at = coalesce(job.archived_at, now()),
       archive_reason = 'integration_token_expired',
       blocking_error_code = null,
       blocking_error_detail = null,
       lease_owner = null,
       lease_expires_at = null,
       runtime_stopped_at = coalesce(job.runtime_stopped_at, now()),
       lock_version = job.lock_version + 1
  from integration_token token
 where token.id = job.token_id
   and token.expires_at <= now()
   and job.state not in ('ACTIVE','FAILED','QUARANTINED','CANCELLED');

update integration_token token
   set revoked_at = coalesce(token.revoked_at, now()),
       lock_version = lock_version + 1
 where token.expires_at <= now()
   and token.revoked_at is null;

alter table integration_token
  add constraint integration_token_single_use_24h_check
  check (
    initial_expires_at <= expires_at
    and expires_at <= max_expires_at
    and max_expires_at <= issued_at + interval '24 hours'
    and max_child_jobs = 1
  );
