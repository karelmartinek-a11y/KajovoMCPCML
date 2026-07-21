alter table component
  drop constraint if exists component_activation_state_check;

alter table component
  add constraint component_activation_state_check
  check (activation_state in ('INACTIVE','READY','READY_FOR_ACTIVATION','ACTIVE','BLOCKED','ENABLE_REQUESTED','DISABLE_REQUESTED','DISABLE_UNCONFIRMED'));

alter table component_onboarding_job
  drop constraint if exists component_onboarding_job_state_check;

alter table component_onboarding_job
  add constraint component_onboarding_job_state_check
  check (state in ('SUBMITTED','IN_REVIEW','GATES_PENDING','READY','READY_FOR_ACTIVATION','BLOCKED','ACTIVE','CANCELLED','FAILED'));

update component_onboarding_job
   set state='BLOCKED'
 where state='GATES_PENDING';
