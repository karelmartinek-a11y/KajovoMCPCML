alter table operational_alert
  add column if not exists managed_service_id uuid references managed_service(id) on delete cascade;

drop index if exists operational_alert_active_unique_idx;

create unique index if not exists operational_alert_active_unique_idx
  on operational_alert(
    coalesce(server_id, '00000000-0000-0000-0000-000000000000'::uuid),
    coalesce(managed_service_id, '00000000-0000-0000-0000-000000000000'::uuid),
    alert_type
  )
  where status in ('OPEN','ACKNOWLEDGED','SUPPRESSED');

create index if not exists operational_alert_managed_service_status_idx
  on operational_alert(managed_service_id, status, severity, last_seen_at desc)
  where managed_service_id is not null;
