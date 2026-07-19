alter table secret_admin_reveal_grant
  add column if not exists admin_session_id uuid references admin_session(id) on delete cascade,
  add column if not exists purpose text not null default 'admin reveal',
  add column if not exists ui_event_count integer not null default 0 check (ui_event_count >= 0);

create index if not exists secret_admin_reveal_grant_session_live_idx
  on secret_admin_reveal_grant(admin_account_id, admin_session_id, secret_version_id, expires_at)
  where consumed_at is null;
