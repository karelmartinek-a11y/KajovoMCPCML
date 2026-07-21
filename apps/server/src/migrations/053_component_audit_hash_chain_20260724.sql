alter table component_audit_stream
  add column if not exists current_event_hash text,
  add column if not exists integrity_state text not null default 'VALID' check (integrity_state in ('VALID','CONFLICT','BROKEN')),
  add column if not exists integrity_reason text,
  add column if not exists broken_at timestamptz;

alter table component_audit_event
  add column if not exists revision_id uuid references component_revision(id) on delete set null,
  add column if not exists previous_event_hash text,
  add column if not exists canonical_payload_digest text,
  add column if not exists event_hash text;

create unique index if not exists component_audit_event_hash_unique_idx
  on component_audit_event(stream_id, event_hash)
  where event_hash is not null;
