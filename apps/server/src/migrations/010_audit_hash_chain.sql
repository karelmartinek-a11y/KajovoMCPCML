alter table audit_event
  add column if not exists prev_hash bytea,
  add column if not exists event_hash bytea;

alter table audit_event disable trigger audit_event_append_only_update;

with recursive chain as (
  select
    first_row.id,
    null::bytea as prev_hash,
    digest(
      jsonb_build_object(
        'prevHash', null,
        'eventType', first_row.event_type,
        'actorType', first_row.actor_type,
        'actorId', first_row.actor_id,
        'objectType', first_row.object_type,
        'objectId', first_row.object_id,
        'before', coalesce(first_row.before_json, 'null'::jsonb),
        'after', coalesce(first_row.after_json, 'null'::jsonb),
        'correlationId', first_row.correlation_id::text
      )::text,
      'sha256'
    ) as event_hash
  from audit_event first_row
  where first_row.id = (select min(id) from audit_event)

  union all

  select
    current_row.id,
    chain.event_hash as prev_hash,
    digest(
      jsonb_build_object(
        'prevHash', encode(chain.event_hash, 'hex'),
        'eventType', current_row.event_type,
        'actorType', current_row.actor_type,
        'actorId', current_row.actor_id,
        'objectType', current_row.object_type,
        'objectId', current_row.object_id,
        'before', coalesce(current_row.before_json, 'null'::jsonb),
        'after', coalesce(current_row.after_json, 'null'::jsonb),
        'correlationId', current_row.correlation_id::text
      )::text,
      'sha256'
    ) as event_hash
  from chain
  join audit_event current_row on current_row.id = (
    select min(next_row.id) from audit_event next_row where next_row.id > chain.id
  )
)
update audit_event audit
   set prev_hash = chain.prev_hash,
       event_hash = chain.event_hash
  from chain
 where audit.id = chain.id
   and (audit.prev_hash is null or audit.event_hash is null);

alter table audit_event enable trigger audit_event_append_only_update;

alter table audit_event
  alter column event_hash set not null;

create unique index if not exists audit_event_event_hash_idx on audit_event(event_hash);
