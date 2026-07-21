alter table component_readiness_gate_evidence add column if not exists runtime_digest text;
alter table component_readiness_gate_evidence add column if not exists revision_digest text;
create index if not exists component_readiness_current_evidence_idx on component_readiness_gate_evidence(component_id, revision_id, gate_key, executed_at desc);

create or replace view component_current_readiness as
select c.id as component_id, c.active_revision_id,
       coalesce(bool_and(g.status='PASS' and (g.expires_at is null or g.expires_at > now())), false) as ready
  from component c
  left join lateral (
    select distinct on (gate_key) gate_key,status,expires_at
      from component_readiness_gate_evidence
     where component_id=c.id and revision_id=c.active_revision_id
     order by gate_key,executed_at desc
  ) g on true
 group by c.id,c.active_revision_id;
