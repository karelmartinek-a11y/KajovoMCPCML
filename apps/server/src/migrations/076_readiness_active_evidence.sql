alter table component_readiness_gate_evidence
  add column if not exists artifact_digest text,
  add column if not exists request_digest text,
  add column if not exists response_digest text,
  add column if not exists variant text;

create index if not exists component_readiness_active_evidence_idx
  on component_readiness_gate_evidence(
    component_id,
    revision_id,
    gate_key,
    revision_digest,
    runtime_digest,
    executed_at desc
  );
