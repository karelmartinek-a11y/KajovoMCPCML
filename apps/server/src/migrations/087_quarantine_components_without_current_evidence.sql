-- Active legacy components may not continue serving after the generic contract
-- becomes authoritative unless every current revision/runtime gate is backed by
-- unexpired server-evaluated evidence. Preserve their data for recertification,
-- but fail closed and invalidate every credential path.
do $$
declare
  affected record;
  correlation uuid;
begin
  for affected in
    select c.id,c.code,c.hostname,c.principal_id,c.lifecycle_state,c.activation_state,c.operational_state,
           c.monitoring_state,c.enabled,c.ingress_enabled,c.pulse_enabled,c.egress_enabled
      from component c
      left join component_revision revision on revision.id=c.active_revision_id
      left join component_runtime_target runtime
        on runtime.component_id=c.id and runtime.revision_id=c.active_revision_id
     where (c.lifecycle_state='ACTIVE' or c.activation_state='ACTIVE' or c.enabled)
       and (
         revision.id is null
         or runtime.id is null
         or runtime.status<>'HEALTHY'
         or exists (
           select 1
             from unnest(array[
               'MANIFEST_SCHEMA','ARTIFACT_PROVENANCE','DOCUMENT_CONTENT','HOST_EXCLUSIVITY','TLS_IDENTITY',
               'NEGATIVE_AUTH_MISSING_TOKEN','NEGATIVE_AUTH_EXPIRED_TOKEN','NEGATIVE_AUTH_WRONG_AUDIENCE',
               'NEGATIVE_AUTH_WRONG_CLIENT','NEGATIVE_AUTH_MISSING_SCOPE','NEGATIVE_AUTH_REVOKED_PERMISSION',
               'TOKEN_EPOCH_INVALIDATION','EACH_TOOL_LISTED','EACH_TOOL_POSITIVE_CALL','EACH_TOOL_INPUT_NEGATIVE',
               'EACH_TOOL_OUTPUT_SCHEMA','EACH_ENDPOINT_VARIANT','EACH_INCOMING_PULSE_VARIANT',
               'EACH_OUTGOING_PULSE_VARIANT','REGISTERED_TO_REGISTERED_DISPATCH','EXTERNAL_PRINCIPAL_INBOUND',
               'EXTERNAL_TARGET_OUTBOUND','STATE_FULL_SNAPSHOT','EACH_STATE_SCHEMA','EACH_STATE_TRANSITION',
               'ENABLE_CONTROL','DISABLE_CONTROL','STATE_QUERY_CONTROL','HEARTBEAT_PUSH','HEARTBEAT_CHALLENGE',
               'E2E_ALL_SCENARIOS','SECRET_ALLOWED','SECRET_DENIED','AUDIT_CONTINUITY','AUDIT_PAYLOAD_INTEGRITY',
               'OPERATION_LEASE_ENFORCEMENT','MONITORING_WATCHDOG','RECERTIFICATION'
             ]::text[]) required(gate_key)
            where not exists (
              select 1
                from component_readiness_gate_evidence evidence
               where evidence.component_id=c.id
                 and evidence.revision_id=c.active_revision_id
                 and evidence.gate_key=required.gate_key
                 and evidence.status='PASS'
                 and (evidence.expires_at is null or evidence.expires_at>now())
                 and evidence.revision_digest=revision.manifest_digest
                 and evidence.runtime_digest is not distinct from runtime.runtime_digest
                 and evidence.artifact_digest is not distinct from runtime.runtime_digest
            )
         )
       )
     order by c.kcml_number
     for update of c
  loop
    correlation := gen_random_uuid();

    update component
       set hostname=lower(code::text) || '.kajovocml.hcasc.cz',
           lifecycle_state='QUARANTINED',activation_state='BLOCKED',operational_state='QUARANTINED',
           monitoring_state='FAILED',recertification_state='FAILED',enabled=false,ingress_enabled=false,
           pulse_enabled=false,egress_enabled=false,policy_epoch=policy_epoch+1,
           revocation_epoch=gen_random_uuid(),lock_version=lock_version+1,updated_at=now()
     where id=affected.id;

    update principal
       set status='QUARANTINED',policy_epoch=policy_epoch+1,revocation_epoch=revocation_epoch+1,updated_at=now()
     where id=affected.principal_id;

    update principal_access_token
       set revoked_at=coalesce(revoked_at,now()),rotation_reason=coalesce(rotation_reason,'READINESS_RECONCILIATION')
     where revoked_at is null
       and (source_principal_id=affected.principal_id or target_component_id=affected.id);

    update component_access_token
       set revoked_at=coalesce(revoked_at,now())
     where revoked_at is null
       and (source_component_id=affected.id or target_component_id=affected.id);

    update component_credential
       set status='REVOKED',revoked_at=coalesce(revoked_at,now())
     where component_id=affected.id and revoked_at is null;

    update principal_credential
       set revoked_at=coalesce(revoked_at,now()),revocation_epoch=revocation_epoch+1
     where principal_id=affected.principal_id and revoked_at is null;

    update component_runtime_target
       set status='DISABLED'
     where component_id=affected.id and status<>'DISABLED';

    insert into operational_alert(severity,alert_type,title,detail,correlation_id)
    values (
      'CRITICAL','component.readiness_reconciliation.' || affected.code,
      'Component quarantined pending recertification',
      jsonb_build_object('componentCode',affected.code,'reason','CURRENT_READINESS_EVIDENCE_REQUIRED'),correlation
    );

    perform append_audit_event(
      'component.readiness_reconciliation.quarantined','migration',null,'component',affected.id::text,
      jsonb_build_object(
        'code',affected.code,'hostname',affected.hostname,'lifecycleState',affected.lifecycle_state,'activationState',affected.activation_state,
        'operationalState',affected.operational_state,'monitoringState',affected.monitoring_state,
        'enabled',affected.enabled,'ingressEnabled',affected.ingress_enabled,
        'pulseEnabled',affected.pulse_enabled,'egressEnabled',affected.egress_enabled
      ),
      jsonb_build_object(
        'code',affected.code,'hostname',lower(affected.code::text) || '.kajovocml.hcasc.cz',
        'lifecycleState','QUARANTINED','activationState','BLOCKED',
        'operationalState','QUARANTINED','monitoringState','FAILED','enabled',false,
        'ingressEnabled',false,'pulseEnabled',false,'egressEnabled',false,
        'reason','CURRENT_READINESS_EVIDENCE_REQUIRED'
      ),
      correlation
    );
  end loop;
end $$;
