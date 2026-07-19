import type { Db } from "../db.js";
import { tx } from "../db.js";

export type ComponentAuditInput = {
  sequenceNumber: number;
  eventType: string;
  workflow?: string;
  workflowStep?: string;
  initiatedByType: string;
  initiatedById?: string;
  occurredAt: string;
  modelName?: string;
  toolName?: string;
  serviceName?: string;
  inputClassification?: string;
  outputClassification?: string;
  inputSummary?: unknown;
  outputSummary?: unknown;
  principalId?: string;
  principalFingerprint?: string;
  scopeName?: string;
  route?: string;
  authorizationDecision?: string;
  authorizationReason?: string;
  protocolResult?: string;
  httpStatus?: number;
  retryCount?: number;
  idempotencyKey?: string;
  correlationId: string;
  causationId?: string;
  traceId?: string;
  spanId?: string;
  stateChange?: unknown;
  catalogVersion: string;
  payload?: unknown;
};

export async function ingestComponentAuditEvent(db: Db, componentId: string, event: ComponentAuditInput): Promise<{
  accepted: boolean;
  duplicate: boolean;
  gapState: string;
  expectedNextSequence: number;
  replayFromSequence: number | null;
}> {
  return tx(db, async (client) => {
    const streamResult = await client.query("select * from component_audit_stream where component_id=$1 for update", [componentId]);
    if (!streamResult.rowCount) throw Object.assign(new Error("audit_stream_unavailable"), { statusCode: 503 });
    const stream = streamResult.rows[0];
    const expected = Number(stream.expected_next_sequence);
    if (event.sequenceNumber < expected) {
      const existing = await client.query("select 1 from component_audit_event where stream_id=$1 and sequence_number=$2", [stream.id, event.sequenceNumber]);
      if (!existing.rowCount) throw Object.assign(new Error("audit_sequence_rewind"), { statusCode: 409 });
      return { accepted: true, duplicate: true, gapState: String(stream.gap_state), expectedNextSequence: expected, replayFromSequence: stream.gap_from_sequence ? Number(stream.gap_from_sequence) : null };
    }
    if (event.sequenceNumber > expected) {
      await client.query(
        `update component_audit_stream set gap_state='GAP_DETECTED',gap_from_sequence=$2,gap_to_sequence=$3,
          highest_received_sequence=greatest(highest_received_sequence,$4),updated_at=now(),lock_version=lock_version+1 where id=$1`,
        [stream.id, expected, event.sequenceNumber - 1, event.sequenceNumber]
      );
      return { accepted: false, duplicate: false, gapState: "GAP_DETECTED", expectedNextSequence: expected, replayFromSequence: expected };
    }
    await client.query(
      `insert into component_audit_event(
        stream_id,sequence_number,event_type,workflow,workflow_step,initiated_by_type,initiated_by_id,occurred_at,
        model_name,tool_name,service_name,input_classification,output_classification,input_summary,output_summary,
        principal_id,principal_fingerprint,scope_name,route,authorization_decision,authorization_reason,protocol_result,http_status,
        retry_count,idempotency_key,correlation_id,causation_id,trace_id,span_id,state_change,catalog_version,payload,acknowledged_at
      ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15::jsonb,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30::jsonb,$31,$32::jsonb,now())`,
      [stream.id,event.sequenceNumber,event.eventType,event.workflow ?? null,event.workflowStep ?? null,event.initiatedByType,event.initiatedById ?? null,event.occurredAt,
        event.modelName ?? null,event.toolName ?? null,event.serviceName ?? null,event.inputClassification ?? null,event.outputClassification ?? null,
        JSON.stringify(event.inputSummary ?? null),JSON.stringify(event.outputSummary ?? null),event.principalId ?? null,event.principalFingerprint ?? null,
        event.scopeName ?? null,event.route ?? null,event.authorizationDecision ?? null,event.authorizationReason ?? null,event.protocolResult ?? null,
        event.httpStatus ?? null,event.retryCount ?? 0,event.idempotencyKey ?? null,event.correlationId,event.causationId ?? null,event.traceId ?? null,event.spanId ?? null,
        JSON.stringify(event.stateChange ?? null),event.catalogVersion,JSON.stringify(event.payload ?? {})]
    );
    const next = event.sequenceNumber + 1;
    await client.query(
      `update component_audit_stream set expected_next_sequence=$2::bigint,highest_received_sequence=greatest(highest_received_sequence,$3::bigint),
        highest_acknowledged_sequence=greatest(highest_acknowledged_sequence,$3::bigint),last_event_at=now(),last_acknowledged_at=now(),
        gap_state=case when gap_to_sequence is null or $3::bigint>=gap_to_sequence then 'CONTIGUOUS' else gap_state end,
        gap_from_sequence=case when gap_to_sequence is null or $3::bigint>=gap_to_sequence then null else $2::bigint end,
        gap_to_sequence=case when gap_to_sequence is null or $3::bigint>=gap_to_sequence then null else gap_to_sequence end,
        updated_at=now(),lock_version=lock_version+1 where id=$1`,
      [stream.id, next, event.sequenceNumber]
    );
    return { accepted: true, duplicate: false, gapState: "CONTIGUOUS", expectedNextSequence: next, replayFromSequence: null };
  });
}
