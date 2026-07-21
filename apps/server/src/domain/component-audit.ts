import { createHash } from "node:crypto";
import type { Db } from "../db.js";
import { tx } from "../db.js";
import { canonicalJson } from "./component.js";

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

function digest(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

function canonicalAuditPayload(event: ComponentAuditInput): Record<string, unknown> {
  return {
    authorizationDecision: event.authorizationDecision ?? null,
    authorizationReason: event.authorizationReason ?? null,
    causationId: event.causationId ?? null,
    catalogVersion: event.catalogVersion,
    correlationId: event.correlationId,
    eventType: event.eventType,
    httpStatus: event.httpStatus ?? null,
    idempotencyKey: event.idempotencyKey ?? null,
    initiatedById: event.initiatedById ?? null,
    initiatedByType: event.initiatedByType,
    inputClassification: event.inputClassification ?? null,
    inputSummary: event.inputSummary ?? null,
    modelName: event.modelName ?? null,
    occurredAt: event.occurredAt,
    outputClassification: event.outputClassification ?? null,
    outputSummary: event.outputSummary ?? null,
    payload: event.payload ?? {},
    principalFingerprint: event.principalFingerprint ?? null,
    principalId: event.principalId ?? null,
    protocolResult: event.protocolResult ?? null,
    retryCount: event.retryCount ?? 0,
    route: event.route ?? null,
    scopeName: event.scopeName ?? null,
    serviceName: event.serviceName ?? null,
    spanId: event.spanId ?? null,
    stateChange: event.stateChange ?? null,
    toolName: event.toolName ?? null,
    traceId: event.traceId ?? null,
    workflow: event.workflow ?? null,
    workflowStep: event.workflowStep ?? null
  };
}

function eventHash(input: {
  componentId: string;
  revisionId: string | null;
  sequenceNumber: number;
  previousHash: string | null;
  eventType: string;
  occurredAt: string;
  correlationId: string;
  payloadDigest: string;
  payload: Record<string, unknown>;
}): string {
  return digest({
    componentId: input.componentId,
    revisionId: input.revisionId,
    sequenceNumber: input.sequenceNumber,
    previousHash: input.previousHash,
    eventType: input.eventType,
    occurredAt: input.occurredAt,
    correlationId: input.correlationId,
    payloadDigest: input.payloadDigest,
    payload: input.payload
  });
}

export async function ingestComponentAuditEvent(db: Db, componentId: string, event: ComponentAuditInput): Promise<{
  accepted: boolean;
  duplicate: boolean;
  gapState: string;
  expectedNextSequence: number;
  replayFromSequence: number | null;
}> {
  const outcome = await tx(db, async (client) => {
    const streamResult = await client.query(
      `select stream.*, component.active_revision_id, component.lifecycle_state
         from component_audit_stream stream
         join component on component.id=stream.component_id
        where stream.component_id=$1
        for update of stream, component`,
      [componentId]
    );
    if (!streamResult.rowCount) throw Object.assign(new Error("audit_stream_unavailable"), { statusCode: 503 });
    const stream = streamResult.rows[0];
    const expected = Number(stream.expected_next_sequence);
    const payload = canonicalAuditPayload(event);
    const payloadDigest = digest(payload);
    if (event.sequenceNumber < expected) {
      const existing = await client.query(
        "select event_hash, previous_event_hash, revision_id from component_audit_event where stream_id=$1 and sequence_number=$2",
        [stream.id, event.sequenceNumber]
      );
      if (!existing.rowCount) throw Object.assign(new Error("audit_sequence_rewind"), { statusCode: 409 });
      const duplicateHash = eventHash({
        componentId,
        revisionId: existing.rows[0].revision_id ? String(existing.rows[0].revision_id) : null,
        sequenceNumber: event.sequenceNumber,
        previousHash: existing.rows[0].previous_event_hash ? String(existing.rows[0].previous_event_hash) : null,
        eventType: event.eventType,
        occurredAt: event.occurredAt,
        correlationId: event.correlationId,
        payloadDigest,
        payload
      });
      if (String(existing.rows[0].event_hash ?? "") !== duplicateHash) {
        await client.query(
          `update component_audit_stream
              set integrity_state='CONFLICT',integrity_reason='duplicate_event_hash_conflict',broken_at=now(),updated_at=now(),lock_version=lock_version+1
            where id=$1`,
          [stream.id]
        );
        await client.query(
          `update component
              set lifecycle_state='QUARANTINED',
                  activation_state='BLOCKED',
                  operational_state='QUARANTINED',
                  enabled=false,
                  ingress_enabled=false,
                  pulse_enabled=false,
                  egress_enabled=false,
                  updated_at=now()
            where id=$1`,
          [componentId]
        );
        return {
          accepted: false,
          duplicate: false,
          gapState: "CONFLICT",
          expectedNextSequence: expected,
          replayFromSequence: null,
          errorCode: "audit_stream_conflict",
          statusCode: 409
        } as const;
      }
      return { accepted: true, duplicate: true, gapState: String(stream.gap_state), expectedNextSequence: expected, replayFromSequence: stream.gap_from_sequence ? Number(stream.gap_from_sequence) : null };
    }
    const previousHash = typeof stream.current_event_hash === "string" ? String(stream.current_event_hash) : null;
    const computedEventHash = eventHash({
      componentId,
      revisionId: stream.active_revision_id ? String(stream.active_revision_id) : null,
      sequenceNumber: event.sequenceNumber,
      previousHash,
      eventType: event.eventType,
      occurredAt: event.occurredAt,
      correlationId: event.correlationId,
      payloadDigest,
      payload
    });
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
        retry_count,idempotency_key,correlation_id,causation_id,trace_id,span_id,state_change,catalog_version,payload,acknowledged_at,
        revision_id,previous_event_hash,canonical_payload_digest,event_hash
      ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15::jsonb,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30::jsonb,$31,$32::jsonb,now(),$33,$34,$35,$36)`,
      [stream.id,event.sequenceNumber,event.eventType,event.workflow ?? null,event.workflowStep ?? null,event.initiatedByType,event.initiatedById ?? null,event.occurredAt,
        event.modelName ?? null,event.toolName ?? null,event.serviceName ?? null,event.inputClassification ?? null,event.outputClassification ?? null,
        JSON.stringify(event.inputSummary ?? null),JSON.stringify(event.outputSummary ?? null),event.principalId ?? null,event.principalFingerprint ?? null,
        event.scopeName ?? null,event.route ?? null,event.authorizationDecision ?? null,event.authorizationReason ?? null,event.protocolResult ?? null,
        event.httpStatus ?? null,event.retryCount ?? 0,event.idempotencyKey ?? null,event.correlationId,event.causationId ?? null,event.traceId ?? null,event.spanId ?? null,
        JSON.stringify(event.stateChange ?? null),event.catalogVersion,JSON.stringify(event.payload ?? {}),
        stream.active_revision_id ?? null, previousHash, payloadDigest, computedEventHash]
    );
    const next = event.sequenceNumber + 1;
    await client.query(
      `update component_audit_stream set expected_next_sequence=$2::bigint,highest_received_sequence=greatest(highest_received_sequence,$3::bigint),
        highest_acknowledged_sequence=greatest(highest_acknowledged_sequence,$3::bigint),last_event_at=now(),last_acknowledged_at=now(),
        gap_state=case when gap_to_sequence is null or $3::bigint>=gap_to_sequence then 'CONTIGUOUS' else gap_state end,
        gap_from_sequence=case when gap_to_sequence is null or $3::bigint>=gap_to_sequence then null else $2::bigint end,
        gap_to_sequence=case when gap_to_sequence is null or $3::bigint>=gap_to_sequence then null else gap_to_sequence end,
        current_event_hash=$4,integrity_state='VALID',integrity_reason=null,broken_at=null,
        updated_at=now(),lock_version=lock_version+1 where id=$1`,
      [stream.id, next, event.sequenceNumber, computedEventHash]
    );
    return { accepted: true, duplicate: false, gapState: "CONTIGUOUS", expectedNextSequence: next, replayFromSequence: null };
  });
  if ("errorCode" in outcome) throw Object.assign(new Error(outcome.errorCode), { statusCode: outcome.statusCode });
  return outcome;
}
