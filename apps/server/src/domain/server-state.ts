import type pg from "pg";
import { appendAudit } from "./audit.js";
import { evaluateRecertification, type RecertificationDecision } from "./recertification.js";
import type { OperationalState, RegistrationState } from "./types.js";

const TRANSITIONS: Partial<Record<RegistrationState, ReadonlySet<RegistrationState>>> = {
  DRAFT: new Set(["DOCUMENTATION_INCOMPLETE", "PENDING_TECH_REVIEW", "REJECTED"]),
  DOCUMENTATION_INCOMPLETE: new Set(["PENDING_TECH_REVIEW", "REJECTED"]),
  PENDING_TECH_REVIEW: new Set(["PENDING_SECURITY_REVIEW", "DOCUMENTATION_INCOMPLETE", "REJECTED"]),
  PENDING_SECURITY_REVIEW: new Set(["PENDING_TEST", "DOCUMENTATION_INCOMPLETE", "REJECTED", "QUARANTINED"]),
  PENDING_TEST: new Set(["APPROVED", "TEST_FAILED", "QUARANTINED"]),
  TEST_FAILED: new Set(["REGISTERED_DISABLED", "REJECTED", "QUARANTINED"]),
  APPROVED: new Set(["REGISTERED_DISABLED"]),
  REGISTERED_DISABLED: new Set(["TRIAL", "TEST_FAILED", "SUSPENDED", "QUARANTINED", "RETIRED"]),
  TRIAL: new Set(["ACTIVE", "REGISTERED_DISABLED", "TEST_FAILED", "SUSPENDED", "QUARANTINED"]),
  ACTIVE: new Set(["REGISTERED_DISABLED", "SUSPENDED", "QUARANTINED", "RETIRED"]),
  SUSPENDED: new Set(["REGISTERED_DISABLED", "QUARANTINED", "RETIRED"]),
  QUARANTINED: new Set(["REGISTERED_DISABLED", "RETIRED"]),
  REJECTED: new Set(),
  RETIRED: new Set()
};

export function assertServerTransition(from: RegistrationState, to: RegistrationState): void {
  if (!TRANSITIONS[from]?.has(to)) {
    throw Object.assign(new Error(`invalid_server_state_transition:${from}:${to}`), { statusCode: 409 });
  }
}

type TransitionParams = {
  serverId: string;
  to: RegistrationState;
  actorType: "admin" | "system";
  actorId?: string | null;
  reason: string;
  correlationId: string;
  activationEvidence?: Record<string, unknown>;
  recoveryApproved?: boolean;
  operationalState?: OperationalState;
};

function operationalStateFor(to: RegistrationState, requested?: OperationalState): OperationalState {
  if (requested) return requested;
  if (to === "TRIAL") return "UNKNOWN";
  if (to === "ACTIVE") return "HEALTHY";
  if (to === "QUARANTINED") return "QUARANTINED";
  if (to === "RETIRED") return "RETIRED";
  return "DISABLED";
}

export async function transitionServerState(client: pg.PoolClient, params: TransitionParams): Promise<{
  from: RegistrationState;
  to: RegistrationState;
  operationalState: OperationalState;
  recertification: RecertificationDecision;
}> {
  const current = await client.query(
    `select ms.id,ms.code,ms.registration_state,ms.operational_state,ms.manifest_digest,ms.artifact_digest,
            rr.id as revision_id,rr.validation_state,rr.approved_at,rr.review_due_at,rr.review_interval_days,rr.created_at as revision_created_at,
            coalesce(mp.enabled,false) as monitoring_enabled,mp.profile_digest,
            quarantine.recorded_at as last_quarantine_at
       from mcp_server ms
       left join registration_revision rr on rr.id=ms.active_revision_id and rr.server_id=ms.id and rr.active=true
       left join monitoring_profile mp on mp.server_id=ms.id and mp.registration_revision_id=rr.id
       left join lateral (
         select recorded_at from server_state_history
          where server_id=ms.id and registration_state in ('SUSPENDED','QUARANTINED')
          order by recorded_at desc limit 1
       ) quarantine on true
      where ms.id=$1
      for update of ms`,
    [params.serverId]
  );
  if (!current.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
  const row = current.rows[0];
  const from = String(row.registration_state) as RegistrationState;
  assertServerTransition(from, params.to);
  const recertification = evaluateRecertification({
    activeRevisionId: row.revision_id ? String(row.revision_id) : null,
    validationState: row.validation_state ? String(row.validation_state) : null,
    approvedAt: row.approved_at ? new Date(row.approved_at).toISOString() : null,
    reviewDueAt: row.review_due_at ? new Date(row.review_due_at).toISOString() : null,
    reviewIntervalDays: row.review_interval_days === null ? null : Number(row.review_interval_days)
  });

  if (["TRIAL", "ACTIVE"].includes(params.to)) {
    if (!recertification.canActivate) throw Object.assign(new Error(recertification.reason ?? "recertification_blocks_activation"), { statusCode: 409 });
    if (!row.monitoring_enabled || !row.profile_digest) throw Object.assign(new Error("active_monitoring_profile_required"), { statusCode: 409 });
  }
  if (params.to === "ACTIVE" && (!params.activationEvidence || Object.keys(params.activationEvidence).length === 0)) {
    throw Object.assign(new Error("activation_evidence_required"), { statusCode: 409 });
  }
  if (["SUSPENDED", "QUARANTINED"].includes(from) && params.to === "REGISTERED_DISABLED") {
    const revisionCreatedAt = row.revision_created_at ? new Date(row.revision_created_at).getTime() : 0;
    const quarantineAt = row.last_quarantine_at ? new Date(row.last_quarantine_at).getTime() : Number.POSITIVE_INFINITY;
    if (!params.recoveryApproved || revisionCreatedAt <= quarantineAt) {
      throw Object.assign(new Error("new_approved_revision_required"), { statusCode: 409 });
    }
  }

  const enabled = params.to === "TRIAL" || params.to === "ACTIVE";
  const operationalState = operationalStateFor(params.to, params.operationalState);
  await client.query(
    `update mcp_server
        set enabled=$2,
            registration_state=$3::registration_state,
            operational_state=$4,
            revocation_epoch=case when $2 then revocation_epoch else gen_random_uuid() end,
            lock_version=lock_version+1,
            updated_at=now(),
            retired_at=case when $3::registration_state='RETIRED'::registration_state then now() else retired_at end
      where id=$1`,
    [params.serverId, enabled, params.to, operationalState]
  );
  if (!enabled) {
    await client.query("update access_token set revoked_at=coalesce(revoked_at,now()) where server_id=$1", [params.serverId]);
    await client.query("update egress_capability set revoked_at=coalesce(revoked_at,now()) where server_id=$1", [params.serverId]);
  }
  await client.query(
    `insert into server_state_history(server_id,registration_state,operational_state,recertification_phase,reason,correlation_id)
     values ($1,$2,$3,$4,$5,$6)`,
    [params.serverId, params.to, operationalState, recertification.phase, params.reason, params.correlationId]
  );
  await appendAudit(client, {
    eventType: `mcp_server.state.${params.to.toLowerCase()}`,
    actorType: params.actorType,
    actorId: params.actorId,
    objectType: "mcp_server",
    objectId: params.serverId,
    before: { registrationState: from, operationalState: row.operational_state },
    after: {
      code: row.code,
      registrationState: params.to,
      operationalState,
      reason: params.reason,
      manifestDigest: row.manifest_digest,
      artifactDigest: row.artifact_digest,
      registrationRevisionId: row.revision_id,
      recertificationPhase: recertification.phase,
      activationEvidence: params.activationEvidence ?? null
    },
    correlationId: params.correlationId
  });
  return { from, to: params.to, operationalState, recertification };
}

export async function setComputedOperationalState(client: pg.PoolClient, params: {
  serverId: string;
  state: OperationalState;
  reason: string;
  correlationId: string;
  recertification: RecertificationDecision;
}): Promise<void> {
  const result = await client.query(
    `update mcp_server
        set operational_state=$2,updated_at=now(),lock_version=lock_version+1
      where id=$1 and operational_state is distinct from $2
      returning code,registration_state,operational_state,manifest_digest,artifact_digest`,
    [params.serverId, params.state]
  );
  if (!result.rowCount) return;
  await client.query(
    `insert into server_state_history(server_id,registration_state,operational_state,recertification_phase,reason,correlation_id)
     values ($1,$2,$3,$4,$5,$6)`,
    [params.serverId, result.rows[0].registration_state, params.state, params.recertification.phase, params.reason, params.correlationId]
  );
  await appendAudit(client, {
    eventType: "mcp_server.operational_state.changed",
    actorType: "system",
    objectType: "mcp_server",
    objectId: params.serverId,
    after: {
      code: result.rows[0].code,
      operationalState: params.state,
      reason: params.reason,
      manifestDigest: result.rows[0].manifest_digest,
      artifactDigest: result.rows[0].artifact_digest,
      recertificationPhase: params.recertification.phase
    },
    correlationId: params.correlationId
  });
}
