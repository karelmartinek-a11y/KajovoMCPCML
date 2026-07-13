import { createHash, randomBytes, randomUUID } from "node:crypto";
import type pg from "pg";
import type { AppConfig } from "../config.js";
import type { Db } from "../db.js";
import { tx } from "../db.js";
import { fingerprintSecret, hmacToken } from "../security/secrets.js";
import { appendAudit } from "./audit.js";
import type { OnboardingManifest } from "./registration.js";

export const ONBOARDING_JOB_STATES = [
  "CREATED",
  "SOURCE_UPLOADED",
  "PR_CREATED",
  "CI_RUNNING",
  "AWAITING_REVISION",
  "MERGED",
  "ARTIFACT_BUILDING",
  "DEPLOYING",
  "REGISTERED_DISABLED",
  "TRIAL_TESTING",
  "ACTIVE",
  "FAILED",
  "QUARANTINED",
  "CANCELLED"
] as const;

export type OnboardingJobState = (typeof ONBOARDING_JOB_STATES)[number];
export type GateStatus = "PENDING" | "RUNNING" | "PASS" | "FAIL" | "QUARANTINED" | "SKIPPED";

export const TERMINAL_JOB_STATES = new Set<OnboardingJobState>(["ACTIVE", "FAILED", "QUARANTINED", "CANCELLED"]);
const HEARTBEAT_EXTENSION_MS = 2 * 60 * 60 * 1000;
const INITIAL_TTL_MS = 2 * 60 * 60 * 1000;
const MAX_TTL_MS = 24 * 60 * 60 * 1000;

const TRANSITIONS: Record<OnboardingJobState, ReadonlySet<OnboardingJobState>> = {
  CREATED: new Set(["SOURCE_UPLOADED", "CANCELLED", "FAILED", "QUARANTINED"]),
  SOURCE_UPLOADED: new Set(["PR_CREATED", "AWAITING_REVISION", "CANCELLED", "FAILED", "QUARANTINED"]),
  PR_CREATED: new Set(["CI_RUNNING", "AWAITING_REVISION", "CANCELLED", "FAILED", "QUARANTINED"]),
  CI_RUNNING: new Set(["AWAITING_REVISION", "MERGED", "CANCELLED", "FAILED", "QUARANTINED"]),
  AWAITING_REVISION: new Set(["SOURCE_UPLOADED", "CANCELLED", "FAILED", "QUARANTINED"]),
  MERGED: new Set(["ARTIFACT_BUILDING", "CANCELLED", "FAILED", "QUARANTINED"]),
  ARTIFACT_BUILDING: new Set(["DEPLOYING", "CANCELLED", "FAILED", "QUARANTINED"]),
  DEPLOYING: new Set(["REGISTERED_DISABLED", "CANCELLED", "FAILED", "QUARANTINED"]),
  REGISTERED_DISABLED: new Set(["TRIAL_TESTING", "CANCELLED", "FAILED", "QUARANTINED"]),
  TRIAL_TESTING: new Set(["ACTIVE", "REGISTERED_DISABLED", "CANCELLED", "FAILED", "QUARANTINED"]),
  ACTIVE: new Set(),
  FAILED: new Set(["SOURCE_UPLOADED", "CANCELLED"]),
  QUARANTINED: new Set(["AWAITING_REVISION"]),
  CANCELLED: new Set()
};

export type IntegrationTokenPrincipal = {
  id: string;
  jobId: string | null;
  fingerprint: string;
  expiresAt: string;
  maxExpiresAt: string;
};

export type SourceEvidence = {
  archivePath: string;
  sourceDigest: string;
  requestDigest: string;
  manifestDigest: string;
  validation: Record<string, unknown>;
};

export type ProgrammerActionKind = "UPLOAD_SOURCE" | "WAIT" | "UPLOAD_REVISION" | "COMPLETE" | "STOP";

export function programmerActionForState(state: OnboardingJobState, blockingErrorCode?: string | null) {
  if (state === "CREATED") {
    return { kind: "UPLOAD_SOURCE" as const, canUploadRevision: false, message: "Upload the initial manifest and source ZIP." };
  }
  if (state === "AWAITING_REVISION" || state === "FAILED") {
    return {
      kind: "UPLOAD_REVISION" as const,
      canUploadRevision: true,
      message: blockingErrorCode
        ? `Fix ${blockingErrorCode}, fetch the current ETag and upload a new source revision.`
        : "Inspect failed gates, fetch the current ETag and upload a new source revision."
    };
  }
  if (state === "ACTIVE") {
    return { kind: "COMPLETE" as const, canUploadRevision: false, message: "Onboarding is complete and the MCP server is active." };
  }
  if (state === "QUARANTINED") {
    return { kind: "STOP" as const, canUploadRevision: false, message: "A non-bypassable security gate quarantined the server." };
  }
  if (state === "CANCELLED") {
    return { kind: "STOP" as const, canUploadRevision: false, message: "Onboarding was cancelled." };
  }
  return { kind: "WAIT" as const, canUploadRevision: false, message: "Poll this job until it becomes ACTIVE or requests a new revision." };
}

export function issueIntegrationSecret(): { value: string; fingerprint: string } {
  const value = `kci_${randomBytes(64).toString("base64url")}`;
  return { value, fingerprint: fingerprintSecret(value) };
}

export function tokenDeadlines(issuedAt = new Date()): { issuedAt: Date; initialExpiresAt: Date; expiresAt: Date; maxExpiresAt: Date } {
  const initialExpiresAt = new Date(issuedAt.getTime() + INITIAL_TTL_MS);
  return {
    issuedAt,
    initialExpiresAt,
    expiresAt: initialExpiresAt,
    maxExpiresAt: new Date(issuedAt.getTime() + MAX_TTL_MS)
  };
}

export function nextHeartbeatExpiry(now: Date, current: Date, maximum: Date): Date {
  const candidate = new Date(Math.min(now.getTime() + HEARTBEAT_EXTENSION_MS, maximum.getTime()));
  return candidate.getTime() > current.getTime() ? candidate : current;
}

export function requestDigest(manifestDigest: string, sourceDigest: string): string {
  return `sha256:${createHash("sha256").update(`${manifestDigest}:${sourceDigest}`).digest("hex")}`;
}

function asIso(value: unknown): string | null {
  if (!value) return null;
  if (value instanceof Date) return value.toISOString();
  if (typeof value === "string") return value;
  if (typeof value === "number") return new Date(value).toISOString();
  return null;
}

function optionalText(value: unknown): string | null {
  return typeof value === "string" ? value : typeof value === "number" ? String(value) : null;
}

function mapToken(row: Record<string, unknown>) {
  return {
    id: String(row.id),
    label: String(row.label),
    fingerprint: String(row.fingerprint),
    jobId: optionalText(row.onboarding_job_id),
    issuedAt: asIso(row.issued_at) ?? "",
    initialExpiresAt: asIso(row.initial_expires_at) ?? "",
    expiresAt: asIso(row.expires_at) ?? "",
    maxExpiresAt: asIso(row.max_expires_at) ?? "",
    lastUsedAt: asIso(row.last_used_at),
    revokedAt: asIso(row.revoked_at),
    deletedAt: asIso(row.deleted_at),
    active: !row.revoked_at && !row.deleted_at && new Date(String(row.expires_at)).getTime() > Date.now(),
    jobState: optionalText(row.job_state),
    code: optionalText(row.code),
    hostname: optionalText(row.hostname),
    heartbeatAt: asIso(row.heartbeat_at),
    tokenExtendedAt: asIso(row.token_extended_at)
  };
}

export async function createIntegrationToken(
  db: Db,
  config: AppConfig,
  actorId: string,
  correlationId: string,
  label: string,
  resumeJobId?: string
) {
  const secret = issueIntegrationSecret();
  const deadlines = tokenDeadlines();
  const digest = hmacToken(secret.value, config.INTEGRATION_TOKEN_HMAC_KEY_BASE64);
  const result = await tx(db, async (client) => {
    let resumeState: OnboardingJobState | null = null;
    let resumeHasServer = false;
    if (resumeJobId) {
      const job = await client.query(
        `select oj.id, oj.state, ms.enabled
           from onboarding_job oj
           left join mcp_server ms on ms.id=oj.server_id
          where oj.id=$1 for update`,
        [resumeJobId]
      );
      if (!job.rowCount) throw Object.assign(new Error("job_not_found"), { statusCode: 404 });
      if (["ACTIVE", "QUARANTINED", "CANCELLED"].includes(String(job.rows[0].state)) || Boolean(job.rows[0].enabled)) {
        throw Object.assign(new Error("job_not_resumable"), { statusCode: 409 });
      }
      resumeState = job.rows[0].state as OnboardingJobState;
      resumeHasServer = job.rows[0].enabled !== null;
    }
    const inserted = await client.query(
      `insert into integration_token
        (label, lookup_digest, key_id, fingerprint, created_by, onboarding_job_id,
         issued_at, initial_expires_at, expires_at, max_expires_at)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       returning *`,
      [label, digest, config.INTEGRATION_TOKEN_HMAC_KEY_ID, secret.fingerprint, actorId, resumeJobId ?? null,
        deadlines.issuedAt, deadlines.initialExpiresAt, deadlines.expiresAt, deadlines.maxExpiresAt]
    );
    if (resumeJobId) {
      await client.query(
        `update integration_token set revoked_at=coalesce(revoked_at, now()), lock_version=lock_version+1
          where onboarding_job_id=$1 and id<>$2 and revoked_at is null`,
        [resumeJobId, inserted.rows[0].id]
      );
      const resumeDeployment = resumeHasServer && !["AWAITING_REVISION", "FAILED"].includes(String(resumeState));
      await client.query(
        `update onboarding_job
            set token_id=$2, state=case when $3 then 'DEPLOYING' else state end,
                runtime_stopped_at=case when $3 then null else runtime_stopped_at end,
                next_run_at=now(), blocking_error_code=null,
                blocking_error_detail=null, lock_version=lock_version+1
          where id=$1`,
        [resumeJobId, inserted.rows[0].id, resumeDeployment]
      );
      if (resumeState && resumeDeployment) {
        await recordTransition(client, resumeJobId, resumeState, "DEPLOYING", "job.resumed", {}, correlationId);
      }
    }
    await appendAudit(client, {
      eventType: resumeJobId ? "integration_token.resumed" : "integration_token.created",
      actorType: "admin",
      actorId,
      objectType: "integration_token",
      objectId: inserted.rows[0].id,
      after: { label, fingerprint: secret.fingerprint, resumeJobId: resumeJobId ?? null, initialExpiresAt: deadlines.initialExpiresAt, maxExpiresAt: deadlines.maxExpiresAt },
      correlationId
    });
    return inserted.rows[0] as Record<string, unknown>;
  });
  return {
    ...mapToken(result),
    token: secret.value
  };
}

export async function releaseQuarantinedOnboardingJob(
  db: Db,
  jobId: string,
  confirmedCode: string,
  reason: string,
  actorId: string,
  correlationId: string
): Promise<void> {
  await tx(db, async (client) => {
    const result = await client.query("select * from onboarding_job where id=$1 for update", [jobId]);
    if (!result.rowCount) throw Object.assign(new Error("job_not_found"), { statusCode: 404 });
    const row = result.rows[0];
    if (String(row.state) !== "QUARANTINED") throw Object.assign(new Error("job_not_quarantined"), { statusCode: 409 });
    if (!row.code || String(row.code) !== confirmedCode) throw Object.assign(new Error("confirmation_code_mismatch"), { statusCode: 400 });
    assertTransition("QUARANTINED", "AWAITING_REVISION");
    await client.query(
      `update onboarding_job
          set state='AWAITING_REVISION', completed_at=null, next_run_at=now(), lock_version=lock_version+1
        where id=$1`,
      [jobId]
    );
    await client.query("update integration_token set revoked_at=coalesce(revoked_at,now()), lock_version=lock_version+1 where onboarding_job_id=$1 and revoked_at is null", [jobId]);
    await client.query("update egress_capability set revoked_at=coalesce(revoked_at,now()) where job_id=$1 and revoked_at is null", [jobId]);
    await recordTransition(client, jobId, "QUARANTINED", "AWAITING_REVISION", "quarantine.revision_approved", { reason }, correlationId);
    await appendAudit(client, {
      eventType: "onboarding.quarantine.revision_approved",
      actorType: "admin",
      actorId,
      objectType: "onboarding_job",
      objectId: jobId,
      before: { state: "QUARANTINED" },
      after: { state: "AWAITING_REVISION", confirmedCode, reason },
      correlationId
    });
  });
}

export async function listIntegrationTokens(db: Db) {
  const result = await db.query(`
    select it.*, oj.state as job_state, oj.code, oj.hostname, oj.heartbeat_at, oj.token_extended_at
      from integration_token it
      left join onboarding_job oj on oj.id=it.onboarding_job_id
     where it.deleted_at is null
     order by it.issued_at desc
  `);
  return result.rows.map((row) => mapToken(row as Record<string, unknown>));
}

export async function authenticateIntegrationToken(db: Db, token: string, config: AppConfig): Promise<IntegrationTokenPrincipal> {
  if (!token.startsWith("kci_") || token.length < 80 || token.length > 100) throw new Error("invalid_integration_token");
  const digest = hmacToken(token, config.INTEGRATION_TOKEN_HMAC_KEY_BASE64);
  const result = await db.query(
    `select it.id, it.onboarding_job_id, it.fingerprint, it.expires_at, it.max_expires_at
       from integration_token it
       left join onboarding_job oj on oj.id=it.onboarding_job_id
      where it.lookup_digest=$1
        and it.key_id=$2
        and it.revoked_at is null
        and it.deleted_at is null
        and it.expires_at > now()
        and (oj.id is null or oj.token_id=it.id)`,
    [digest, config.INTEGRATION_TOKEN_HMAC_KEY_ID]
  );
  if (!result.rowCount) throw new Error("invalid_integration_token");
  await db.query("update integration_token set last_used_at=now() where id=$1", [result.rows[0].id]);
  return {
    id: String(result.rows[0].id),
    jobId: result.rows[0].onboarding_job_id ? String(result.rows[0].onboarding_job_id) : null,
    fingerprint: String(result.rows[0].fingerprint),
    expiresAt: String(result.rows[0].expires_at),
    maxExpiresAt: String(result.rows[0].max_expires_at)
  };
}

function toolNameFor(code: string, handlerKey: string): string {
  return `${code.toLowerCase()}_${handlerKey}`.replace(/[^a-z0-9_-]/g, "_");
}

export async function createOnboardingJob(
  db: Db,
  config: AppConfig,
  principal: IntegrationTokenPrincipal,
  idempotencyKey: string,
  manifest: OnboardingManifest,
  evidence: SourceEvidence,
  correlationId: string
) {
  return tx(db, async (client) => {
    const token = await client.query(
      `select * from integration_token
        where id=$1 and revoked_at is null and deleted_at is null and expires_at>now()
        for update`,
      [principal.id]
    );
    if (!token.rowCount) throw Object.assign(new Error("invalid_integration_token"), { statusCode: 401 });
    if (token.rows[0].onboarding_job_id) {
      const existing = await client.query(
        `select oj.*, osr.request_digest
           from onboarding_job oj
           left join onboarding_source_revision osr on osr.job_id=oj.id and osr.idempotency_key=$2
          where oj.id=$1`,
        [token.rows[0].onboarding_job_id, idempotencyKey]
      );
      if (existing.rowCount && existing.rows[0].request_digest === evidence.requestDigest) return mapJob(existing.rows[0]);
      throw Object.assign(new Error("integration_token_already_bound"), { statusCode: 409 });
    }
    const allocation = await client.query("select nextval('kcml_number_seq') as number");
    const number = Number(allocation.rows[0].number);
    const code = `KCML${String(number).padStart(4, "0")}`;
    const hostname = `${code.toLowerCase()}.${config.PUBLIC_BASE_DOMAIN}`;
    const toolName = toolNameFor(code, manifest.handlerKey);
    const job = await client.query(
      `insert into onboarding_job
        (token_id, state, correlation_id, manifest, manifest_digest, source_digest,
         source_archive_path, source_revision, kcml_number, code, hostname, tool_name)
       values ($1,'SOURCE_UPLOADED',$2,$3,$4,$5,$6,1,$7,$8,$9,$10)
       returning *`,
      [principal.id, correlationId, manifest, evidence.manifestDigest, evidence.sourceDigest,
        evidence.archivePath, number, code, hostname, toolName]
    );
    const jobId = String(job.rows[0].id);
    await client.query("update integration_token set onboarding_job_id=$2, lock_version=lock_version+1 where id=$1", [principal.id, jobId]);
    await client.query(
      `insert into onboarding_source_revision
        (job_id, revision, idempotency_key, request_digest, source_digest, archive_path, manifest, manifest_digest, validation_evidence)
       values ($1,1,$2,$3,$4,$5,$6,$7,$8)`,
      [jobId, idempotencyKey, evidence.requestDigest, evidence.sourceDigest, evidence.archivePath, manifest, evidence.manifestDigest, evidence.validation]
    );
    await client.query(
      `insert into onboarding_event(job_id, from_state, to_state, event_type, detail, correlation_id)
       values ($1,'CREATED','SOURCE_UPLOADED','source.accepted',$2,$3)`,
      [jobId, JSON.stringify({ sourceDigest: evidence.sourceDigest, manifestDigest: evidence.manifestDigest, revision: 1 }), correlationId]
    );
    await initializeGates(client, jobId, correlationId);
    await appendAudit(client, {
      eventType: "onboarding.created",
      actorType: "integration_token",
      actorId: principal.fingerprint,
      objectType: "onboarding_job",
      objectId: jobId,
      after: { code, hostname, toolName, sourceDigest: evidence.sourceDigest, manifestDigest: evidence.manifestDigest },
      correlationId
    });
    return mapJob(job.rows[0]);
  });
}

export async function replaceOnboardingSource(
  db: Db,
  principal: IntegrationTokenPrincipal,
  jobId: string,
  expectedLockVersion: number,
  idempotencyKey: string,
  manifest: OnboardingManifest,
  evidence: SourceEvidence,
  correlationId: string
) {
  if (principal.jobId !== jobId) throw Object.assign(new Error("invalid_integration_token"), { statusCode: 401 });
  return tx(db, async (client) => {
    const current = await client.query("select * from onboarding_job where id=$1 and token_id=$2 for update", [jobId, principal.id]);
    if (!current.rowCount) throw Object.assign(new Error("invalid_integration_token"), { statusCode: 401 });
    const row = current.rows[0];
    if (Number(row.lock_version) !== expectedLockVersion) throw Object.assign(new Error("lock_version_conflict"), { statusCode: 412 });
    const duplicate = await client.query("select request_digest from onboarding_source_revision where job_id=$1 and idempotency_key=$2", [jobId, idempotencyKey]);
    if (duplicate.rowCount) {
      if (duplicate.rows[0].request_digest !== evidence.requestDigest) throw Object.assign(new Error("idempotency_key_reused"), { statusCode: 409 });
      return mapJob(row);
    }
    if (!["AWAITING_REVISION", "FAILED"].includes(String(row.state))) throw Object.assign(new Error("source_revision_not_allowed"), { statusCode: 409 });
    const revision = Number(row.source_revision) + 1;
    const updated = await client.query(
      `update onboarding_job
          set state='SOURCE_UPLOADED', manifest=$3, manifest_digest=$4, source_digest=$5,
              source_archive_path=$6, source_revision=$7, github_branch=null, github_pr_number=null,
              github_pr_url=null, source_commit=null, blocking_error_code=null, blocking_error_detail=null,
              completed_at=null, next_run_at=now(), lock_version=lock_version+1
        where id=$1 and lock_version=$2 returning *`,
      [jobId, expectedLockVersion, manifest, evidence.manifestDigest, evidence.sourceDigest, evidence.archivePath, revision]
    );
    if (!updated.rowCount) throw Object.assign(new Error("lock_version_conflict"), { statusCode: 412 });
    await client.query(
      `insert into onboarding_source_revision
        (job_id, revision, idempotency_key, request_digest, source_digest, archive_path, manifest, manifest_digest, validation_evidence)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [jobId, revision, idempotencyKey, evidence.requestDigest, evidence.sourceDigest, evidence.archivePath, manifest, evidence.manifestDigest, evidence.validation]
    );
    await client.query("update onboarding_gate set status='PENDING', evidence='{}', started_at=null, completed_at=null where job_id=$1 and status<>'PASS'", [jobId]);
    await recordTransition(client, jobId, row.state as OnboardingJobState, "SOURCE_UPLOADED", "source.revised", { revision }, correlationId);
    await appendAudit(client, {
      eventType: "onboarding.source.revised",
      actorType: "integration_token",
      actorId: principal.fingerprint,
      objectType: "onboarding_job",
      objectId: jobId,
      after: { revision, sourceDigest: evidence.sourceDigest },
      correlationId
    });
    return mapJob(updated.rows[0]);
  });
}

async function initializeGates(client: pg.PoolClient, jobId: string, correlationId: string): Promise<void> {
  const gates = [
    ["archive_policy", "intake"], ["manifest_schema", "intake"], ["secret_scan", "intake"], ["dependency_policy", "intake"],
    ["path_policy", "ci"], ["lint", "ci"], ["typecheck", "ci"], ["unit_tests", "ci"], ["contract_tests", "ci"],
    ["sast", "ci"], ["sca", "ci"], ["license", "ci"], ["sbom", "ci"], ["reproducible_build", "ci"],
    ["source_commit", "supply_chain"], ["image_signature", "supply_chain"], ["image_digest", "supply_chain"], ["provenance", "supply_chain"],
    ["runtime_isolation", "deploy"], ["worker_readiness", "deploy"], ["dns", "preflight"], ["tls_san", "preflight"], ["host_routing", "preflight"],
    ["oauth_metadata", "trial"], ["audience_binding", "trial"], ["negative_auth", "trial"], ["mcp_initialize", "trial"],
    ["mcp_tools_list", "trial"], ["safe_tools_call", "trial"], ["cross_host", "trial"], ["schema_contract", "trial"],
    ["correlation_chain", "trial"], ["logging_redaction", "trial"], ["audit_persistence", "trial"], ["monitoring_probes", "trial"]
  ];
  for (const [name, stage] of gates) {
    await client.query(
      `insert into onboarding_gate(job_id, gate_name, stage, status, correlation_id)
       values ($1,$2,$3,'PENDING',$4) on conflict (job_id, gate_name) do nothing`,
      [jobId, name, stage, correlationId]
    );
  }
  for (const gate of ["archive_policy", "manifest_schema", "secret_scan", "dependency_policy"]) {
    await client.query("update onboarding_gate set status='PASS', started_at=now(), completed_at=now() where job_id=$1 and gate_name=$2", [jobId, gate]);
  }
}

async function recordTransition(
  client: pg.PoolClient,
  jobId: string,
  from: OnboardingJobState,
  to: OnboardingJobState,
  eventType: string,
  detail: unknown,
  correlationId: string
): Promise<void> {
  await client.query(
    `insert into onboarding_event(job_id, from_state, to_state, event_type, detail, correlation_id)
     values ($1,$2,$3,$4,$5,$6)`,
    [jobId, from, to, eventType, JSON.stringify(detail ?? {}), correlationId]
  );
}

export function assertTransition(from: OnboardingJobState, to: OnboardingJobState): void {
  if (!TRANSITIONS[from].has(to)) throw Object.assign(new Error(`invalid_state_transition:${from}:${to}`), { statusCode: 409 });
}

export async function transitionJob(
  db: Db,
  jobId: string,
  expectedLockVersion: number,
  to: OnboardingJobState,
  eventType: string,
  detail: Record<string, unknown>,
  correlationId: string,
  patch: Record<string, unknown> = {}
) {
  return tx(db, async (client) => {
    const current = await client.query("select * from onboarding_job where id=$1 for update", [jobId]);
    if (!current.rowCount) throw Object.assign(new Error("job_not_found"), { statusCode: 404 });
    const row = current.rows[0] as Record<string, unknown>;
    if (Number(row.lock_version) !== expectedLockVersion) throw Object.assign(new Error("lock_version_conflict"), { statusCode: 409 });
    const from = String(row.state) as OnboardingJobState;
    assertTransition(from, to);
    const allowedPatch = [
      "github_branch", "github_pr_number", "github_pr_url", "source_commit", "build_id", "image_reference",
      "image_digest", "sbom_digest", "provenance_digest", "server_id", "blocking_error_code", "blocking_error_detail"
    ];
    const entries = Object.entries(patch).filter(([key]) => allowedPatch.includes(key));
    const values: unknown[] = [jobId, expectedLockVersion, to];
    const assignments = entries.map(([key, value], index) => {
      values.push(value);
      return `${key}=$${index + 4}`;
    });
    const terminal = TERMINAL_JOB_STATES.has(to) ? ", completed_at=now(), lease_owner=null, lease_expires_at=null" : "";
    const updated = await client.query(
      `update onboarding_job set state=$3::onboarding_job_state, ${assignments.length ? `${assignments.join(", ")}, ` : ""}
              runtime_stopped_at=case when $3::onboarding_job_state='DEPLOYING'::onboarding_job_state then null else runtime_stopped_at end,
              lock_version=lock_version+1, next_run_at=now()${terminal}
        where id=$1 and lock_version=$2 returning *`,
      values
    );
    if (!updated.rowCount) throw Object.assign(new Error("lock_version_conflict"), { statusCode: 409 });
    await recordTransition(client, jobId, from, to, eventType, detail, correlationId);
    await appendAudit(client, {
      eventType: `onboarding.${eventType}`,
      actorType: "system",
      objectType: "onboarding_job",
      objectId: jobId,
      before: { state: from },
      after: { state: to, ...detail },
      correlationId
    });
    return mapJob(updated.rows[0]);
  });
}

export async function setGate(db: Db, jobId: string, gateName: string, status: GateStatus, evidence: Record<string, unknown>, correlationId: string): Promise<void> {
  await tx(db, async (client) => {
    const updated = await client.query(
      `update onboarding_gate
          set status=$3, evidence=$4,
              started_at=case when $3='RUNNING' then coalesce(started_at,now()) else started_at end,
              completed_at=case when $3 in ('PASS','FAIL','QUARANTINED','SKIPPED') then now() else completed_at end,
              correlation_id=$5, updated_at=now()
        where job_id=$1 and gate_name=$2
          and (status<>$3 or evidence<>$4::jsonb)
        returning id`,
      [jobId, gateName, status, JSON.stringify(evidence), correlationId]
    );
    if (updated.rowCount) {
      await appendAudit(client, {
        eventType: "onboarding.gate.updated", actorType: "system", objectType: "onboarding_job", objectId: jobId,
        after: { gateName, status, evidence }, correlationId
      });
    }
  });
}

export async function heartbeatJob(db: Db, jobId: string, workerId: string): Promise<{ expiresAt: string; extended: boolean }> {
  return tx(db, async (client) => {
    const result = await client.query(
      `select oj.state, oj.token_id, oj.token_extended_at, oj.correlation_id, it.expires_at, it.max_expires_at
         from onboarding_job oj join integration_token it on it.id=oj.token_id
        where oj.id=$1 and oj.lease_owner=$2 and it.expires_at>now() and it.revoked_at is null
        for update of oj, it`,
      [jobId, workerId]
    );
    if (!result.rowCount) throw Object.assign(new Error("job_lease_lost"), { statusCode: 409 });
    const row = result.rows[0];
    const current = new Date(row.expires_at);
    const lastExtended = row.token_extended_at ? new Date(row.token_extended_at).getTime() : 0;
    if (lastExtended > Date.now() - 15 * 60 * 1000) {
      await client.query("update onboarding_job set heartbeat_at=now(), lease_expires_at=now()+interval '1 minute' where id=$1", [jobId]);
      return { expiresAt: current.toISOString(), extended: false };
    }
    if (TERMINAL_JOB_STATES.has(row.state as OnboardingJobState) || current.getTime() >= new Date(row.max_expires_at).getTime()) {
      return { expiresAt: current.toISOString(), extended: false };
    }
    const next = nextHeartbeatExpiry(new Date(), current, new Date(row.max_expires_at));
    await client.query(
      "update integration_token set expires_at=$2, lock_version=lock_version+1 where id=$1 and revoked_at is null",
      [row.token_id, next]
    );
    await client.query("update onboarding_job set heartbeat_at=now(), token_extended_at=now(), lease_expires_at=now()+interval '1 minute' where id=$1", [jobId]);
    await appendAudit(client, {
      eventType: "integration_token.extended", actorType: "system", objectType: "integration_token", objectId: String(row.token_id),
      after: { jobId, expiresAt: next.toISOString(), maxExpiresAt: new Date(row.max_expires_at).toISOString() },
      correlationId: String(row.correlation_id)
    });
    return { expiresAt: next.toISOString(), extended: next.getTime() > current.getTime() };
  });
}

export async function leaseNextJob(db: Db, workerId: string) {
  return tx(db, async (client) => {
    const result = await client.query(
      `select oj.* from onboarding_job oj
       join integration_token it on it.id=oj.token_id
       where oj.state not in ('ACTIVE','FAILED','QUARANTINED','CANCELLED','AWAITING_REVISION')
         and oj.next_run_at<=now()
         and (oj.lease_expires_at is null or oj.lease_expires_at<now())
         and it.revoked_at is null and it.deleted_at is null and it.expires_at>now()
       order by oj.next_run_at, oj.created_at
       for update of oj skip locked limit 1`
    );
    if (!result.rowCount) return null;
    const leased = await client.query(
      `update onboarding_job set lease_owner=$2, lease_expires_at=now()+interval '1 minute', heartbeat_at=now()
        where id=$1 returning *`,
      [result.rows[0].id, workerId]
    );
    return mapJob(leased.rows[0]);
  });
}

export async function releaseLease(db: Db, jobId: string, workerId: string, delaySeconds = 15): Promise<void> {
  await db.query(
    `update onboarding_job
        set lease_owner=null, lease_expires_at=null, next_run_at=now()+($3 || ' seconds')::interval
      where id=$1 and lease_owner=$2`,
    [jobId, workerId, delaySeconds]
  );
}

export async function revokeIntegrationToken(db: Db, tokenId: string, actorId: string, correlationId: string): Promise<void> {
  await tx(db, async (client) => {
    const result = await client.query(
      `update integration_token set revoked_at=coalesce(revoked_at,now()), lock_version=lock_version+1
        where id=$1 and deleted_at is null returning id, onboarding_job_id, fingerprint`,
      [tokenId]
    );
    if (!result.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    await appendAudit(client, {
      eventType: "integration_token.revoked", actorType: "admin", actorId,
      objectType: "integration_token", objectId: tokenId,
      after: { fingerprint: result.rows[0].fingerprint, jobId: result.rows[0].onboarding_job_id }, correlationId
    });
  });
}

export async function deleteIntegrationToken(db: Db, tokenId: string, actorId: string, correlationId: string): Promise<void> {
  await tx(db, async (client) => {
    const result = await client.query(
      `update integration_token set revoked_at=coalesce(revoked_at,now()), deleted_at=coalesce(deleted_at,now()), lock_version=lock_version+1
        where id=$1 and deleted_at is null returning id, fingerprint`,
      [tokenId]
    );
    if (!result.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    await appendAudit(client, {
      eventType: "integration_token.deleted", actorType: "admin", actorId,
      objectType: "integration_token", objectId: tokenId,
      after: { fingerprint: result.rows[0].fingerprint }, correlationId
    });
  });
}

export async function cancelOnboardingJob(db: Db, jobId: string, actorType: "admin" | "integration_token", actorId: string, correlationId: string): Promise<void> {
  await tx(db, async (client) => {
    const result = await client.query("select * from onboarding_job where id=$1 for update", [jobId]);
    if (!result.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    const row = result.rows[0];
    const from = row.state as OnboardingJobState;
    if (["ACTIVE", "QUARANTINED", "CANCELLED"].includes(from)) throw Object.assign(new Error("job_terminal"), { statusCode: 409 });
    assertTransition(from, "CANCELLED");
    await client.query(
      `update onboarding_job set state='CANCELLED', completed_at=now(), lease_owner=null, lease_expires_at=null,
              lock_version=lock_version+1 where id=$1`,
      [jobId]
    );
    await client.query("update integration_token set revoked_at=coalesce(revoked_at,now()) where onboarding_job_id=$1", [jobId]);
    await client.query("update egress_capability set revoked_at=coalesce(revoked_at,now()) where job_id=$1", [jobId]);
    if (row.server_id) {
      await client.query("update mcp_server set enabled=false, registration_state='REGISTERED_DISABLED', operational_state='DISABLED', revocation_epoch=gen_random_uuid() where id=$1", [row.server_id]);
      await client.query("update access_token set revoked_at=coalesce(revoked_at,now()) where server_id=$1", [row.server_id]);
    }
    await recordTransition(client, jobId, from, "CANCELLED", "job.cancelled", {}, correlationId);
    await appendAudit(client, { eventType: "onboarding.cancelled", actorType, actorId, objectType: "onboarding_job", objectId: jobId, correlationId });
  });
}

export async function cleanupIntegrationTokens(db: Db): Promise<number> {
  return tx(db, async (client) => {
    await client.query("update egress_capability set revoked_at=coalesce(revoked_at,now()) where expires_at<now() and revoked_at is null");
    const result = await client.query(
      `update integration_token
          set deleted_at=now(), revoked_at=coalesce(revoked_at,now()), lock_version=lock_version+1
        where deleted_at is null
          and coalesce(revoked_at, expires_at) < now()-interval '30 days'
        returning id,fingerprint,onboarding_job_id`
    );
    for (const row of result.rows) {
      await appendAudit(client, {
        eventType: "integration_token.auto_deleted", actorType: "system", objectType: "integration_token", objectId: String(row.id),
        after: { fingerprint: row.fingerprint, jobId: row.onboarding_job_id }, correlationId: randomUUID()
      });
    }
    return result.rowCount ?? 0;
  });
}

export async function pauseExpiredOnboardingJobs(db: Db): Promise<Array<{ id: string; code: string; serverId: string | null }>> {
  return tx(db, async (client) => {
    const expired = await client.query(
      `select oj.id,oj.code,oj.server_id,oj.state,oj.correlation_id,it.id as token_id
         from onboarding_job oj join integration_token it on it.id=oj.token_id
        where it.expires_at<=now()
          and oj.state not in ('ACTIVE','FAILED','QUARANTINED','CANCELLED')
          and oj.blocking_error_code is distinct from 'integration_token_expired'
        for update of oj`
    );
    for (const row of expired.rows) {
      await client.query(
        `update onboarding_job set blocking_error_code='integration_token_expired',
                blocking_error_detail='The current integration token expired; issue a resume token for this job.',
                lease_owner=null,lease_expires_at=null,lock_version=lock_version+1 where id=$1`,
        [row.id]
      );
      await client.query("update egress_capability set revoked_at=coalesce(revoked_at,now()) where job_id=$1", [row.id]);
      if (row.server_id) {
        await client.query(
          "update mcp_server set enabled=false,registration_state='REGISTERED_DISABLED',operational_state='DISABLED',revocation_epoch=gen_random_uuid(),lock_version=lock_version+1 where id=$1",
          [row.server_id]
        );
        await client.query("update access_token set revoked_at=coalesce(revoked_at,now()) where server_id=$1", [row.server_id]);
      }
      await client.query(
        `insert into onboarding_event(job_id,from_state,to_state,event_type,detail,correlation_id)
         values ($1,$2,$2,'integration_token.expired',$3,$4)`,
        [row.id, row.state, JSON.stringify({ tokenId: row.token_id, serverDisabled: Boolean(row.server_id) }), row.correlation_id]
      );
      await appendAudit(client, {
        eventType: "onboarding.integration_token_expired", actorType: "system", objectType: "onboarding_job", objectId: String(row.id),
        after: { tokenId: row.token_id, state: row.state, serverDisabled: Boolean(row.server_id) }, correlationId: String(row.correlation_id)
      });
    }
    return expired.rows.map((row) => ({ id: String(row.id), code: String(row.code), serverId: row.server_id ? String(row.server_id) : null }));
  });
}

export async function listOnboardingJobs(db: Db) {
  const result = await db.query("select * from onboarding_job order by created_at desc limit 200");
  return result.rows.map(mapJob);
}

export async function getOnboardingJob(db: Db, jobId: string) {
  const [job, gates, events] = await Promise.all([
    db.query("select * from onboarding_job where id=$1", [jobId]),
    db.query("select gate_name,stage,status,evidence,correlation_id,started_at,completed_at,updated_at from onboarding_gate where job_id=$1 order by stage,gate_name", [jobId]),
    db.query("select id,from_state,to_state,event_type,detail,correlation_id,created_at from onboarding_event where job_id=$1 order by id", [jobId])
  ]);
  if (!job.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
  return {
    ...mapJob(job.rows[0]),
    gates: gates.rows,
    events: events.rows
  };
}

export function mapJob(row: Record<string, unknown>) {
  const hostname = optionalText(row.hostname);
  const state = String(row.state) as OnboardingJobState;
  const blockingErrorCode = optionalText(row.blocking_error_code);
  return {
    id: String(row.id),
    state,
    correlationId: String(row.correlation_id),
    lockVersion: Number(row.lock_version),
    sourceRevision: Number(row.source_revision),
    code: optionalText(row.code),
    hostname,
    resource: hostname ? `https://${hostname}/mcp` : null,
    toolName: optionalText(row.tool_name),
    serverId: optionalText(row.server_id),
    manifestDigest: optionalText(row.manifest_digest),
    sourceDigest: optionalText(row.source_digest),
    githubBranch: optionalText(row.github_branch),
    githubPrNumber: row.github_pr_number ? Number(row.github_pr_number) : null,
    githubPrUrl: optionalText(row.github_pr_url),
    sourceCommit: optionalText(row.source_commit),
    buildId: optionalText(row.build_id),
    imageReference: optionalText(row.image_reference),
    imageDigest: optionalText(row.image_digest),
    sbomDigest: optionalText(row.sbom_digest),
    provenanceDigest: optionalText(row.provenance_digest),
    blockingErrorCode,
    blockingErrorDetail: optionalText(row.blocking_error_detail),
    programmerAction: programmerActionForState(state, blockingErrorCode),
    createdAt: asIso(row.created_at),
    updatedAt: asIso(row.updated_at),
    completedAt: asIso(row.completed_at)
  };
}
