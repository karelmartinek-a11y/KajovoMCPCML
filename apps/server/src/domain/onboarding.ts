import { createHash, randomBytes, randomUUID } from "node:crypto";
import type pg from "pg";
import type { IntegrationTokenConfig } from "../config.js";
import type { Db } from "../db.js";
import { tx } from "../db.js";
import { fingerprintSecret, hmacToken } from "../security/secrets.js";
import { appendAudit } from "./audit.js";
import { kcmlCodeFromNumber, kcmlHostnameForCode } from "./hostnames.js";
import type { OnboardingManifest } from "./registration.js";
import { KCML_RELEASE } from "./release.js";
import { transitionServerState } from "./server-state.js";

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

async function disableOnboardingServer(client: pg.PoolClient, serverId: string, reason: string, correlationId: string): Promise<void> {
  const result = await client.query("select registration_state from mcp_server where id=$1", [serverId]);
  if (!result.rowCount) return;
  const state = String(result.rows[0].registration_state);
  if (["TRIAL", "ACTIVE", "TEST_FAILED"].includes(state)) {
    await transitionServerState(client, {
      serverId,
      to: "REGISTERED_DISABLED",
      actorType: "system",
      reason,
      correlationId
    });
    return;
  }
  await client.query("update access_token set revoked_at=coalesce(revoked_at,now()) where server_id=$1", [serverId]);
  await client.query("update egress_capability set revoked_at=coalesce(revoked_at,now()) where server_id=$1", [serverId]);
}

export const TERMINAL_JOB_STATES = new Set<OnboardingJobState>(["REGISTERED_DISABLED", "ACTIVE", "FAILED", "QUARANTINED", "CANCELLED"]);
const INITIAL_TTL_MS = 24 * 60 * 60 * 1000;

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
  ACTIVE: new Set(["AWAITING_REVISION"]),
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
  serviceKind: "COMPONENT" | "MCP" | "EXTERNAL_API";
  allowedPipeline: "COMPONENT_ONBOARDING" | "MCP_ONBOARDING" | "EXTERNAL_API_REGISTRATION";
  tokenKind: "SINGLE_COMPONENT";
  releaseVersion: string;
  maxChildJobs: number;
};

export type SourceEvidence = {
  archivePath: string;
  sourceDigest: string;
  requestDigest: string;
  manifestDigest: string;
  validation: Record<string, unknown>;
};

export type OnboardingDescriptor = {
  summary: string;
  businessPurpose: string;
  serviceOwner: string;
  technicalOwner: string;
  criticality: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
};

export type CreateIntegrationTokenOptions = {
  serviceKind?: "COMPONENT" | "MCP" | "EXTERNAL_API";
  allowedPipeline?: "COMPONENT_ONBOARDING" | "MCP_ONBOARDING" | "EXTERNAL_API_REGISTRATION";
  tokenKind?: "SINGLE_COMPONENT";
  releaseVersion?: string;
  maxChildJobs?: number;
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
  if (state === "REGISTERED_DISABLED") {
    return { kind: "COMPLETE" as const, canUploadRevision: false, message: "Registration completed successfully and the managed service remains disabled until an administrator explicitly enables API access." };
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
    maxExpiresAt: initialExpiresAt
  };
}

export function nextHeartbeatExpiry(now: Date, current: Date, maximum: Date): Date {
  void now;
  void maximum;
  return current;
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
  const descriptor = row.descriptor && typeof row.descriptor === "object"
    ? row.descriptor as Record<string, unknown>
    : {};
  return {
    id: String(row.id),
    label: String(row.label),
    fingerprint: String(row.fingerprint),
    descriptor: {
      summary: typeof descriptor.summary === "string" ? descriptor.summary : String(row.label),
      businessPurpose: typeof descriptor.businessPurpose === "string" ? descriptor.businessPurpose : "",
      serviceOwner: typeof descriptor.serviceOwner === "string" ? descriptor.serviceOwner : "",
      technicalOwner: typeof descriptor.technicalOwner === "string" ? descriptor.technicalOwner : "",
      criticality: typeof descriptor.criticality === "string" ? descriptor.criticality as OnboardingDescriptor["criticality"] : "MEDIUM"
    } satisfies OnboardingDescriptor,
    legacyBackfill: Boolean(row.legacy_backfill),
    serviceKind: optionalText(row.service_kind) ?? "COMPONENT",
    allowedPipeline: optionalText(row.allowed_pipeline) ?? "COMPONENT_ONBOARDING",
    tokenKind: optionalText(row.token_kind) ?? "SINGLE_COMPONENT",
    releaseVersion: optionalText(row.release_version) ?? KCML_RELEASE.catalogVersion,
    maxChildJobs: Number(row.max_child_jobs ?? 1),
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

function normalizeTokenOptions(options?: CreateIntegrationTokenOptions): Required<Pick<CreateIntegrationTokenOptions, "serviceKind" | "allowedPipeline" | "tokenKind" | "releaseVersion" | "maxChildJobs">> {
  const tokenKind = "SINGLE_COMPONENT";
  const releaseVersion = options?.releaseVersion ?? KCML_RELEASE.catalogVersion;
  const maxChildJobs = 1;
  return {
    serviceKind: options?.serviceKind ?? "COMPONENT",
    allowedPipeline: options?.allowedPipeline ?? "COMPONENT_ONBOARDING",
    tokenKind,
    releaseVersion,
    maxChildJobs
  };
}

export async function createIntegrationToken(
  db: Db,
  config: IntegrationTokenConfig,
  actorId: string,
  correlationId: string,
  label: string,
  descriptor: OnboardingDescriptor,
  resumeJobId?: string,
  options?: CreateIntegrationTokenOptions
) {
  if (resumeJobId) throw Object.assign(new Error("resume_token_not_supported"), { statusCode: 410 });
  const secret = issueIntegrationSecret();
  const deadlines = tokenDeadlines();
  const digest = hmacToken(secret.value, config.INTEGRATION_TOKEN_HMAC_KEY_BASE64);
  const normalizedOptions = normalizeTokenOptions(options);
  const result = await tx(db, async (client) => {
    const inserted = await client.query(
      `insert into integration_token
        (label, lookup_digest, key_id, fingerprint, created_by, onboarding_job_id,
         descriptor, service_kind, allowed_pipeline, token_kind, release_version,
         max_child_jobs, auto_activate_after_pass,
         manual_approval_required_after_issuance, issued_at, initial_expires_at, expires_at, max_expires_at)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
       returning *`,
      [label, digest, config.INTEGRATION_TOKEN_HMAC_KEY_ID, secret.fingerprint, actorId, resumeJobId ?? null, descriptor,
        normalizedOptions.serviceKind, normalizedOptions.allowedPipeline, normalizedOptions.tokenKind,
        normalizedOptions.releaseVersion, normalizedOptions.maxChildJobs, false,
        false,
        deadlines.issuedAt, deadlines.initialExpiresAt, deadlines.expiresAt, deadlines.maxExpiresAt]
    );
    await appendAudit(client, {
      eventType: "integration_token.created",
      actorType: "admin",
      actorId,
      objectType: "integration_token",
      objectId: inserted.rows[0].id,
       after: {
         label,
         descriptor,
         serviceKind: normalizedOptions.serviceKind,
         allowedPipeline: normalizedOptions.allowedPipeline,
         tokenKind: "LEGACY_INTERNAL_METADATA",
         releaseVersion: normalizedOptions.releaseVersion,
         genericComponentScope: true,
         maxChildJobs: normalizedOptions.maxChildJobs,
         fingerprint: secret.fingerprint,
         initialExpiresAt: deadlines.initialExpiresAt,
         maxExpiresAt: deadlines.maxExpiresAt
       },
      correlationId
    });
    return inserted.rows[0] as Record<string, unknown>;
  });
  return {
    ...mapToken(result),
    token: secret.value
  };
}

export async function beginActiveServerRevision(db: Db, serverId: string, actorId: string, correlationId: string): Promise<string> {
  return tx(db, async (client) => {
    const result = await client.query(
      `select oj.id,oj.state,ms.code,ms.registration_state
         from onboarding_job oj
         join mcp_server ms on ms.id=oj.server_id
        where ms.id=$1
        for update of oj,ms`,
      [serverId]
    );
    if (!result.rowCount) throw Object.assign(new Error("onboarding_job_not_found"), { statusCode: 404 });
    const row = result.rows[0];
    if (String(row.state) === "AWAITING_REVISION") return String(row.id);
    if (String(row.state) !== "ACTIVE" || String(row.registration_state) !== "ACTIVE") {
      throw Object.assign(new Error("active_server_revision_not_available"), { statusCode: 409 });
    }
    assertTransition("ACTIVE", "AWAITING_REVISION");
    await client.query(
      `update onboarding_job
          set state='AWAITING_REVISION',completed_at=null,next_run_at=now(),
              blocking_error_code='registration_revision_required',
              blocking_error_detail='Upload a complete manifest 1.5 and evidence bundle.',
              lock_version=lock_version+1
        where id=$1`,
      [row.id]
    );
    await recordTransition(client, String(row.id), "ACTIVE", "AWAITING_REVISION", "registration_revision.requested", { serverId }, correlationId);
    await appendAudit(client, {
      eventType: "registration_revision.requested",
      actorType: "admin",
      actorId,
      objectType: "mcp_server",
      objectId: serverId,
      after: { code: row.code, onboardingJobId: row.id, requiredSchemaVersion: "1.5" },
      correlationId
    });
    return String(row.id);
  });
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

export async function authenticateIntegrationToken(db: Db, token: string, config: IntegrationTokenConfig): Promise<IntegrationTokenPrincipal> {
  if (!token.startsWith("kci_") || token.length < 80 || token.length > 100) throw new Error("invalid_integration_token");
  const digest = hmacToken(token, config.INTEGRATION_TOKEN_HMAC_KEY_BASE64);
  const result = await db.query(
    `select it.id, it.onboarding_job_id, it.fingerprint, it.expires_at, it.max_expires_at,
            it.service_kind, it.allowed_pipeline, it.token_kind, it.release_version,it.max_child_jobs
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
  await db.query("update integration_token set last_used_at=now(), usage_count=usage_count+1 where id=$1", [result.rows[0].id]);
  return {
    id: String(result.rows[0].id),
    jobId: result.rows[0].onboarding_job_id ? String(result.rows[0].onboarding_job_id) : null,
    fingerprint: String(result.rows[0].fingerprint),
    expiresAt: String(result.rows[0].expires_at),
    maxExpiresAt: String(result.rows[0].max_expires_at),
    serviceKind: (optionalText(result.rows[0].service_kind) ?? "COMPONENT") as IntegrationTokenPrincipal["serviceKind"],
    allowedPipeline: (optionalText(result.rows[0].allowed_pipeline) ?? "COMPONENT_ONBOARDING") as IntegrationTokenPrincipal["allowedPipeline"],
    tokenKind: (optionalText(result.rows[0].token_kind) ?? "SINGLE_COMPONENT") as IntegrationTokenPrincipal["tokenKind"],
    releaseVersion: optionalText(result.rows[0].release_version) ?? KCML_RELEASE.catalogVersion,
    maxChildJobs: Number(result.rows[0].max_child_jobs ?? 1)
  };
}

function toolNameFor(code: string, handlerKey: string): string {
  return `${code.toLowerCase()}_${handlerKey}`.replace(/[^a-z0-9_-]/g, "_");
}

export async function createOnboardingJob(
  db: Db,
  config: { PUBLIC_BASE_DOMAIN: string },
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
    const code = kcmlCodeFromNumber(number);
    const hostname = kcmlHostnameForCode(code, config.PUBLIC_BASE_DOMAIN);
    const toolName = toolNameFor(code, manifest.handlerKey);
    const job = await client.query(
      `insert into onboarding_job
        (token_id, state, correlation_id, manifest, manifest_digest, source_digest,
         source_archive_path, source_revision, kcml_number, code, hostname, tool_name, service_kind)
       values ($1,'SOURCE_UPLOADED',$2,$3,$4,$5,$6,1,$7,$8,$9,$10,$11)
       returning *`,
      [principal.id, correlationId, manifest, evidence.manifestDigest, evidence.sourceDigest,
        evidence.archivePath, number, code, hostname, toolName, principal.serviceKind]
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

export const MCP_ONBOARDING_GATES = [
    ["archive_policy", "intake"], ["manifest_schema", "intake"], ["secret_scan", "intake"], ["dependency_policy", "intake"],
    ["path_policy", "ci"], ["lint", "ci"], ["typecheck", "ci"], ["unit_tests", "ci"], ["contract_tests", "ci"],
    ["sast", "ci"], ["sca", "ci"], ["license", "ci"], ["sbom", "ci"], ["reproducible_build", "ci"],
    ["source_commit", "supply_chain"], ["image_signature", "supply_chain"], ["image_digest", "supply_chain"], ["provenance", "supply_chain"],
    ["runtime_isolation", "deploy"], ["worker_readiness", "deploy"], ["dns", "preflight"], ["tls_san", "preflight"], ["host_routing", "preflight"],
    ["oauth_metadata", "trial"], ["audience_binding", "trial"], ["negative_auth", "trial"], ["mcp_initialize", "trial"],
    ["mcp_tools_list", "trial"], ["safe_tools_call", "trial"], ["cross_host", "trial"], ["schema_contract", "trial"],
    ["correlation_chain", "trial"], ["logging_redaction", "trial"], ["audit_persistence", "trial"], ["monitoring_probes", "trial"]
  ] as const;

async function initializeGates(client: pg.PoolClient, jobId: string, correlationId: string): Promise<void> {
  for (const [name, stage] of MCP_ONBOARDING_GATES) {
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
      `select it.expires_at
         from onboarding_job oj join integration_token it on it.id=oj.token_id
        where oj.id=$1 and oj.lease_owner=$2 and it.expires_at>now() and it.revoked_at is null
        for update of oj, it`,
      [jobId, workerId]
    );
    if (!result.rowCount) throw Object.assign(new Error("job_lease_lost"), { statusCode: 409 });
    const row = result.rows[0];
    const current = new Date(row.expires_at);
    await client.query("update onboarding_job set heartbeat_at=now(), lease_expires_at=now()+interval '1 minute' where id=$1", [jobId]);
    return { expiresAt: current.toISOString(), extended: false };
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

export async function deleteRegisteredServer(db: Db, serverId: string, actorId: string, correlationId: string, reason: string): Promise<void> {
  await tx(db, async (client) => {
    const server = await client.query(
      `select id, code, hostname, tool_name, display_name, registration_state, operational_state, active_revision_id
         from mcp_server
        where id=$1
        for update`,
      [serverId]
    );
    if (!server.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    const serverRow = server.rows[0];
    const jobs = await client.query(
      `select id, token_id, state
         from onboarding_job
        where server_id=$1 or code=$2
        for update`,
      [serverId, serverRow.code]
    );
    const jobIds = jobs.rows.map((row) => String(row.id));
    const tokenIds = [...new Set(jobs.rows.map((row) => String(row.token_id)))];
    const tokenFingerprints = tokenIds.length
      ? await client.query(
        `select id, fingerprint
           from integration_token
          where id = any($1::uuid[])
          for update`,
        [tokenIds]
      )
      : { rows: [] as Array<{ id: string; fingerprint: string }> };
    const managed = await client.query(
      `select id, code
         from managed_service
        where legacy_mcp_server_id=$1
        for update`,
      [serverId]
    );
    const managedIds = managed.rows.map((row) => String(row.id));

    await client.query("update access_token set revoked_at=coalesce(revoked_at,now()) where server_id=$1", [serverId]);
    await client.query("update egress_capability set revoked_at=coalesce(revoked_at,now()) where server_id=$1", [serverId]);

    if (tokenIds.length) {
      await client.query(
        `update integration_token
            set revoked_at=coalesce(revoked_at,now()),
                deleted_at=coalesce(deleted_at,now()),
                lock_version=lock_version+1
          where id = any($1::uuid[])`,
        [tokenIds]
      );
    }

    if (jobIds.length) {
      await client.query(
        `update onboarding_job
            set archived_at=coalesce(archived_at,now()),
                archive_reason=$2,
                runtime_stopped_at=coalesce(runtime_stopped_at,now()),
                lease_owner=null,
                lease_expires_at=null,
                state=case when state in ('ACTIVE','REGISTERED_DISABLED','TRIAL_TESTING') then 'CANCELLED'::onboarding_job_state else state end,
                lock_version=lock_version+1
          where id = any($1::uuid[])`,
        [jobIds, reason]
      );
    }

    if (managedIds.length) {
      await client.query(
        `update managed_service
            set enabled=false,
                lifecycle_state='RETIRED',
                api_state='DISABLED',
                retired_at=coalesce(retired_at,now()),
                lock_version=lock_version+1
          where id = any($1::uuid[])`,
        [managedIds]
      );
    }

    await client.query(
      `update mcp_server
          set enabled=false,
              registration_state='RETIRED'::registration_state,
              operational_state='RETIRED'::operational_state,
              retired_at=coalesce(retired_at,now()),
              archived_at=coalesce(archived_at,now()),
              archive_reason=$2,
              lock_version=lock_version+1
        where id=$1`,
      [serverId, reason]
    );
    await client.query(
      `update component c
          set enabled=false,
              ingress_enabled=false,
              pulse_enabled=false,
              egress_enabled=false,
              lifecycle_state='RETIRED',
              activation_state='INACTIVE',
              operational_state='RETIRED',
              retired_at=coalesce(c.retired_at,now()),
              lock_version=c.lock_version+1
         from mcp_server server
        where server.id=$1
          and c.id=server.component_id`,
      [serverId]
    );

    await appendAudit(client, {
      eventType: "mcp_server.archived",
      actorType: "admin",
      actorId,
      objectType: "mcp_server",
      objectId: serverId,
      before: {
        code: serverRow.code,
        hostname: serverRow.hostname,
        toolName: serverRow.tool_name,
        displayName: serverRow.display_name,
        registrationState: serverRow.registration_state,
        operationalState: serverRow.operational_state,
        onboardingJobIds: jobIds,
        integrationTokenFingerprints: tokenFingerprints.rows.map((row) => String(row.fingerprint)),
        managedServiceIds: managedIds
      },
      after: {
        archived: true,
        runtimeAccessRevoked: true,
        code: serverRow.code,
        reason
      },
      correlationId
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
      await disableOnboardingServer(client, String(row.server_id), "onboarding_job_cancelled", correlationId);
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
        for update of oj`
    );
    for (const row of expired.rows) {
      await client.query(
        `update onboarding_job
            set state='CANCELLED',
                completed_at=now(),
                archived_at=coalesce(archived_at,now()),
                archive_reason='integration_token_expired',
                blocking_error_code=null,
                blocking_error_detail=null,
                lease_owner=null,
                lease_expires_at=null,
                runtime_stopped_at=coalesce(runtime_stopped_at,now()),
                lock_version=lock_version+1
          where id=$1`,
        [row.id]
      );
      await client.query("update integration_token set revoked_at=coalesce(revoked_at,now()), lock_version=lock_version+1 where id=$1", [row.token_id]);
      await client.query("update egress_capability set revoked_at=coalesce(revoked_at,now()) where job_id=$1", [row.id]);
      if (row.server_id) {
        await disableOnboardingServer(client, String(row.server_id), "integration_token_expired", String(row.correlation_id));
      }
      await client.query(
        `insert into onboarding_event(job_id,from_state,to_state,event_type,detail,correlation_id)
         values ($1,$2,'CANCELLED','integration_token.expired_cleanup',$3,$4)`,
        [row.id, row.state, JSON.stringify({ tokenId: row.token_id, serverDisabled: Boolean(row.server_id) }), row.correlation_id]
      );
      await appendAudit(client, {
        eventType: "onboarding.integration_token_expired_cleanup", actorType: "system", objectType: "onboarding_job", objectId: String(row.id),
        after: { tokenId: row.token_id, previousState: row.state, runtimeVisible: false, serverDisabled: Boolean(row.server_id) }, correlationId: String(row.correlation_id)
      });
    }
    return expired.rows.map((row) => ({ id: String(row.id), code: String(row.code), serverId: row.server_id ? String(row.server_id) : null }));
  });
}

export async function listOnboardingJobs(db: Db) {
  const result = await db.query("select * from onboarding_job where archived_at is null order by created_at desc limit 200");
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
