import { createHash, randomUUID } from "node:crypto";
import type { Db } from "../db.js";
import { tx } from "../db.js";
import { hmacToken, issueOpaqueSecret } from "../security/secrets.js";
import { appendAudit } from "./audit.js";

export const COMPONENT_CATALOG_VERSION = "2026.07.21";
export const MCP_REQUIRED_CAPABILITIES = [
  "mcp.initialize",
  "mcp.notifications.initialized",
  "mcp.tools.list",
  "mcp.tools.call"
] as const;
export const ACTIVATION_GATES = [
  "AUTHORIZATION",
  "PUBLIC_ENDPOINT",
  "TECHNICAL_DISABLE",
  "MONITORING",
  "AUDIT_CONTINUITY"
] as const;

export type ComponentManifest = {
  schemaVersion: "2026.07.21";
  name: string;
  description?: string;
  category: "AI_CLIENT" | "AI_AGENT" | "MCP_SERVER" | "MANAGED_RUNTIME" | "EXTERNAL_SERVICE" | "PLATFORM_SERVICE";
  registrationType: string;
  role: "CLIENT" | "AGENT" | "SERVICE" | "RUNTIME" | "PLATFORM";
  revision: string;
  capabilities: string[];
  protocols: string[];
  transports: string[];
  owners: Record<string, unknown>;
  contacts?: Record<string, unknown>;
  monitoring: { enabled: boolean };
  audit: { enabled: boolean; replaySupported: boolean };
  authorization: { mode: "OAUTH2_CLIENT_CREDENTIALS" };
  endpoint: { public: boolean };
  technicalDisable: { supported: boolean };
};

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
}

export function componentManifestDigest(manifest: ComponentManifest): string {
  return createHash("sha256").update(canonicalJson(manifest)).digest("hex");
}

function text(value: unknown): string {
  return typeof value === "string" || typeof value === "number" || typeof value === "boolean" ? String(value) : "";
}

function optionalText(value: unknown): string | null {
  const resolved = text(value);
  return resolved || null;
}

export function validateComponentManifest(input: unknown): ComponentManifest {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw Object.assign(new Error("invalid_manifest"), { statusCode: 400 });
  const value = input as Record<string, unknown>;
  const category = text(value.category) as ComponentManifest["category"];
  const role = text(value.role) as ComponentManifest["role"];
  const capabilities = Array.isArray(value.capabilities) ? [...new Set(value.capabilities.map(String))].sort() : [];
  const protocols = Array.isArray(value.protocols) ? [...new Set(value.protocols.map(String))].sort() : [];
  const transports = Array.isArray(value.transports) ? [...new Set(value.transports.map(String))].sort() : [];
  const allowedCategories: ComponentManifest["category"][] = ["AI_CLIENT", "AI_AGENT", "MCP_SERVER", "MANAGED_RUNTIME", "EXTERNAL_SERVICE", "PLATFORM_SERVICE"];
  const allowedRoles: ComponentManifest["role"][] = ["CLIENT", "AGENT", "SERVICE", "RUNTIME", "PLATFORM"];
  if (value.schemaVersion !== COMPONENT_CATALOG_VERSION
    || typeof value.name !== "string" || value.name.trim().length < 2
    || typeof value.registrationType !== "string" || !value.registrationType.trim()
    || typeof value.revision !== "string" || !value.revision.trim()
    || !allowedCategories.includes(category) || !allowedRoles.includes(role)
    || !value.owners || typeof value.owners !== "object"
    || !value.monitoring || typeof value.monitoring !== "object"
    || !value.audit || typeof value.audit !== "object"
    || !value.authorization || typeof value.authorization !== "object"
    || !value.endpoint || typeof value.endpoint !== "object"
    || !value.technicalDisable || typeof value.technicalDisable !== "object") {
    throw Object.assign(new Error("invalid_manifest"), { statusCode: 400 });
  }
  if (category === "MCP_SERVER" && MCP_REQUIRED_CAPABILITIES.some((capability) => !capabilities.includes(capability))) {
    throw Object.assign(new Error("catalog_incompatible"), { statusCode: 409 });
  }
  return {
    schemaVersion: COMPONENT_CATALOG_VERSION,
    name: value.name.trim(),
    description: typeof value.description === "string" ? value.description.trim() : "",
    category,
    registrationType: value.registrationType.trim(),
    role,
    revision: value.revision.trim(),
    capabilities,
    protocols,
    transports,
    owners: value.owners as Record<string, unknown>,
    contacts: value.contacts && typeof value.contacts === "object" ? value.contacts as Record<string, unknown> : {},
    monitoring: value.monitoring as ComponentManifest["monitoring"],
    audit: value.audit as ComponentManifest["audit"],
    authorization: value.authorization as ComponentManifest["authorization"],
    endpoint: value.endpoint as ComponentManifest["endpoint"],
    technicalDisable: value.technicalDisable as ComponentManifest["technicalDisable"]
  };
}

function gateResults(manifest: ComponentManifest): Array<{ gate: typeof ACTIVATION_GATES[number]; passed: boolean }> {
  return [
    { gate: "AUTHORIZATION", passed: manifest.authorization.mode === "OAUTH2_CLIENT_CREDENTIALS" },
    { gate: "PUBLIC_ENDPOINT", passed: manifest.endpoint.public === true },
    { gate: "TECHNICAL_DISABLE", passed: manifest.technicalDisable.supported === true },
    { gate: "MONITORING", passed: manifest.monitoring.enabled === true },
    { gate: "AUDIT_CONTINUITY", passed: manifest.audit.enabled === true && manifest.audit.replaySupported === true }
  ];
}

export async function createComponentOnboarding(db: Db, params: {
  integrationTokenId: string;
  idempotencyKey: string;
  manifest: ComponentManifest;
  claimHmacKey: Buffer;
  baseDomain: string;
  correlationId: string;
}): Promise<Record<string, unknown>> {
  const digest = componentManifestDigest(params.manifest);
  return tx(db, async (client) => {
    const existing = await client.query(
      "select * from component_onboarding_job where integration_token_id=$1 and idempotency_key=$2 for update",
      [params.integrationTokenId, params.idempotencyKey]
    );
    if (existing.rowCount) {
      if (String(existing.rows[0].request_digest) !== digest) throw Object.assign(new Error("idempotency_conflict"), { statusCode: 409 });
      return componentOnboardingView(existing.rows[0]);
    }
    const identity = await client.query("select nextval('kcml_number_seq')::bigint as number");
    const number = Number(identity.rows[0].number);
    const code = `KCML${String(number).padStart(4, "0")}`;
    const hostname = `${code.toLowerCase()}.${params.baseDomain}`;
    const componentId = randomUUID();
    await client.query(
      `insert into component(
        id,kcml_number,code,hostname,display_name,description,category,registration_type,component_role,owners,contacts,
        lifecycle_state,activation_state,operational_state,monitoring_state,enabled,release_version
      ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,'REVIEW','INACTIVE','UNKNOWN',$12,false,$13)`,
      [componentId, number, code, hostname, params.manifest.name, params.manifest.description ?? "", params.manifest.category,
        params.manifest.registrationType, params.manifest.role, JSON.stringify(params.manifest.owners), JSON.stringify(params.manifest.contacts ?? {}),
        params.manifest.monitoring.enabled ? "PENDING" : "NOT_CONFIGURED", COMPONENT_CATALOG_VERSION]
    );
    const revision = await client.query(
      `insert into component_revision(
        component_id,revision,manifest,manifest_digest,capabilities,protocols,transports,derived_gates
      ) values ($1,$2,$3::jsonb,$4,$5::text[],$6::text[],$7::text[],$8::jsonb) returning id`,
      [componentId, params.manifest.revision, JSON.stringify(params.manifest), digest, params.manifest.capabilities,
        params.manifest.protocols, params.manifest.transports, JSON.stringify(ACTIVATION_GATES)]
    );
    await client.query("insert into component_audit_stream(component_id) values ($1)", [componentId]);
    const inserted = await client.query(
      `insert into component_onboarding_job(
        integration_token_id,component_id,idempotency_key,request_digest,category,registration_type,manifest,manifest_digest,state
      ) values ($1,$2,$3,$4,$5,$6,$7::jsonb,$4,'IN_REVIEW') returning *`,
      [params.integrationTokenId, componentId, params.idempotencyKey, digest, params.manifest.category, params.manifest.registrationType, JSON.stringify(params.manifest)]
    );
    await client.query("update component set active_revision_id=$2 where id=$1", [componentId, revision.rows[0].id]);
    await appendAudit(client, {
      eventType: "component_onboarding.created", actorType: "integration_token", actorId: params.integrationTokenId,
      objectType: "component", objectId: componentId, after: { code, hostname, catalogVersion: COMPONENT_CATALOG_VERSION }, correlationId: params.correlationId
    });
    return componentOnboardingView(inserted.rows[0]);
  });
}

function componentOnboardingView(row: Record<string, unknown>): Record<string, unknown> {
  return {
    id: String(row.id),
    componentId: optionalText(row.component_id),
    state: String(row.state),
    category: String(row.category),
    registrationType: String(row.registration_type),
    manifestDigest: String(row.manifest_digest),
    gateResults: row.gate_results ?? [],
    credentialClaimAvailable: Boolean(row.credential_claim_digest) && !row.credential_claimed_at,
    failureCode: optionalText(row.failure_code),
    lockVersion: Number(row.lock_version),
    releaseVersion: String(row.release_version),
    createdAt: String(row.created_at),
    updatedAt: String(row.updated_at)
  };
}

export async function getComponentOnboarding(db: Db, jobId: string, integrationTokenId?: string): Promise<Record<string, unknown>> {
  const result = await db.query(
    `select * from component_onboarding_job where id=$1${integrationTokenId ? " and integration_token_id=$2" : ""}`,
    integrationTokenId ? [jobId, integrationTokenId] : [jobId]
  );
  if (!result.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
  return componentOnboardingView(result.rows[0]);
}

export async function reviseComponentOnboarding(db: Db, params: {
  jobId: string;
  integrationTokenId: string;
  manifest: ComponentManifest;
  correlationId: string;
}): Promise<Record<string, unknown>> {
  const digest = componentManifestDigest(params.manifest);
  return tx(db, async (client) => {
    const current = await client.query(
      "select * from component_onboarding_job where id=$1 and integration_token_id=$2 for update",
      [params.jobId, params.integrationTokenId]
    );
    if (!current.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    const job = current.rows[0];
    if (["ACTIVE", "CANCELLED"].includes(String(job.state))) throw Object.assign(new Error("invalid_state"), { statusCode: 409 });
    const revision = await client.query(
      `insert into component_revision(component_id,revision,manifest,manifest_digest,capabilities,protocols,transports,derived_gates)
       values ($1,$2,$3::jsonb,$4,$5::text[],$6::text[],$7::text[],$8::jsonb)
       on conflict (component_id,revision) do update set manifest=excluded.manifest,manifest_digest=excluded.manifest_digest,
         capabilities=excluded.capabilities,protocols=excluded.protocols,transports=excluded.transports,validation_state='PENDING',evidence='{}'::jsonb
       returning id`,
      [job.component_id, params.manifest.revision, JSON.stringify(params.manifest), digest, params.manifest.capabilities,
        params.manifest.protocols, params.manifest.transports, JSON.stringify(ACTIVATION_GATES)]
    );
    await client.query("update component set active_revision_id=$2,lifecycle_state='REVIEW',activation_state='INACTIVE',enabled=false,ingress_enabled=false,pulse_enabled=false,egress_enabled=false where id=$1", [job.component_id, revision.rows[0].id]);
    const updated = await client.query(
      `update component_onboarding_job set manifest=$2::jsonb,manifest_digest=$3,request_digest=$3,state='IN_REVIEW',
        gate_results='[]'::jsonb,credential_claim_digest=null,credential_claim_expires_at=null,failure_code=null,
        lock_version=lock_version+1,updated_at=now() where id=$1 returning *`,
      [params.jobId, JSON.stringify(params.manifest), digest]
    );
    await appendAudit(client, {
      eventType: "component_onboarding.revised", actorType: "integration_token", actorId: params.integrationTokenId,
      objectType: "component", objectId: String(job.component_id), after: { revision: params.manifest.revision, manifestDigest: digest }, correlationId: params.correlationId
    });
    return componentOnboardingView(updated.rows[0]);
  });
}

export async function evaluateComponentReadiness(db: Db, params: {
  jobId: string;
  integrationTokenId: string;
  claimHmacKey: Buffer;
  correlationId: string;
}): Promise<{ job: Record<string, unknown>; credentialClaimToken?: string }> {
  return tx(db, async (client) => {
    const jobResult = await client.query(
      "select * from component_onboarding_job where id=$1 and integration_token_id=$2 for update",
      [params.jobId, params.integrationTokenId]
    );
    if (!jobResult.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    const job = jobResult.rows[0];
    if (["CANCELLED", "FAILED"].includes(String(job.state))) throw Object.assign(new Error("invalid_state"), { statusCode: 409 });
    const manifest = validateComponentManifest(job.manifest);
    const gates = gateResults(manifest);
    const passed = gates.every((gate) => gate.passed);
    let claimToken: string | undefined;
    let claimDigest: Buffer | null = job.credential_claim_digest ?? null;
    if (passed && !job.credential_id && !job.credential_claimed_at) {
      claimToken = issueOpaqueSecret().value;
      claimDigest = hmacToken(claimToken, params.claimHmacKey);
    }
    const updated = await client.query(
      `update component_onboarding_job
          set state=$2, gate_results=$3::jsonb, credential_claim_digest=coalesce(credential_claim_digest,$4),
              credential_claim_expires_at=case when credential_claimed_at is null then coalesce(credential_claim_expires_at,now()+interval '24 hours') else credential_claim_expires_at end,
              lock_version=lock_version+1, updated_at=now()
        where id=$1 returning *`,
      [params.jobId, passed ? "READY" : "GATES_PENDING", JSON.stringify(gates), claimDigest]
    );
    await client.query(
      "update component set lifecycle_state=$2,activation_state=$3,monitoring_state=$4 where id=$1",
      [job.component_id, passed ? "APPROVED" : "REVIEW", passed ? "READY" : "BLOCKED", manifest.monitoring.enabled ? "PENDING" : "NOT_CONFIGURED"]
    );
    await client.query(
      `update component_revision set validation_state=$2,approved_at=case when $2='APPROVED' then now() else approved_at end
        where id=(select active_revision_id from component where id=$1)`,
      [job.component_id, passed ? "APPROVED" : "PENDING"]
    );
    await appendAudit(client, {
      eventType: "component_onboarding.readiness_evaluated", actorType: "integration_token", actorId: params.integrationTokenId,
      objectType: "component", objectId: String(job.component_id), after: { passed, gates }, correlationId: params.correlationId
    });
    return { job: componentOnboardingView(updated.rows[0]), ...(claimToken ? { credentialClaimToken: claimToken } : {}) };
  });
}

export async function claimComponentCredential(db: Db, params: {
  jobId: string;
  integrationTokenId: string;
  claimToken: string;
  claimHmacKey: Buffer;
  credentialHmacKey: Buffer;
  keyId: string;
  correlationId: string;
}): Promise<{ clientId: string; clientSecret: string; fingerprint: string }> {
  return tx(db, async (client) => {
    const claimDigest = hmacToken(params.claimToken, params.claimHmacKey);
    const result = await client.query(
      `select job.*,component.code
         from component_onboarding_job job join component on component.id=job.component_id
        where job.id=$1 and job.integration_token_id=$2 for update`,
      [params.jobId, params.integrationTokenId]
    );
    if (!result.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    const job = result.rows[0];
    if (job.state !== "READY" || job.credential_claimed_at || !job.credential_claim_digest
      || !Buffer.from(job.credential_claim_digest).equals(claimDigest)
      || !job.credential_claim_expires_at || new Date(job.credential_claim_expires_at).getTime() <= Date.now()) {
      throw Object.assign(new Error("credential_claim_invalid"), { statusCode: 409 });
    }
    const secret = issueOpaqueSecret();
    const clientId = `${String(job.code).toUpperCase()}-C01`;
    const credential = await client.query(
      `insert into component_credential(component_id,public_id,key_id,secret_digest,secret_fingerprint)
       values ($1,$2,$3,$4,$5) returning id`,
      [job.component_id, clientId, params.keyId, hmacToken(secret.value, params.credentialHmacKey), secret.fingerprint]
    );
    await client.query(
      `update component_onboarding_job
          set credential_id=$2,credential_claimed_at=now(),credential_claim_digest=null,lock_version=lock_version+1,updated_at=now()
        where id=$1`,
      [params.jobId, credential.rows[0].id]
    );
    await appendAudit(client, {
      eventType: "component_credential.claimed", actorType: "integration_token", actorId: params.integrationTokenId,
      objectType: "component_credential", objectId: String(credential.rows[0].id),
      after: { clientId, fingerprint: secret.fingerprint }, correlationId: params.correlationId
    });
    return { clientId, clientSecret: secret.value, fingerprint: secret.fingerprint };
  });
}

export async function cancelComponentOnboarding(db: Db, jobId: string, integrationTokenId: string, correlationId: string): Promise<Record<string, unknown>> {
  return tx(db, async (client) => {
    const updated = await client.query(
      `update component_onboarding_job set state='CANCELLED',cancelled_at=now(),updated_at=now(),lock_version=lock_version+1
        where id=$1 and integration_token_id=$2 and state not in ('ACTIVE','CANCELLED') returning *`,
      [jobId, integrationTokenId]
    );
    if (!updated.rowCount) throw Object.assign(new Error("invalid_state"), { statusCode: 409 });
    await client.query("update component set enabled=false,ingress_enabled=false,pulse_enabled=false,egress_enabled=false,activation_state='INACTIVE' where id=$1", [updated.rows[0].component_id]);
    await appendAudit(client, {
      eventType: "component_onboarding.cancelled", actorType: "integration_token", actorId: integrationTokenId,
      objectType: "component", objectId: String(updated.rows[0].component_id), correlationId
    });
    return componentOnboardingView(updated.rows[0]);
  });
}

export async function listComponents(db: Db): Promise<Record<string, unknown>[]> {
  const result = await db.query(`
    select c.*,r.revision,r.capabilities,r.protocols,r.transports,
      (select count(*)::int from component_permission p where (p.source_component_id=c.id or p.target_component_id=c.id) and p.revoked_at is null) permission_count,
      (select count(*)::int from component_credential cr where cr.component_id=c.id and cr.status='ACTIVE') credential_count,
      stream.gap_state,stream.highest_received_sequence,stream.highest_acknowledged_sequence
    from component c
    left join component_revision r on r.id=c.active_revision_id
    left join component_audit_stream stream on stream.component_id=c.id
    order by c.kcml_number`);
  return result.rows.map(componentView);
}

export async function getComponent(db: Db, id: string): Promise<Record<string, unknown>> {
  const result = await db.query(`
    select c.*,r.revision,r.capabilities,r.protocols,r.transports,r.derived_gates,
      stream.gap_state,stream.highest_received_sequence,stream.highest_acknowledged_sequence
    from component c
    left join component_revision r on r.id=c.active_revision_id
    left join component_audit_stream stream on stream.component_id=c.id
    where c.id=$1`, [id]);
  if (!result.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
  const permissions = await db.query(`select id,source_component_id,target_component_id,route_pattern,scope_name,access_level,granted_at,revoked_at from component_permission where source_component_id=$1 or target_component_id=$1 order by granted_at desc`, [id]);
  const credentials = await db.query(`select id,public_id,secret_fingerprint,status,issued_at,expires_at,last_used_at,revoked_at from component_credential where component_id=$1 order by issued_at desc`, [id]);
  return { ...componentView(result.rows[0]), permissions: permissions.rows, credentials: credentials.rows };
}

function componentView(row: Record<string, unknown>): Record<string, unknown> {
  return {
    id: String(row.id), code: String(row.code), hostname: String(row.hostname), displayName: String(row.display_name), description: String(row.description),
    category: String(row.category), registrationType: String(row.registration_type), role: String(row.component_role), owners: row.owners, contacts: row.contacts,
    lifecycleState: String(row.lifecycle_state), activationState: String(row.activation_state), operationalState: String(row.operational_state),
    monitoringState: String(row.monitoring_state), recertificationState: String(row.recertification_state), enabled: Boolean(row.enabled),
    ingressEnabled: Boolean(row.ingress_enabled), pulseEnabled: Boolean(row.pulse_enabled), egressEnabled: Boolean(row.egress_enabled),
    revision: optionalText(row.revision), capabilities: row.capabilities ?? [], protocols: row.protocols ?? [], transports: row.transports ?? [],
    permissionCount: Number(row.permission_count ?? 0), credentialCount: Number(row.credential_count ?? 0), policyEpoch: Number(row.policy_epoch),
    audit: { gapState: optionalText(row.gap_state) ?? "UNAVAILABLE", highestReceivedSequence: Number(row.highest_received_sequence ?? 0), highestAcknowledgedSequence: Number(row.highest_acknowledged_sequence ?? 0) },
    releaseVersion: String(row.release_version), createdAt: String(row.created_at), updatedAt: String(row.updated_at)
  };
}

export async function setComponentActivation(db: Db, params: { componentId: string; enabled: boolean; actorId: string; correlationId: string }): Promise<Record<string, unknown>> {
  return tx(db, async (client) => {
    const current = await client.query(`
      select c.*,r.validation_state,stream.gap_state
      from component c left join component_revision r on r.id=c.active_revision_id
      left join component_audit_stream stream on stream.component_id=c.id
      where c.id=$1 for update of c`, [params.componentId]);
    if (!current.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    const component = current.rows[0];
    if (params.enabled) {
      if (!component.active_revision_id || component.validation_state !== "APPROVED") throw Object.assign(new Error("catalog_incompatible"), { statusCode: 409 });
      if (component.monitoring_state !== "HEALTHY") throw Object.assign(new Error("monitoring_failed"), { statusCode: 409 });
      if (component.gap_state !== "CONTIGUOUS") throw Object.assign(new Error("audit_gap"), { statusCode: 409 });
    }
    const updated = await client.query(
      `update component set enabled=$2,ingress_enabled=$2,pulse_enabled=$2,egress_enabled=$2,
        activation_state=case when $2 then 'ACTIVE' else 'READY' end,
        lifecycle_state=case when $2 then 'ACTIVE' else case when lifecycle_state='ACTIVE' then 'APPROVED' else lifecycle_state end end,
        operational_state=case when $2 then 'HEALTHY' else 'DISABLED' end,
        lock_version=lock_version+1 where id=$1 returning id`,
      [params.componentId, params.enabled]
    );
    await appendAudit(client, {
      eventType: params.enabled ? "component.activated" : "component.deactivated", actorType: "admin", actorId: params.actorId,
      objectType: "component", objectId: params.componentId,
      before: { enabled: component.enabled, revocationEpoch: component.revocation_epoch, policyEpoch: component.policy_epoch },
      after: { enabled: params.enabled, credentialRevoked: false }, correlationId: params.correlationId
    });
    return getComponent(client as unknown as Db, String(updated.rows[0].id));
  });
}

export type ComponentLifecycleAction = "QUARANTINE" | "RESTORE" | "RETIRE" | "DEREGISTER";

export async function setComponentLifecycle(db: Db, params: {
  componentId: string;
  action: ComponentLifecycleAction;
  actorId: string;
  correlationId: string;
}): Promise<Record<string, unknown>> {
  return tx(db, async (client) => {
    const current = await client.query("select * from component where id=$1 for update", [params.componentId]);
    if (!current.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    const component = current.rows[0];
    if (params.action === "RESTORE" && !["QUARANTINED", "SUSPENDED"].includes(String(component.lifecycle_state))) {
      throw Object.assign(new Error("invalid_state"), { statusCode: 409 });
    }
    if (params.action === "RETIRE" && component.lifecycle_state === "DEREGISTERED") {
      throw Object.assign(new Error("invalid_state"), { statusCode: 409 });
    }
    if (params.action === "DEREGISTER" && component.lifecycle_state !== "RETIRED") {
      throw Object.assign(new Error("component_must_be_retired"), { statusCode: 409 });
    }
    const states = {
      QUARANTINE: { lifecycle: "QUARANTINED", activation: "BLOCKED", operational: "QUARANTINED" },
      RESTORE: { lifecycle: "APPROVED", activation: "READY", operational: "DISABLED" },
      RETIRE: { lifecycle: "RETIRED", activation: "INACTIVE", operational: "RETIRED" },
      DEREGISTER: { lifecycle: "DEREGISTERED", activation: "INACTIVE", operational: "RETIRED" }
    } as const;
    const next = states[params.action];
    await client.query(
      `update component set lifecycle_state=$2,activation_state=$3,operational_state=$4,
        enabled=false,ingress_enabled=false,pulse_enabled=false,egress_enabled=false,
        retired_at=case when $5 in ('RETIRE','DEREGISTER') then coalesce(retired_at,now()) else retired_at end,
        deregistered_at=case when $5='DEREGISTER' then now() else deregistered_at end,
        lock_version=lock_version+1 where id=$1`,
      [params.componentId, next.lifecycle, next.activation, next.operational, params.action]
    );
    await appendAudit(client, {
      eventType: `component.lifecycle.${params.action.toLowerCase()}`, actorType: "admin", actorId: params.actorId,
      objectType: "component", objectId: params.componentId,
      before: { lifecycleState: component.lifecycle_state, activationState: component.activation_state, operationalState: component.operational_state },
      after: { lifecycleState: next.lifecycle, activationState: next.activation, operationalState: next.operational, credentialRevoked: false },
      correlationId: params.correlationId
    });
    return getComponent(client as unknown as Db, params.componentId);
  });
}

export async function setComponentPermissionEnabled(db: Db, params: {
  componentId: string;
  permissionId: string;
  enabled: boolean;
  actorId: string;
  correlationId: string;
}): Promise<Record<string, unknown>> {
  return tx(db, async (client) => {
    const permission = await client.query(
      `select * from component_permission
        where id=$1 and (source_component_id=$2 or target_component_id=$2) for update`,
      [params.permissionId, params.componentId]
    );
    if (!permission.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    const current = permission.rows[0];
    await client.query(
      "update component_permission set revoked_at=case when $2 then null else coalesce(revoked_at,now()) end where id=$1",
      [params.permissionId, params.enabled]
    );
    await client.query(
      "update component set policy_epoch=policy_epoch+1 where id=any($1::uuid[])",
      [[current.source_component_id, current.target_component_id]]
    );
    await appendAudit(client, {
      eventType: params.enabled ? "component_permission.restored" : "component_permission.revoked",
      actorType: "admin", actorId: params.actorId, objectType: "component_permission", objectId: params.permissionId,
      before: { revoked: Boolean(current.revoked_at) },
      after: { revoked: !params.enabled, scope: current.scope_name, route: current.route_pattern },
      correlationId: params.correlationId
    });
    return getComponent(client as unknown as Db, params.componentId);
  });
}

export async function revokeComponentCredential(db: Db, params: {
  componentId: string;
  credentialId: string;
  actorId: string;
  correlationId: string;
}): Promise<Record<string, unknown>> {
  return tx(db, async (client) => {
    const credential = await client.query(
      "select * from component_credential where id=$1 and component_id=$2 for update",
      [params.credentialId, params.componentId]
    );
    if (!credential.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    if (credential.rows[0].status === "REVOKED") throw Object.assign(new Error("credential_already_revoked"), { statusCode: 409 });
    await client.query(
      "update component_credential set status='REVOKED',revoked_at=now(),revocation_epoch=gen_random_uuid() where id=$1",
      [params.credentialId]
    );
    await client.query("update component_access_token set revoked_at=coalesce(revoked_at,now()) where credential_id=$1", [params.credentialId]);
    await appendAudit(client, {
      eventType: "component_credential.revoked", actorType: "admin", actorId: params.actorId,
      objectType: "component_credential", objectId: params.credentialId,
      before: { status: credential.rows[0].status, fingerprint: credential.rows[0].secret_fingerprint },
      after: { status: "REVOKED" }, correlationId: params.correlationId
    });
    return getComponent(client as unknown as Db, params.componentId);
  });
}

export async function rotateComponentCredential(db: Db, params: {
  componentId: string;
  credentialId: string;
  actorId: string;
  credentialHmacKey: Buffer;
  keyId: string;
  correlationId: string;
}): Promise<{ component: Record<string, unknown>; credential: { clientId: string; clientSecret: string; fingerprint: string } }> {
  return tx(db, async (client) => {
    const credential = await client.query(
      `select credential.*,component.code from component_credential credential
        join component on component.id=credential.component_id
        where credential.id=$1 and credential.component_id=$2 for update of credential`,
      [params.credentialId, params.componentId]
    );
    if (!credential.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    if (credential.rows[0].status !== "ACTIVE") throw Object.assign(new Error("invalid_state"), { statusCode: 409 });
    const nextNumber = await client.query(
      `select coalesce(max(substring(public_id::text from '[-]C([0-9]+)$')::int),0)+1 as value
         from component_credential where component_id=$1`,
      [params.componentId]
    );
    const clientId = `${String(credential.rows[0].code).toUpperCase()}-C${String(nextNumber.rows[0].value).padStart(2, "0")}`;
    const secret = issueOpaqueSecret();
    const inserted = await client.query(
      `insert into component_credential(component_id,public_id,key_id,secret_digest,secret_fingerprint)
       values ($1,$2,$3,$4,$5) returning id`,
      [params.componentId, clientId, params.keyId, hmacToken(secret.value, params.credentialHmacKey), secret.fingerprint]
    );
    await client.query(
      "update component_credential set status='REVOKED',revoked_at=now(),rotated_at=now(),revocation_epoch=gen_random_uuid() where id=$1",
      [params.credentialId]
    );
    await client.query("update component_access_token set revoked_at=coalesce(revoked_at,now()) where credential_id=$1", [params.credentialId]);
    await appendAudit(client, {
      eventType: "component_credential.rotated", actorType: "admin", actorId: params.actorId,
      objectType: "component_credential", objectId: String(inserted.rows[0].id),
      before: { credentialId: params.credentialId, fingerprint: credential.rows[0].secret_fingerprint },
      after: { clientId, fingerprint: secret.fingerprint }, correlationId: params.correlationId
    });
    return {
      component: await getComponent(client as unknown as Db, params.componentId),
      credential: { clientId, clientSecret: secret.value, fingerprint: secret.fingerprint }
    };
  });
}
