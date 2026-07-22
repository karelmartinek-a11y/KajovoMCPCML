import { createHash, randomUUID } from "node:crypto";
import { Ajv2020 } from "ajv/dist/2020.js";
import type pg from "pg";
import componentManifestSchema from "../contracts/component-manifest-2026.07.22-compliance.1.schema.json" with { type: "json" };
import type { Db } from "../db.js";
import { tx } from "../db.js";
import { decryptVaultSecret, encryptVaultSecret, hmacToken, issueOpaqueSecret } from "../security/secrets.js";
import { appendAudit } from "./audit.js";
import { authorizeComponentCall, componentSourceIdentityMatches } from "./component-auth.js";
import { KCML_RELEASE } from "./release.js";
import { resolveSecret, type SecretPrincipal } from "./secret-manager.js";

export const COMPONENT_CATALOG_VERSION = KCML_RELEASE.catalogVersion;
export const MCP_REQUIRED_CAPABILITIES = [
  "mcp.initialize",
  "mcp.notifications.initialized",
  "mcp.tools.list",
  "mcp.tools.call"
] as const;
export const ACTIVATION_GATES = [
  "MANIFEST_SCHEMA",
  "ARTIFACT_PROVENANCE",
  "DOCUMENT_CONTENT",
  "HOST_EXCLUSIVITY",
  "TLS_IDENTITY",
  "NEGATIVE_AUTH_MISSING_TOKEN",
  "NEGATIVE_AUTH_EXPIRED_TOKEN",
  "NEGATIVE_AUTH_WRONG_AUDIENCE",
  "NEGATIVE_AUTH_WRONG_CLIENT",
  "NEGATIVE_AUTH_MISSING_SCOPE",
  "NEGATIVE_AUTH_REVOKED_PERMISSION",
  "TOKEN_EPOCH_INVALIDATION",
  "EACH_TOOL_LISTED",
  "EACH_TOOL_POSITIVE_CALL",
  "EACH_TOOL_INPUT_NEGATIVE",
  "EACH_TOOL_OUTPUT_SCHEMA",
  "EACH_ENDPOINT_VARIANT",
  "EACH_INCOMING_PULSE_VARIANT",
  "EACH_OUTGOING_PULSE_VARIANT",
  "REGISTERED_TO_REGISTERED_DISPATCH",
  "EXTERNAL_PRINCIPAL_INBOUND",
  "EXTERNAL_TARGET_OUTBOUND",
  "STATE_FULL_SNAPSHOT",
  "EACH_STATE_SCHEMA",
  "EACH_STATE_TRANSITION",
  "ENABLE_CONTROL",
  "DISABLE_CONTROL",
  "STATE_QUERY_CONTROL",
  "HEARTBEAT_PUSH",
  "HEARTBEAT_CHALLENGE",
  "E2E_ALL_SCENARIOS",
  "SECRET_ALLOWED",
  "SECRET_DENIED",
  "AUDIT_CONTINUITY",
  "AUDIT_PAYLOAD_INTEGRITY",
  "OPERATION_LEASE_ENFORCEMENT",
  "MONITORING_WATCHDOG",
  "RECERTIFICATION"
] as const;

export const STRICT_COMPONENT_HOST_SUFFIX = "kajovocml.hcasc.cz";

export type JsonRecord = Record<string, unknown>;

export type ComponentManifest = JsonRecord & {
  schemaVersion: typeof COMPONENT_CATALOG_VERSION;
  registrationRevision: string;
  displayName: string;
  businessPurpose: string;
  kind: string;
  owners: unknown[];
  contacts: unknown[];
  criticality: JsonRecord;
  artifact: JsonRecord;
  runtime: JsonRecord;
  capabilities: string[];
  tools: JsonRecord[];
  endpoints: JsonRecord[];
  pulses: { incoming: JsonRecord[]; outgoing: JsonRecord[] };
  auditPolicy: JsonRecord;
  monitoring: JsonRecord;
  states: { states: JsonRecord[]; transitions: JsonRecord[] };
  e2eScenarios: JsonRecord[];
  documentationEvidence: JsonRecord[];
  controlPlane: JsonRecord;
  outboundPolicies: JsonRecord[];
  secretPolicy: JsonRecord;
};

type GateResult = {
  gate: typeof ACTIVATION_GATES[number];
  status: "PASS" | "FAIL";
  reasonCode: string;
  evaluatorVersion: string;
  evidence: JsonRecord;
  expiresAt: string | null;
  requestDigest?: string | null;
  responseDigest?: string | null;
  variant?: string | null;
};

const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: false });
const validateCatalogComponentManifest = ajv.compile(componentManifestSchema);

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

function record(value: unknown): JsonRecord | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as JsonRecord : null;
}

function isEmptyObjectSchema(value: unknown): boolean {
  const schema = record(value);
  if (!schema) return false;
  const keys = Object.keys(schema);
  return schema.type === "object" && (!Array.isArray(schema.required) || schema.required.length === 0)
    && (!record(schema.properties) || Object.keys(record(schema.properties) ?? {}).length === 0)
    && keys.every((key) => ["type", "additionalProperties", "$schema", "title", "description"].includes(key));
}

function isPayloadSkeletonSchema(value: unknown): boolean {
  const schema = record(value);
  const properties = record(schema?.properties);
  const payload = record(properties?.payload);
  return schema?.type === "object"
    && Array.isArray(schema.required)
    && schema.required.length === 1
    && schema.required[0] === "payload"
    && schema.additionalProperties === false
    && Boolean(payload)
    && payload?.type === "object"
    && Number(payload?.minProperties ?? 0) === 1
    && !record(payload?.properties);
}

function fakeDigest(value: unknown): boolean {
  const digest = text(value);
  const match = /^sha256:([a-f0-9]{64})$/i.exec(digest);
  if (!match) return true;
  return /^([a-f0-9])\1{63}$/i.test(match[1]!);
}

function rejectPlaceholderSchemas(value: unknown, path = "manifest"): void {
  if (isEmptyObjectSchema(value)) throw Object.assign(new Error(`placeholder_schema:${path}`), { statusCode: 400 });
  if (isPayloadSkeletonSchema(value)) throw Object.assign(new Error(`placeholder_schema:${path}`), { statusCode: 400 });
  if (Array.isArray(value)) {
    value.forEach((item, index) => rejectPlaceholderSchemas(item, `${path}[${index}]`));
    return;
  }
  const candidate = record(value);
  if (!candidate) return;
  for (const [key, nested] of Object.entries(candidate)) {
    if (key.toLowerCase().includes("schema") || key === "expectedOutput") rejectPlaceholderSchemas(nested, `${path}.${key}`);
    else if (Array.isArray(nested) || record(nested)) rejectPlaceholderSchemas(nested, `${path}.${key}`);
  }
}

function nonPlaceholderRef(value: unknown): boolean {
  const ref = text(value).trim();
  return ref.length >= 3 && !/(^|[/_.-])(todo|tbd|placeholder|example|sample|stub)([/_.-]|$)/i.test(ref);
}

function rejectIncompleteContract(manifest: ComponentManifest): void {
  if (!manifest.states.states.length) throw Object.assign(new Error("state_contract_required"), { statusCode: 400 });
  if (!manifest.e2eScenarios.length) throw Object.assign(new Error("e2e_scenarios_required"), { statusCode: 400 });
  if (!manifest.documentationEvidence.length) throw Object.assign(new Error("documentation_evidence_required"), { statusCode: 400 });
  const requiredCapabilities = new Set([
    "mcp.initialize", "mcp.notifications.initialized", "mcp.tools.list", "mcp.tools.call",
    "component.control.ack", "component.state.query", "component.heartbeat", "component.audit.write"
  ]);
  if (manifest.pulses.incoming.length) requiredCapabilities.add("component.pulse");
  if (manifest.pulses.outgoing.length) requiredCapabilities.add("component.outbound.pulse");
  const declaredCapabilities = new Set(manifest.capabilities);
  const missingCapability = [...requiredCapabilities].find((capability) => !declaredCapabilities.has(capability));
  if (missingCapability) throw Object.assign(new Error(`required_capability_not_declared:${missingCapability}`), { statusCode: 400 });
  const artifactType = text(manifest.artifact.type);
  if (artifactType === "SOURCE_PACKAGE" && !record(manifest.artifact.buildContract)) {
    throw Object.assign(new Error("source_build_contract_required"), { statusCode: 400 });
  }
  if (manifest.runtime.transport === "HTTPS" && (!optionalText(manifest.runtime.upstream) || !optionalText(manifest.runtime.tlsIdentity))) {
    throw Object.assign(new Error("remote_runtime_tls_contract_required"), { statusCode: 400 });
  }
  if (manifest.runtime.transport === "UDS" && !optionalText(manifest.runtime.socketPath)) {
    throw Object.assign(new Error("runtime_socket_required"), { statusCode: 400 });
  }
  for (const evidence of manifest.documentationEvidence) {
    if (!nonPlaceholderRef(evidence.path) || fakeDigest(evidence.digest) || !record(evidence.content)) {
      throw Object.assign(new Error("manifest_evidence_missing"), { statusCode: 400 });
    }
  }
  for (const scenario of manifest.e2eScenarios) {
    if (!record(scenario.input) || !record(scenario.expected) || !record(scenario.invocation)) {
      throw Object.assign(new Error("e2e_fixture_required"), { statusCode: 400 });
    }
  }
  if (fakeDigest(manifest.artifact.digest) || fakeDigest(manifest.runtime.runtimeDigest)) {
    throw Object.assign(new Error("integrity_digest_invalid"), { statusCode: 400 });
  }
  rejectPlaceholderSchemas(manifest);
}

function manifestRevision(manifest: ComponentManifest): string {
  return text(manifest.registrationRevision);
}

function manifestCapabilities(manifest: ComponentManifest): string[] {
  return [...new Set(manifest.capabilities.map(String))].sort();
}

function manifestProtocols(manifest: ComponentManifest): string[] {
  const protocols = new Set(["KCML_CONTROL"]);
  if (manifest.capabilities.some((capability) => capability.startsWith("mcp.")) || manifest.tools.length) protocols.add("MCP");
  if (manifest.pulses.incoming.length || manifest.pulses.outgoing.length) protocols.add("KCML_PULSE");
  return [...protocols].sort();
}

function manifestTransports(manifest: ComponentManifest): string[] {
  return [text(manifest.runtime.transport), ...(manifest.tools.length ? ["STREAMABLE_HTTP"] : [])].sort();
}

export function validateComponentManifest(input: unknown): ComponentManifest {
  if (!validateCatalogComponentManifest(input)) {
    throw Object.assign(new Error("invalid_manifest"), { statusCode: 400, errors: validateCatalogComponentManifest.errors });
  }
  const manifest = input as ComponentManifest;
  rejectIncompleteContract(manifest);
  return manifest;
}

function evidenceDigest(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

function manifestContent(value: unknown): { bytes: Buffer; mediaType: string; json: unknown; digest: string } {
  const content = record(value);
  if (!content) throw Object.assign(new Error("fixture_content_invalid"), { statusCode: 400 });
  const mediaType = text(content.mediaType);
  const json = Object.hasOwn(content, "json") ? content.json : null;
  const bytes = json !== null ? Buffer.from(canonicalJson(json)) : Buffer.from(text(content.base64), "base64");
  if (!bytes.length) throw Object.assign(new Error("fixture_content_empty"), { statusCode: 400 });
  return { bytes, mediaType, json, digest: `sha256:${createHash("sha256").update(bytes).digest("hex")}` };
}

function statePayloadMatchesCommand(expectedStateKey: string | null, payload: unknown): boolean {
  if (!expectedStateKey) return false;
  const body = record(payload);
  const candidates = [body, ...Object.values(body ?? {}).map(record)].filter((value): value is JsonRecord => Boolean(value));
  const activationState = candidates.map((value) => text(value.activationState).toUpperCase()).find(Boolean) ?? "";
  const operationalState = candidates.map((value) => text(value.operationalState).toUpperCase()).find(Boolean) ?? "";
  const enabled = candidates.map((value) => typeof value.enabled === "boolean" ? value.enabled : null).find((value) => value !== null) ?? null;
  if (expectedStateKey === "ENABLED") {
    return enabled === true || activationState === "ACTIVE" || operationalState === "HEALTHY";
  }
  if (expectedStateKey === "DISABLED") {
    return enabled === false || activationState === "DISABLED" || operationalState === "DISABLED";
  }
  return activationState === expectedStateKey || operationalState === expectedStateKey;
}

async function gateResults(db: Db, componentId: string, manifest: ComponentManifest, authorizationSnapshot: Record<string, unknown>): Promise<GateResult[]> {
  void authorizationSnapshot;
  const evidence = await db.query(
    `select c.hostname,c.recertification_state,c.active_revision_id,r.manifest_digest,target.runtime_digest,
            target.transport,target.upstream,target.expected_tls_identity,target.socket_path,
            stream.gap_state,stream.integrity_state,
            (select count(*)::int from component other where other.hostname=c.hostname) as hostname_owners
       from component c
       join component_revision r on r.id=c.active_revision_id
       left join component_runtime_target target on target.component_id=c.id and target.revision_id=r.id
       left join component_audit_stream stream on stream.component_id=c.id
      where c.id=$1`,
    [componentId]
  );
  const row = evidence.rows[0] ?? {};
  const documentation = await db.query(
    `select evidence_key,evidence_digest,content
       from component_documentation_evidence
      where component_id=$1 and revision_id=$2`,
    [componentId, row.active_revision_id]
  );
  const declaredDocumentation = new Map(manifest.documentationEvidence.map((item) => [text(item.key), text(item.digest)]));
  const documentationValid = documentation.rows.length === declaredDocumentation.size && documentation.rows.every((item) => {
    const content = Buffer.isBuffer(item.content) ? item.content : Buffer.from(item.content ?? "");
    const computed = `sha256:${createHash("sha256").update(content).digest("hex")}`;
    return declaredDocumentation.get(String(item.evidence_key)) === computed && String(item.evidence_digest) === computed;
  });
  const now = new Date().toISOString();
  const manifestDigest = componentManifestDigest(manifest);
  const prior = await db.query(
    `select distinct on (gate_key) gate_key,status,reason_code,evaluator_version,evidence,expires_at,
            request_digest,response_digest,variant
       from component_readiness_gate_evidence
      where component_id=$1 and revision_id=$2 and revision_digest=$3 and runtime_digest is not distinct from $4
        and (expires_at is null or expires_at>now())
      order by gate_key,executed_at desc`,
    [componentId, row.active_revision_id, row.manifest_digest, row.runtime_digest]
  );
  const priorByGate = new Map(prior.rows.map((item) => [String(item.gate_key), item]));
  const tools = await db.query(
    `select name,input_schema,output_schema,scope_name from component_tool_contract
      where component_id=$1 and revision_id=$2 order by name`,
    [componentId, row.active_revision_id]
  );
  const declaredTools = [...manifest.tools].sort((left, right) => text(left.name).localeCompare(text(right.name)));
  const toolContractsMatch = tools.rows.length === declaredTools.length && tools.rows.every((stored, index) => {
    const declared = declaredTools[index];
    if (!declared) return false;
    return String(stored.name) === text(declared.name)
      && canonicalJson(stored.input_schema) === canonicalJson(declared.inputSchema)
      && canonicalJson(stored.output_schema) === canonicalJson(declared.outputSchema)
      && String(stored.scope_name) === text(declared.scope);
  });
  const negativeInputResults = tools.rows.map((tool) => {
    const validate = ajv.compile(tool.input_schema);
    const candidates: unknown[] = [null, [], {}, { __kcmlUnexpected: true }];
    return { name: String(tool.name), rejected: candidates.some((candidate) => !validate(candidate)) };
  });
  const externalContracts = await db.query(
    `select
       (select count(*)::int from principal_component_permission permission where permission.target_component_id=$1 and permission.revoked_at is null
         and exists(select 1 from component_external_principal external where external.principal_id=permission.source_principal_id and external.status='ACTIVE')) inbound_count,
       (select count(*)::int from component_external_permission permission where permission.component_id=$1 and permission.revoked_at is null) outbound_count`,
    [componentId]
  );
  const runtime = record(manifest.runtime) ?? {};
  const artifact = record(manifest.artifact) ?? {};
  const provenance = record(artifact.provenance) ?? {};
  const digestPattern = /^sha256:[a-f0-9]{64}$/;
  let provenanceIssuerValid = false;
  try {
    provenanceIssuerValid = new URL(text(provenance.issuer)).protocol === "https:";
  } catch {
    provenanceIssuerValid = false;
  }
  const artifactProvenanceValid = digestPattern.test(text(artifact.digest))
    && digestPattern.test(text(runtime.runtimeDigest))
    && text(runtime.runtimeDigest) === String(row.runtime_digest)
    && provenanceIssuerValid;
  let transportIdentityValid = false;
  if (row.transport === "HTTPS") {
    try {
      const upstream = new URL(String(row.upstream));
      transportIdentityValid = upstream.protocol === "https:" && upstream.hostname === String(row.expected_tls_identity)
        && text(runtime.tlsIdentity) === String(row.expected_tls_identity);
    } catch {
      transportIdentityValid = false;
    }
  } else if (row.transport === "UDS") {
    const socketPath: string = typeof row.socket_path === "string" ? String(row.socket_path) : "";
    transportIdentityValid = socketPath.startsWith("/") && text(runtime.transport) === "UDS";
  }
  const direct = new Map<string, { pass: boolean; reason: string; evidence: JsonRecord }>([
    ["MANIFEST_SCHEMA", { pass: row.manifest_digest === manifestDigest, reason: "manifest_schema_and_digest_recomputed", evidence: { schemaVersion: manifest.schemaVersion, manifestDigest } }],
    ["ARTIFACT_PROVENANCE", { pass: artifactProvenanceValid, reason: "artifact_and_runtime_provenance_recomputed", evidence: { artifactDigest: artifact.digest ?? null, runtimeDigest: row.runtime_digest ?? null, issuer: provenance.issuer ?? null } }],
    ["DOCUMENT_CONTENT", { pass: documentationValid, reason: "documentation_bytes_and_digests_recomputed", evidence: { declaredKeys: [...declaredDocumentation.keys()].sort(), storedKeys: documentation.rows.map((item) => String(item.evidence_key)).sort() } }],
    ["HOST_EXCLUSIVITY", { pass: Number(row.hostname_owners) === 1 && String(row.hostname).endsWith(`.${STRICT_COMPONENT_HOST_SUFFIX}`), reason: "canonical_hostname_exclusivity_recomputed", evidence: { hostname: row.hostname, owners: Number(row.hostname_owners) } }],
    ["TLS_IDENTITY", { pass: transportIdentityValid, reason: row.transport === "UDS" ? "uds_peer_boundary_recomputed" : "https_tls_identity_recomputed", evidence: { transport: row.transport ?? null, upstream: row.upstream ?? null, tlsIdentity: row.expected_tls_identity ?? null, socketPath: row.socket_path ?? null } }],
    ["EACH_TOOL_LISTED", { pass: toolContractsMatch, reason: "canonical_tool_catalog_recomputed", evidence: { declared: declaredTools.map((tool) => text(tool.name)), stored: tools.rows.map((tool) => String(tool.name)) } }],
    ["EACH_TOOL_INPUT_NEGATIVE", { pass: negativeInputResults.every((result) => result.rejected), reason: "tool_invalid_inputs_actively_rejected", evidence: { results: negativeInputResults } }],
    ["AUDIT_CONTINUITY", { pass: manifest.auditPolicy.technicalAudit === "PLATFORM" && row.gap_state === "CONTIGUOUS", reason: "audit_sequence_recomputed", evidence: { gapState: row.gap_state ?? null } }],
    ["AUDIT_PAYLOAD_INTEGRITY", { pass: row.integrity_state === "VALID", reason: "audit_chain_integrity_recomputed", evidence: { integrityState: row.integrity_state ?? null } }],
    ["RECERTIFICATION", { pass: ["NOT_DUE", "PASSED"].includes(String(row.recertification_state)), reason: "recertification_state_recomputed", evidence: { recertificationState: row.recertification_state ?? null } }]
  ]);
  if (Number(externalContracts.rows[0]?.inbound_count ?? 0) === 0) direct.set("EXTERNAL_PRINCIPAL_INBOUND", {
    pass: true, reason: "no_external_inbound_grants_declared", evidence: { declaredExternalInboundGrants: 0 }
  });
  if (manifest.outboundPolicies.length === 0 && Number(externalContracts.rows[0]?.outbound_count ?? 0) === 0) direct.set("EXTERNAL_TARGET_OUTBOUND", {
    pass: true, reason: "no_external_outbound_policies_declared", evidence: { declaredOutboundPolicies: 0, currentExternalPermissions: 0 }
  });
  if (manifest.states.transitions.length === 0) direct.set("EACH_STATE_TRANSITION", {
    pass: true, reason: "no_state_transitions_declared", evidence: { declaredTransitions: 0 }
  });
  return ACTIVATION_GATES.map((gate) => {
    const evaluated = direct.get(gate);
    if (evaluated) return {
      gate, status: evaluated.pass ? "PASS" : "FAIL", reasonCode: evaluated.pass ? evaluated.reason : `${gate.toLowerCase()}_failed`,
      evaluatorVersion: COMPONENT_CATALOG_VERSION, evidence: { ...evaluated.evidence, checkedAt: now }, expiresAt: gate === "RECERTIFICATION" ? new Date(Date.now() + 15 * 60_000).toISOString() : null,
      requestDigest: evidenceDigest({ componentId, gate, manifestDigest }), responseDigest: evidenceDigest(evaluated.evidence), variant: "server_recomputed"
    };
    const active = priorByGate.get(gate);
    if (active?.status === "PASS") return {
      gate, status: "PASS", reasonCode: String(active.reason_code), evaluatorVersion: String(active.evaluator_version),
      evidence: { ...(record(active.evidence) ?? {}), reusedAt: now }, expiresAt: active.expires_at ? new Date(active.expires_at).toISOString() : null,
      requestDigest: optionalText(active.request_digest), responseDigest: optionalText(active.response_digest), variant: optionalText(active.variant)
    };
    return {
      gate, status: "FAIL", reasonCode: "active_evidence_missing", evaluatorVersion: COMPONENT_CATALOG_VERSION,
      evidence: { checkedAt: now, requiredRevisionDigest: row.manifest_digest ?? null, requiredRuntimeDigest: row.runtime_digest ?? null },
      expiresAt: null, requestDigest: null, responseDigest: null, variant: null
    };
  });
}

async function persistGateEvidence(
  client: pg.PoolClient,
  componentId: string,
  revisionId: string,
  gates: GateResult[],
  correlationId: string
): Promise<void> {
  const digests = await client.query(
    `select revision.manifest_digest,target.runtime_digest
       from component_revision revision
       left join component_runtime_target target on target.component_id=revision.component_id and target.revision_id=revision.id
      where revision.id=$1`,
    [revisionId]
  );
  const revisionDigest = optionalText(digests.rows[0]?.manifest_digest);
  const runtimeDigest = optionalText(digests.rows[0]?.runtime_digest);
  await client.query("delete from component_readiness_gate_evidence where component_id=$1 and revision_id=$2", [componentId, revisionId]);
  for (const gate of gates) {
    await client.query(
      `insert into component_readiness_gate_evidence(
        component_id,revision_id,gate_key,evaluator_version,status,reason_code,evidence,evidence_digest,correlation_id,expires_at,
        revision_digest,runtime_digest,artifact_digest,request_digest,response_digest,variant
      ) values ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
      [componentId, revisionId, gate.gate, gate.evaluatorVersion, gate.status, gate.reasonCode, JSON.stringify(gate.evidence), evidenceDigest(gate.evidence), correlationId, gate.expiresAt,
        revisionDigest, runtimeDigest, runtimeDigest, gate.requestDigest ?? null, gate.responseDigest ?? null, gate.variant ?? null]
    );
  }
}

async function recordActiveGateEvidence(client: pg.PoolClient, params: {
  componentId: string;
  revisionId: string;
  gate: typeof ACTIVATION_GATES[number];
  pass: boolean;
  reasonCode: string;
  evidence: JsonRecord;
  correlationId: string;
  requestDigest?: string | null;
  responseDigest?: string | null;
  variant: string;
}): Promise<void> {
  const digests = await client.query(
    `select revision.manifest_digest,target.runtime_digest
       from component_revision revision
       left join component_runtime_target target on target.component_id=revision.component_id and target.revision_id=revision.id
      where revision.id=$1 and revision.component_id=$2`,
    [params.revisionId, params.componentId]
  );
  if (!digests.rowCount) throw Object.assign(new Error("component_revision_not_found"), { statusCode: 409 });
  const runtimeDigest = optionalText(digests.rows[0].runtime_digest);
  await client.query(
    `insert into component_readiness_gate_evidence(
      component_id,revision_id,gate_key,evaluator_version,status,reason_code,evidence,evidence_digest,correlation_id,expires_at,
      revision_digest,runtime_digest,artifact_digest,request_digest,response_digest,variant
    ) values ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,now()+interval '15 minutes',$10,$11,$11,$12,$13,$14)`,
    [params.componentId, params.revisionId, params.gate, COMPONENT_CATALOG_VERSION, params.pass ? "PASS" : "FAIL", params.reasonCode,
      JSON.stringify(params.evidence), evidenceDigest(params.evidence), params.correlationId, digests.rows[0].manifest_digest, runtimeDigest,
      params.requestDigest ?? null, params.responseDigest ?? null, params.variant]
  );
}

async function runAuthorizationReadinessProbes(db: Db, params: {
  jobId: string;
  integrationTokenId: string;
  hmacKey: Buffer;
  hmacKeyId: string;
  correlationId: string;
}): Promise<void> {
  const target = await db.query(
    `select job.component_id,component.active_revision_id,component.code,component.hostname
       from component_onboarding_job job
       join component on component.id=job.component_id
      where job.id=$1 and job.integration_token_id=$2`,
    [params.jobId, params.integrationTokenId]
  );
  if (!target.rowCount || !target.rows[0].active_revision_id) throw Object.assign(new Error("not_found"), { statusCode: 404 });
  const row = target.rows[0];
  const probePrincipalId = randomUUID();
  const probePublicId = `KCML-READINESS-${randomUUID()}`;
  const probeToken = issueOpaqueSecret();
  const probeScope = "platform.control.readiness";
  const probeRoute = "/v1/kcml/readiness/probe";
  const call = (overrides: Partial<Parameters<typeof authorizeComponentCall>[1]> = {}) => authorizeComponentCall(db, {
    token: probeToken.value,
    audience: `https://${String(row.hostname)}`,
    host: String(row.hostname),
    scope: probeScope,
    route: probeRoute,
    hmacKey: params.hmacKey,
    correlationId: params.correlationId,
    ...overrides
  });
  let expiredConstraintEnforced = false;
  try {
    await db.query(
      `insert into principal(id,kind,public_id,status,policy_epoch,revocation_epoch,metadata)
       values ($1,'PLATFORM',$2,'ACTIVE',1,1,$3::jsonb)`,
      [probePrincipalId, probePublicId, JSON.stringify({ purpose: "component_readiness_probe", componentId: row.component_id })]
    );
    await db.query(
      `insert into principal_component_permission(source_principal_id,target_component_id,route_pattern,scope_name)
       values ($1,$2,$3,$4)`,
      [probePrincipalId, row.component_id, probeRoute, probeScope]
    );
    await db.query(
      `insert into principal_access_token(lookup_digest,key_id,fingerprint,source_principal_id,target_component_id,audience,scope_names,issued_policy_epoch,issued_revocation_epoch,expires_at)
       values ($1,$2,$3,$4,null,'*',$5::text[],1,1,'infinity')`,
      [hmacToken(probeToken.value, params.hmacKey), params.hmacKeyId, probeToken.fingerprint, probePrincipalId, [probeScope]]
    );
    const allowed = await call();
    const missingToken = await call({ token: `kca_missing_${randomUUID()}` });
    const wrongAudience = await call({ audience: "https://wrong-audience.invalid" });
    const missingScope = await call({ scope: "platform.control.scope-not-issued" });
    const wrongClientRejected = allowed.allow && !componentSourceIdentityMatches(allowed, { clientId: String(row.code), componentCode: String(row.code) });

    const expiredSecret = issueOpaqueSecret();
    const client = await db.connect();
    try {
      await client.query("begin");
      await client.query("savepoint expired_token_probe");
      try {
        await client.query(
          `insert into principal_access_token(lookup_digest,key_id,fingerprint,source_principal_id,target_component_id,audience,scope_names,issued_policy_epoch,issued_revocation_epoch,expires_at)
           values ($1,$2,$3,$4,null,'*',$5::text[],1,1,now()-interval '1 second')`,
          [hmacToken(expiredSecret.value, params.hmacKey), params.hmacKeyId, expiredSecret.fingerprint, probePrincipalId, [probeScope]]
        );
      } catch (error) {
        expiredConstraintEnforced = Boolean(error && typeof error === "object" && "code" in error && error.code === "23514");
        await client.query("rollback to savepoint expired_token_probe");
      }
      await client.query("rollback");
    } finally {
      client.release();
    }

    await db.query("update principal_component_permission set revoked_at=now() where source_principal_id=$1 and target_component_id=$2 and scope_name=$3", [probePrincipalId, row.component_id, probeScope]);
    const revokedPermission = await call();
    await db.query("update principal_component_permission set revoked_at=null where source_principal_id=$1 and target_component_id=$2 and scope_name=$3", [probePrincipalId, row.component_id, probeScope]);
    await db.query("update principal set revocation_epoch=revocation_epoch+1 where id=$1", [probePrincipalId]);
    const invalidEpoch = await call();

    const outcomes: Array<{ gate: typeof ACTIVATION_GATES[number]; pass: boolean; reason: string; response: unknown; variant: string }> = [
      { gate: "NEGATIVE_AUTH_MISSING_TOKEN", pass: missingToken.reasonCode === "invalid_token", reason: "missing_or_unknown_bearer_rejected", response: missingToken, variant: "unknown_bearer" },
      { gate: "NEGATIVE_AUTH_EXPIRED_TOKEN", pass: expiredConstraintEnforced, reason: "expired_access_token_forbidden_by_database", response: { expiredConstraintEnforced }, variant: "long_lived_token_constraint" },
      { gate: "NEGATIVE_AUTH_WRONG_AUDIENCE", pass: wrongAudience.reasonCode === "invalid_audience", reason: "wrong_audience_rejected", response: wrongAudience, variant: "foreign_https_audience" },
      { gate: "NEGATIVE_AUTH_WRONG_CLIENT", pass: wrongClientRejected, reason: "declared_client_binding_mismatch_rejected", response: { authenticatedClientId: allowed.sourceClientId, declaredClientId: row.code }, variant: "declared_client_mismatch" },
      { gate: "NEGATIVE_AUTH_MISSING_SCOPE", pass: missingScope.reasonCode === "insufficient_scope", reason: "token_scope_missing_rejected", response: missingScope, variant: "scope_not_issued" },
      { gate: "NEGATIVE_AUTH_REVOKED_PERMISSION", pass: revokedPermission.reasonCode === "insufficient_scope", reason: "current_permission_revocation_rejected", response: revokedPermission, variant: "live_permission_revocation" },
      { gate: "TOKEN_EPOCH_INVALIDATION", pass: invalidEpoch.reasonCode === "revoked_token", reason: "revocation_epoch_change_rejected", response: invalidEpoch, variant: "principal_revocation_epoch" }
    ];
    await tx(db, async (client) => {
      for (const outcome of outcomes) {
        const evidence = { pass: outcome.pass, reason: outcome.reason, response: outcome.response };
        await recordActiveGateEvidence(client, {
          componentId: String(row.component_id), revisionId: String(row.active_revision_id), gate: outcome.gate,
          pass: outcome.pass, reasonCode: outcome.pass ? outcome.reason : `${outcome.gate.toLowerCase()}_probe_failed`,
          evidence, correlationId: params.correlationId,
          requestDigest: evidenceDigest({ gate: outcome.gate, variant: outcome.variant }), responseDigest: evidenceDigest(evidence), variant: outcome.variant
        });
      }
    });
  } finally {
    await db.query("delete from principal where id=$1", [probePrincipalId]).catch(() => undefined);
  }
}

async function runSecretReadinessProbes(db: Db, params: {
  jobId: string;
  integrationTokenId: string;
  vaultMasterKey: Buffer;
  vaultMasterKeyId: string;
  accessTokenHmacKey: Buffer;
  integrationTokenHmacKey: Buffer;
  integrationTokenHmacKeyId: string;
  correlationId: string;
}): Promise<void> {
  const job = await db.query(
    `select job.component_id,component.active_revision_id,component.code
       from component_onboarding_job job join component on component.id=job.component_id
      where job.id=$1 and job.integration_token_id=$2 and job.principal_access_token_digest is not null`,
    [params.jobId, params.integrationTokenId]
  );
  if (!job.rowCount) return;
  const row = job.rows[0];
  const principal: SecretPrincipal = { kind: "COMPONENT", id: String(row.component_id), publicId: String(row.code), auditActorType: "component" };
  const config = {
    CONFIG_VAULT_MASTER_KEY_BASE64: params.vaultMasterKey,
    CONFIG_VAULT_MASTER_KEY_ID: params.vaultMasterKeyId,
    ACCESS_TOKEN_HMAC_KEY_BASE64: params.accessTokenHmacKey,
    INTEGRATION_TOKEN_HMAC_KEY_BASE64: params.integrationTokenHmacKey,
    INTEGRATION_TOKEN_HMAC_KEY_ID: params.integrationTokenHmacKeyId
  };
  const grants = await db.query(
    `select secret.stable_name
       from secret_grant grant_row join secret_record secret on secret.id=grant_row.secret_id
      where grant_row.principal_kind='COMPONENT' and grant_row.revoked_at is null
        and (grant_row.principal_id=$1 or grant_row.principal_public_id=$2)
        and secret.status='ACTIVE' order by secret.stable_name`,
    [row.component_id, row.code]
  );
  const allowedResults: Array<{ name: string; fingerprint: string; version: number }> = [];
  let allowed = true;
  for (const grant of grants.rows) {
    try {
      const resolved = await resolveSecret(db, config, principal, String(grant.stable_name), params.correlationId);
      allowedResults.push({ name: resolved.name, fingerprint: resolved.fingerprint, version: resolved.version });
    } catch {
      allowed = false;
    }
  }
  let denied = false;
  const deniedName = `KCML_READINESS_DENIED_${randomUUID().replaceAll("-", "").toUpperCase()}`;
  try {
    await resolveSecret(db, config, principal, deniedName, params.correlationId);
  } catch (error) {
    denied = error instanceof Error && error.message === "secret_unavailable";
  }
  await tx(db, async (client) => {
    const evidenceAllowed = { declaredGrantCount: grants.rows.length, resolved: allowedResults, noGrantsDeclared: grants.rows.length === 0 };
    await recordActiveGateEvidence(client, { componentId: String(row.component_id), revisionId: String(row.active_revision_id), gate: "SECRET_ALLOWED",
      pass: allowed, reasonCode: allowed ? (grants.rows.length ? "each_granted_secret_resolved" : "no_secret_grants_declared") : "granted_secret_resolution_failed",
      evidence: evidenceAllowed, correlationId: params.correlationId, requestDigest: evidenceDigest(grants.rows.map((grant) => String(grant.stable_name))),
      responseDigest: evidenceDigest(evidenceAllowed), variant: grants.rows.length ? "all_current_grants" : "no_grants" });
    const evidenceDenied = { deniedNameDigest: evidenceDigest(deniedName), denied };
    await recordActiveGateEvidence(client, { componentId: String(row.component_id), revisionId: String(row.active_revision_id), gate: "SECRET_DENIED",
      pass: denied, reasonCode: denied ? "ungranted_secret_denied" : "ungranted_secret_resolution_allowed",
      evidence: evidenceDenied, correlationId: params.correlationId, requestDigest: evidenceDigest({ name: deniedName }),
      responseDigest: evidenceDigest(evidenceDenied), variant: "random_ungranted_name" });
  });
}

async function controlContract(client: pg.PoolClient, componentId: string, commandType: "enable" | "disable" | "state" | "heartbeat") {
  const revisionId = await componentActiveRevision(client, componentId);
  const contract = await client.query(
    `select id,endpoint_path,request_schema,response_schema
       from component_control_command
      where component_id=$1 and revision_id=$2 and command_type=$3`,
    [componentId, revisionId, commandType]
  );
  if (!contract.rowCount) throw Object.assign(new Error("control_contract_missing"), { statusCode: 409 });
  return { revisionId, row: contract.rows[0] };
}

async function enqueueControlDispatch(client: pg.PoolClient, params: {
  componentId: string;
  commandType: "enable" | "disable" | "state" | "heartbeat";
  requestedPolicyEpoch: number;
  correlationId: string;
  causationId?: string;
  expectedStateKey?: string | null;
  probeOnly?: boolean;
}): Promise<Record<string, unknown>> {
  const { revisionId, row } = await controlContract(client, params.componentId, params.commandType);
  const target = await client.query("select hostname,code from component where id=$1", [params.componentId]);
  const dispatchId = randomUUID();
  const requestBody = {
    commandId: dispatchId,
    commandType: params.commandType,
    componentId: params.componentId,
    componentCode: String(target.rows[0]?.code ?? ""),
    policyEpoch: params.requestedPolicyEpoch,
    expectedStateKey: params.expectedStateKey ?? null,
    requestedAt: new Date().toISOString()
  };
  const dispatch = await client.query(
    `insert into component_control_dispatch(
      id,component_id,revision_id,command_contract_id,command_type,target_hostname,endpoint_path,request_body,request_digest,
      requested_policy_epoch,expected_state_key,correlation_id,causation_id,deadline_at,retry_policy
    ) values ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11,$12,$13,now()+interval '5 minutes',$14::jsonb)
    returning *`,
    [
      dispatchId,
      params.componentId,
      revisionId,
      row.id,
      params.commandType,
      String(target.rows[0]?.hostname ?? ""),
      String(row.endpoint_path),
      JSON.stringify(requestBody),
      evidenceDigest(requestBody),
      params.requestedPolicyEpoch,
      params.expectedStateKey ?? null,
      params.correlationId,
      params.causationId ?? null,
      JSON.stringify({ maxAttempts: 3, strategy: "fail_closed", probeOnly: params.probeOnly === true })
    ]
  );
  return dispatch.rows[0] as Record<string, unknown>;
}

async function createStateQueryRun(client: pg.PoolClient, params: {
  componentId: string;
  revisionId: string;
  dispatchId: string;
  requestedPolicyEpoch: number;
  expectedStateKey: string;
  correlationId: string;
}): Promise<{ id: string; challenge_nonce: string }> {
  const nonce = randomUUID();
  const result = await client.query(
    `insert into component_state_query_run(
      component_id,revision_id,dispatch_id,requested_state_keys,challenge_nonce,requested_policy_epoch,correlation_id
    ) values ($1,$2,$3,$4::text[],$5,$6,$7) returning id,challenge_nonce`,
    [params.componentId, params.revisionId, params.dispatchId, [params.expectedStateKey], nonce, params.requestedPolicyEpoch, params.correlationId]
  );
  return { id: String(result.rows[0].id), challenge_nonce: String(result.rows[0].challenge_nonce) };
}

async function createHeartbeatChallenge(client: pg.PoolClient, params: {
  componentId: string;
  revisionId: string;
  dispatchId: string;
  requestedPolicyEpoch: number;
  correlationId: string;
}): Promise<{ id: string; challenge_nonce: string }> {
  const nonce = randomUUID();
  const result = await client.query(
    `insert into component_heartbeat_challenge(
      component_id,revision_id,dispatch_id,challenge_nonce,requested_policy_epoch,correlation_id
    ) values ($1,$2,$3,$4,$5,$6) returning id,challenge_nonce`,
    [params.componentId, params.revisionId, params.dispatchId, nonce, params.requestedPolicyEpoch, params.correlationId]
  );
  return { id: String(result.rows[0].id), challenge_nonce: String(result.rows[0].challenge_nonce) };
}

async function queueReadinessControlProbes(client: pg.PoolClient, params: {
  componentId: string;
  revisionId: string;
  policyEpoch: number;
  correlationId: string;
  gates: GateResult[];
}): Promise<void> {
  const missing = new Set(params.gates.filter((gate) => gate.status !== "PASS").map((gate) => gate.gate));
  const alreadyPending = await client.query(
    `select command_type from component_control_dispatch
      where component_id=$1 and revision_id=$2 and state in ('QUEUED','CLAIMED','SENT','ACK_PENDING','ACKED')
        and deadline_at>now() and coalesce((retry_policy->>'probeOnly')::boolean,false)`,
    [params.componentId, params.revisionId]
  );
  const pending = new Set(alreadyPending.rows.map((row) => String(row.command_type)));
  const queueActivationProbe = async (commandType: "enable" | "disable") => {
    if (pending.has(commandType)) return;
    const expectedStateKey = commandType === "enable" ? "ENABLED" : "DISABLED";
    const dispatch = await enqueueControlDispatch(client, {
      componentId: params.componentId, commandType, requestedPolicyEpoch: params.policyEpoch,
      expectedStateKey, correlationId: params.correlationId, probeOnly: true
    });
    await createStateQueryRun(client, {
      componentId: params.componentId, revisionId: params.revisionId, dispatchId: String(dispatch.id),
      requestedPolicyEpoch: params.policyEpoch, expectedStateKey, correlationId: params.correlationId
    });
    if (commandType === "enable") await createHeartbeatChallenge(client, {
      componentId: params.componentId, revisionId: params.revisionId, dispatchId: String(dispatch.id),
      requestedPolicyEpoch: params.policyEpoch, correlationId: params.correlationId
    });
  };
  if (missing.has("ENABLE_CONTROL")) await queueActivationProbe("enable");
  if (missing.has("DISABLE_CONTROL")) await queueActivationProbe("disable");
  if ((missing.has("STATE_QUERY_CONTROL") || missing.has("STATE_FULL_SNAPSHOT") || missing.has("EACH_STATE_SCHEMA")) && !pending.has("state")) {
    const dispatch = await enqueueControlDispatch(client, { componentId: params.componentId, commandType: "state",
      requestedPolicyEpoch: params.policyEpoch, expectedStateKey: "FULL_SNAPSHOT", correlationId: params.correlationId, probeOnly: true });
    await createStateQueryRun(client, { componentId: params.componentId, revisionId: params.revisionId, dispatchId: String(dispatch.id),
      requestedPolicyEpoch: params.policyEpoch, expectedStateKey: "FULL_SNAPSHOT", correlationId: params.correlationId });
  }
  if (missing.has("HEARTBEAT_CHALLENGE") && !pending.has("heartbeat")) {
    const dispatch = await enqueueControlDispatch(client, { componentId: params.componentId, commandType: "heartbeat",
      requestedPolicyEpoch: params.policyEpoch, correlationId: params.correlationId, probeOnly: true });
    await createHeartbeatChallenge(client, { componentId: params.componentId, revisionId: params.revisionId, dispatchId: String(dispatch.id),
      requestedPolicyEpoch: params.policyEpoch, correlationId: params.correlationId });
  }
}

async function finalizeDispatchFromEvidence(client: pg.PoolClient, dispatchId: string, correlationId: string): Promise<void> {
  const result = await client.query(
    `select d.*, c.enabled, c.lifecycle_state, c.activation_state,
            sq.status as query_status, sq.response_state_key, sq.response_payload,
            hb.status as heartbeat_status
       from component_control_dispatch d
       join component c on c.id=d.component_id
       left join component_state_query_run sq on sq.dispatch_id=d.id
       left join component_heartbeat_challenge hb on hb.dispatch_id=d.id
      where d.id=$1
      for update of d, c`,
    [dispatchId]
  );
  if (!result.rowCount) return;
  const row = result.rows[0];
  const commandType = String(row.command_type);
  const queryOkay = commandType === "state"
    ? row.query_status === "RESPONDED"
    : ["enable", "disable"].includes(commandType)
      ? row.query_status === "RESPONDED" && statePayloadMatchesCommand(optionalText(row.expected_state_key), row.response_payload)
      : true;
  const heartbeatOkay = ["enable", "heartbeat"].includes(commandType) ? row.heartbeat_status === "RESPONDED" : true;
  const acked = ["ACKED", "STATE_CONFIRMED", "HEARTBEAT_CONFIRMED", "COMPLETED"].includes(String(row.state));
  if (!acked || !queryOkay || !heartbeatOkay) return;
  const activationCommand = commandType === "enable" || commandType === "disable";
  const activating = commandType === "enable";
  const probeOnly = record(row.retry_policy)?.probeOnly === true;
  if (activationCommand && !probeOnly) await client.query(
    `update component
        set enabled=$2,
            ingress_enabled=$2,
            pulse_enabled=$2,
            egress_enabled=$2,
            activation_state=$3,
            lifecycle_state=case when $2 then 'ACTIVE' else case when lifecycle_state='ACTIVE' then 'APPROVED' else lifecycle_state end end,
            operational_state=$4,
            monitoring_state=$5,
            activated_at=case when $2 then now() else activated_at end,
            updated_at=now()
      where id=$1`,
    [
      row.component_id,
      activating,
      activating ? "ACTIVE" : "READY",
      activating ? "HEALTHY" : "DISABLED",
      activating ? "HEALTHY" : "PENDING"
    ]
  );
  if (activationCommand && !probeOnly) await client.query(
    `update principal set status=$2,updated_at=now()
      where id=(select principal_id from component where id=$1)`,
    [row.component_id, activating ? "ACTIVE" : "SUSPENDED"]
  );
  await client.query(
    `update component_control_dispatch
        set state='COMPLETED',
            final_result=$2::jsonb,
            updated_at=now()
      where id=$1`,
    [dispatchId, JSON.stringify({ queryStateKey: row.response_state_key ?? null, heartbeatConfirmed: heartbeatOkay })]
  );
  if (activationCommand) {
    await recordActiveGateEvidence(client, {
      componentId: String(row.component_id), revisionId: String(row.revision_id),
      gate: activating ? "ENABLE_CONTROL" : "DISABLE_CONTROL", pass: true,
      reasonCode: activating ? "enable_control_state_and_heartbeat_verified" : "disable_control_state_verified",
      evidence: { dispatchId, commandType, queryOkay, heartbeatOkay, probeOnly }, correlationId,
      requestDigest: optionalText(row.request_digest), responseDigest: optionalText(row.ack_digest), variant: probeOnly ? "readiness_probe" : "lifecycle_command"
    });
  }
  await appendAudit(client, {
    eventType: activationCommand ? (activating ? "component.activation.confirmed" : "component.deactivation.confirmed") : `component.control.${commandType}.confirmed`,
    actorType: "system",
    objectType: "component_control_dispatch",
    objectId: dispatchId,
    after: { componentId: row.component_id, commandType, queryOkay, heartbeatOkay },
    correlationId
  });
}

async function replaceDerivedComponentContracts(client: pg.PoolClient, componentId: string, revisionId: string, manifest: ComponentManifest, hostname: string): Promise<void> {
  const tables = [
    "component_secret_policy",
    "component_control_command",
    "component_documentation_evidence",
    "component_e2e_result",
    "component_e2e_scenario",
    "component_attribute_contract",
    "component_endpoint_contract",
    "component_call_mask",
    "component_pulse_mask",
    "component_state_transition",
    "component_state_contract",
    "component_tool_contract",
    "component_runtime_target"
  ];
  for (const table of tables) {
    await client.query(`delete from ${table} where component_id=$1 and revision_id=$2`, [componentId, revisionId]);
  }

  for (const state of manifest.states.states) {
    await client.query(
      `insert into component_state_contract(component_id,revision_id,state_key,category,state_schema,terminal)
       values ($1,$2,$3,$4,$5::jsonb,$6)`,
      [componentId, revisionId, text(state.key), text(state.category) || "OPERATIONAL", JSON.stringify(state.schema ?? {}), state.terminal === true]
    );
  }
  for (const transition of manifest.states.transitions) {
    await client.query(
      `insert into component_state_transition(component_id,revision_id,from_state_key,to_state_key,trigger_mask)
       values ($1,$2,$3,$4,$5)`,
      [componentId, revisionId, text(transition.from), text(transition.to), text(transition.trigger)]
    );
  }

  const pulseMasks: JsonRecord[] = [
    ...manifest.pulses.incoming.map((pulse) => ({ ...pulse, direction: "INCOMING" })),
    ...manifest.pulses.outgoing.map((pulse) => ({ ...pulse, direction: "OUTGOING" }))
  ];
  for (const pulse of pulseMasks) {
    await client.query(
      `insert into component_pulse_mask(component_id,revision_id,pulse_type,direction,route_acl,scopes,envelope_schema,execution_mode,idempotency,token_required)
       values ($1,$2,$3,$4,$5::text[],$6::text[],$7::jsonb,$8,$9,true)`,
      [componentId, revisionId, text(pulse.type), text(pulse.direction), [], [text(pulse.scope)], JSON.stringify(pulse.schema ?? {}), "SYNC", "REQUIRED"]
    );
  }

  for (const endpoint of manifest.endpoints) {
    const endpointId = text(endpoint.key);
    await client.query(
      `insert into component_endpoint_contract(component_id,revision_id,endpoint_id,public_hostname,path,methods,auth_mode,request_schema,response_schema)
       values ($1,$2,$3,$4,$5,$6::text[],$7,$8::jsonb,$9::jsonb)`,
      [componentId, revisionId, endpointId, hostname, text(endpoint.path), [text(endpoint.method)],
        "KCML_BEARER", JSON.stringify(endpoint.requestSchema ?? {}), JSON.stringify(endpoint.responseSchema ?? {})]
    );
    await client.query(
      `insert into component_call_mask(component_id,revision_id,mask_key,direction,route_pattern,scope_name,request_schema,response_schema)
       values ($1,$2,$3,'INBOUND',$4,$5,$6::jsonb,$7::jsonb)`,
      [componentId, revisionId, `endpoint:${endpointId}`, text(endpoint.path), text(endpoint.scope),
        JSON.stringify(endpoint.requestSchema ?? {}), JSON.stringify(endpoint.responseSchema ?? {})]
    );
  }

  for (const tool of manifest.tools) {
    const annotations = record(tool.annotations) ?? {};
    await client.query(
      `insert into component_tool_contract(
        component_id,revision_id,name,title,description,input_schema,output_schema,annotations,scope_name,
        timeout_ms,limits,idempotency,variants
      ) values ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8::jsonb,$9,$10,$11::jsonb,$12::jsonb,$13::jsonb)`,
      [componentId, revisionId, text(tool.name), text(tool.title) || text(tool.name), text(tool.description) || text(tool.title) || text(tool.name),
        JSON.stringify(tool.inputSchema ?? {}), JSON.stringify(tool.outputSchema ?? {}), JSON.stringify(annotations), text(tool.scope),
        Number(tool.timeoutMs), JSON.stringify(tool.limits ?? {}), JSON.stringify({}), JSON.stringify([])]
    );
    await client.query(
      `insert into component_call_mask(component_id,revision_id,mask_key,direction,route_pattern,scope_name,request_schema,response_schema)
       values ($1,$2,$3,'INBOUND',$4,$5,$6::jsonb,$7::jsonb)`,
      [componentId, revisionId, `tool:${text(tool.name)}`, `/mcp/tools/${text(tool.name)}`, text(tool.scope),
        JSON.stringify(tool.inputSchema ?? {}), JSON.stringify(tool.outputSchema ?? {})]
    );
    await client.query(
      `insert into component_permission(source_component_id,target_component_id,route_pattern,scope_name,access_level,granted_by_type)
       values ($1,$1,$2,$3,'INVOKE','system')
       on conflict (source_component_id,target_component_id,route_pattern,scope_name) do update set revoked_at=null`,
      [componentId, `/mcp/tools/${text(tool.name)}`, text(tool.scope)]
    );
  }

  const runtime = record(manifest.runtime);
  const upstream = optionalText(runtime?.upstream);
  const socketPath = optionalText(runtime?.socketPath);
  const runtimeDigest = text(runtime?.runtimeDigest);
  if (socketPath) {
    await client.query(
      `insert into component_runtime_target(component_id,revision_id,transport,upstream,socket_path,status,runtime_digest,runtime_resources)
       values ($1,$2,'UDS',$3,$3,'PENDING',$4,$5::jsonb)`,
      [componentId, revisionId, socketPath, runtimeDigest, JSON.stringify(runtime?.resources ?? {})]
    );
  } else if (upstream) {
    const parsed = new URL(upstream);
    if (parsed.protocol !== "https:") throw Object.assign(new Error("runtime_https_required"), { statusCode: 400 });
    await client.query(
      `insert into component_runtime_target(component_id,revision_id,transport,upstream,expected_tls_identity,status,runtime_digest,runtime_resources)
       values ($1,$2,'HTTPS',$3,$4,'PENDING',$5,$6::jsonb)`,
      [componentId, revisionId, parsed.toString(), text(runtime?.tlsIdentity), runtimeDigest, JSON.stringify(runtime?.resources ?? {})]
    );
  }

  for (const pulse of pulseMasks) {
    const schema = record(pulse.schema) ?? {};
    const required = Array.isArray(schema.required) ? schema.required.map(String) : [];
    for (const attribute of required) {
      await client.query(
        `insert into component_attribute_contract(component_id,revision_id,contract_kind,mask_key,attribute_path,required,attribute_schema)
         values ($1,$2,'PULSE',$3,$4,true,$5::jsonb)
         on conflict do nothing`,
        [componentId, revisionId, text(pulse.type), attribute, JSON.stringify(record(schema.properties)?.[attribute] ?? {})]
      );
    }
  }

  for (const scenario of manifest.e2eScenarios) {
    const input = manifestContent(scenario.input);
    const expected = manifestContent(scenario.expected);
    const storedScenario = await client.query(
      `insert into component_e2e_scenario(component_id,revision_id,scenario_key,variant,input_ref,input_digest,expected_output_ref,expected_output_digest,expected_output,test_commands)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,'{}'::text[]) returning id`,
      [componentId, revisionId, text(scenario.scenarioKey), text(scenario.variantKey), `bundle:e2e/${text(scenario.scenarioKey)}/${text(scenario.variantKey)}/input`, input.digest,
        `bundle:e2e/${text(scenario.scenarioKey)}/${text(scenario.variantKey)}/expected`, expected.digest,
        JSON.stringify(expected.json ?? { mediaType: expected.mediaType, digest: expected.digest })]
    );
    await client.query(
      `insert into component_e2e_fixture(
        revision_id,scenario_key,variant_key,input_content,input_media_type,input_digest,expected_content,expected_media_type,expected_digest,
        invocation_kind,invocation_name,timeout_ms,cleanup_contract
      ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb)`,
      [revisionId, text(scenario.scenarioKey), text(scenario.variantKey), input.bytes, input.mediaType, input.digest,
        expected.bytes, expected.mediaType, expected.digest, text(record(scenario.invocation)?.kind), text(record(scenario.invocation)?.name),
        Number(scenario.timeoutMs), JSON.stringify(scenario.cleanup ?? { required: false })]
    );
    void storedScenario;
  }

  for (const evidence of manifest.documentationEvidence) {
    const storedContent = manifestContent(evidence.content);
    if (storedContent.digest !== text(evidence.digest)) throw Object.assign(new Error("documentation_evidence_digest_mismatch"), { statusCode: 400 });
    await client.query(
      `insert into component_documentation_evidence(component_id,revision_id,evidence_key,evidence_ref,evidence_digest,media_type,required,content)
       values ($1,$2,$3,$4,$5,$6,true,$7)`,
      [componentId, revisionId, text(evidence.key), text(evidence.path), text(evidence.digest), storedContent.mediaType, storedContent.bytes]
    );
  }

  const controlPlane = manifest.controlPlane;
  for (const commandType of ["enable", "disable", "state", "heartbeat"] as const) {
    const command = record(controlPlane[commandType]) ?? {};
    await client.query(
      `insert into component_control_command(component_id,revision_id,command_key,command_type,endpoint_path,request_schema,response_schema)
       values ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb)`,
      [componentId, revisionId, `control:${commandType}`, commandType, text(command.path), JSON.stringify(command.requestSchema ?? {}), JSON.stringify(command.responseSchema ?? {})]
    );
    await client.query(
      `insert into principal_component_permission(source_principal_id,target_component_id,route_pattern,scope_name)
       select id,$1,$2,$3 from principal where public_id='KCML-PLATFORM-WORKER'
       on conflict (source_principal_id,target_component_id,route_pattern,scope_name) do update set revoked_at=null`,
      [componentId, text(command.path), `platform.control.${commandType}`]
    );
  }
  await client.query(
    `insert into principal_component_permission(source_principal_id,target_component_id,route_pattern,scope_name)
     select id,$1,'/v1/kcml/runtime/*','platform.e2e.execute' from principal where public_id='KCML-PLATFORM-WORKER'
     on conflict (source_principal_id,target_component_id,route_pattern,scope_name) do update set revoked_at=null`,
    [componentId]
  );

  const platformPermissions = [
    ["/v2/component-control-ack", "component.control.ack"],
    ["/v2/component-state-push", "component.state.query"],
    ["/v2/component-state-response", "component.state.query"],
    ["/v2/component-heartbeat", "component.heartbeat"],
    ["/v2/component-audit-events", "component.audit.write"],
    ["/v2/component-pulse", "component.pulse"],
    ["/v2/component-outbound-pulse", "component.outbound.pulse"]
  ] as const;
  for (const [routePattern, scopeName] of platformPermissions) {
    if (!manifest.capabilities.includes(scopeName)) continue;
    await client.query(
      `insert into component_permission(source_component_id,target_component_id,route_pattern,scope_name,access_level,granted_by_type)
       values ($1,$1,$2,$3,'INVOKE','system')
       on conflict (source_component_id,target_component_id,route_pattern,scope_name) do update set revoked_at=null`,
      [componentId, routePattern, scopeName]
    );
  }

  await client.query(
    `insert into component_secret_policy(component_id,revision_id,policy_mode,all_secrets_requires_grant,audit_level)
     values ($1,$2,$3,$4,$5)`,
    [componentId, revisionId, "GRANTED_SECRETS", manifest.secretPolicy.allSecretsRequireGrant === true, text(manifest.secretPolicy.auditLevel) || "FULL"]
  );
  for (const scopeName of ["mcp.initialize", "mcp.notifications.initialized", "mcp.tools.list", "mcp.tools.call"]) {
    const routePattern = scopeName === "mcp.tools.call" ? "/mcp/*" : "/mcp";
    await client.query(
      `insert into component_permission(source_component_id,target_component_id,route_pattern,scope_name,access_level,granted_by_type)
       values ($1,$1,$2,$3,'INVOKE','system')
       on conflict (source_component_id,target_component_id,route_pattern,scope_name) do nothing`,
      [componentId, routePattern, scopeName]
    );
  }
}

export async function createComponentOnboarding(db: Db, params: {
  integrationTokenId: string;
  idempotencyKey: string;
  manifest: ComponentManifest;
  correlationId: string;
}): Promise<Record<string, unknown>> {
  const digest = componentManifestDigest(params.manifest);
  return tx(db, async (client) => {
    const token = await client.query(
      `select id,token_kind,release_version,max_child_jobs
         from integration_token
        where id=$1
          and revoked_at is null
          and deleted_at is null
          and expires_at > now()
        for update`,
      [params.integrationTokenId]
    );
    if (!token.rowCount) throw Object.assign(new Error("invalid_integration_token"), { statusCode: 401 });
    const tokenRow = token.rows[0];
    await cleanupRetryableComponentOnboardings(client, params.integrationTokenId, params.correlationId);
    const existing = await client.query(
      "select * from component_onboarding_job where integration_token_id=$1 and idempotency_key=$2 for update",
      [params.integrationTokenId, params.idempotencyKey]
    );
    if (existing.rowCount) {
      if (String(existing.rows[0].request_digest) !== digest) throw Object.assign(new Error("idempotency_conflict"), { statusCode: 409 });
      return componentOnboardingView(existing.rows[0]);
    }
    const successfulRegistration = await client.query(
      `select 1
         from component_onboarding_job
        where integration_token_id=$1
          and principal_access_token_handed_off_at is not null
        limit 1`,
      [params.integrationTokenId]
    );
    if (successfulRegistration.rowCount) throw Object.assign(new Error("integration_token_consumed"), { statusCode: 409 });
    const activeJob = await client.query(
      `select 1
         from component_onboarding_job
        where integration_token_id=$1
          and state not in ('CANCELLED','FAILED')
          and principal_access_token_handed_off_at is null
        limit 1`,
      [params.integrationTokenId]
    );
    if (activeJob.rowCount) throw Object.assign(new Error("integration_token_already_bound"), { statusCode: 409 });
    const identity = await client.query("select nextval('kcml_number_seq')::bigint as number");
    const number = Number(identity.rows[0].number);
    const code = `KCML${String(number).padStart(4, "0")}`;
    const hostname = `${code.toLowerCase()}.${STRICT_COMPONENT_HOST_SUFFIX}`;
    const componentId = randomUUID();
    const principalId = randomUUID();
    const category = "EXTERNAL_SERVICE";
    const registrationType = "GENERIC_COMPONENT";
    const role = "SERVICE";
    const capabilities = manifestCapabilities(params.manifest);
    const protocols = manifestProtocols(params.manifest);
    const transports = manifestTransports(params.manifest);
    const authorizationSnapshot = {
      tokenId: params.integrationTokenId,
      tokenKind: String(tokenRow.token_kind),
      releaseVersion: COMPONENT_CATALOG_VERSION,
      manifestDigest: digest,
      registrationType,
      componentKind: params.manifest.kind,
      category,
      capturedAt: new Date().toISOString()
    };
    await client.query(
      `insert into principal(id,kind,public_id,status,policy_epoch,revocation_epoch,metadata)
       values ($1,'COMPONENT',$2,'SUSPENDED',1,1,$3::jsonb)`,
      [principalId, code, JSON.stringify({ componentId, assignedBy: "component_onboarding" })]
    );
    await client.query(
      `insert into component(
        id,principal_id,kcml_number,code,hostname,display_name,description,category,registration_type,component_role,owners,contacts,
        lifecycle_state,activation_state,operational_state,monitoring_state,enabled,release_version
      ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,'REVIEW','INACTIVE','UNKNOWN',$13,false,$14)`,
      [componentId, principalId, number, code, hostname, params.manifest.displayName, params.manifest.businessPurpose, category,
        registrationType, role, JSON.stringify(params.manifest.owners), JSON.stringify(params.manifest.contacts),
        "PENDING", COMPONENT_CATALOG_VERSION]
    );
    const revision = await client.query(
      `insert into component_revision(
        component_id,revision,manifest,manifest_digest,capabilities,protocols,transports,derived_gates
      ) values ($1,$2,$3::jsonb,$4,$5::text[],$6::text[],$7::text[],$8::jsonb) returning id`,
      [componentId, manifestRevision(params.manifest), JSON.stringify(params.manifest), digest, capabilities,
        protocols, transports, JSON.stringify(ACTIVATION_GATES)]
    );
    await replaceDerivedComponentContracts(client, componentId, String(revision.rows[0].id), params.manifest, hostname);
    await client.query("insert into component_audit_stream(component_id) values ($1)", [componentId]);
    const inserted = await client.query(
      `insert into component_onboarding_job(
        integration_token_id,component_id,idempotency_key,request_digest,category,registration_type,manifest,manifest_digest,state,
        release_version,authorization_snapshot
      ) values ($1,$2,$3,$4,$5,$6,$7::jsonb,$4,'IN_REVIEW',$8,$9::jsonb) returning *`,
      [params.integrationTokenId, componentId, params.idempotencyKey, digest, category, registrationType,
        JSON.stringify(params.manifest), COMPONENT_CATALOG_VERSION, JSON.stringify(authorizationSnapshot)]
    );
    await client.query("update component set active_revision_id=$2 where id=$1", [componentId, revision.rows[0].id]);
    await appendAudit(client, {
      eventType: "component_onboarding.created", actorType: "integration_token", actorId: params.integrationTokenId,
      objectType: "component", objectId: componentId,
      after: { code, hostname, catalogVersion: COMPONENT_CATALOG_VERSION, componentKind: params.manifest.kind },
      correlationId: params.correlationId
    });
    return componentOnboardingView(inserted.rows[0]);
  });
}

async function cleanupRetryableComponentOnboardings(client: pg.PoolClient, integrationTokenId: string, correlationId: string): Promise<void> {
  const retryable = await client.query(
    `select job.id, job.component_id, job.state
       from component_onboarding_job job
      where job.integration_token_id=$1
        and job.principal_access_token_handed_off_at is null
        and job.state in ('GATES_PENDING','BLOCKED','FAILED','CANCELLED')
      for update`,
    [integrationTokenId]
  );
  for (const row of retryable.rows) {
    await cleanupComponentOnboardingRow(client, row, "component_onboarding.retry_cleanup", correlationId);
  }
}

async function cleanupComponentOnboardingRow(
  client: pg.PoolClient,
  row: Record<string, unknown>,
  eventType: string,
  correlationId: string
): Promise<void> {
  const jobId = String(row.id);
  const componentId = optionalText(row.component_id);
  await client.query(
      `update component_onboarding_job
        set state='CANCELLED', cancelled_at=coalesce(cancelled_at,now()), credential_claim_digest=null,
            credential_claim_expires_at=null, principal_access_token_ciphertext=null,
            principal_access_token_key_id=null, lock_version=lock_version+1, updated_at=now()
      where id=$1 and principal_access_token_handed_off_at is null`,
    [jobId]
  );
  if (componentId) {
    await client.query(
      "update principal_access_token set revoked_at=coalesce(revoked_at,now()),rotation_reason='ONBOARDING_CANCELLED' where source_principal_id=(select principal_id from component where id=$1) and revoked_at is null",
      [componentId]
    );
    await client.query("update principal set status='REVOKED',revocation_epoch=revocation_epoch+1,updated_at=now() where id=(select principal_id from component where id=$1)", [componentId]);
    await client.query("update component_permission set revoked_at=coalesce(revoked_at,now()) where source_component_id=$1 or target_component_id=$1", [componentId]);
    await client.query(
      `update component
          set enabled=false, ingress_enabled=false, pulse_enabled=false, egress_enabled=false,
              lifecycle_state='DEREGISTERED', activation_state='INACTIVE', operational_state='RETIRED',
              deregistered_at=coalesce(deregistered_at,now()), lock_version=lock_version+1
        where id=$1`,
      [componentId]
    );
  }
  await appendAudit(client, {
    eventType,
    actorType: "system",
    objectType: "component_onboarding_job",
    objectId: jobId,
    after: { runtimeVisible: false, componentId },
    correlationId
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
  expectedLockVersion: number;
  idempotencyKey: string;
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
    if (Number(job.lock_version) !== params.expectedLockVersion) throw Object.assign(new Error("lock_version_conflict"), { statusCode: 412 });
    if (["ACTIVE", "CANCELLED"].includes(String(job.state))) throw Object.assign(new Error("invalid_state"), { statusCode: 409 });
    const duplicateRequest = await client.query(
      "select request_digest from component_onboarding_revision_request where job_id=$1 and idempotency_key=$2",
      [params.jobId, params.idempotencyKey]
    );
    if (duplicateRequest.rowCount) {
      if (String(duplicateRequest.rows[0].request_digest) !== digest) {
        throw Object.assign(new Error("idempotency_conflict"), { statusCode: 409 });
      }
      return componentOnboardingView(job);
    }
    const revision = await client.query(
      `insert into component_revision(component_id,revision,manifest,manifest_digest,capabilities,protocols,transports,derived_gates)
       values ($1,$2,$3::jsonb,$4,$5::text[],$6::text[],$7::text[],$8::jsonb)
       on conflict (component_id,revision) do update set manifest=excluded.manifest,manifest_digest=excluded.manifest_digest,
         capabilities=excluded.capabilities,protocols=excluded.protocols,transports=excluded.transports,validation_state='PENDING',evidence='{}'::jsonb
       returning id`,
      [job.component_id, manifestRevision(params.manifest), JSON.stringify(params.manifest), digest, manifestCapabilities(params.manifest),
        manifestProtocols(params.manifest), manifestTransports(params.manifest), JSON.stringify(ACTIVATION_GATES)]
    );
    await replaceDerivedComponentContracts(client, String(job.component_id), String(revision.rows[0].id), params.manifest, String((await client.query("select hostname from component where id=$1", [job.component_id])).rows[0].hostname));
    await client.query("update component set active_revision_id=$2,lifecycle_state='REVIEW',activation_state='INACTIVE',enabled=false,ingress_enabled=false,pulse_enabled=false,egress_enabled=false where id=$1", [job.component_id, revision.rows[0].id]);
    const updated = await client.query(
      `update component_onboarding_job set manifest=$2::jsonb,manifest_digest=$3,request_digest=$3,state='IN_REVIEW',
        gate_results='[]'::jsonb,credential_claim_digest=null,credential_claim_expires_at=null,failure_code=null,
        lock_version=lock_version+1,updated_at=now() where id=$1 and lock_version=$4 returning *`,
      [params.jobId, JSON.stringify(params.manifest), digest, params.expectedLockVersion]
    );
    if (!updated.rowCount) throw Object.assign(new Error("lock_version_conflict"), { statusCode: 412 });
    await client.query(
      `insert into component_onboarding_revision_request(job_id,idempotency_key,request_digest)
       values ($1,$2,$3)`,
      [params.jobId, params.idempotencyKey, digest]
    );
    await appendAudit(client, {
      eventType: "component_onboarding.revised", actorType: "integration_token", actorId: params.integrationTokenId,
      objectType: "component", objectId: String(job.component_id), after: { revision: manifestRevision(params.manifest), manifestDigest: digest }, correlationId: params.correlationId
    });
    return componentOnboardingView(updated.rows[0]);
  });
}

export async function evaluateComponentReadiness(db: Db, params: {
  jobId: string;
  integrationTokenId: string;
  accessTokenHmacKey: Buffer;
  accessTokenHmacKeyId: string;
  vaultMasterKey: Buffer;
  vaultMasterKeyId: string;
  integrationTokenHmacKey: Buffer;
  integrationTokenHmacKeyId: string;
  correlationId: string;
}): Promise<{ job: Record<string, unknown>; accessToken?: string }> {
  await runAuthorizationReadinessProbes(db, {
    jobId: params.jobId,
    integrationTokenId: params.integrationTokenId,
    hmacKey: params.accessTokenHmacKey,
    hmacKeyId: params.accessTokenHmacKeyId,
    correlationId: params.correlationId
  });
  await runSecretReadinessProbes(db, {
    jobId: params.jobId, integrationTokenId: params.integrationTokenId,
    vaultMasterKey: params.vaultMasterKey, vaultMasterKeyId: params.vaultMasterKeyId,
    accessTokenHmacKey: params.accessTokenHmacKey,
    integrationTokenHmacKey: params.integrationTokenHmacKey,
    integrationTokenHmacKeyId: params.integrationTokenHmacKeyId,
    correlationId: params.correlationId
  });
  return tx(db, async (client) => {
    const jobResult = await client.query(
      "select * from component_onboarding_job where id=$1 and integration_token_id=$2 for update",
      [params.jobId, params.integrationTokenId]
    );
    if (!jobResult.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    const job = jobResult.rows[0];
    if (["CANCELLED", "FAILED"].includes(String(job.state))) throw Object.assign(new Error("invalid_state"), { statusCode: 409 });
    const manifest = validateComponentManifest(job.manifest);
    const authorizationSnapshot = job.authorization_snapshot && typeof job.authorization_snapshot === "object"
      ? job.authorization_snapshot as Record<string, unknown>
      : {};
    const componentCurrent = await client.query(
      `select c.active_revision_id,c.principal_id,c.policy_epoch as component_policy_epoch,p.policy_epoch as principal_policy_epoch,p.revocation_epoch as principal_revocation_epoch
         from component c join principal p on p.id=c.principal_id where c.id=$1 for update of c,p`,
      [job.component_id]
    );
    const activeRevisionId = optionalText(componentCurrent.rows[0]?.active_revision_id);
    if (!activeRevisionId) throw Object.assign(new Error("catalog_incompatible"), { statusCode: 409 });
    let pendingAccessToken: string | undefined;
    let accessDigest: Buffer | null = job.principal_access_token_digest ?? null;
    let accessFingerprint: string | null = job.principal_access_token_fingerprint ?? null;
    let accessCiphertext: string | null = optionalText(job.principal_access_token_ciphertext);
    let accessCiphertextKeyId: string | null = optionalText(job.principal_access_token_key_id);
    if (!accessDigest) {
      const issued = issueOpaqueSecret();
      pendingAccessToken = issued.value;
      accessDigest = hmacToken(issued.value, params.accessTokenHmacKey);
      accessFingerprint = issued.fingerprint;
      accessCiphertext = encryptVaultSecret(issued.value, params.vaultMasterKey, {
        keyId: params.vaultMasterKeyId,
        settingKey: `component-onboarding:${params.jobId}`
      });
      accessCiphertextKeyId = params.vaultMasterKeyId;
      const accessScopes = [...new Set([...manifest.capabilities, ...manifest.tools.map((tool) => text(tool.scope)), ...manifest.endpoints.map((endpoint) => text(endpoint.scope))])].filter(Boolean);
      await client.query(
        `insert into principal_access_token(
          lookup_digest,key_id,fingerprint,source_principal_id,target_component_id,audience,scope_names,
          issued_policy_epoch,issued_revocation_epoch,expires_at
        ) values ($1,$2,$3,$4,null,'*',$5::text[],$6,$7,'infinity')`,
        [accessDigest, params.accessTokenHmacKeyId, issued.fingerprint, componentCurrent.rows[0].principal_id, accessScopes,
          componentCurrent.rows[0].principal_policy_epoch, componentCurrent.rows[0].principal_revocation_epoch]
      );
      await client.query("update principal set status='ACTIVE',updated_at=now() where id=$1", [componentCurrent.rows[0].principal_id]);
    } else if (accessCiphertext && accessCiphertextKeyId) {
      pendingAccessToken = decryptVaultSecret(accessCiphertext, new Map([[accessCiphertextKeyId, params.vaultMasterKey]]), `component-onboarding:${params.jobId}`);
    }
    const gates = await gateResults(client as unknown as Db, String(job.component_id), manifest, authorizationSnapshot);
    await persistGateEvidence(client, String(job.component_id), activeRevisionId, gates, params.correlationId);
    const passed = gates.every((gate) => gate.status === "PASS");
    if (!passed) await queueReadinessControlProbes(client, {
      componentId: String(job.component_id), revisionId: activeRevisionId,
      policyEpoch: Number(componentCurrent.rows[0].component_policy_epoch), correlationId: params.correlationId, gates
    });
    const accessToken = passed && !job.principal_access_token_handed_off_at ? pendingAccessToken : undefined;
    const updated = await client.query(
      `update component_onboarding_job
          set state=$2, gate_results=$3::jsonb,
              principal_access_token_digest=coalesce(principal_access_token_digest,$4),
              principal_access_token_fingerprint=coalesce(principal_access_token_fingerprint,$5),
              principal_access_token_ciphertext=case when $6 then null else coalesce(principal_access_token_ciphertext,$7) end,
              principal_access_token_key_id=case when $6 then null else coalesce(principal_access_token_key_id,$8) end,
              principal_access_token_handed_off_at=case when $6 then now() else principal_access_token_handed_off_at end,
              lock_version=lock_version+1, updated_at=now()
        where id=$1 returning *`,
      [params.jobId, passed ? "READY_FOR_ACTIVATION" : "BLOCKED", JSON.stringify(gates), accessDigest, accessFingerprint, Boolean(accessToken), accessCiphertext, accessCiphertextKeyId]
    );
    if (accessToken) {
      await client.query(
        "update integration_token set revoked_at=coalesce(revoked_at,now()), lock_version=lock_version+1 where id=$1 and revoked_at is null",
        [params.integrationTokenId]
      );
    }
    await client.query(
      `update component
          set lifecycle_state=$2,
              activation_state=$3,
              monitoring_state=case when $4 then monitoring_state else 'PENDING' end
        where id=$1`,
      [job.component_id, passed ? "APPROVED" : "REVIEW", passed ? "READY_FOR_ACTIVATION" : "BLOCKED", passed]
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
    return { job: componentOnboardingView(updated.rows[0]), ...(accessToken ? { accessToken } : {}) };
  });
}

export async function cancelComponentOnboarding(db: Db, jobId: string, integrationTokenId: string, correlationId: string): Promise<Record<string, unknown>> {
  return tx(db, async (client) => {
    const current = await client.query(
      `select * from component_onboarding_job
        where id=$1 and integration_token_id=$2 and state not in ('ACTIVE','CANCELLED')
        for update`,
      [jobId, integrationTokenId]
    );
    if (!current.rowCount) throw Object.assign(new Error("invalid_state"), { statusCode: 409 });
    await cleanupComponentOnboardingRow(client, current.rows[0], "component_onboarding.cancelled", correlationId);
    const updated = await client.query("select * from component_onboarding_job where id=$1", [jobId]);
    return componentOnboardingView(updated.rows[0]);
  });
}

export async function cleanupExpiredComponentOnboardings(db: Db, correlationId: string): Promise<number> {
  return tx(db, async (client) => {
    const expired = await client.query(
      `select job.*
         from component_onboarding_job job
         join integration_token token on token.id=job.integration_token_id
        where token.expires_at <= now()
          and job.credential_id is null
          and job.state not in ('CANCELLED','FAILED')
        for update of job`,
    );
    for (const row of expired.rows) {
      await cleanupComponentOnboardingRow(client, row, "component_onboarding.expired_cleanup", correlationId);
    }
    return expired.rowCount ?? 0;
  });
}

export type ComponentPulseEnvelope = {
  pulseType: string;
  direction: "INCOMING" | "OUTGOING";
  source: JsonRecord;
  target: JsonRecord;
  state: JsonRecord;
  operation: JsonRecord;
  input: unknown;
  process: unknown;
  output: unknown;
  success: boolean;
  correlationId: string;
  causationId?: string;
  traceId?: string;
  accessTokenFingerprint: string;
  occurredAt: string;
};

function digestPayload(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function validateAgainstStoredSchema(schema: unknown, payload: unknown, code: string): void {
  const schemaObject = record(schema);
  if (!schemaObject) throw Object.assign(new Error(code), { statusCode: 422 });
  const validate = ajv.compile(schemaObject);
  if (!validate(payload)) throw Object.assign(new Error(code), { statusCode: 422, errors: validate.errors });
}

async function componentActiveRevision(client: pg.PoolClient, componentId: string): Promise<string> {
  const result = await client.query("select active_revision_id from component where id=$1", [componentId]);
  const revisionId = optionalText(result.rows[0]?.active_revision_id);
  if (!revisionId) throw Object.assign(new Error("catalog_incompatible"), { statusCode: 409 });
  return revisionId;
}

export async function ingestComponentPulse(db: Db, componentId: string, envelope: ComponentPulseEnvelope, authorization: {
  tokenFingerprint: string;
  permissionEpoch: number;
  sourceClientId: string;
}): Promise<{ accepted: true; correlationId: string }> {
  return tx(db, async (client) => {
    const mask = await client.query(
      `select mask.*,component.code as component_code
         from component_pulse_mask mask
         join component on component.id=mask.component_id
        where component_id=$1 and pulse_type=$2 and direction=$3`,
      [componentId, envelope.pulseType, envelope.direction]
    );
    if (!mask.rowCount) throw Object.assign(new Error("unknown_pulse_type"), { statusCode: 409 });
    if (envelope.accessTokenFingerprint !== authorization.tokenFingerprint) throw Object.assign(new Error("access_token_fingerprint_mismatch"), { statusCode: 403 });
    const source = record(envelope.source);
    const target = record(envelope.target);
    const routeAclRaw = mask.rows[0].route_acl;
    const routeAcl = Array.isArray(routeAclRaw) ? routeAclRaw.map((value: unknown) => String(value)) : [];
    if (!text(source?.clientId) || !text(source?.componentCode) || !text(target?.componentCode)) {
      throw Object.assign(new Error("component_identity_required"), { statusCode: 400 });
    }
    if (target?.componentCode !== mask.rows[0].component_code) {
      throw Object.assign(new Error("target_component_mismatch"), { statusCode: 403 });
    }
    if (routeAcl.length > 0 && !routeAcl.includes(text(source?.componentCode))) {
      throw Object.assign(new Error("route_denied"), { statusCode: 403 });
    }
    validateAgainstStoredSchema(mask.rows[0].envelope_schema, {
      state: envelope.state, operation: envelope.operation, input: envelope.input, process: envelope.process,
      output: envelope.output, success: envelope.success
    }, "pulse_schema_invalid");
    const sourcePrincipal = await client.query("select id from principal where public_id=$1 and status='ACTIVE'", [authorization.sourceClientId]);
    if (!sourcePrincipal.rowCount) throw Object.assign(new Error("source_principal_unavailable"), { statusCode: 403 });
    const lease = await client.query(
      `insert into component_operation_lease(source_principal_id,target_component_id,operation_kind,operation_name,input_payload,input_digest,
        output_payload,output_digest,process_trace,success,finished_at,expires_at,correlation_id,causation_id,trace_id,token_fingerprint,permission_epoch)
       values ($1,$2,'PULSE',$3,$4::jsonb,'sha256:'||encode(sha256(convert_to(($4::jsonb)::text,'utf8')),'hex'),
        $5::jsonb,'sha256:'||encode(sha256(convert_to(($5::jsonb)::text,'utf8')),'hex'),$6::jsonb,$7,now(),now()+interval '1 minute',$8,$9,$10,$11,$12)
       returning id`,
      [sourcePrincipal.rows[0].id, componentId, envelope.pulseType, JSON.stringify(envelope.input), JSON.stringify(envelope.output),
        JSON.stringify(envelope.process), envelope.success, envelope.correlationId, envelope.causationId ?? null, envelope.traceId ?? null,
        authorization.tokenFingerprint, authorization.permissionEpoch]
    );
    await client.query(
      `insert into component_operation_event(
        component_id,pulse_type,direction,operation_key,input_digest,input_payload,process_trace,output_digest,output_payload,
        success,correlation_id,causation_id,trace_id,access_token_fingerprint,occurred_at
      ) values ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8,$9::jsonb,$10,$11,$12,$13,$14,$15)`,
      [componentId, envelope.pulseType, envelope.direction, text(envelope.operation.operationKey) || envelope.pulseType,
        `sha256:${digestPayload(envelope.input)}`, JSON.stringify(envelope.input), JSON.stringify(envelope.process),
        `sha256:${digestPayload(envelope.output)}`, JSON.stringify(envelope.output), envelope.success, envelope.correlationId,
        envelope.causationId ?? null, envelope.traceId ?? null, envelope.accessTokenFingerprint, envelope.occurredAt]
    );
    await appendAudit(client, { eventType: "component.pulse.finalized", actorType: "component", actorId: String(sourcePrincipal.rows[0].id),
      objectType: "component_operation_lease", objectId: String(lease.rows[0].id),
      after: { pulseType: envelope.pulseType, direction: envelope.direction, success: envelope.success }, correlationId: envelope.correlationId });
    await client.query(
      `update component
          set operational_state=case when $2 then operational_state else 'UNHEALTHY' end,
              monitoring_state=case when $2 then monitoring_state else 'FAILED' end,
              updated_at=now()
        where id=$1`,
      [componentId, envelope.success]
    );
    return { accepted: true, correlationId: envelope.correlationId };
  });
}

export async function ingestComponentOperationEvent(db: Db, componentId: string, event: {
  operationKey: string;
  inputDigest: string;
  inputPayload: unknown;
  processTrace: unknown;
  outputDigest: string;
  outputPayload: unknown;
  success: boolean;
  correlationId: string;
  causationId?: string;
  traceId?: string;
  accessTokenFingerprint?: string;
  occurredAt: string;
}): Promise<{ accepted: true }> {
  return tx(db, async (client) => {
    await client.query(
      `insert into component_operation_event(
        component_id,operation_key,input_digest,input_payload,process_trace,output_digest,output_payload,success,
        correlation_id,causation_id,trace_id,access_token_fingerprint,occurred_at
      ) values ($1,$2,$3,$4::jsonb,$5::jsonb,$6,$7::jsonb,$8,$9,$10,$11,$12,$13)`,
      [componentId, event.operationKey, event.inputDigest, JSON.stringify(event.inputPayload), JSON.stringify(event.processTrace),
        event.outputDigest, JSON.stringify(event.outputPayload), event.success, event.correlationId, event.causationId ?? null,
        event.traceId ?? null, event.accessTokenFingerprint ?? null, event.occurredAt]
    );
    if (!event.success) {
      await client.query("update component set operational_state='UNHEALTHY',monitoring_state='FAILED',updated_at=now() where id=$1", [componentId]);
    }
    return { accepted: true };
  });
}

export async function recordComponentHeartbeat(db: Db, componentId: string, heartbeat: {
  heartbeatAt: string;
  operationalState: string;
  stateDigest?: string;
  correlationId: string;
  declaredClientId: string;
  declaredComponentCode: string;
  policyEpoch: number;
  challengeId?: string;
  challengeNonce?: string;
  payload?: unknown;
}): Promise<{ accepted: boolean; policyEpoch: number; failClosed: boolean; rejectionReason?: string }> {
  return tx(db, async (client) => {
    const current = await client.query("select policy_epoch,code,activation_state,recertification_state,active_revision_id from component where id=$1 for update", [componentId]);
    if (!current.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    const policyEpoch = Number(current.rows[0].policy_epoch);
    const heartbeatAtMs = Date.parse(heartbeat.heartbeatAt);
    const skewMs = Math.abs(Date.now() - heartbeatAtMs);
    let validationState: "ACCEPTED" | "REJECTED" = "ACCEPTED";
    let rejectionReason: string | null = null;
    if (!Number.isFinite(heartbeatAtMs) || skewMs > 120_000) {
      validationState = "REJECTED";
      rejectionReason = "heartbeat_clock_skew";
    } else if (heartbeat.policyEpoch !== policyEpoch) {
      validationState = "REJECTED";
      rejectionReason = "policy_epoch_mismatch";
    } else if (heartbeat.declaredComponentCode !== String(current.rows[0].code)) {
      validationState = "REJECTED";
      rejectionReason = "component_identity_mismatch";
    }
    if (heartbeat.challengeId || heartbeat.challengeNonce) {
      const challenge = await client.query(
        `select * from component_heartbeat_challenge
          where id=$1 and component_id=$2
          for update`,
        [heartbeat.challengeId ?? null, componentId]
      );
      if (!challenge.rowCount || heartbeat.challengeNonce !== String(challenge.rows[0].challenge_nonce)) {
        validationState = "REJECTED";
        rejectionReason = "heartbeat_challenge_mismatch";
      } else if (validationState === "ACCEPTED") {
        await client.query(
          `update component_heartbeat_challenge
              set status='RESPONDED',response_digest=$2,responded_at=now(),response_payload=$3::jsonb
            where id=$1`,
          [challenge.rows[0].id, heartbeat.stateDigest ?? evidenceDigest(heartbeat.payload ?? {}), JSON.stringify(heartbeat.payload ?? {})]
        );
      }
    }
    await client.query(
      `insert into component_heartbeat(
        component_id,heartbeat_at,policy_epoch,operational_state,state_digest,correlation_id,payload,
        challenge_id,challenge_nonce,declared_client_id,declared_component_code,validation_state,rejection_reason
      ) values ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11,$12,$13)`,
      [
        componentId,
        heartbeat.heartbeatAt,
        policyEpoch,
        heartbeat.operationalState,
        heartbeat.stateDigest ?? null,
        heartbeat.correlationId,
        JSON.stringify(heartbeat.payload ?? {}),
        heartbeat.challengeId ?? null,
        heartbeat.challengeNonce ?? null,
        heartbeat.declaredClientId,
        heartbeat.declaredComponentCode,
        validationState,
        rejectionReason
      ]
    );
    if (validationState === "REJECTED") {
      await client.query("update component set monitoring_state='DEGRADED',updated_at=now() where id=$1", [componentId]);
      return { accepted: false, policyEpoch, failClosed: true, rejectionReason: rejectionReason ?? "heartbeat_rejected" };
    }
    if (heartbeat.challengeId) {
      const dispatch = await client.query("select dispatch_id from component_heartbeat_challenge where id=$1", [heartbeat.challengeId]);
      if (dispatch.rowCount && dispatch.rows[0].dispatch_id) {
        await finalizeDispatchFromEvidence(client, String(dispatch.rows[0].dispatch_id), heartbeat.correlationId);
      }
    }
    await recordActiveGateEvidence(client, {
      componentId,
      revisionId: String(current.rows[0].active_revision_id),
      gate: heartbeat.challengeId ? "HEARTBEAT_CHALLENGE" : "HEARTBEAT_PUSH",
      pass: true,
      reasonCode: heartbeat.challengeId ? "heartbeat_challenge_response_verified" : "heartbeat_push_verified",
      evidence: { heartbeatAt: heartbeat.heartbeatAt, operationalState: heartbeat.operationalState, challengeId: heartbeat.challengeId ?? null },
      correlationId: heartbeat.correlationId,
      requestDigest: heartbeat.challengeId ? evidenceDigest({ challengeId: heartbeat.challengeId, nonce: heartbeat.challengeNonce }) : null,
      responseDigest: heartbeat.stateDigest ?? evidenceDigest(heartbeat.payload ?? {}),
      variant: heartbeat.challengeId ? "challenge_response" : "unsolicited_push"
    });
    return { accepted: true, policyEpoch, failClosed: false };
  });
}

export async function markStaleComponentHeartbeats(db: Db, staleAfterSeconds: number, disableAfterSeconds: number, correlationId: string): Promise<number> {
  return tx(db, async (client) => {
    const stale = await client.query(
      `select c.id,
              max(h.heartbeat_at) as last_heartbeat,
              c.activated_at,
              coalesce((r.manifest->'monitoring'->>'staleAfterSeconds')::int,$1) stale_after_seconds,
              coalesce((r.manifest->'monitoring'->>'disableAfterSeconds')::int,$2) disable_after_seconds
         from component c
         join component_revision r on r.id=c.active_revision_id
         left join component_heartbeat h on h.component_id=c.id
        where c.lifecycle_state='ACTIVE' and c.enabled=true
        group by c.id,c.activated_at,r.manifest
        for update of c`,
      [staleAfterSeconds, disableAfterSeconds]
    );
    let staleCount = 0;
    for (const row of stale.rows) {
      const livenessReference = row.last_heartbeat ?? row.activated_at;
      if (!livenessReference) continue;
      const elapsedMs = Date.now() - new Date(String(livenessReference)).getTime();
      const rowStaleAfter = Number(row.stale_after_seconds);
      const rowDisableAfter = Math.max(rowStaleAfter, Number(row.disable_after_seconds));
      if (elapsedMs <= rowStaleAfter * 1000) continue;
      staleCount += 1;
      const disable = elapsedMs > rowDisableAfter * 1000;
      await client.query(
        `update component
            set operational_state=case when $2 then 'DISABLED' else 'UNHEALTHY' end,
                monitoring_state='FAILED',
                enabled=case when $2 then false else enabled end,
                ingress_enabled=case when $2 then false else ingress_enabled end,
                pulse_enabled=case when $2 then false else pulse_enabled end,
                egress_enabled=case when $2 then false else egress_enabled end,
                policy_epoch=policy_epoch+1,
                updated_at=now()
          where id=$1`,
        [row.id, disable]
      );
      await appendAudit(client, {
        eventType: disable ? "component.heartbeat.disabled" : "component.heartbeat.stale",
        actorType: "system",
        objectType: "component",
        objectId: String(row.id),
        after: { lastHeartbeat: row.last_heartbeat ?? null, activatedAt: row.activated_at ?? null, staleAfterSeconds: rowStaleAfter, disableAfterSeconds: rowDisableAfter },
        correlationId
      });
    }
    return staleCount;
  });
}

export async function recordComponentMonitoringWatchdog(db: Db, params: {
  componentId: string;
  pass: boolean;
  evidence: JsonRecord;
  correlationId: string;
}): Promise<void> {
  await tx(db, async (client) => {
    const component = await client.query("select active_revision_id from component where id=$1 for update", [params.componentId]);
    if (!component.rowCount || !component.rows[0].active_revision_id) return;
    await recordActiveGateEvidence(client, {
      componentId: params.componentId, revisionId: String(component.rows[0].active_revision_id), gate: "MONITORING_WATCHDOG",
      pass: params.pass, reasonCode: params.pass ? "runtime_watchdog_probe_passed" : "runtime_watchdog_probe_failed",
      evidence: params.evidence, correlationId: params.correlationId,
      requestDigest: evidenceDigest({ componentId: params.componentId, probe: "runtime_watchdog" }),
      responseDigest: evidenceDigest(params.evidence), variant: "runtime_health"
    });
    await client.query("update component set monitoring_state=$2,updated_at=now() where id=$1", [params.componentId, params.pass ? "HEALTHY" : "FAILED"]);
  });
}

export async function recordComponentStateObservation(db: Db, componentId: string, input: {
  stateKey: string;
  observedAt: string;
  correlationId: string;
  declaredClientId: string;
  declaredComponentCode: string;
  policyEpoch: number;
  queryId?: string;
  statePayload: unknown;
}): Promise<{ accepted: boolean; validationState: "ACCEPTED" | "REJECTED"; rejectionReason?: string }> {
  return tx(db, async (client) => {
    const component = await client.query("select policy_epoch,code from component where id=$1", [componentId]);
    if (!component.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    const contract = await client.query(
      "select state_schema from component_state_contract where component_id=$1 and state_key=$2",
      [componentId, input.stateKey]
    );
    let validationState: "ACCEPTED" | "REJECTED" = contract.rowCount ? "ACCEPTED" : "REJECTED";
    let rejectionReason: string | null = contract.rowCount ? null : "unknown_component_state";
    if (contract.rowCount) {
      try {
        validateAgainstStoredSchema(contract.rows[0].state_schema, input.statePayload, "state_schema_invalid");
      } catch (error) {
        validationState = "REJECTED";
        rejectionReason = error instanceof Error ? error.message : "state_schema_invalid";
      }
    }
    if (input.policyEpoch !== Number(component.rows[0].policy_epoch)) {
      validationState = "REJECTED";
      rejectionReason = "policy_epoch_mismatch";
    }
    if (input.declaredComponentCode !== String(component.rows[0].code)) {
      validationState = "REJECTED";
      rejectionReason = "component_identity_mismatch";
    }
    await client.query(
      `insert into component_state_observation(
        component_id,state_key,observed_at,correlation_id,state_payload,validation_state,rejection_reason,
        query_run_id,declared_client_id,declared_component_code,policy_epoch
      ) values ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10,$11)`,
      [
        componentId,
        input.stateKey,
        input.observedAt,
        input.correlationId,
        JSON.stringify(input.statePayload),
        validationState,
        rejectionReason,
        input.queryId ?? null,
        input.declaredClientId,
        input.declaredComponentCode,
        input.policyEpoch
      ]
    );
    if (input.queryId && validationState === "ACCEPTED") {
      await client.query(
        `update component_state_query_run
            set status='RESPONDED',response_state_key=$2,response_digest=$3,response_payload=$4::jsonb,observed_at=$5
          where id=$1 and component_id=$6`,
        [input.queryId, input.stateKey, evidenceDigest(input.statePayload), JSON.stringify(input.statePayload), input.observedAt, componentId]
      );
      const dispatch = await client.query("select dispatch_id from component_state_query_run where id=$1", [input.queryId]);
      if (dispatch.rowCount && dispatch.rows[0].dispatch_id) {
        await finalizeDispatchFromEvidence(client, String(dispatch.rows[0].dispatch_id), input.correlationId);
      }
    }
    if (validationState === "REJECTED") {
      await client.query("update component set monitoring_state='DEGRADED',updated_at=now() where id=$1", [componentId]);
    }
    await appendAudit(client, { eventType: validationState === "ACCEPTED" ? "component.state.accepted" : "component.state.rejected",
      actorType: "component", actorId: componentId, objectType: "component", objectId: componentId,
      after: { stateKey: input.stateKey, validationState, rejectionReason }, correlationId: input.correlationId });
    if (validationState === "REJECTED") return { accepted: false, validationState, rejectionReason: rejectionReason ?? "state_schema_invalid" };
    return { accepted: true, validationState };
  });
}

export async function recordComponentStateSnapshot(db: Db, componentId: string, input: {
  queryId: string;
  queryNonce: string;
  observedAt: string;
  correlationId: string;
  declaredClientId: string;
  declaredComponentCode: string;
  policyEpoch: number;
  states: Record<string, unknown>;
}): Promise<{ accepted: boolean; validationState: "ACCEPTED" | "REJECTED"; rejectionReason?: string; stateDigest: string }> {
  return tx(db, async (client) => {
    const current = await client.query("select active_revision_id,policy_epoch,code from component where id=$1 for update", [componentId]);
    if (!current.rowCount || !current.rows[0].active_revision_id) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    const contracts = await client.query(
      "select state_key,state_schema from component_state_contract where component_id=$1 and revision_id=$2 order by state_key",
      [componentId, current.rows[0].active_revision_id]
    );
    const query = await client.query(
      "select id,dispatch_id,challenge_nonce,requested_policy_epoch,status from component_state_query_run where id=$1 and component_id=$2 for update",
      [input.queryId, componentId]
    );
    let rejectionReason: string | null = null;
    if (!query.rowCount || query.rows[0].challenge_nonce !== input.queryNonce || query.rows[0].status !== "PENDING") rejectionReason = "state_query_mismatch";
    else if (input.policyEpoch !== Number(current.rows[0].policy_epoch) || input.policyEpoch !== Number(query.rows[0].requested_policy_epoch)) rejectionReason = "policy_epoch_mismatch";
    else if (input.declaredComponentCode !== String(current.rows[0].code)) rejectionReason = "component_identity_mismatch";
    const expectedKeys = contracts.rows.map((row) => String(row.state_key));
    const actualKeys = Object.keys(input.states).sort();
    if (!rejectionReason && canonicalJson(expectedKeys) !== canonicalJson(actualKeys)) rejectionReason = "state_snapshot_keys_mismatch";
    if (!rejectionReason) {
      for (const contract of contracts.rows) {
        try {
          validateAgainstStoredSchema(contract.state_schema, input.states[String(contract.state_key)], "state_schema_invalid");
        } catch {
          rejectionReason = `state_schema_invalid:${String(contract.state_key)}`;
          break;
        }
      }
    }
    const stateDigest = evidenceDigest(input.states);
    const validationState = rejectionReason ? "REJECTED" : "ACCEPTED";
    await client.query(
      `insert into component_state_snapshot(component_id,revision_id,query_run_id,observed_at,states,state_digest,validation_state,rejection_reason,correlation_id)
       values ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9)`,
      [componentId, current.rows[0].active_revision_id, query.rowCount ? input.queryId : null, input.observedAt,
        JSON.stringify(input.states), stateDigest, validationState, rejectionReason, input.correlationId]
    );
    if (validationState === "ACCEPTED") {
      await client.query(
        `update component_state_query_run set status='RESPONDED',response_state_key='FULL_SNAPSHOT',response_digest=$2,
                response_payload=$3::jsonb,observed_at=$4 where id=$1`,
        [input.queryId, stateDigest, JSON.stringify(input.states), input.observedAt]
      );
      await finalizeDispatchFromEvidence(client, String(query.rows[0].dispatch_id), input.correlationId);
      const shared = {
        componentId,
        revisionId: String(current.rows[0].active_revision_id),
        pass: true,
        correlationId: input.correlationId,
        requestDigest: evidenceDigest({ queryId: input.queryId, queryNonce: input.queryNonce }),
        responseDigest: stateDigest
      };
      await recordActiveGateEvidence(client, { ...shared, gate: "STATE_QUERY_CONTROL", reasonCode: "state_query_response_verified", evidence: { queryId: input.queryId, keys: actualKeys }, variant: "full_snapshot_query" });
      await recordActiveGateEvidence(client, { ...shared, gate: "STATE_FULL_SNAPSHOT", reasonCode: "full_state_snapshot_verified", evidence: { queryId: input.queryId, keys: actualKeys }, variant: "all_declared_states" });
      await recordActiveGateEvidence(client, { ...shared, gate: "EACH_STATE_SCHEMA", reasonCode: "each_state_schema_validated", evidence: { queryId: input.queryId, validatedStateKeys: actualKeys }, variant: "all_declared_states" });
    } else {
      await client.query("update component set monitoring_state='DEGRADED',updated_at=now() where id=$1", [componentId]);
    }
    await appendAudit(client, { eventType: validationState === "ACCEPTED" ? "component.state_snapshot.accepted" : "component.state_snapshot.rejected",
      actorType: "component", actorId: componentId, objectType: "component_state_snapshot", objectId: input.queryId,
      after: { validationState, rejectionReason, stateDigest, keys: actualKeys }, correlationId: input.correlationId });
    return rejectionReason ? { accepted: false, validationState, rejectionReason, stateDigest } : { accepted: true, validationState, stateDigest };
  });
}

export async function recordComponentControlAck(db: Db, componentId: string, input: {
  commandId: string;
  commandType: "enable" | "disable" | "state" | "heartbeat";
  status: "ACKED" | "FAILED";
  ackPayload: unknown;
  correlationId: string;
  declaredClientId: string;
  declaredComponentCode: string;
  policyEpoch: number;
}): Promise<{ accepted: true }> {
  return tx(db, async (client) => {
    const component = await client.query("select code,policy_epoch from component where id=$1", [componentId]);
    if (!component.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    if (input.policyEpoch !== Number(component.rows[0].policy_epoch)) throw Object.assign(new Error("policy_epoch_mismatch"), { statusCode: 409 });
    if (input.declaredComponentCode !== String(component.rows[0].code)) throw Object.assign(new Error("component_identity_mismatch"), { statusCode: 403 });
    const result = await client.query(
      `select d.id,contract.response_schema
         from component_control_dispatch d
         join component_control_command contract on contract.id=d.command_contract_id
        where d.id=$1 and d.component_id=$2 and d.command_type=$3
        for update of d`,
      [input.commandId, componentId, input.commandType]
    );
    if (!result.rowCount) throw Object.assign(new Error("control_command_unknown"), { statusCode: 409 });
    validateAgainstStoredSchema(result.rows[0].response_schema, input.ackPayload, "control_ack_schema_invalid");
    const nextState = input.status === "ACKED" ? "ACKED" : "FAILED";
    await client.query(
      `update component_control_dispatch
          set state=$2,ack_digest=$3,final_result=$4::jsonb,final_error_code=$5,updated_at=now()
        where id=$1`,
      [input.commandId, nextState, evidenceDigest(input.ackPayload), JSON.stringify(input.ackPayload), input.status === "FAILED" ? "component_ack_failed" : null]
    );
    if (input.status === "FAILED") {
      await client.query(
        `update component
            set activation_state=case when $2='disable' then 'DISABLE_UNCONFIRMED' else 'BLOCKED' end,
                monitoring_state='DEGRADED',
                ingress_enabled=false,
                pulse_enabled=false,
                egress_enabled=false,
                enabled=false,
                updated_at=now()
          where id=$1`,
        [componentId, input.commandType]
      );
    } else {
      await finalizeDispatchFromEvidence(client, input.commandId, input.correlationId);
    }
    await appendAudit(client, {
      eventType: `component.control.${input.commandType}.${input.status.toLowerCase()}`,
      actorType: "component",
      actorId: componentId,
      objectType: "component",
      objectId: componentId,
      after: { commandType: input.commandType, status: input.status },
      correlationId: input.correlationId
    });
    return { accepted: true };
  });
}

export async function queueComponentE2ERun(db: Db, params: {
  componentId?: string;
  jobId?: string;
  integrationTokenId?: string;
  correlationId: string;
}): Promise<Record<string, unknown>> {
  return tx(db, async (client) => {
    const target = params.jobId
      ? await client.query(
        `select c.id,c.active_revision_id,rt.runtime_digest
           from component_onboarding_job job
           join component c on c.id=job.component_id
           join component_runtime_target rt on rt.component_id=c.id and rt.revision_id=c.active_revision_id
          where job.id=$1 and job.integration_token_id=$2 for update of c`,
        [params.jobId, params.integrationTokenId]
      )
      : await client.query(
        `select c.id,c.active_revision_id,rt.runtime_digest
           from component c
           join component_runtime_target rt on rt.component_id=c.id and rt.revision_id=c.active_revision_id
          where c.id=$1 for update of c`,
        [params.componentId]
      );
    if (!target.rowCount) throw Object.assign(new Error("e2e_target_not_found"), { statusCode: 404 });
    const row = target.rows[0];
    const fixtures = await client.query("select count(*)::int as count from component_e2e_fixture where revision_id=$1", [row.active_revision_id]);
    if (Number(fixtures.rows[0]?.count ?? 0) < 1) throw Object.assign(new Error("e2e_fixtures_missing"), { statusCode: 409 });
    const active = await client.query(
      `select * from component_e2e_run
        where component_id=$1 and revision_id=$2 and runtime_digest=$3 and status in ('QUEUED','RUNNING')
        order by created_at desc limit 1`,
      [row.id, row.active_revision_id, row.runtime_digest]
    );
    if (active.rowCount) return active.rows[0] as Record<string, unknown>;
    const inserted = await client.query(
      `insert into component_e2e_run(component_id,revision_id,runtime_digest,status,correlation_id,deadline_at)
       values ($1,$2,$3,'QUEUED',$4,now()+interval '15 minutes') returning *`,
      [row.id, row.active_revision_id, row.runtime_digest, params.correlationId]
    );
    await appendAudit(client, { eventType: "component.e2e.queued", actorType: params.integrationTokenId ? "integration_token" : "admin",
      actorId: params.integrationTokenId, objectType: "component_e2e_run", objectId: String(inserted.rows[0].id),
      after: { componentId: row.id, revisionId: row.active_revision_id, runtimeDigest: row.runtime_digest }, correlationId: params.correlationId });
    return inserted.rows[0] as Record<string, unknown>;
  });
}

export async function listComponents(db: Db): Promise<Record<string, unknown>[]> {
  const result = await db.query(`
    select c.*,r.revision,r.capabilities,r.protocols,r.transports,
      (select count(*)::int from component_permission p where (p.source_component_id=c.id or p.target_component_id=c.id) and p.revoked_at is null) permission_count,
      (select count(*)::int from principal_access_token token where token.source_principal_id=c.principal_id and token.revoked_at is null) credential_count,
      stream.gap_state,stream.highest_received_sequence,stream.highest_acknowledged_sequence,
      stream.current_event_hash,stream.integrity_state,stream.integrity_reason
    from component c
    left join component_revision r on r.id=c.active_revision_id
    left join component_audit_stream stream on stream.component_id=c.id
    where c.lifecycle_state <> 'DEREGISTERED'
    order by c.kcml_number`);
  return result.rows.map(componentView);
}

export async function getComponent(db: Db, id: string): Promise<Record<string, unknown>> {
  const result = await db.query(`
    select c.*,r.revision,r.capabilities,r.protocols,r.transports,r.derived_gates,r.manifest,r.manifest_digest,
      stream.gap_state,stream.highest_received_sequence,stream.highest_acknowledged_sequence,
      stream.current_event_hash,stream.integrity_state,stream.integrity_reason
    from component c
    left join component_revision r on r.id=c.active_revision_id
    left join component_audit_stream stream on stream.component_id=c.id
    where c.id=$1`, [id]);
  if (!result.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
  const permissions = await db.query(`select id,source_component_id,target_component_id,route_pattern,scope_name,access_level,granted_at,revoked_at from component_permission where source_component_id=$1 or target_component_id=$1 order by granted_at desc`, [id]);
  const accessTokens = await db.query(
    `select token.id,token.fingerprint,token.audience,token.scope_names,token.created_at as issued_at,
            token.last_used_at,token.revoked_at,token.rotated_at,token.rotation_reason
       from principal_access_token token
       join component c on c.principal_id=token.source_principal_id
      where c.id=$1
      order by token.created_at desc`,
    [id]
  );
  const [readinessGates, controlDispatches, stateObservations, heartbeats, runtimeTargets, tools, endpoints, pulseMasks,
    stateContracts, stateTransitions, stateSnapshots, e2eRuns, documentation, operationLeases] = await Promise.all([
    db.query(
      `select gate_key,status,reason_code,evaluator_version,evidence,evidence_digest,correlation_id,executed_at,expires_at
         from component_readiness_gate_evidence
        where component_id=$1
        order by executed_at desc, gate_key`,
      [id]
    ),
    db.query(
      `select dispatch.id,dispatch.command_type,dispatch.target_hostname,dispatch.endpoint_path,dispatch.request_body,dispatch.request_digest,
              dispatch.requested_policy_epoch,dispatch.expected_state_key,dispatch.correlation_id,dispatch.deadline_at,dispatch.state,
              dispatch.final_result,dispatch.final_error_code,dispatch.attempt_count,dispatch.last_attempt_at,dispatch.ack_digest,dispatch.created_at,dispatch.updated_at,
              coalesce((select jsonb_agg(to_jsonb(attempt) order by attempt.attempt_number) from component_control_dispatch_attempt attempt where attempt.dispatch_id=dispatch.id),'[]'::jsonb) attempts
         from component_control_dispatch dispatch
        where dispatch.component_id=$1
        order by dispatch.created_at desc
        limit 20`,
      [id]
    ),
    db.query(
      `select id,state_key,observed_at,correlation_id,validation_state,rejection_reason,declared_client_id,declared_component_code,policy_epoch,state_payload
         from component_state_observation
        where component_id=$1
        order by observed_at desc
        limit 20`,
      [id]
    ),
    db.query(
      `select id,heartbeat_at,policy_epoch,operational_state,state_digest,correlation_id,declared_client_id,declared_component_code,
              validation_state,rejection_reason,challenge_id,challenge_nonce
         from component_heartbeat
        where component_id=$1
        order by heartbeat_at desc
        limit 20`,
      [id]
    ),
    db.query("select transport,upstream,expected_tls_identity,socket_path,status,runtime_digest,last_probe_at,circuit_failure_count,circuit_open_until,last_dispatch_error from component_runtime_target where component_id=$1 order by revision_id desc", [id]),
    db.query("select name,title,description,input_schema,output_schema,scope_name,timeout_ms,limits,annotations from component_tool_contract where component_id=$1 order by name", [id]),
    db.query("select endpoint_id,public_hostname,path,methods,auth_mode,request_schema,response_schema from component_endpoint_contract where component_id=$1 order by endpoint_id", [id]),
    db.query("select pulse_type,direction,route_acl,scopes,envelope_schema,execution_mode,idempotency,token_required from component_pulse_mask where component_id=$1 order by direction,pulse_type", [id]),
    db.query("select state_key,category,state_schema,terminal from component_state_contract where component_id=$1 order by state_key", [id]),
    db.query("select from_state_key,to_state_key,trigger_mask from component_state_transition where component_id=$1 order by from_state_key,to_state_key", [id]),
    db.query("select id,query_run_id,observed_at,state_digest,validation_state,rejection_reason,states,received_at from component_state_snapshot where component_id=$1 order by observed_at desc limit 20", [id]),
    db.query(`select run.id,run.status,run.runtime_digest,run.attempt_count,run.final_error_code,run.created_at,run.started_at,run.completed_at,
      coalesce((select jsonb_agg(to_jsonb(result) order by fixture.scenario_key,fixture.variant_key) from component_e2e_run_result result join component_e2e_fixture fixture on fixture.id=result.fixture_id where result.run_id=run.id),'[]'::jsonb) results
      from component_e2e_run run where run.component_id=$1 order by run.created_at desc limit 20`, [id]),
    db.query("select evidence_key,evidence_ref,evidence_digest,media_type,required,octet_length(content) content_bytes,encode(content,'base64') content_base64,created_at from component_documentation_evidence where component_id=$1 order by evidence_key", [id]),
    db.query("select id,operation_kind,operation_name,input_digest,output_digest,success,started_at,finished_at,expires_at,correlation_id,trace_id,token_fingerprint,permission_epoch from component_operation_lease where target_component_id=$1 order by started_at desc limit 50", [id])
  ]);
  return {
    ...componentView(result.rows[0]),
    permissions: permissions.rows,
    accessTokens: accessTokens.rows,
    readinessGates: readinessGates.rows,
    controlDispatches: controlDispatches.rows,
    stateObservations: stateObservations.rows,
    heartbeatHistory: heartbeats.rows,
    runtimeTargets: runtimeTargets.rows,
    tools: tools.rows,
    endpoints: endpoints.rows,
    pulseMasks: pulseMasks.rows,
    stateContracts: stateContracts.rows,
    stateTransitions: stateTransitions.rows,
    stateSnapshots: stateSnapshots.rows,
    e2eRuns: e2eRuns.rows,
    documentation: documentation.rows,
    operationLeases: operationLeases.rows
  };
}

export async function getComponentDiscovery(db: Db, hostname: string): Promise<Record<string, unknown>> {
    const result = await db.query(`
    select c.id,c.code,c.hostname,c.display_name,c.description,c.category,c.registration_type,c.component_role,
      c.lifecycle_state,c.activation_state,c.operational_state,c.monitoring_state,c.recertification_state,
      c.enabled,c.policy_epoch,c.release_version,c.created_at,c.updated_at,
      r.revision,r.capabilities,r.protocols,r.transports
    from component c
    left join component_revision r on r.id=c.active_revision_id
    where c.hostname=$1`, [hostname]);
  if (!result.rowCount) throw Object.assign(new Error("invalid_component_hostname"), { statusCode: 404 });
  const row = result.rows[0];
  return {
    id: String(row.id), code: String(row.code), hostname: String(row.hostname), displayName: String(row.display_name),
    description: String(row.description), category: String(row.category), registrationType: String(row.registration_type),
    role: String(row.component_role), lifecycleState: String(row.lifecycle_state), activationState: String(row.activation_state),
    operationalState: String(row.operational_state), monitoringState: String(row.monitoring_state),
    recertificationState: String(row.recertification_state), enabled: Boolean(row.enabled), policyEpoch: Number(row.policy_epoch),
    revision: optionalText(row.revision), capabilities: row.capabilities ?? [], protocols: row.protocols ?? [], transports: row.transports ?? [],
    releaseVersion: String(row.release_version),
    createdAt: String(row.created_at), updatedAt: String(row.updated_at)
  };
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
    audit: {
      gapState: optionalText(row.gap_state) ?? "UNAVAILABLE",
      highestReceivedSequence: Number(row.highest_received_sequence ?? 0),
      highestAcknowledgedSequence: Number(row.highest_acknowledged_sequence ?? 0),
      currentEventHash: optionalText(row.current_event_hash),
      integrityState: optionalText(row.integrity_state) ?? "UNAVAILABLE",
      integrityReason: optionalText(row.integrity_reason)
    },
    releaseVersion: String(row.release_version),
    artifact: record(record(row.manifest)?.artifact) ?? null,
    manifestDigest: optionalText(row.manifest_digest),
    createdAt: String(row.created_at), updatedAt: String(row.updated_at)
  };
}

async function advanceComponentPolicyEpoch(client: pg.PoolClient, componentId: string): Promise<void> {
  await client.query(
    `update component
        set revocation_epoch=gen_random_uuid(),
            policy_epoch=policy_epoch+1
      where id=$1`,
    [componentId]
  );
}

export async function setComponentActivation(db: Db, params: { componentId: string; enabled: boolean; actorId: string; correlationId: string }): Promise<Record<string, unknown>> {
  const componentId = await tx(db, async (client) => {
    const current = await client.query(`
      select c.*,r.validation_state,r.manifest_digest as active_manifest_digest,target.runtime_digest,stream.gap_state
      from component c left join component_revision r on r.id=c.active_revision_id
      left join component_runtime_target target on target.component_id=c.id and target.revision_id=c.active_revision_id
      left join component_audit_stream stream on stream.component_id=c.id
      where c.id=$1 for update of c`, [params.componentId]);
    if (!current.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    const component = current.rows[0];
    if (params.enabled) {
      if (!component.active_revision_id || component.validation_state !== "APPROVED") throw Object.assign(new Error("catalog_incompatible"), { statusCode: 409 });
      const gateEvidence = await client.query(
        `with latest as (
           select distinct on (gate_key) gate_key,status
             from component_readiness_gate_evidence
            where component_id=$1 and revision_id=$2
              and revision_digest=$3 and runtime_digest is not distinct from $4
              and artifact_digest is not distinct from $4
              and gate_key=any($5::text[])
            order by gate_key,executed_at desc
         )
         select count(*)::int as gate_count,
                count(*) filter (where status='PASS')::int as pass_count
           from latest`,
        [params.componentId, component.active_revision_id, component.active_manifest_digest, component.runtime_digest, [...ACTIVATION_GATES]]
      );
      if (Number(gateEvidence.rows[0]?.gate_count) !== ACTIVATION_GATES.length
        || Number(gateEvidence.rows[0]?.pass_count) !== ACTIVATION_GATES.length) {
        throw Object.assign(new Error("active_readiness_evidence_required"), { statusCode: 409 });
      }
      if (component.monitoring_state !== "HEALTHY") throw Object.assign(new Error("monitoring_failed"), { statusCode: 409 });
      if (component.gap_state !== "CONTIGUOUS") throw Object.assign(new Error("audit_gap"), { statusCode: 409 });
      if (!["NOT_DUE", "PASSED"].includes(String(component.recertification_state))) throw Object.assign(new Error("recertification_required"), { statusCode: 409 });
    }
    const requestedPolicyEpoch = Number(component.policy_epoch) + 1;
    const dispatch = await enqueueControlDispatch(client, {
      componentId: params.componentId,
      commandType: params.enabled ? "enable" : "disable",
      requestedPolicyEpoch,
      expectedStateKey: params.enabled ? "ENABLED" : "DISABLED",
      correlationId: params.correlationId
    });
    const stateRun = await createStateQueryRun(client, {
      componentId: params.componentId,
      revisionId: String(component.active_revision_id),
      dispatchId: String(dispatch.id),
      requestedPolicyEpoch,
      expectedStateKey: params.enabled ? "ENABLED" : "DISABLED",
      correlationId: params.correlationId
    });
    const heartbeatChallenge = params.enabled ? await createHeartbeatChallenge(client, {
      componentId: params.componentId,
      revisionId: String(component.active_revision_id),
      dispatchId: String(dispatch.id),
      requestedPolicyEpoch,
      correlationId: params.correlationId
    }) : null;
    const updated = await client.query(
      `update component
          set enabled=false,
              ingress_enabled=false,
              pulse_enabled=false,
              egress_enabled=false,
              activation_state=$2,
              lifecycle_state=case when $3 then lifecycle_state else case when lifecycle_state='ACTIVE' then 'APPROVED' else lifecycle_state end end,
              operational_state=case when $3 then 'DISABLED' else 'DISABLED' end,
              policy_epoch=$4,
              lock_version=lock_version+1
        where id=$1 returning id`,
      [params.componentId, params.enabled ? "ENABLE_REQUESTED" : "DISABLE_REQUESTED", params.enabled, requestedPolicyEpoch]
    );
    if (!params.enabled) await advanceComponentPolicyEpoch(client, params.componentId);
    await appendAudit(client, {
      eventType: params.enabled ? "component.activation_requested" : "component.deactivation_requested", actorType: "admin", actorId: params.actorId,
      objectType: "component", objectId: params.componentId,
      before: { enabled: component.enabled, revocationEpoch: component.revocation_epoch, policyEpoch: component.policy_epoch },
      after: {
        enabled: false,
        accessTokensRevoked: false,
        accessTokenUseBlockedByComponentState: !params.enabled,
        dispatchId: dispatch.id,
        stateQueryId: stateRun.id,
        heartbeatChallengeId: heartbeatChallenge?.id ?? null,
        heartbeatNonce: heartbeatChallenge?.challenge_nonce ?? null
      },
      correlationId: params.correlationId
    });
    return String(updated.rows[0].id);
  });
  return getComponent(db, componentId);
}

export async function queueComponentStateQuery(db: Db, params: { componentId: string; actorId?: string; correlationId: string }): Promise<Record<string, unknown>> {
  return tx(db, async (client) => {
    const component = await client.query("select id,active_revision_id,policy_epoch from component where id=$1 for update", [params.componentId]);
    if (!component.rowCount || !component.rows[0].active_revision_id) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    const dispatch = await enqueueControlDispatch(client, { componentId: params.componentId, commandType: "state",
      requestedPolicyEpoch: Number(component.rows[0].policy_epoch), expectedStateKey: "FULL_SNAPSHOT", correlationId: params.correlationId });
    const query = await createStateQueryRun(client, { componentId: params.componentId, revisionId: String(component.rows[0].active_revision_id),
      dispatchId: String(dispatch.id), requestedPolicyEpoch: Number(component.rows[0].policy_epoch), expectedStateKey: "FULL_SNAPSHOT", correlationId: params.correlationId });
    await appendAudit(client, { eventType: "component.state_query.queued", actorType: params.actorId ? "admin" : "system", actorId: params.actorId,
      objectType: "component_control_dispatch", objectId: String(dispatch.id), after: { queryId: query.id }, correlationId: params.correlationId });
    return dispatch;
  });
}

export async function queueComponentHeartbeatChallenge(db: Db, params: { componentId: string; actorId?: string; correlationId: string }): Promise<Record<string, unknown>> {
  return tx(db, async (client) => {
    const component = await client.query("select id,active_revision_id,policy_epoch from component where id=$1 for update", [params.componentId]);
    if (!component.rowCount || !component.rows[0].active_revision_id) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    const existing = await client.query("select id from component_control_dispatch where component_id=$1 and command_type='heartbeat' and state in ('QUEUED','CLAIMED','ACK_PENDING','ACKED') and deadline_at>now() limit 1", [params.componentId]);
    if (existing.rowCount) return { id: String(existing.rows[0].id), alreadyQueued: true };
    const dispatch = await enqueueControlDispatch(client, { componentId: params.componentId, commandType: "heartbeat",
      requestedPolicyEpoch: Number(component.rows[0].policy_epoch), correlationId: params.correlationId });
    const challenge = await createHeartbeatChallenge(client, { componentId: params.componentId, revisionId: String(component.rows[0].active_revision_id),
      dispatchId: String(dispatch.id), requestedPolicyEpoch: Number(component.rows[0].policy_epoch), correlationId: params.correlationId });
    await appendAudit(client, { eventType: "component.heartbeat_challenge.queued", actorType: params.actorId ? "admin" : "system", actorId: params.actorId,
      objectType: "component_control_dispatch", objectId: String(dispatch.id), after: { challengeId: challenge.id }, correlationId: params.correlationId });
    return dispatch;
  });
}

export type ComponentLifecycleAction = "QUARANTINE" | "RESTORE" | "RETIRE" | "DEREGISTER";

export async function setComponentLifecycle(db: Db, params: {
  componentId: string;
  action: ComponentLifecycleAction;
  actorId: string;
  correlationId: string;
}): Promise<Record<string, unknown>> {
  await tx(db, async (client) => {
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
    const permanentlyRevoked = ["RETIRE", "DEREGISTER"].includes(params.action);
    await client.query(
      `update principal set status=$2,revocation_epoch=case when $3 then revocation_epoch+1 else revocation_epoch end,updated_at=now()
        where id=(select principal_id from component where id=$1)`,
      [params.componentId, params.action === "QUARANTINE" ? "QUARANTINED" : params.action === "RESTORE" ? "SUSPENDED" : "REVOKED", permanentlyRevoked]
    );
    const revoked = permanentlyRevoked ? await client.query(
      "update principal_access_token set revoked_at=coalesce(revoked_at,now()),rotation_reason=$2 where source_principal_id=(select principal_id from component where id=$1) and revoked_at is null",
      [params.componentId, `LIFECYCLE_${params.action}`]
    ) : { rowCount: 0 };
    await appendAudit(client, {
      eventType: `component.lifecycle.${params.action.toLowerCase()}`, actorType: "admin", actorId: params.actorId,
      objectType: "component", objectId: params.componentId,
      before: { lifecycleState: component.lifecycle_state, activationState: component.activation_state, operationalState: component.operational_state },
      after: { lifecycleState: next.lifecycle, activationState: next.activation, operationalState: next.operational, accessTokensRevoked: revoked.rowCount ?? 0 },
      correlationId: params.correlationId
    });
  });
  return getComponent(db, params.componentId);
}

export async function setComponentPermissionEnabled(db: Db, params: {
  componentId: string;
  permissionId: string;
  enabled: boolean;
  actorId: string;
  correlationId: string;
}): Promise<Record<string, unknown>> {
  await tx(db, async (client) => {
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
  });
  return getComponent(db, params.componentId);
}

export async function revokeComponentAccessToken(db: Db, params: {
  componentId: string;
  tokenId: string;
  actorId: string;
  correlationId: string;
}): Promise<Record<string, unknown>> {
  await tx(db, async (client) => {
    const token = await client.query(
      `select token.* from principal_access_token token
        join component c on c.principal_id=token.source_principal_id
       where token.id=$1 and c.id=$2 for update of token`,
      [params.tokenId, params.componentId]
    );
    if (!token.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    if (token.rows[0].revoked_at) throw Object.assign(new Error("access_token_already_revoked"), { statusCode: 409 });
    await client.query("update principal_access_token set revoked_at=now(),rotation_reason='ADMIN_REVOKE' where id=$1", [params.tokenId]);
    await appendAudit(client, {
      eventType: "principal_access_token.revoked", actorType: "admin", actorId: params.actorId,
      objectType: "principal_access_token", objectId: params.tokenId,
      before: { revokedAt: null, fingerprint: token.rows[0].fingerprint },
      after: { revokedAt: "NOW", reason: "ADMIN_REVOKE" }, correlationId: params.correlationId
    });
  });
  return getComponent(db, params.componentId);
}

export async function rotateComponentAccessToken(db: Db, params: {
  componentId: string;
  tokenId: string;
  actorId: string;
  accessTokenHmacKey: Buffer;
  accessTokenHmacKeyId: string;
  correlationId: string;
}): Promise<{ component: Record<string, unknown>; accessToken: { token: string; fingerprint: string } }> {
  const accessToken = await tx(db, async (client) => {
    const current = await client.query(
      `select token.*,p.policy_epoch as current_policy_epoch,p.revocation_epoch as current_revocation_epoch
         from principal_access_token token
         join component c on c.principal_id=token.source_principal_id
         join principal p on p.id=token.source_principal_id
        where token.id=$1 and c.id=$2 for update of token,p`,
      [params.tokenId, params.componentId]
    );
    if (!current.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    if (current.rows[0].revoked_at) throw Object.assign(new Error("access_token_already_revoked"), { statusCode: 409 });
    const secret = issueOpaqueSecret();
    const inserted = await client.query(
      `insert into principal_access_token(
         lookup_digest,key_id,fingerprint,source_principal_id,target_component_id,audience,scope_names,
         issued_policy_epoch,issued_revocation_epoch,expires_at
       ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,'infinity') returning id`,
      [hmacToken(secret.value, params.accessTokenHmacKey), params.accessTokenHmacKeyId, secret.fingerprint, current.rows[0].source_principal_id,
        current.rows[0].target_component_id, current.rows[0].audience, current.rows[0].scope_names,
        current.rows[0].current_policy_epoch, current.rows[0].current_revocation_epoch]
    );
    await client.query(
      "update principal_access_token set revoked_at=now(),rotated_at=now(),rotation_reason='ADMIN_ROTATE' where id=$1",
      [params.tokenId]
    );
    await appendAudit(client, {
      eventType: "principal_access_token.rotated", actorType: "admin", actorId: params.actorId,
      objectType: "principal_access_token", objectId: String(inserted.rows[0].id),
      before: { tokenId: params.tokenId, fingerprint: current.rows[0].fingerprint },
      after: { fingerprint: secret.fingerprint, expiresAt: "infinity" }, correlationId: params.correlationId
    });
    return { token: secret.value, fingerprint: secret.fingerprint };
  });
  return { component: await getComponent(db, params.componentId), accessToken };
}
