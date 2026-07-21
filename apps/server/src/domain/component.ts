import { createHash, randomUUID } from "node:crypto";
import { Ajv2020 } from "ajv/dist/2020.js";
import type pg from "pg";
import componentManifestSchema from "../contracts/component-manifest-2026.07.24.schema.json" with { type: "json" };
import type { Db } from "../db.js";
import { tx } from "../db.js";
import { hmacToken, issueOpaqueSecret } from "../security/secrets.js";
import { appendAudit } from "./audit.js";
import { blueprintComponentContract, KCML_RELEASE, KCML_RELEASE_WAVE_KEY } from "./release.js";

export const COMPONENT_CATALOG_VERSION = KCML_RELEASE.catalogVersion;
export const MCP_REQUIRED_CAPABILITIES = [
  "mcp.initialize",
  "mcp.notifications.initialized",
  "mcp.tools.list",
  "mcp.tools.call"
] as const;
export const ACTIVATION_GATES = [
  "FULL_SCHEMA",
  "PULSE_CONTRACT",
  "STATE_CONTRACT",
  "CALL_MASKS",
  "E2E_SCENARIOS",
  "DOCUMENTATION",
  "CONTROL_PLANE",
  "SECRET_POLICY",
  "OUTBOUND_AUTH",
  "AUTHORIZATION",
  "PUBLIC_ENDPOINT",
  "TECHNICAL_DISABLE",
  "MONITORING",
  "AUDIT_CONTINUITY",
  "RECERTIFICATION"
] as const;

export const STRICT_COMPONENT_HOST_SUFFIX = "kajovocml.hcasc.cz";

export type JsonRecord = Record<string, unknown>;

export type ComponentManifest = JsonRecord & {
  schemaVersion: typeof COMPONENT_CATALOG_VERSION;
  releaseVersion: typeof COMPONENT_CATALOG_VERSION;
  registrationRevision: string;
  environment: "production" | "staging";
  componentType: "AI_AGENT" | "MCP_SERVER" | "KCML_MANAGED_SERVICE" | "GENERIC_COMPONENT";
  blueprint: {
    componentId: string;
    version: typeof COMPONENT_CATALOG_VERSION;
    releaseWaveKey: typeof KCML_RELEASE_WAVE_KEY;
  };
  pulseEnvelopeVersion: typeof COMPONENT_CATALOG_VERSION;
  displayName: string;
  businessPurpose: string;
  registrationType: string;
  owners: unknown[];
  contacts: unknown[];
  source: JsonRecord;
  pulseContract: { incoming: JsonRecord[]; outgoing: JsonRecord[] };
  auditPolicy: JsonRecord;
  monitoringProfile: JsonRecord;
  evidence: JsonRecord;
  stateContract: { states: JsonRecord[]; transitions: JsonRecord[] };
  e2eScenarios: JsonRecord[];
  documentationEvidence: JsonRecord[];
  controlPlane: JsonRecord;
  outboundAuthorization: JsonRecord;
  secretPolicy: JsonRecord;
};

type GateResult = {
  gate: typeof ACTIVATION_GATES[number];
  status: "PASS" | "FAIL";
  reasonCode: string;
  evaluatorVersion: string;
  evidence: JsonRecord;
  expiresAt: string | null;
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

function normalizeRegistrationType(value: string): string {
  return value === "KAJA_CLIENT" ? "KCML_ACCESS_CLIENT" : value;
}

function cloneAndNormalizeManifest(input: unknown): unknown {
  if (!input || typeof input !== "object" || Array.isArray(input)) return input;
  const cloned = JSON.parse(JSON.stringify(input)) as JsonRecord;
  if (typeof cloned.registrationType === "string") cloned.registrationType = normalizeRegistrationType(cloned.registrationType);
  return cloned;
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
  const incoming = manifest.pulseContract.incoming;
  const outgoing = manifest.pulseContract.outgoing;
  if (!incoming.length || !outgoing.length) throw Object.assign(new Error("pulse_contract_required"), { statusCode: 400 });
  if (!manifest.stateContract.states.length) throw Object.assign(new Error("state_contract_required"), { statusCode: 400 });
  if (!manifest.e2eScenarios.length) throw Object.assign(new Error("e2e_scenarios_required"), { statusCode: 400 });
  if (!manifest.documentationEvidence.length) throw Object.assign(new Error("documentation_evidence_required"), { statusCode: 400 });
  if (manifest.source.testCommand !== "pnpm kcml:contract-test") throw Object.assign(new Error("contract_test_command_required"), { statusCode: 400 });
  for (const evidence of manifest.documentationEvidence) {
    if (!nonPlaceholderRef(evidence.evidenceRef) || fakeDigest(evidence.evidenceDigest)) {
      throw Object.assign(new Error("manifest_evidence_missing"), { statusCode: 400 });
    }
  }
  for (const scenario of manifest.e2eScenarios) {
    if (!nonPlaceholderRef(scenario.inputRef) || !nonPlaceholderRef(scenario.expectedOutputRef)
      || fakeDigest(scenario.inputDigest) || fakeDigest(scenario.expectedOutputDigest)
      || !record(scenario.expectedOutput)) {
      throw Object.assign(new Error("e2e_fixture_required"), { statusCode: 400 });
    }
  }
  const integrity = record(manifest.integrity);
  if (fakeDigest(integrity?.manifestDigest) || fakeDigest(integrity?.sourceDigest)) {
    throw Object.assign(new Error("integrity_digest_invalid"), { statusCode: 400 });
  }
  rejectPlaceholderSchemas(manifest);
}

function manifestCategory(manifest: ComponentManifest): "AI_AGENT" | "MCP_SERVER" | "PLATFORM_SERVICE" | "EXTERNAL_SERVICE" {
  if (manifest.componentType === "KCML_MANAGED_SERVICE") return "PLATFORM_SERVICE";
  if (manifest.componentType === "GENERIC_COMPONENT") return "EXTERNAL_SERVICE";
  return manifest.componentType;
}

function manifestRole(manifest: ComponentManifest): "AGENT" | "SERVICE" | "PLATFORM" {
  if (manifest.componentType === "AI_AGENT") return "AGENT";
  if (manifest.componentType === "KCML_MANAGED_SERVICE") return "PLATFORM";
  return "SERVICE";
}

function manifestRevision(manifest: ComponentManifest): string {
  return text(manifest.registrationRevision);
}

function manifestCapabilities(manifest: ComponentManifest): string[] {
  const capabilities = new Set(["mcp.initialize", "mcp.notifications.initialized", "mcp.tools.list", "mcp.tools.call", "component.pulse", "component.audit.write", "component.heartbeat", "component.state.query", "component.control.ack", "component.outbound.pulse"]);
  if (manifest.componentType === "MCP_SERVER") MCP_REQUIRED_CAPABILITIES.forEach((capability) => capabilities.add(capability));
  const protocol = record(manifest.protocol);
  const declared = Array.isArray(protocol?.capabilities) ? protocol.capabilities : [];
  declared.map(String).forEach((capability) => capabilities.add(capability === "tools" ? "mcp.tools.call" : capability));
  return [...capabilities].sort();
}

function manifestProtocols(manifest: ComponentManifest): string[] {
  const protocols = new Set(["KCML_PULSE", "KCML_AUDIT", "KCML_CONTROL"]);
  if (manifest.componentType === "MCP_SERVER") protocols.add("MCP");
  return [...protocols].sort();
}

function manifestTransports(): string[] {
  return ["HTTPS", "STREAMABLE_HTTP"].sort();
}

export function validateComponentManifest(input: unknown): ComponentManifest {
  const normalized = cloneAndNormalizeManifest(input);
  if (!validateCatalogComponentManifest(normalized)) {
    throw Object.assign(new Error("invalid_manifest"), { statusCode: 400, errors: validateCatalogComponentManifest.errors });
  }
  const manifest = normalized as ComponentManifest;
  const contract = blueprintComponentContract(manifest.blueprint.componentId);
  if (!contract || manifest.registrationType !== contract.registrationType) {
    throw Object.assign(new Error("registration_type_mismatch"), { statusCode: 409 });
  }
  rejectIncompleteContract(manifest);
  return manifest;
}

function evidenceDigest(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

function statePayloadMatchesCommand(expectedStateKey: string | null, payload: unknown): boolean {
  if (!expectedStateKey) return false;
  const body = record(payload);
  const activationState = text(body?.activationState).toUpperCase();
  const operationalState = text(body?.operationalState).toUpperCase();
  const enabled = typeof body?.enabled === "boolean" ? body.enabled : null;
  if (expectedStateKey === "ENABLED") {
    return enabled === true || activationState === "ACTIVE" || operationalState === "HEALTHY";
  }
  if (expectedStateKey === "DISABLED") {
    return enabled === false || activationState === "DISABLED" || operationalState === "DISABLED";
  }
  return activationState === expectedStateKey || operationalState === expectedStateKey;
}

async function gateResults(db: Db, componentId: string, manifest: ComponentManifest, authorizationSnapshot: Record<string, unknown>): Promise<GateResult[]> {
  const evidence = await db.query(
    `select c.monitoring_state,c.recertification_state,stream.gap_state,
            c.hostname,c.category,c.activation_state,c.lifecycle_state,c.enabled,
            (select count(*)::int from component_pulse_mask where component_id=c.id) as pulse_masks,
            (select count(*)::int from component_state_contract where component_id=c.id) as state_contracts,
            (select count(*)::int from component_call_mask where component_id=c.id) as call_masks,
            (select count(*)::int from component_endpoint_contract where component_id=c.id) as endpoint_contracts,
            (select count(*)::int from component_e2e_scenario where component_id=c.id) as e2e_scenarios,
            (select count(*)::int from component_e2e_scenario s
              where s.component_id=c.id
                and exists (select 1 from component_e2e_result r where r.scenario_id=s.id and r.status='PASS')) as e2e_passed,
            (select count(*)::int from component_documentation_evidence where component_id=c.id) as documentation,
            (select count(distinct command_type)::int from component_control_command where component_id=c.id and command_type in ('enable','disable','state','heartbeat')) as control_commands,
            exists (select 1 from component_secret_policy where component_id=c.id) as secret_policy,
            exists (select 1 from component_pulse_mask where component_id=c.id and direction='OUTGOING' and token_required is true) as outbound_auth,
            exists (select 1 from component_readiness_gate_evidence g where g.component_id=c.id and g.gate_key='MONITORING' and g.status='PASS' and (g.expires_at is null or g.expires_at > now())) as monitoring_probe_evidence
       from component c
       left join component_audit_stream stream on stream.component_id=c.id
      where c.id=$1`,
    [componentId]
  );
  const row = evidence.rows[0] ?? {};
  const e2eScenarios = Number(row.e2e_scenarios ?? 0);
  const now = new Date().toISOString();
  return [
    {
      gate: "FULL_SCHEMA",
      status: "PASS",
      reasonCode: "manifest_validated",
      evaluatorVersion: "2026.07.24",
      evidence: { schemaVersion: manifest.schemaVersion, manifestDigest: componentManifestDigest(manifest), checkedAt: now },
      expiresAt: null
    },
    {
      gate: "PULSE_CONTRACT",
      status: Number(row.pulse_masks ?? 0) >= manifest.pulseContract.incoming.length + manifest.pulseContract.outgoing.length ? "PASS" : "FAIL",
      reasonCode: Number(row.pulse_masks ?? 0) >= manifest.pulseContract.incoming.length + manifest.pulseContract.outgoing.length ? "pulse_masks_complete" : "pulse_masks_incomplete",
      evaluatorVersion: "2026.07.24",
      evidence: { declaredIncoming: manifest.pulseContract.incoming.length, declaredOutgoing: manifest.pulseContract.outgoing.length, storedMasks: Number(row.pulse_masks ?? 0), checkedAt: now },
      expiresAt: null
    },
    {
      gate: "STATE_CONTRACT",
      status: Number(row.state_contracts ?? 0) >= manifest.stateContract.states.length ? "PASS" : "FAIL",
      reasonCode: Number(row.state_contracts ?? 0) >= manifest.stateContract.states.length ? "state_contract_complete" : "state_contract_incomplete",
      evaluatorVersion: "2026.07.24",
      evidence: { declaredStates: manifest.stateContract.states.map((state) => text(state.stateKey)), storedStates: Number(row.state_contracts ?? 0), checkedAt: now },
      expiresAt: null
    },
    {
      gate: "CALL_MASKS",
      status: Number(row.call_masks ?? 0) > 0 && Number(row.endpoint_contracts ?? 0) > 0 ? "PASS" : "FAIL",
      reasonCode: Number(row.call_masks ?? 0) > 0 && Number(row.endpoint_contracts ?? 0) > 0 ? "call_masks_complete" : "call_masks_missing",
      evaluatorVersion: "2026.07.24",
      evidence: { storedCallMasks: Number(row.call_masks ?? 0), storedEndpoints: Number(row.endpoint_contracts ?? 0), checkedAt: now },
      expiresAt: null
    },
    {
      gate: "E2E_SCENARIOS",
      status: e2eScenarios > 0 && Number(row.e2e_passed ?? 0) >= e2eScenarios ? "PASS" : "FAIL",
      reasonCode: e2eScenarios > 0 && Number(row.e2e_passed ?? 0) >= e2eScenarios ? "e2e_all_variants_passed" : "e2e_variants_missing_or_failed",
      evaluatorVersion: "2026.07.24",
      evidence: { declaredScenarioCount: e2eScenarios, passingScenarioCount: Number(row.e2e_passed ?? 0), checkedAt: now },
      expiresAt: null
    },
    {
      gate: "DOCUMENTATION",
      status: Number(row.documentation ?? 0) >= manifest.documentationEvidence.length ? "PASS" : "FAIL",
      reasonCode: Number(row.documentation ?? 0) >= manifest.documentationEvidence.length ? "documentation_evidence_complete" : "documentation_evidence_missing",
      evaluatorVersion: "2026.07.24",
      evidence: { declaredEvidence: manifest.documentationEvidence.map((item) => text(item.evidenceKey)), storedEvidenceCount: Number(row.documentation ?? 0), checkedAt: now },
      expiresAt: null
    },
    {
      gate: "CONTROL_PLANE",
      status: Number(row.control_commands ?? 0) === 4 ? "PASS" : "FAIL",
      reasonCode: Number(row.control_commands ?? 0) === 4 ? "control_contract_complete" : "control_contract_incomplete",
      evaluatorVersion: "2026.07.24",
      evidence: { storedControlCommands: Number(row.control_commands ?? 0), expectedCommands: ["enable", "disable", "state", "heartbeat"], checkedAt: now },
      expiresAt: null
    },
    {
      gate: "SECRET_POLICY",
      status: row.secret_policy === true ? "PASS" : "FAIL",
      reasonCode: row.secret_policy === true ? "secret_policy_present" : "secret_policy_missing",
      evaluatorVersion: "2026.07.24",
      evidence: { policyDeclared: row.secret_policy === true, checkedAt: now },
      expiresAt: null
    },
    {
      gate: "OUTBOUND_AUTH",
      status: row.outbound_auth === true && manifest.outboundAuthorization.tokenRequired === true ? "PASS" : "FAIL",
      reasonCode: row.outbound_auth === true && manifest.outboundAuthorization.tokenRequired === true ? "outbound_auth_enforced" : "outbound_auth_incomplete",
      evaluatorVersion: "2026.07.24",
      evidence: { tokenRequired: manifest.outboundAuthorization.tokenRequired === true, outboundMaskRequiresToken: row.outbound_auth === true, checkedAt: now },
      expiresAt: null
    },
    {
      gate: "AUTHORIZATION",
      status: manifest.secretPolicy.authorizationAuthority === "KCML" && authorizationSnapshot.blueprintComponentId === manifest.blueprint.componentId ? "PASS" : "FAIL",
      reasonCode: manifest.secretPolicy.authorizationAuthority === "KCML" && authorizationSnapshot.blueprintComponentId === manifest.blueprint.componentId ? "authorization_bound" : "authorization_snapshot_mismatch",
      evaluatorVersion: "2026.07.24",
      evidence: { authorizationAuthority: manifest.secretPolicy.authorizationAuthority, snapshotBlueprint: authorizationSnapshot.blueprintComponentId ?? null, manifestBlueprint: manifest.blueprint.componentId, checkedAt: now },
      expiresAt: null
    },
    {
      gate: "PUBLIC_ENDPOINT",
      status: typeof row.hostname === "string" && String(row.hostname).endsWith(`.${STRICT_COMPONENT_HOST_SUFFIX}`) ? "PASS" : "FAIL",
      reasonCode: typeof row.hostname === "string" && String(row.hostname).endsWith(`.${STRICT_COMPONENT_HOST_SUFFIX}`) ? "canonical_hostname_verified" : "canonical_hostname_missing",
      evaluatorVersion: "2026.07.24",
      evidence: { hostname: row.hostname ?? null, category: row.category ?? null, checkedAt: now },
      expiresAt: null
    },
    {
      gate: "TECHNICAL_DISABLE",
      status: record(manifest.controlPlane.disable)?.supported === true && record(manifest.controlPlane.enable)?.supported === true ? "PASS" : "FAIL",
      reasonCode: record(manifest.controlPlane.disable)?.supported === true && record(manifest.controlPlane.enable)?.supported === true ? "enable_disable_supported" : "enable_disable_missing",
      evaluatorVersion: "2026.07.24",
      evidence: { enable: record(manifest.controlPlane.enable) ?? null, disable: record(manifest.controlPlane.disable) ?? null, checkedAt: now },
      expiresAt: null
    },
    {
      gate: "MONITORING",
      status: Array.isArray(manifest.monitoringProfile.probes) && (row.monitoring_probe_evidence === true || row.monitoring_state === "HEALTHY") ? "PASS" : "FAIL",
      reasonCode: Array.isArray(manifest.monitoringProfile.probes) && (row.monitoring_probe_evidence === true || row.monitoring_state === "HEALTHY") ? "monitoring_probe_evidence_present" : "monitoring_probe_evidence_missing",
      evaluatorVersion: "2026.07.24",
      evidence: { probes: manifest.monitoringProfile.probes ?? [], monitoringState: row.monitoring_state ?? null, priorEvidence: row.monitoring_probe_evidence === true, checkedAt: now },
      expiresAt: new Date(Date.now() + 15 * 60_000).toISOString()
    },
    {
      gate: "AUDIT_CONTINUITY",
      status: manifest.auditPolicy.technicalAudit === "PLATFORM" && row.gap_state === "CONTIGUOUS" ? "PASS" : "FAIL",
      reasonCode: manifest.auditPolicy.technicalAudit === "PLATFORM" && row.gap_state === "CONTIGUOUS" ? "audit_contiguous" : "audit_gap_detected",
      evaluatorVersion: "2026.07.24",
      evidence: { technicalAudit: manifest.auditPolicy.technicalAudit, gapState: row.gap_state ?? null, checkedAt: now },
      expiresAt: null
    },
    {
      gate: "RECERTIFICATION",
      status: ["NOT_DUE", "PASSED"].includes(String(row.recertification_state)) ? "PASS" : "FAIL",
      reasonCode: ["NOT_DUE", "PASSED"].includes(String(row.recertification_state)) ? "recertification_current" : "recertification_blocked",
      evaluatorVersion: "2026.07.24",
      evidence: { recertificationState: row.recertification_state ?? null, checkedAt: now },
      expiresAt: null
    }
  ];
}

async function persistGateEvidence(
  client: pg.PoolClient,
  componentId: string,
  revisionId: string,
  gates: GateResult[],
  correlationId: string
): Promise<void> {
  await client.query("delete from component_readiness_gate_evidence where component_id=$1 and revision_id=$2", [componentId, revisionId]);
  for (const gate of gates) {
    await client.query(
      `insert into component_readiness_gate_evidence(
        component_id,revision_id,gate_key,evaluator_version,status,reason_code,evidence,evidence_digest,correlation_id,expires_at
      ) values ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10)`,
      [componentId, revisionId, gate.gate, gate.evaluatorVersion, gate.status, gate.reasonCode, JSON.stringify(gate.evidence), evidenceDigest(gate.evidence), correlationId, gate.expiresAt]
    );
  }
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
}): Promise<Record<string, unknown>> {
  const { revisionId, row } = await controlContract(client, params.componentId, params.commandType);
  const target = await client.query("select hostname,code from component where id=$1", [params.componentId]);
  const requestBody = {
    commandId: randomUUID(),
    commandType: params.commandType,
    componentId: params.componentId,
    componentCode: String(target.rows[0]?.code ?? ""),
    policyEpoch: params.requestedPolicyEpoch,
    expectedStateKey: params.expectedStateKey ?? null,
    requestedAt: new Date().toISOString()
  };
  const dispatch = await client.query(
    `insert into component_control_dispatch(
      component_id,revision_id,command_contract_id,command_type,target_hostname,endpoint_path,request_body,request_digest,
      requested_policy_epoch,expected_state_key,correlation_id,causation_id,deadline_at,retry_policy
    ) values ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11,$12,now()+interval '5 minutes',$13::jsonb)
    returning *`,
    [
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
      JSON.stringify({ maxAttempts: 3, strategy: "fail_closed" })
    ]
  );
  await client.query(
    `insert into component_control_dispatch_attempt(
      dispatch_id,attempt_number,status,request_body,correlation_id
    ) values ($1,1,'SENT',$2::jsonb,$3)`,
    [dispatch.rows[0].id, JSON.stringify(requestBody), params.correlationId]
  );
  await client.query(
    `update component_control_dispatch
        set state='ACK_PENDING',attempt_count=1,last_attempt_at=now(),updated_at=now()
      where id=$1`,
    [dispatch.rows[0].id]
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
  const queryOkay = row.query_status === "RESPONDED" && statePayloadMatchesCommand(optionalText(row.expected_state_key), row.response_payload);
  const heartbeatOkay = commandType === "enable" ? row.heartbeat_status === "RESPONDED" : true;
  const acked = ["ACKED", "STATE_CONFIRMED", "HEARTBEAT_CONFIRMED", "COMPLETED"].includes(String(row.state));
  if (!acked || !queryOkay || !heartbeatOkay) return;
  const activating = commandType === "enable";
  await client.query(
    `update component
        set enabled=$2,
            ingress_enabled=$2,
            pulse_enabled=$2,
            egress_enabled=$2,
            activation_state=$3,
            operational_state=$4,
            monitoring_state=$5,
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
  await client.query(
    `update component_control_dispatch
        set state='COMPLETED',
            final_result=$2::jsonb,
            updated_at=now()
      where id=$1`,
    [dispatchId, JSON.stringify({ queryStateKey: row.response_state_key ?? null, heartbeatConfirmed: heartbeatOkay })]
  );
  await appendAudit(client, {
    eventType: activating ? "component.activation.confirmed" : "component.deactivation.confirmed",
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
    "component_state_contract"
  ];
  for (const table of tables) {
    await client.query(`delete from ${table} where component_id=$1 and revision_id=$2`, [componentId, revisionId]);
  }

  for (const state of manifest.stateContract.states) {
    await client.query(
      `insert into component_state_contract(component_id,revision_id,state_key,category,state_schema,terminal)
       values ($1,$2,$3,$4,$5::jsonb,$6)`,
      [componentId, revisionId, text(state.stateKey), text(state.category) || "OPERATIONAL", JSON.stringify(state.schema ?? {}), state.terminal === true]
    );
  }
  for (const transition of manifest.stateContract.transitions) {
    await client.query(
      `insert into component_state_transition(component_id,revision_id,from_state_key,to_state_key,trigger_mask)
       values ($1,$2,$3,$4,$5)`,
      [componentId, revisionId, text(transition.from), text(transition.to), text(transition.triggerMask)]
    );
  }

  const pulseMasks: JsonRecord[] = [
    ...manifest.pulseContract.incoming.map((pulse) => ({ ...pulse, direction: "INCOMING" })),
    ...manifest.pulseContract.outgoing.map((pulse) => ({ ...pulse, direction: "OUTGOING" }))
  ];
  for (const pulse of pulseMasks) {
    await client.query(
      `insert into component_pulse_mask(component_id,revision_id,pulse_type,direction,route_acl,scopes,envelope_schema,execution_mode,idempotency,token_required)
       values ($1,$2,$3,$4,$5::text[],$6::text[],$7::jsonb,$8,$9,true)`,
      [componentId, revisionId, text(pulse.pulseType), text(pulse.direction), Array.isArray(pulse.routeAcl) ? pulse.routeAcl.map(String) : [],
        Array.isArray(pulse.scopes) ? pulse.scopes.map(String) : [], JSON.stringify(pulse.schema ?? {}), text(pulse.executionMode), text(pulse.idempotency)]
    );
  }

  const publicEndpoints = Array.isArray(manifest.publicEndpoints) ? manifest.publicEndpoints as JsonRecord[] : [];
  for (const endpoint of publicEndpoints) {
    const endpointId = text(endpoint.endpointId);
    await client.query(
      `insert into component_endpoint_contract(component_id,revision_id,endpoint_id,public_hostname,path,methods,auth_mode,request_schema,response_schema)
       values ($1,$2,$3,$4,$5,$6::text[],$7,$8::jsonb,$9::jsonb)`,
      [componentId, revisionId, endpointId, hostname, text(endpoint.path), Array.isArray(endpoint.methods) ? endpoint.methods.map(String) : [],
        text(endpoint.authMode), JSON.stringify(endpoint.requestSchema ?? {}), JSON.stringify(endpoint.responseSchema ?? {})]
    );
    await client.query(
      `insert into component_call_mask(component_id,revision_id,mask_key,direction,route_pattern,scope_name,request_schema,response_schema)
       values ($1,$2,$3,'INBOUND',$4,$5,$6::jsonb,$7::jsonb)`,
      [componentId, revisionId, `endpoint:${endpointId}`, text(endpoint.path), text(record(endpoint.eventMapping)?.pulseType) || endpointId,
        JSON.stringify(endpoint.requestSchema ?? {}), JSON.stringify(endpoint.responseSchema ?? {})]
    );
  }

  const facadeTools = Array.isArray(manifest.facadeTools) ? manifest.facadeTools as JsonRecord[] : [];
  for (const tool of facadeTools) {
    await client.query(
      `insert into component_call_mask(component_id,revision_id,mask_key,direction,route_pattern,scope_name,request_schema,response_schema)
       values ($1,$2,$3,'INBOUND',$4,$5,$6::jsonb,$7::jsonb)`,
      [componentId, revisionId, `tool:${text(tool.name)}`, `/mcp/tools/${text(tool.name)}`, "mcp.tools.call",
        JSON.stringify(tool.inputSchema ?? {}), JSON.stringify(tool.outputSchema ?? {})]
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
        [componentId, revisionId, text(pulse.pulseType), attribute, JSON.stringify(record(schema.properties)?.[attribute] ?? {})]
      );
    }
  }

  for (const scenario of manifest.e2eScenarios) {
    await client.query(
      `insert into component_e2e_scenario(component_id,revision_id,scenario_key,variant,input_ref,input_digest,expected_output_ref,expected_output_digest,expected_output,test_commands)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::text[])`,
      [componentId, revisionId, text(scenario.scenarioId), text(scenario.variant), text(scenario.inputRef), text(scenario.inputDigest),
        text(scenario.expectedOutputRef), text(scenario.expectedOutputDigest), JSON.stringify(scenario.expectedOutput), Array.isArray(scenario.testCommands) ? scenario.testCommands.map(String) : ["pnpm kcml:contract-test"]]
    );
  }

  for (const evidence of manifest.documentationEvidence) {
    await client.query(
      `insert into component_documentation_evidence(component_id,revision_id,evidence_key,evidence_ref,evidence_digest,media_type,required)
       values ($1,$2,$3,$4,$5,$6,$7)`,
      [componentId, revisionId, text(evidence.evidenceKey), text(evidence.evidenceRef), optionalText(evidence.evidenceDigest), optionalText(evidence.mediaType), evidence.required !== false]
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
  }

  await client.query(
    `insert into component_secret_policy(component_id,revision_id,policy_mode,all_secrets_requires_grant,audit_level)
     values ($1,$2,$3,$4,$5)`,
    [componentId, revisionId, text(manifest.secretPolicy.mode) || "GRANTED_SECRETS", manifest.secretPolicy.allSecretsRequiresGrant !== false, text(manifest.secretPolicy.auditLevel) || "FULL"]
  );
  for (const scopeName of ["mcp.initialize", "mcp.notifications.initialized", "mcp.tools.list", "mcp.tools.call"]) {
    await client.query(
      `insert into component_permission(source_component_id,target_component_id,route_pattern,scope_name,access_level,granted_by_type)
       values ($1,$1,'/v2/component-mcp',$2,'INVOKE','system')
       on conflict (source_component_id,target_component_id,route_pattern,scope_name) do nothing`,
      [componentId, scopeName]
    );
  }
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
    const token = await client.query(
      `select id,token_kind,release_version,release_wave_key,max_child_jobs
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
    const blueprintComponentId = params.manifest.blueprint.componentId;
    const allowed = await client.query(
      `select registration_type, category, component_role
         from release_wave_component
        where blueprint_component_id=$1
          and release_version=$2
          and wave_key=$3`,
      [blueprintComponentId, COMPONENT_CATALOG_VERSION, KCML_RELEASE_WAVE_KEY]
    );
    if (!allowed.rowCount) throw Object.assign(new Error("integration_token_scope_mismatch"), { statusCode: 403 });
    if (normalizeRegistrationType(String(allowed.rows[0].registration_type)) !== params.manifest.registrationType) {
      throw Object.assign(new Error("registration_type_mismatch"), { statusCode: 409 });
    }
    const existing = await client.query(
      "select * from component_onboarding_job where integration_token_id=$1 and idempotency_key=$2 for update",
      [params.integrationTokenId, params.idempotencyKey]
    );
    if (existing.rowCount) {
      if (String(existing.rows[0].request_digest) !== digest) throw Object.assign(new Error("idempotency_conflict"), { statusCode: 409 });
      return componentOnboardingView(existing.rows[0]);
    }
    const successfulCredential = await client.query(
      `select 1
         from component_onboarding_job
        where integration_token_id=$1
          and credential_id is not null
        limit 1`,
      [params.integrationTokenId]
    );
    if (successfulCredential.rowCount) throw Object.assign(new Error("integration_token_consumed"), { statusCode: 409 });
    const activeJob = await client.query(
      `select 1
         from component_onboarding_job
        where integration_token_id=$1
          and state not in ('CANCELLED','FAILED')
          and credential_id is null
        limit 1`,
      [params.integrationTokenId]
    );
    if (activeJob.rowCount) throw Object.assign(new Error("integration_token_already_bound"), { statusCode: 409 });
    const duplicate = await client.query(
      `select id from component_onboarding_job
        where integration_token_id=$1
          and blueprint_component_id=$2
          and state not in ('CANCELLED','FAILED')
        limit 1`,
      [params.integrationTokenId, blueprintComponentId]
    );
    if (duplicate.rowCount) throw Object.assign(new Error("blueprint_component_duplicate"), { statusCode: 409 });
    const identity = await client.query("select nextval('kcml_number_seq')::bigint as number");
    const number = Number(identity.rows[0].number);
    const code = `KCML${String(number).padStart(4, "0")}`;
    const hostname = `${code.toLowerCase()}.${STRICT_COMPONENT_HOST_SUFFIX}`;
    const componentId = randomUUID();
    const category = manifestCategory(params.manifest);
    const role = manifestRole(params.manifest);
    const capabilities = manifestCapabilities(params.manifest);
    const protocols = manifestProtocols(params.manifest);
    const transports = manifestTransports();
    const authorizationSnapshot = {
      tokenId: params.integrationTokenId,
      tokenKind: String(tokenRow.token_kind),
      releaseVersion: COMPONENT_CATALOG_VERSION,
      releaseWaveKey: KCML_RELEASE_WAVE_KEY,
      blueprintComponentId,
      registrationType: params.manifest.registrationType,
      category,
      capturedAt: new Date().toISOString()
    };
    await client.query(
      `insert into component(
        id,kcml_number,code,hostname,display_name,description,category,registration_type,component_role,owners,contacts,
        lifecycle_state,activation_state,operational_state,monitoring_state,enabled,release_version,release_wave_key,blueprint_component_id
      ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb,'REVIEW','INACTIVE','UNKNOWN',$12,false,$13,$14,$15)`,
      [componentId, number, code, hostname, params.manifest.displayName, params.manifest.businessPurpose, category,
        params.manifest.registrationType, role, JSON.stringify(params.manifest.owners), JSON.stringify(params.manifest.contacts),
        "PENDING", COMPONENT_CATALOG_VERSION, KCML_RELEASE_WAVE_KEY, blueprintComponentId]
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
        release_version,release_wave_key,blueprint_component_id,authorization_snapshot
      ) values ($1,$2,$3,$4,$5,$6,$7::jsonb,$4,'IN_REVIEW',$8,$9,$10,$11::jsonb) returning *`,
      [params.integrationTokenId, componentId, params.idempotencyKey, digest, category, params.manifest.registrationType,
        JSON.stringify(params.manifest), COMPONENT_CATALOG_VERSION, KCML_RELEASE_WAVE_KEY, blueprintComponentId, JSON.stringify(authorizationSnapshot)]
    );
    await client.query(
      `insert into integration_token_child_job(
         token_id, component_onboarding_job_id, blueprint_component_id, registration_type,
         release_version, release_wave_key, authorization_snapshot
       ) values ($1,$2,$3,$4,$5,$6,$7::jsonb)`,
      [params.integrationTokenId, inserted.rows[0].id, blueprintComponentId, params.manifest.registrationType,
        COMPONENT_CATALOG_VERSION, KCML_RELEASE_WAVE_KEY, JSON.stringify(authorizationSnapshot)]
    );
    await client.query("update component set active_revision_id=$2 where id=$1", [componentId, revision.rows[0].id]);
    await appendAudit(client, {
      eventType: "component_onboarding.created", actorType: "integration_token", actorId: params.integrationTokenId,
      objectType: "component", objectId: componentId,
      after: { code, hostname, catalogVersion: COMPONENT_CATALOG_VERSION, releaseWaveKey: KCML_RELEASE_WAVE_KEY, blueprintComponentId },
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
        and job.credential_id is null
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
            credential_claim_expires_at=null, lock_version=lock_version+1, updated_at=now()
      where id=$1 and credential_id is null`,
    [jobId]
  );
  await client.query("delete from integration_token_child_job where component_onboarding_job_id=$1", [jobId]);
  if (componentId) {
    await client.query("update component_credential set status='REVOKED',revoked_at=coalesce(revoked_at,now()),revocation_epoch=gen_random_uuid() where component_id=$1 and status<>'REVOKED'", [componentId]);
    await client.query("update component_access_token set revoked_at=coalesce(revoked_at,now()) where source_component_id=$1 or target_component_id=$1", [componentId]);
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
    credentialClaimAvailable: Boolean(row.credential_claim_digest) && !row.credential_claimed_at,
    failureCode: optionalText(row.failure_code),
    lockVersion: Number(row.lock_version),
    releaseVersion: String(row.release_version),
    releaseWaveKey: optionalText(row.release_wave_key),
    blueprintComponentId: optionalText(row.blueprint_component_id),
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
    if (String(job.blueprint_component_id) !== params.manifest.blueprint.componentId) {
      throw Object.assign(new Error("blueprint_component_immutable"), { statusCode: 409 });
    }
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
        manifestProtocols(params.manifest), manifestTransports(), JSON.stringify(ACTIVATION_GATES)]
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
    const authorizationSnapshot = job.authorization_snapshot && typeof job.authorization_snapshot === "object"
      ? job.authorization_snapshot as Record<string, unknown>
      : {};
    const componentCurrent = await client.query("select active_revision_id from component where id=$1", [job.component_id]);
    const activeRevisionId = optionalText(componentCurrent.rows[0]?.active_revision_id);
    if (!activeRevisionId) throw Object.assign(new Error("catalog_incompatible"), { statusCode: 409 });
    const gates = await gateResults(client as unknown as Db, String(job.component_id), manifest, authorizationSnapshot);
    await persistGateEvidence(client, String(job.component_id), activeRevisionId, gates, params.correlationId);
    const passed = gates.every((gate) => gate.status === "PASS");
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
      [params.jobId, passed ? "READY_FOR_ACTIVATION" : "BLOCKED", JSON.stringify(gates), claimDigest]
    );
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
    if (job.state !== "READY_FOR_ACTIVATION" || job.credential_claimed_at || !job.credential_claim_digest
      || !Buffer.from(job.credential_claim_digest).equals(claimDigest)
      || !job.credential_claim_expires_at || new Date(job.credential_claim_expires_at).getTime() <= Date.now()) {
      throw Object.assign(new Error("credential_claim_invalid"), { statusCode: 409 });
    }
    const manifest = validateComponentManifest(job.manifest);
    const authorizationSnapshot = job.authorization_snapshot && typeof job.authorization_snapshot === "object"
      ? job.authorization_snapshot as Record<string, unknown>
      : {};
    const gates = await gateResults(client as unknown as Db, String(job.component_id), manifest, authorizationSnapshot);
    if (!gates.every((gate) => gate.status === "PASS")) {
      await client.query(
        `update component_onboarding_job set state='BLOCKED',gate_results=$2::jsonb,credential_claim_digest=null,
          credential_claim_expires_at=null,lock_version=lock_version+1,updated_at=now() where id=$1`,
        [params.jobId, JSON.stringify(gates)]
      );
      throw Object.assign(new Error("credential_claim_gates_not_passed"), { statusCode: 409 });
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
    await client.query(
      "update integration_token set revoked_at=coalesce(revoked_at,now()), lock_version=lock_version+1 where id=$1 and revoked_at is null",
      [params.integrationTokenId]
    );
    await appendAudit(client, {
      eventType: "component_credential.claimed", actorType: "integration_token", actorId: params.integrationTokenId,
      objectType: "component_credential", objectId: String(credential.rows[0].id),
      after: { clientId, fingerprint: secret.fingerprint, integrationTokenConsumed: true }, correlationId: params.correlationId
    });
    return { clientId, clientSecret: secret.value, fingerprint: secret.fingerprint };
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

export async function ingestComponentPulse(db: Db, componentId: string, envelope: ComponentPulseEnvelope): Promise<{ accepted: true; correlationId: string }> {
  return tx(db, async (client) => {
    const mask = await client.query(
      `select mask.*,component.code as component_code
         from component_pulse_mask mask
         join component on component.id=mask.component_id
        where component_id=$1 and pulse_type=$2 and direction=$3`,
      [componentId, envelope.pulseType, envelope.direction]
    );
    if (!mask.rowCount) throw Object.assign(new Error("unknown_pulse_type"), { statusCode: 409 });
    if (!envelope.accessTokenFingerprint) throw Object.assign(new Error("access_token_required"), { statusCode: 401 });
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
    validateAgainstStoredSchema(mask.rows[0].envelope_schema, envelope.input, "pulse_schema_invalid");
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
}): Promise<{ accepted: true; policyEpoch: number; failClosed: boolean }> {
  return tx(db, async (client) => {
    const current = await client.query("select policy_epoch,code,activation_state,recertification_state from component where id=$1 for update", [componentId]);
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
      return { accepted: true, policyEpoch, failClosed: true };
    }
    if (current.rows[0].activation_state === "ENABLE_REQUESTED" && heartbeat.challengeId) {
      const dispatch = await client.query("select dispatch_id from component_heartbeat_challenge where id=$1", [heartbeat.challengeId]);
      if (dispatch.rowCount && dispatch.rows[0].dispatch_id) {
        await finalizeDispatchFromEvidence(client, String(dispatch.rows[0].dispatch_id), heartbeat.correlationId);
      }
    }
    return { accepted: true, policyEpoch, failClosed: false };
  });
}

export async function markStaleComponentHeartbeats(db: Db, staleAfterSeconds: number, disableAfterSeconds: number, correlationId: string): Promise<number> {
  return tx(db, async (client) => {
    const stale = await client.query(
      `select c.id,
              max(h.heartbeat_at) as last_heartbeat
         from component c
         left join component_heartbeat h on h.component_id=c.id
        where c.lifecycle_state='ACTIVE' and c.enabled=true
        group by c.id
       having coalesce(max(h.heartbeat_at), c.created_at) < now()-($1||' seconds')::interval
        for update of c`,
      [staleAfterSeconds]
    );
    for (const row of stale.rows) {
      const disable = new Date(String(row.last_heartbeat ?? 0)).getTime() <= Date.now() - disableAfterSeconds * 1000;
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
      if (disable) await revokeComponentRuntimeTokens(client, String(row.id));
      await appendAudit(client, {
        eventType: disable ? "component.heartbeat.disabled" : "component.heartbeat.stale",
        actorType: "system",
        objectType: "component",
        objectId: String(row.id),
        after: { lastHeartbeat: row.last_heartbeat ?? null, staleAfterSeconds, disableAfterSeconds },
        correlationId
      });
    }
    return stale.rowCount ?? 0;
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
}): Promise<{ accepted: boolean; validationState: "ACCEPTED" | "REJECTED" }> {
  return tx(db, async (client) => {
    const component = await client.query("select policy_epoch,code from component where id=$1", [componentId]);
    if (!component.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    const contract = await client.query(
      "select state_schema from component_state_contract where component_id=$1 and state_key=$2",
      [componentId, input.stateKey]
    );
    if (!contract.rowCount) throw Object.assign(new Error("unknown_component_state"), { statusCode: 409 });
    let validationState: "ACCEPTED" | "REJECTED" = "ACCEPTED";
    let rejectionReason: string | null = null;
    try {
      validateAgainstStoredSchema(contract.rows[0].state_schema, input.statePayload, "state_schema_invalid");
    } catch (error) {
      validationState = "REJECTED";
      rejectionReason = error instanceof Error ? error.message : "state_schema_invalid";
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
    if (validationState === "REJECTED") throw Object.assign(new Error(rejectionReason ?? "state_schema_invalid"), { statusCode: 422 });
    return { accepted: true, validationState };
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

export async function recordComponentE2EResult(db: Db, params: {
  jobId: string;
  integrationTokenId: string;
  scenarioKey: string;
  generatedOutput: unknown;
  generatedOutputDigest?: string;
  correlationId: string;
}): Promise<{ status: "PASS" | "FAIL" }> {
  return tx(db, async (client) => {
    const job = await client.query("select component_id from component_onboarding_job where id=$1 and integration_token_id=$2 for update", [params.jobId, params.integrationTokenId]);
    if (!job.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    const scenario = await client.query(
      `select s.*
         from component_e2e_scenario s
         join component c on c.active_revision_id=s.revision_id and c.id=s.component_id
        where s.component_id=$1 and s.scenario_key=$2`,
      [job.rows[0].component_id, params.scenarioKey]
    );
    if (!scenario.rowCount) throw Object.assign(new Error("e2e_scenario_unknown"), { statusCode: 404 });
    const generatedCanonicalDigest = `sha256:${digestPayload(params.generatedOutput)}`;
    const expectedCanonical = canonicalJson(scenario.rows[0].expected_output);
    const generatedCanonical = canonicalJson(params.generatedOutput);
    const digestMatch = generatedCanonicalDigest === String(scenario.rows[0].expected_output_digest);
    const payloadMatch = generatedCanonical === expectedCanonical;
    const status = digestMatch && payloadMatch ? "PASS" : "FAIL";
    await client.query(
      `insert into component_e2e_result(component_id,revision_id,scenario_id,status,generated_output_digest,generated_output,correlation_id)
       values ($1,$2,$3,$4,$5,$6::jsonb,$7)`,
      [job.rows[0].component_id, scenario.rows[0].revision_id, scenario.rows[0].id, status, generatedCanonicalDigest, JSON.stringify(params.generatedOutput), params.correlationId]
    );
    await client.query(
      `insert into component_e2e_execution_run(
        component_id,revision_id,scenario_id,onboarding_job_id,executor_kind,caller_generated_output_digest,computed_output_digest,
        expected_output_digest,canonical_output_match,digest_match,generated_output,correlation_id
      ) values ($1,$2,$3,$4,'component.report',$5,$6,$7,$8,$9,$10::jsonb,$11)`,
      [
        job.rows[0].component_id,
        scenario.rows[0].revision_id,
        scenario.rows[0].id,
        params.jobId,
        params.generatedOutputDigest ?? null,
        generatedCanonicalDigest,
        String(scenario.rows[0].expected_output_digest),
        payloadMatch,
        digestMatch,
        JSON.stringify(params.generatedOutput),
        params.correlationId
      ]
    );
    return { status };
  });
}

export async function listComponents(db: Db): Promise<Record<string, unknown>[]> {
  const result = await db.query(`
    select c.*,r.revision,r.capabilities,r.protocols,r.transports,
      (select count(*)::int from component_permission p where (p.source_component_id=c.id or p.target_component_id=c.id) and p.revoked_at is null) permission_count,
      (select count(*)::int from component_credential cr where cr.component_id=c.id and cr.status='ACTIVE') credential_count,
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
    select c.*,r.revision,r.capabilities,r.protocols,r.transports,r.derived_gates,
      stream.gap_state,stream.highest_received_sequence,stream.highest_acknowledged_sequence,
      stream.current_event_hash,stream.integrity_state,stream.integrity_reason
    from component c
    left join component_revision r on r.id=c.active_revision_id
    left join component_audit_stream stream on stream.component_id=c.id
    where c.id=$1`, [id]);
  if (!result.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
  const permissions = await db.query(`select id,source_component_id,target_component_id,route_pattern,scope_name,access_level,granted_at,revoked_at from component_permission where source_component_id=$1 or target_component_id=$1 order by granted_at desc`, [id]);
  const credentials = await db.query(`select id,public_id,secret_fingerprint,status,issued_at,expires_at,last_used_at,revoked_at from component_credential where component_id=$1 order by issued_at desc`, [id]);
  const [readinessGates, controlDispatches, stateObservations, heartbeats] = await Promise.all([
    db.query(
      `select gate_key,status,reason_code,evaluator_version,evidence,evidence_digest,correlation_id,executed_at,expires_at
         from component_readiness_gate_evidence
        where component_id=$1
        order by executed_at desc, gate_key`,
      [id]
    ),
    db.query(
      `select id,command_type,target_hostname,endpoint_path,request_body,request_digest,requested_policy_epoch,expected_state_key,
              correlation_id,deadline_at,state,final_result,final_error_code,attempt_count,last_attempt_at,ack_digest,created_at,updated_at
         from component_control_dispatch
        where component_id=$1
        order by created_at desc
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
    )
  ]);
  return {
    ...componentView(result.rows[0]),
    permissions: permissions.rows,
    credentials: credentials.rows,
    readinessGates: readinessGates.rows,
    controlDispatches: controlDispatches.rows,
    stateObservations: stateObservations.rows,
    heartbeatHistory: heartbeats.rows
  };
}

export async function getComponentDiscovery(db: Db, hostname: string): Promise<Record<string, unknown>> {
    const result = await db.query(`
    select c.id,c.code,c.hostname,c.display_name,c.description,c.category,c.registration_type,c.component_role,
      c.lifecycle_state,c.activation_state,c.operational_state,c.monitoring_state,c.recertification_state,
      c.enabled,c.policy_epoch,c.release_version,c.release_wave_key,c.blueprint_component_id,c.created_at,c.updated_at,
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
    releaseVersion: String(row.release_version), releaseWaveKey: optionalText(row.release_wave_key),
    blueprintComponentId: optionalText(row.blueprint_component_id),
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
    releaseVersion: String(row.release_version), releaseWaveKey: optionalText(row.release_wave_key),
    blueprintComponentId: optionalText(row.blueprint_component_id),
    createdAt: String(row.created_at), updatedAt: String(row.updated_at)
  };
}

async function revokeComponentRuntimeTokens(client: pg.PoolClient, componentId: string): Promise<number> {
  const tokens = await client.query(
    `update component_access_token
        set revoked_at=coalesce(revoked_at,now())
      where revoked_at is null
        and (source_component_id=$1 or target_component_id=$1)`,
    [componentId]
  );
  await client.query(
    `update component
        set revocation_epoch=gen_random_uuid(),
            policy_epoch=policy_epoch+1
      where id=$1`,
    [componentId]
  );
  return tokens.rowCount ?? 0;
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
    const revokedTokens = params.enabled ? 0 : await revokeComponentRuntimeTokens(client, params.componentId);
    await appendAudit(client, {
      eventType: params.enabled ? "component.activation_requested" : "component.deactivation_requested", actorType: "admin", actorId: params.actorId,
      objectType: "component", objectId: params.componentId,
      before: { enabled: component.enabled, revocationEpoch: component.revocation_epoch, policyEpoch: component.policy_epoch },
      after: {
        enabled: false,
        accessTokensRevoked: revokedTokens,
        dispatchId: dispatch.id,
        stateQueryId: stateRun.id,
        heartbeatChallengeId: heartbeatChallenge?.id ?? null,
        heartbeatNonce: heartbeatChallenge?.challenge_nonce ?? null
      },
      correlationId: params.correlationId
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
    const revokedTokens = params.action === "RESTORE" ? 0 : await revokeComponentRuntimeTokens(client, params.componentId);
    await appendAudit(client, {
      eventType: `component.lifecycle.${params.action.toLowerCase()}`, actorType: "admin", actorId: params.actorId,
      objectType: "component", objectId: params.componentId,
      before: { lifecycleState: component.lifecycle_state, activationState: component.activation_state, operationalState: component.operational_state },
      after: { lifecycleState: next.lifecycle, activationState: next.activation, operationalState: next.operational, accessTokensRevoked: revokedTokens },
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
