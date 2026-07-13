import { createHash } from "node:crypto";
import { Ajv2020, type AnySchema } from "ajv/dist/2020.js";
import type { AppConfig } from "../config.js";
import type { Db } from "../db.js";
import {
  HOME_ASSISTANT_INVENTORY_HANDLER_KEY,
  HOME_ASSISTANT_INVENTORY_HANDLER_VERSION,
  HOME_ASSISTANT_INVENTORY_INPUT_SCHEMA,
  HOME_ASSISTANT_INVENTORY_OUTPUT_SCHEMA,
  HOME_ASSISTANT_INVENTORY_TOOL_NAME
} from "../handlers/home-assistant-device-inventory.js";
import { getHandler, registeredHandlerIds } from "../handlers/registry.js";
import { appendAudit } from "./audit.js";
import { createKajaCredential, deleteKajaCredential, replaceKajaPermissions } from "./auth.js";
import { getServerById, getServerByHostname } from "./catalog.js";
import { validateManifest } from "./registration.js";

export const ACCEPTANCE_IDS = [
  ...Array.from({ length: 10 }, (_, index) => `C-${String(index + 1).padStart(2, "0")}`),
  ...Array.from({ length: 25 }, (_, index) => `T-${String(index + 1).padStart(2, "0")}`)
] as const;

export type AcceptanceStatus = "PASS" | "FAIL" | "BLOCKED" | "NOT TESTED";
export type AcceptanceMatrix = Record<string, AcceptanceStatus>;

type JsonRpcEnvelope = {
  result?: Record<string, unknown>;
  error?: { code?: number; message?: string };
};

function sha256(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nested]) => [key, canonicalize(nested)])
    );
  }
  return value;
}

function digestJson(value: unknown): string {
  return sha256(JSON.stringify(canonicalize(value)));
}

function buildManifest(actorId: string, identity: { code: string; hostname: string; resource: string }) {
  const artifactDigest = digestJson({
    handlerKey: HOME_ASSISTANT_INVENTORY_HANDLER_KEY,
    handlerVersion: HOME_ASSISTANT_INVENTORY_HANDLER_VERSION,
    inputSchema: HOME_ASSISTANT_INVENTORY_INPUT_SCHEMA,
    outputSchema: HOME_ASSISTANT_INVENTORY_OUTPUT_SCHEMA
  });
  return {
    schemaVersion: "1.3" as const,
    registrationRevision: "ha-device-inventory-1.0.0",
    environment: "production" as const,
    identity,
    handlerKey: HOME_ASSISTANT_INVENTORY_HANDLER_KEY,
    handlerVersion: HOME_ASSISTANT_INVENTORY_HANDLER_VERSION,
    displayName: "Seznam zařízení Home Assistant",
    businessPurpose: "Vrací aktuální tabulkový inventář zařízení Home Assistant včetně umístění, typů, ovládání, čitelných údajů a aktuálních stavů.",
    owners: { service: actorId, technical: actorId, security: actorId, operations: actorId },
    tool: {
      name: HOME_ASSISTANT_INVENTORY_TOOL_NAME,
      title: "Vyžádat seznam zařízení Home Assistant",
      description: "Read-only přehled všech zařízení z produkčního Home Assistantu. Výsledek obsahuje strukturované řádky i Markdown tabulku; neprovádí žádnou změnu zařízení.",
      inputSchema: HOME_ASSISTANT_INVENTORY_INPUT_SCHEMA,
      outputSchema: HOME_ASSISTANT_INVENTORY_OUTPUT_SCHEMA,
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false, taskSupport: "forbidden" as const }
    },
    contractDigests: {
      inputSchema: digestJson(HOME_ASSISTANT_INVENTORY_INPUT_SCHEMA),
      outputSchema: digestJson(HOME_ASSISTANT_INVENTORY_OUTPUT_SCHEMA)
    },
    behavior: {
      effectClass: "READ_ONLY" as const,
      timeoutMs: 15_000,
      maxConcurrency: 2,
      requestMaxBytes: 1024,
      responseMaxBytes: 2 * 1024 * 1024,
      rateLimit: { windowSeconds: 60, maxRequests: 10 },
      shutdownPolicy: "COMPLETE_IN_FLIGHT" as const,
      idempotencyPolicy: "Read-only snapshot; repeated calls do not mutate Home Assistant.",
      retryPolicy: { automaticRetry: false as const }
    },
    testContract: {
      safeInput: {},
      expectedResult: { minimumDeviceCount: 1, resultShape: "columns+summary+rows+markdown_table" },
      cleanupOrCompensation: "No cleanup required; the handler is read-only."
    },
    monitoringProfile: {
      sloTargets: { availability: 0.99, p95LatencyMs: 15_000 },
      probeIntervals: { handlerSmokeSeconds: 300 },
      alertRules: [{ severity: "critical", condition: "three consecutive handler failures" }],
      runbookRef: "docs/runbooks/home-assistant-device-inventory.md",
      primaryAlertChannel: "KCML operations dashboard",
      backupAlertChannel: "systemd and structured application log"
    },
    approvals: { architecture: actorId, security: actorId, operations: actorId },
    artifact: { digest: artifactDigest, sbomDigest: sha256("pnpm-lock.yaml@home-assistant-device-inventory-1.0.0") },
    change: {
      rollbackRef: "docs/runbooks/home-assistant-device-inventory.md#rollback",
      decommissionRef: "docs/runbooks/home-assistant-device-inventory.md#decommission",
      reviewDueAt: "2027-01-13T00:00:00.000Z"
    }
  };
}

function initialEvidence(): Record<string, unknown> {
  return {
    handlerSmoke: { status: "NOT TESTED" },
    identityBound: true,
    acceptanceMatrix: Object.fromEntries(ACCEPTANCE_IDS.map((id) => [id, "NOT TESTED"])),
    acceptancePassed: false
  };
}

export async function registerHomeAssistantInventory(db: Db, actorId: string, correlationId: string) {
  const handlerId = `${HOME_ASSISTANT_INVENTORY_HANDLER_KEY}@${HOME_ASSISTANT_INVENTORY_HANDLER_VERSION}`;
  if (!registeredHandlerIds().includes(handlerId)) throw Object.assign(new Error("handler_unavailable"), { statusCode: 503 });
  const existing = await db.query("select id from mcp_server where handler_key=$1 and registration_state <> 'RETIRED'", [HOME_ASSISTANT_INVENTORY_HANDLER_KEY]);
  if (existing.rowCount) throw Object.assign(new Error("server_already_registered"), { statusCode: 409 });
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    const sequence = await client.query("select nextval('kcml_number_seq') as number");
    const number = Number(sequence.rows[0].number);
    const code = `KCML${String(number).padStart(4, "0")}`;
    const hostname = `${code.toLowerCase()}.hcasc.cz`;
    const manifest = buildManifest(actorId, { code, hostname, resource: `https://${hostname}/mcp` });
    const validated = validateManifest(manifest);
    const inserted = await client.query(
      `insert into mcp_server
        (kcml_number, code, hostname, tool_name, display_name, description, enabled, registration_state, operational_state,
         input_schema, output_schema, handler_key, handler_version, contract_version, artifact_digest, manifest_digest)
       values ($1,$2,$3,$4,$5,$6,false,'REGISTERED_DISABLED','DISABLED',$7,$8,$9,$10,$11,$12,$13)
       returning id`,
      [
        number, code, hostname, manifest.tool.name, manifest.displayName, manifest.tool.description,
        JSON.stringify(manifest.tool.inputSchema), JSON.stringify(manifest.tool.outputSchema), manifest.handlerKey,
        manifest.handlerVersion, "1.0.0", manifest.artifact.digest, validated.digest
      ]
    );
    const serverId = String(inserted.rows[0].id);
    await client.query(
      `insert into registration_revision(server_id, revision, state, manifest, manifest_digest, artifact_digest, evidence)
       values ($1,$2,'REGISTERED_DISABLED',$3,$4,$5,$6)`,
      [serverId, manifest.registrationRevision, JSON.stringify(manifest), validated.digest, manifest.artifact.digest, JSON.stringify(initialEvidence())]
    );
    await appendAudit(client, {
      eventType: "server.registered",
      actorType: "admin",
      actorId,
      objectType: "mcp_server",
      objectId: serverId,
      after: { code, hostname, handlerId, registrationState: "REGISTERED_DISABLED" },
      correlationId
    });
    await client.query("COMMIT");
    const server = await getServerByHostname(db, hostname);
    if (!server) throw new Error("registered_server_not_found");
    return server;
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

async function latestRevision(db: Db, serverId: string) {
  const result = await db.query(
    "select id,evidence from registration_revision where server_id=$1 order by created_at desc limit 1",
    [serverId]
  );
  if (!result.rowCount) throw Object.assign(new Error("registration_revision_not_found"), { statusCode: 404 });
  return { id: String(result.rows[0].id), evidence: (result.rows[0].evidence ?? {}) as Record<string, unknown> };
}

async function updateEvidence(db: Db, serverId: string, patch: Record<string, unknown>): Promise<Record<string, unknown>> {
  const revision = await latestRevision(db, serverId);
  const evidence = { ...revision.evidence, ...patch };
  await db.query("update registration_revision set evidence=$2 where id=$1", [revision.id, JSON.stringify(evidence)]);
  return evidence;
}

export async function bindHomeAssistantInventoryManifestIdentity(db: Db, serverId: string, actorId: string, correlationId: string) {
  const server = await getServerById(db, serverId);
  if (!server) throw Object.assign(new Error("not_found"), { statusCode: 404 });
  const revisionResult = await db.query(
    "select id,manifest,evidence from registration_revision where server_id=$1 order by created_at desc limit 1",
    [serverId]
  );
  if (!revisionResult.rowCount) throw Object.assign(new Error("registration_revision_not_found"), { statusCode: 404 });
  const manifest = {
    ...(revisionResult.rows[0].manifest as Record<string, unknown>),
    identity: { code: server.code, hostname: server.hostname, resource: `https://${server.hostname}/mcp` },
    contractDigests: {
      inputSchema: digestJson(server.inputSchema),
      outputSchema: digestJson(server.outputSchema)
    }
  };
  const validated = validateManifest(manifest);
  const evidence = { ...(revisionResult.rows[0].evidence as Record<string, unknown>), identityBound: true, identityBoundAt: new Date().toISOString() };
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      "update registration_revision set manifest=$2,manifest_digest=$3,evidence=$4 where id=$1",
      [revisionResult.rows[0].id, JSON.stringify(validated.manifest), validated.digest, JSON.stringify(evidence)]
    );
    await client.query("update mcp_server set manifest_digest=$2,updated_at=now() where id=$1", [serverId, validated.digest]);
    await appendAudit(client, {
      eventType: "server.manifest.identity_bound",
      actorType: "admin",
      actorId,
      objectType: "mcp_server",
      objectId: serverId,
      after: { identity: validated.manifest.identity, manifestDigest: validated.digest },
      correlationId
    });
    await client.query("COMMIT");
    return { ok: true, identity: validated.manifest.identity, manifestDigest: validated.digest };
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

async function readJsonResponse(response: Response, maximumBytes = 4 * 1024 * 1024): Promise<Record<string, unknown>> {
  const text = await response.text();
  if (Buffer.byteLength(text, "utf8") > maximumBytes) throw new Error("test_response_too_large");
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    throw new Error("test_response_not_json");
  }
}

async function postMcp(resource: string, accessToken: string, payload: Record<string, unknown>): Promise<{ response: Response; body: JsonRpcEnvelope }> {
  const response = await fetch(resource, {
    method: "POST",
    headers: { authorization: `Bearer ${accessToken}`, "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(20_000)
  });
  return { response, body: await readJsonResponse(response) };
}

export async function smokeTestHomeAssistantInventory(db: Db, serverId: string, actorId: string, correlationId: string) {
  const server = await getServerById(db, serverId);
  if (!server) throw Object.assign(new Error("not_found"), { statusCode: 404 });
  const handler = getHandler(server);
  if (!handler) throw Object.assign(new Error("handler_unavailable"), { statusCode: 503 });
  const started = Date.now();
  try {
    const output = await handler.invoke({}, {
      correlationId,
      server,
      logger: { info: () => undefined, error: () => undefined }
    });
    const validate = new Ajv2020({ strict: true, allErrors: true }).compile(server.outputSchema as AnySchema);
    if (!validate(output)) throw new Error("output_schema_failed");
    const revision = await latestRevision(db, serverId);
    const evidence = { ...revision.evidence, handlerSmoke: { status: "PASS", testedAt: new Date().toISOString(), latencyMs: Date.now() - started } };
    await db.query("update registration_revision set evidence=$2 where id=$1", [revision.id, JSON.stringify(evidence)]);
    await appendAudit(db, { eventType: "server.test.completed", actorType: "admin", actorId, objectType: "mcp_server", objectId: serverId, after: evidence.handlerSmoke, correlationId });
    return evidence.handlerSmoke;
  } catch (error) {
    const revision = await latestRevision(db, serverId);
    const evidence = { ...revision.evidence, handlerSmoke: { status: "FAIL", testedAt: new Date().toISOString(), latencyMs: Date.now() - started, errorCode: error instanceof Error ? error.message : "unknown" } };
    await db.query("update registration_revision set evidence=$2 where id=$1", [revision.id, JSON.stringify(evidence)]);
    await appendAudit(db, { eventType: "server.test.failed", actorType: "admin", actorId, objectType: "mcp_server", objectId: serverId, after: evidence.handlerSmoke, correlationId });
    throw Object.assign(new Error("handler_smoke_failed"), { statusCode: 503 });
  }
}

export async function testHomeAssistantInventoryThroughMcp(
  db: Db,
  config: AppConfig,
  serverId: string,
  actorId: string,
  correlationId: string
) {
  const server = await getServerById(db, serverId);
  if (!server) throw Object.assign(new Error("not_found"), { statusCode: 404 });
  if (!server.enabled || !["TRIAL", "ACTIVE"].includes(server.registrationState)) {
    throw Object.assign(new Error("server_must_be_enabled_for_mcp_test"), { statusCode: 409 });
  }
  const resource = `https://${server.hostname}/mcp`;
  const started = Date.now();
  let credentialId: string | null = null;
  try {
    const credential = await createKajaCredential(
      db,
      actorId,
      correlationId,
      `UI MCP test ${server.code}`,
      new Date(Date.now() + 5 * 60_000).toISOString()
    );
    const credentialRow = await db.query("select id from kaja_credential where public_id=$1 and deleted_at is null", [credential.publicId]);
    if (!credentialRow.rowCount) throw new Error("test_credential_not_found");
    credentialId = String(credentialRow.rows[0].id);
    await replaceKajaPermissions(db, actorId, correlationId, credentialId, [{ serverId, accessLevel: "EXECUTE" }]);

    const basic = Buffer.from(`${encodeURIComponent(credential.publicId)}:${encodeURIComponent(credential.clientSecret)}`).toString("base64");
    const tokenResponse = await fetch(`https://${config.AUTH_HOST}/oauth/token`, {
      method: "POST",
      headers: { authorization: `Basic ${basic}`, "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: new URLSearchParams({ grant_type: "client_credentials", resource }),
      signal: AbortSignal.timeout(10_000)
    });
    const tokenBody = await readJsonResponse(tokenResponse, 64 * 1024);
    if (!tokenResponse.ok || typeof tokenBody.access_token !== "string") throw new Error(`oauth_test_${tokenResponse.status}`);
    const accessToken = tokenBody.access_token;

    const initialized = await postMcp(resource, accessToken, { jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    const serverInfo = initialized.body.result?.serverInfo as { name?: string; version?: string } | undefined;
    if (!initialized.response.ok || serverInfo?.name !== server.code || serverInfo.version !== server.handlerVersion) {
      throw new Error("mcp_initialize_contract_failed");
    }

    const listed = await postMcp(resource, accessToken, { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
    const tools = listed.body.result?.tools as Array<{ name?: string }> | undefined;
    if (!listed.response.ok || tools?.length !== 1 || tools[0]?.name !== server.toolName) throw new Error("mcp_tools_list_contract_failed");

    const called = await postMcp(resource, accessToken, {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: server.toolName, arguments: {} }
    });
    const structuredContent = called.body.result?.structuredContent;
    const validate = new Ajv2020({ strict: true, allErrors: true }).compile(server.outputSchema as AnySchema);
    if (!called.response.ok || called.body.error || !validate(structuredContent)) throw new Error("mcp_tools_call_contract_failed");
    const output = structuredContent as { summary?: { device_count?: number; entity_count?: number }; rows?: unknown[] };
    const result = {
      status: "PASS" as const,
      testedAt: new Date().toISOString(),
      latencyMs: Date.now() - started,
      schemaValidated: true,
      toolCount: tools.length,
      deviceCount: Number(output.summary?.device_count ?? 0),
      entityCount: Number(output.summary?.entity_count ?? 0),
      rowCount: Array.isArray(output.rows) ? output.rows.length : 0
    };
    await updateEvidence(db, serverId, { uiMcpTest: result });
    await appendAudit(db, { eventType: "server.mcp_test.completed", actorType: "admin", actorId, objectType: "mcp_server", objectId: serverId, after: result, correlationId });
    return { result, response: called.body.result };
  } catch (error) {
    const result = {
      status: "FAIL" as const,
      testedAt: new Date().toISOString(),
      latencyMs: Date.now() - started,
      errorCode: error instanceof Error ? error.message : "unknown"
    };
    await updateEvidence(db, serverId, { uiMcpTest: result });
    await appendAudit(db, { eventType: "server.mcp_test.failed", actorType: "admin", actorId, objectType: "mcp_server", objectId: serverId, after: result, correlationId });
    throw Object.assign(new Error("mcp_flow_test_failed"), { statusCode: 503 });
  } finally {
    if (credentialId) await deleteKajaCredential(db, actorId, correlationId, credentialId);
  }
}

export async function enableHomeAssistantInventoryTrial(db: Db, serverId: string, actorId: string, correlationId: string) {
  const revision = await latestRevision(db, serverId);
  const smoke = revision.evidence.handlerSmoke as { status?: string } | undefined;
  if (smoke?.status !== "PASS") throw Object.assign(new Error("handler_smoke_required"), { statusCode: 409 });
  const result = await db.query(
    `update mcp_server set registration_state='TRIAL', operational_state='HEALTHY', enabled=true,
       revocation_epoch=gen_random_uuid(), updated_at=now()
     where id=$1 and registration_state='REGISTERED_DISABLED' returning id`,
    [serverId]
  );
  if (!result.rowCount) throw Object.assign(new Error("invalid_registration_state"), { statusCode: 409 });
  await db.query("update registration_revision set state='TRIAL' where id=$1", [revision.id]);
  await appendAudit(db, { eventType: "server.enabled.trial", actorType: "admin", actorId, objectType: "mcp_server", objectId: serverId, correlationId });
  return { ok: true, registrationState: "TRIAL" };
}

export async function recordAcceptanceMatrix(db: Db, serverId: string, matrix: AcceptanceMatrix, actorId: string, correlationId: string) {
  const keys = Object.keys(matrix).sort();
  const expected = [...ACCEPTANCE_IDS].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw Object.assign(new Error("incomplete_acceptance_matrix"), { statusCode: 400 });
  }
  const allowed: AcceptanceStatus[] = ["PASS", "FAIL", "BLOCKED", "NOT TESTED"];
  if (Object.values(matrix).some((status) => !allowed.includes(status))) throw Object.assign(new Error("invalid_acceptance_status"), { statusCode: 400 });
  const acceptancePassed = Object.values(matrix).every((status) => status === "PASS");
  const revision = await latestRevision(db, serverId);
  const evidence = { ...revision.evidence, acceptanceMatrix: matrix, acceptancePassed, acceptanceRecordedAt: new Date().toISOString() };
  await db.query("update registration_revision set evidence=$2 where id=$1", [revision.id, JSON.stringify(evidence)]);
  await appendAudit(db, { eventType: "server.acceptance.recorded", actorType: "admin", actorId, objectType: "mcp_server", objectId: serverId, after: { acceptancePassed }, correlationId });
  return { ok: true, acceptancePassed };
}

export async function disableHomeAssistantInventory(db: Db, serverId: string, actorId: string, correlationId: string) {
  const server = await getServerById(db, serverId);
  if (!server) throw Object.assign(new Error("not_found"), { statusCode: 404 });
  if (!server.enabled || !["TRIAL", "ACTIVE"].includes(server.registrationState)) throw Object.assign(new Error("invalid_registration_state"), { statusCode: 409 });
  await updateEvidence(db, serverId, { suspendedFrom: server.registrationState });
  await db.query(
    `update mcp_server set registration_state='SUSPENDED', operational_state='DISABLED', enabled=false,
       revocation_epoch=gen_random_uuid(), updated_at=now() where id=$1`,
    [serverId]
  );
  const revision = await latestRevision(db, serverId);
  await db.query("update registration_revision set state='SUSPENDED' where id=$1", [revision.id]);
  await db.query("update access_token set revoked_at=coalesce(revoked_at,now()) where server_id=$1", [serverId]);
  await appendAudit(db, { eventType: "server.disabled", actorType: "admin", actorId, objectType: "mcp_server", objectId: serverId, before: { registrationState: server.registrationState, enabled: true }, after: { registrationState: "SUSPENDED", enabled: false }, correlationId });
  return { ok: true, registrationState: "SUSPENDED" };
}

export async function resumeHomeAssistantInventory(db: Db, serverId: string, actorId: string, correlationId: string) {
  const revision = await latestRevision(db, serverId);
  const target = revision.evidence.acceptancePassed === true ? "ACTIVE" : "TRIAL";
  const result = await db.query(
    `update mcp_server set registration_state=$2::registration_state, operational_state='HEALTHY', enabled=true,
       revocation_epoch=gen_random_uuid(), updated_at=now() where id=$1 and registration_state='SUSPENDED' returning id`,
    [serverId, target]
  );
  if (!result.rowCount) throw Object.assign(new Error("invalid_registration_state"), { statusCode: 409 });
  await db.query("update registration_revision set state=$2::registration_state where id=$1", [revision.id, target]);
  await appendAudit(db, { eventType: "server.enabled", actorType: "admin", actorId, objectType: "mcp_server", objectId: serverId, after: { registrationState: target, enabled: true }, correlationId });
  return { ok: true, registrationState: target };
}

export async function activateHomeAssistantInventory(db: Db, serverId: string, actorId: string, correlationId: string) {
  const revision = await latestRevision(db, serverId);
  if (revision.evidence.acceptancePassed !== true) throw Object.assign(new Error("acceptance_required"), { statusCode: 409 });
  const result = await db.query(
    `update mcp_server set registration_state='ACTIVE', operational_state='HEALTHY', enabled=true, updated_at=now()
     where id=$1 and registration_state='TRIAL' returning id`,
    [serverId]
  );
  if (!result.rowCount) throw Object.assign(new Error("invalid_registration_state"), { statusCode: 409 });
  await db.query("update registration_revision set state='ACTIVE' where id=$1", [revision.id]);
  await appendAudit(db, { eventType: "server.activated", actorType: "admin", actorId, objectType: "mcp_server", objectId: serverId, correlationId });
  return { ok: true, registrationState: "ACTIVE" };
}
