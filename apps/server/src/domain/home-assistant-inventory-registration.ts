import { createHash } from "node:crypto";
import { Ajv2020, type AnySchema } from "ajv/dist/2020.js";
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
import { getServerById, getServerByHostname } from "./catalog.js";
import { validateManifest } from "./registration.js";

export const ACCEPTANCE_IDS = [
  ...Array.from({ length: 10 }, (_, index) => `C-${String(index + 1).padStart(2, "0")}`),
  ...Array.from({ length: 25 }, (_, index) => `T-${String(index + 1).padStart(2, "0")}`)
] as const;

export type AcceptanceStatus = "PASS" | "FAIL" | "BLOCKED" | "NOT TESTED";
export type AcceptanceMatrix = Record<string, AcceptanceStatus>;

function sha256(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function buildManifest(actorId: string) {
  const artifactDigest = sha256(JSON.stringify({
    handlerKey: HOME_ASSISTANT_INVENTORY_HANDLER_KEY,
    handlerVersion: HOME_ASSISTANT_INVENTORY_HANDLER_VERSION,
    inputSchema: HOME_ASSISTANT_INVENTORY_INPUT_SCHEMA,
    outputSchema: HOME_ASSISTANT_INVENTORY_OUTPUT_SCHEMA
  }));
  return {
    schemaVersion: "1.3" as const,
    registrationRevision: "ha-device-inventory-1.0.0",
    environment: "production" as const,
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
    acceptanceMatrix: Object.fromEntries(ACCEPTANCE_IDS.map((id) => [id, "NOT TESTED"])),
    acceptancePassed: false
  };
}

export async function registerHomeAssistantInventory(db: Db, actorId: string, correlationId: string) {
  const handlerId = `${HOME_ASSISTANT_INVENTORY_HANDLER_KEY}@${HOME_ASSISTANT_INVENTORY_HANDLER_VERSION}`;
  if (!registeredHandlerIds().includes(handlerId)) throw Object.assign(new Error("handler_unavailable"), { statusCode: 503 });
  const existing = await db.query("select id from mcp_server where handler_key=$1 and registration_state <> 'RETIRED'", [HOME_ASSISTANT_INVENTORY_HANDLER_KEY]);
  if (existing.rowCount) throw Object.assign(new Error("server_already_registered"), { statusCode: 409 });
  const manifest = buildManifest(actorId);
  const validated = validateManifest(manifest);
  const client = await db.connect();
  try {
    await client.query("BEGIN");
    const sequence = await client.query("select nextval('kcml_number_seq') as number");
    const number = Number(sequence.rows[0].number);
    const code = `KCML${String(number).padStart(4, "0")}`;
    const hostname = `${code.toLowerCase()}.hcasc.cz`;
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
  await appendAudit(db, { eventType: "server.enabled.trial", actorType: "admin", actorId, objectType: "mcp_server", objectId: serverId, correlationId });
  return { ok: true, registrationState: "TRIAL" };
}

export async function recordAcceptanceMatrix(db: Db, serverId: string, matrix: AcceptanceMatrix, actorId: string, correlationId: string) {
  const keys = Object.keys(matrix).sort();
  const expected = [...ACCEPTANCE_IDS].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw Object.assign(new Error("incomplete_acceptance_matrix"), { statusCode: 400 });
  }
  if (Object.values(matrix).some((status) => status !== "PASS")) {
    throw Object.assign(new Error("acceptance_not_passed"), { statusCode: 409 });
  }
  const revision = await latestRevision(db, serverId);
  const evidence = { ...revision.evidence, acceptanceMatrix: matrix, acceptancePassed: true, acceptanceRecordedAt: new Date().toISOString() };
  await db.query("update registration_revision set evidence=$2 where id=$1", [revision.id, JSON.stringify(evidence)]);
  await appendAudit(db, { eventType: "server.acceptance.recorded", actorType: "admin", actorId, objectType: "mcp_server", objectId: serverId, after: { acceptancePassed: true }, correlationId });
  return { ok: true, acceptancePassed: true };
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
  await appendAudit(db, { eventType: "server.activated", actorType: "admin", actorId, objectType: "mcp_server", objectId: serverId, correlationId });
  return { ok: true, registrationState: "ACTIVE" };
}
