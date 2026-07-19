import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import https from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { promisify } from "node:util";
import Fastify, { type FastifyInstance } from "fastify";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { migrateLegacyMfaSecrets } from "../cli/migrate-mfa-secrets.js";
import { loadBootstrapConfig, loadConfig, type AppConfig } from "../config.js";
import { createDb, type Db, tx } from "../db.js";
import {
  createKajaCredential,
  issueAccessToken,
  listManagedServicePermissions,
  replaceManagedServicePermissions
} from "./auth.js";
import {
  createExternalApiManagedService,
  listExternalApiMonitoringTargets,
  recordExternalApiMonitoringInternalError,
  runExternalApiMonitoringTarget,
  updateExternalApiManagedService,
  validateExternalApiManifest
} from "./external-api.js";
import { managedServiceStateView, setManagedServiceApiState } from "./managed-service.js";
import { loadConfigFromDb } from "./operational-config.js";
import { authenticateIntegrationToken, createIntegrationToken } from "./onboarding.js";
import { buildEgressProxy, listenEgressProxy } from "../onboarding/egress-proxy.js";
import { registerAuthRoutes } from "../http/auth-routes.js";
import { registerExternalApiRoutes } from "../http/external-api-routes.js";
import { decryptMfaSecret } from "../security/secrets.js";

const enabled = process.env.KCML_TEST_DATABASE === "1";
const execFileAsync = promisify(execFile);

async function createSelfSignedCertificate(): Promise<{ certPem: string; keyPem: string; dir: string }> {
  const dir = await mkdtemp(join(tmpdir(), "kcml-cert-"));
  const keyPath = join(dir, "key.pem");
  const certPath = join(dir, "cert.pem");
  await execFileAsync("openssl", [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    keyPath,
    "-out",
    certPath,
    "-days",
    "1",
    "-subj",
    "/CN=localhost",
    "-addext",
    "subjectAltName=DNS:localhost,IP:127.0.0.1"
  ]);
  const [certPem, keyPem] = await Promise.all([
    readFile(certPath, "utf8"),
    readFile(keyPath, "utf8")
  ]);
  return { certPem, keyPem, dir };
}

function manifestFor(baseUrl: string): Record<string, unknown> {
  return {
    schemaVersion: "1.0",
    serviceKind: "EXTERNAL_API",
    environment: "production",
    registrationRevision: "test-reference-api-1",
    displayName: "Test Reference API",
    description: "Local HTTPS reference backend used by the integration test for EXTERNAL_API managed services.",
    serviceIdentity: {
      slug: "test-reference-api",
      region: "local",
      basePath: "/v1"
    },
    owners: {
      service: "KCML Managed Services",
      technical: "KCML Managed Services",
      security: "KCML Security",
      operations: "KCML Operations"
    },
    contacts: {
      serviceEmail: "service@example.com",
      technicalEmail: "tech@example.com",
      securityEmail: "security@example.com",
      operationsOnCall: "test-oncall"
    },
    governance: {
      criticality: "HIGH",
      classification: "CONFIDENTIAL",
      containsPersonalData: true,
      exportAllowed: false,
      retentionDays: 365,
      loggingPolicy: "Redact secrets before storing runtime evidence.",
      redactionFields: ["authorization", "cookie", "set-cookie", "employeeId"]
    },
    review: {
      intervalDays: 90,
      approvedAt: "2026-07-15T00:00:00.000Z",
      reviewDueAt: "2026-10-13T00:00:00.000Z"
    },
    auth: {
      mode: "NONE",
      tokenEndpointUrl: null,
      jwksUrl: null,
      authMetadataUrl: null,
      gatewayEnforced: true
    },
    endpoints: {
      baseUrl,
      healthcheckUrl: `${baseUrl}/health`,
      readinessUrl: `${baseUrl}/ready`
    },
    operations: [
      {
        operationId: "reference.listShifts",
        method: "GET",
        path: "/v1/shifts/{employeeId}",
        requiredScopes: ["reference.shifts.read"],
        idempotency: "READ_ONLY",
        requestSchema: {
          type: "object",
          properties: {},
          additionalProperties: false
        },
        responseSchema: {
          type: "object",
          properties: {
            items: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  employeeId: { type: "string" },
                  shiftDate: { type: "string" },
                  start: { type: "string" },
                  end: { type: "string" }
                },
                required: ["employeeId", "shiftDate", "start", "end"],
                additionalProperties: false
              }
            }
          },
          required: ["items"],
          additionalProperties: false
        },
        timeoutMs: 5000,
        maxPayloadBytes: 65536
      },
      {
        operationId: "reference.requestTimeOff",
        method: "POST",
        path: "/v1/time-off",
        requiredScopes: ["reference.time_off.write"],
        idempotency: "NON_IDEMPOTENT",
        requestSchema: {
          type: "object",
          properties: {
            employeeId: { type: "string" },
            days: { type: "integer", minimum: 1, maximum: 30 }
          },
          required: ["employeeId", "days"],
          additionalProperties: false
        },
        responseSchema: {
          type: "object",
          properties: {
            requestId: { type: "string" },
            accepted: { type: "boolean" }
          },
          required: ["requestId", "accepted"],
          additionalProperties: false
        },
        timeoutMs: 8000,
        maxPayloadBytes: 131072
      }
    ],
    rateLimit: {
      windowSeconds: 60,
      maxRequests: 120
    },
    timeoutMs: 8000,
    monitoringProfile: {
      staleAfterSeconds: 300,
      probeIntervals: {
        healthSeconds: 15,
        readinessSeconds: 15,
        tlsSeconds: 60,
        acceptanceSeconds: 30
      },
      alertRules: [
        { probeType: "health", severity: "HIGH", consecutiveFailures: 1 },
        { probeType: "readiness", severity: "HIGH", consecutiveFailures: 2 },
        { probeType: "tls", severity: "CRITICAL", consecutiveFailures: 1 },
        { probeType: "acceptance", severity: "CRITICAL", consecutiveFailures: 1 }
      ],
      runbookRef: "evidence/runbooks/test-reference-api.md"
    },
    loggingContract: {
      correlationHeader: "x-correlation-id",
      redactHeaders: ["authorization", "cookie", "set-cookie"]
    },
    stateContract: {
      operationalStatePath: "/state/operational",
      apiAcceptancePath: "/state/api-acceptance"
    },
    egressPolicy: {
      redirectsAllowed: false,
      allowlist: [new URL(baseUrl).host]
    },
    errorCatalog: [
      {
        code: "REFERENCE_DIRECT_BYPASS_BLOCKED",
        description: "The backend rejected a request without KCML gateway headers.",
        classification: "SECURITY_BLOCKER",
        retryable: false
      }
    ],
    evidence: {
      contractRefs: ["evidence/contracts/test-reference-api.json"],
      securityRefs: ["evidence/security/test-reference-api.md"],
      runbookRefs: ["evidence/runbooks/test-reference-api.md"]
    }
  };
}

function directHttpsRequest(port: number, path: string, ca: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const request = https.request({
      ca,
      family: 4,
      host: "localhost",
      port,
      path,
      method: "GET"
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
      response.on("error", reject);
      response.on("end", () => resolve({
        status: response.statusCode ?? 500,
        body: Buffer.concat(chunks).toString("utf8")
      }));
    });
    request.on("error", reject);
    request.end();
  });
}

async function seedMcpManagedService(db: Db, code: string) {
  const serverId = randomUUID();
  const revisionId = randomUUID();
  const managedServiceId = randomUUID();
  const scopeId = randomUUID();
  const hostname = `${code.toLowerCase()}.hcasc.cz`;
  const resourceUri = `https://${hostname}/mcp`;
  await tx(db, async (client) => {
    const number = await client.query("select nextval('kcml_number_seq') as value");
    const kcmlNumber = Number(number.rows[0].value);
    await client.query(
      `insert into mcp_server(
        id, kcml_number, code, hostname, tool_name, display_name, description, enabled,
        registration_state, operational_state, input_schema, output_schema, handler_key,
        handler_version, contract_version, artifact_digest, manifest_digest, active_revision_id
     ) values (
        $1::uuid, $2::bigint, $3::citext, $4::citext, $5::citext, $6::text, $7::text, true,
        'ACTIVE', 'HEALTHY', '{"type":"object","additionalProperties":false}', '{"type":"object","additionalProperties":false}',
        $5::text, '1.0.0', '1.0', 'sha256:artifact', 'sha256:manifest', null
      )`,
      [serverId, kcmlNumber, code, hostname, `${code.toLowerCase()}_tool`, code, `${code} fixture`]
    );
    await client.query(
      `insert into registration_revision(
          id, server_id, revision, state, schema_version, validation_state, manifest, manifest_digest, artifact_digest,
          evidence, approved_at, review_due_at, review_interval_days, active
       ) values (
          $1::uuid, $2::uuid, 'prod-1', 'ACTIVE', '1.6', 'VALID', '{"testContract":{"safeInput":{},"expectedResult":{}}}', 'sha256:manifest',
          'sha256:artifact', '{}'::jsonb, now(), now() + interval '365 days', 365, true
       )`,
      [revisionId, serverId]
    );
    await client.query(
      "update mcp_server set active_revision_id=$2 where id=$1",
      [serverId, revisionId]
    );
    await client.query(
      `insert into managed_service(
        id, legacy_mcp_server_id, code, slug, display_name, description, service_kind, lifecycle_state, operational_state,
        enabled, public_hostname, base_url, resource_uri, auth_mode, api_state, active_revision_id, monitoring_enabled,
        monitoring_profile_digest, review_approved_at, review_due_at, review_interval_days
     ) values (
        $1::uuid, $2::uuid, $3::citext, lower($3::text), $3::text, $4::text, 'MCP', 'ACTIVE', 'HEALTHY', true, $5::citext, $6::text, $7::text,
        'OAUTH2_CLIENT_CREDENTIALS', 'ENABLED', null, true, 'sha256:monitoring', now(), now() + interval '365 days', 365
      )`,
      [managedServiceId, serverId, code, `${code} managed fixture`, hostname, `https://${hostname}`, resourceUri]
    );
    await client.query(
      `insert into managed_service_revision(
          id, managed_service_id, revision, schema_version, service_kind, validation_state, manifest, manifest_digest, artifact_digest,
          approved_at, review_due_at, review_interval_days, active
       ) values (
          $1::uuid, $2::uuid, 'prod-1', '1.6', 'MCP', 'VALID', '{"testContract":{"safeInput":{},"expectedResult":{}}}', 'sha256:manifest',
          'sha256:artifact', now(), now() + interval '365 days', 365, true
       )`,
      [revisionId, managedServiceId]
    );
    await client.query("update managed_service set active_revision_id=$2 where id=$1", [managedServiceId, revisionId]);
    await client.query(
      `insert into managed_service_scope(id, managed_service_id, scope_name, level, description)
     values ($1::uuid, $2::uuid, 'mcp.invoke', 'INVOKE', 'Invoke the MCP handler')`,
      [scopeId, managedServiceId]
    );
  });
  return { serverId, managedServiceId, resourceUri };
}

function sendJson(response: import("node:http").ServerResponse, status: number, body: Record<string, unknown>): void {
  const payload = JSON.stringify(body);
  response.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(payload)
  });
  response.end(payload);
}

async function startReferenceBackend(): Promise<{
  certPem: string;
  certDir: string;
  server: https.Server;
  port: number;
  state: { ready: boolean; recentRequests: Array<Record<string, unknown>> };
}> {
  const state = { ready: true, recentRequests: [] as Array<Record<string, unknown>> };
  const { certPem, keyPem, dir } = await createSelfSignedCertificate();
  const server = https.createServer({ cert: certPem, key: keyPem }, (request, response) => {
    void (async () => {
    const url = new URL(request.url ?? "/", "https://127.0.0.1");
    const gatewayHeaders = {
      mode: request.headers["x-kcml-gateway-mode"],
      managedService: request.headers["x-kcml-managed-service"],
      principalId: request.headers["x-kcml-principal-id"],
      operationId: request.headers["x-kcml-operation-id"],
      correlationId: request.headers["x-correlation-id"]
    };
    const record = (status: number) => {
      state.recentRequests.unshift({
        method: request.method ?? "GET",
        path: url.pathname,
        status,
        correlationId: gatewayHeaders.correlationId ?? null,
        operationId: gatewayHeaders.operationId ?? null
      });
      if (state.recentRequests.length > 20) state.recentRequests.length = 20;
    };
    if (request.method === "HEAD" && url.pathname === "/") {
      record(200);
      response.writeHead(200).end();
      return;
    }
    if (request.method === "GET" && url.pathname === "/health") {
      record(200);
      sendJson(response, 200, { ok: true });
      return;
    }
    if (request.method === "GET" && url.pathname === "/ready") {
      const status = state.ready ? 200 : 503;
      record(status);
      sendJson(response, status, { ok: state.ready });
      return;
    }
    if (request.method === "GET" && url.pathname === "/state/operational") {
      record(200);
      sendJson(response, 200, { healthy: true, ready: state.ready, recentRequests: state.recentRequests });
      return;
    }
    if (request.method === "GET" && url.pathname === "/state/api-acceptance") {
      record(200);
      sendJson(response, 200, {
        serviceKind: "EXTERNAL_API",
        schemaVersion: "1.0",
        gatewayEnforced: true,
        directBypassBlocked: true,
        requiredGatewayHeaders: [
          "x-kcml-gateway-mode",
          "x-kcml-managed-service",
          "x-kcml-principal-id",
          "x-kcml-operation-id",
          "x-correlation-id"
        ],
        operations: [
          { operationId: "reference.listShifts", method: "GET", path: "/v1/shifts/{employeeId}", requiredScopes: ["reference.shifts.read"] },
          { operationId: "reference.requestTimeOff", method: "POST", path: "/v1/time-off", requiredScopes: ["reference.time_off.write"] }
        ],
        logging: {
          correlationHeader: "x-correlation-id",
          redactHeaders: ["authorization", "cookie", "set-cookie"]
        },
        monitoring: {
          staleAfterSeconds: 300,
          probeIntervals: {
            healthSeconds: 15,
            readinessSeconds: 15,
            tlsSeconds: 60,
            acceptanceSeconds: 30
          }
        },
        disableMode: "CENTRAL_GATEWAY",
        permissionMutationMode: "KCML_PERMISSION_EPOCH",
        redirectsAllowed: false,
        maxSupportedTimeoutMs: 8000
      });
      return;
    }
    const gatewayOk = gatewayHeaders.mode === "managed-service"
      && gatewayHeaders.managedService
      && gatewayHeaders.principalId
      && gatewayHeaders.operationId
      && gatewayHeaders.correlationId;
    if (request.method === "GET" && url.pathname.startsWith("/v1/shifts/")) {
      if (!gatewayOk) {
        record(403);
        sendJson(response, 403, { code: "REFERENCE_DIRECT_BYPASS_BLOCKED", accepted: false });
        return;
      }
      record(200);
      sendJson(response, 200, {
        items: [
          {
            employeeId: url.pathname.split("/").pop() ?? "",
            shiftDate: "2026-07-15",
            start: "08:00",
            end: "16:00"
          }
        ]
      });
      return;
    }
    if (request.method === "POST" && url.pathname === "/v1/time-off") {
      const chunks: Buffer[] = [];
      for await (const chunk of request) chunks.push(Buffer.from(chunk));
      if (!gatewayOk) {
        record(403);
        sendJson(response, 403, { code: "REFERENCE_DIRECT_BYPASS_BLOCKED", accepted: false });
        return;
      }
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { employeeId?: string; days?: number };
      record(200);
      sendJson(response, 200, {
        requestId: `rto_${String(body.employeeId ?? "unknown")}_${Number(body.days ?? 0)}`,
        accepted: true
      });
      return;
    }
    record(404);
    sendJson(response, 404, { error: "not_found" });
    })().catch((error: unknown) => {
      sendJson(response, 500, { error: error instanceof Error ? error.message : "backend_failed" });
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  return { certPem, certDir: dir, server, port: (server.address() as AddressInfo).port, state };
}

describe.skipIf(!enabled)("EXTERNAL_API PostgreSQL integration", () => {
  let db: Db;
  let config: AppConfig;
  let socketDir: string;
  let backend: Awaited<ReturnType<typeof startReferenceBackend>>;
  let egressServer: import("node:http").Server;
  let app: FastifyInstance;
  let adminId: string;

  beforeAll(async () => {
    backend = await startReferenceBackend();
    socketDir = await mkdtemp(join(tmpdir(), "kcml-egress-"));
    config = loadConfig({
      ...process.env,
      NODE_ENV: "test",
      EGRESS_PROXY_SOCKET_PATH: join(socketDir, "proxy.sock")
    });
    db = createDb(config);
    const existingAdmin = await db.query("select id from admin_account where username = $1", [config.ADMIN_BOOTSTRAP_USERNAME]);
    if (!existingAdmin.rowCount) {
      await db.query(
        "insert into admin_account(username, password_hash, mfa_enabled) values ($1, $2, false)",
        [config.ADMIN_BOOTSTRAP_USERNAME, "integration-test"]
      );
    }
    const admin = await db.query("select id from admin_account where username = $1", [config.ADMIN_BOOTSTRAP_USERNAME]);
    adminId = String(admin.rows[0].id);
    egressServer = await buildEgressProxy(db, config);
    await listenEgressProxy(egressServer, config.EGRESS_PROXY_SOCKET_PATH);
    app = Fastify();
    registerAuthRoutes(app, db, config);
    registerExternalApiRoutes(app, db, config);
    await app.ready();
  });

  beforeEach(async () => {
    await db.query("truncate table onboarding_job, integration_token, managed_service, managed_service_revision, managed_service_scope, managed_service_access_token, mcp_server, registration_revision, access_token, kaja_credential, operational_alert, audit_event restart identity cascade");
    await db.query(
      "select setval('kcml_number_seq', greatest(coalesce((select max(kcml_number) from component), 0) + 1, 1), false)"
    );
    await db.query("update audit_head set last_sequence=0,event_hash=null,updated_at=now() where singleton=true");
    backend.state.ready = true;
    backend.state.recentRequests.length = 0;
  });

  afterAll(async () => {
    await app.close();
    await new Promise<void>((resolve, reject) => egressServer.close((error) => error ? reject(error) : resolve()));
    await new Promise<void>((resolve, reject) => backend.server.close((error) => error ? reject(error) : resolve()));
    await db.end();
    await rm(backend.certDir, { recursive: true, force: true });
    await rm(socketDir, { recursive: true, force: true });
  });

  it("enforces gateway runtime, disable/enable, permission churn and monitoring alerts through the real egress path", async () => {
    const manifestInput = manifestFor(`https://127.0.0.1:${backend.port}`);
    const { manifest, digest: manifestDigest } = validateExternalApiManifest(manifestInput);
    const integration = await createIntegrationToken(db, config, adminId, randomUUID(), "External API integration", {
      summary: "Reference external API",
      businessPurpose: "Integration test",
      serviceOwner: "KCML Managed Services",
      technicalOwner: "KCML Managed Services",
      criticality: "HIGH"
    }, undefined, { serviceKind: "EXTERNAL_API", allowedPipeline: "EXTERNAL_API_REGISTRATION" });
    const principal = await authenticateIntegrationToken(db, integration.token, config);
    const receipt = await createExternalApiManagedService(
      db,
      config,
      principal,
      "external-api-db-test",
      manifest,
      manifestDigest,
      randomUUID()
    );
    expect(receipt.finalState).toBe("REGISTERED_DISABLED");
    expect(receipt.serviceId).toBeTruthy();
    const serviceId = String(receipt.serviceId);
    const resource = String(receipt.resourceUri);
    const resumedIntegration = await createIntegrationToken(db, config, adminId, randomUUID(), "External API integration resume", {
      summary: "Reference external API resume",
      businessPurpose: "Integration test resume",
      serviceOwner: "KCML Managed Services",
      technicalOwner: "KCML Managed Services",
      criticality: "HIGH"
    }, receipt.jobId, { serviceKind: "EXTERNAL_API", allowedPipeline: "EXTERNAL_API_REGISTRATION" });
    const resumedPrincipal = await authenticateIntegrationToken(db, resumedIntegration.token, config);
    const resumedJob = await db.query("select lock_version from onboarding_job where id=$1", [receipt.jobId]);
    const resumedLockVersion = Number(resumedJob.rows[0].lock_version);
    const revisionReceipt = await updateExternalApiManagedService(
      db,
      config,
      resumedPrincipal,
      receipt.jobId,
      resumedLockVersion,
      "external-api-db-test-repeat",
      manifest,
      manifestDigest,
      randomUUID()
    );
    expect(revisionReceipt).toMatchObject({
      jobId: receipt.jobId,
      lockVersion: resumedLockVersion + 1,
      serviceId,
      finalState: "REGISTERED_DISABLED"
    });

    const credential = await createKajaCredential(db, adminId, randomUUID(), "Gateway client", null);
    const credentialRow = await db.query("select id from kaja_credential where public_id = $1", [credential.publicId]);
    const credentialId = String(credentialRow.rows[0].id);
    await replaceManagedServicePermissions(db, adminId, randomUUID(), credentialId, [{
      managedServiceId: serviceId,
      scopeNames: ["reference.shifts.read", "reference.time_off.write"]
    }]);
    const initialMonitoringTarget = (await listExternalApiMonitoringTargets(db)).find((item) => item.managedServiceId === serviceId);
    expect(initialMonitoringTarget).toBeTruthy();
    await runExternalApiMonitoringTarget(db, config, initialMonitoringTarget!);

    let state = await managedServiceStateView(db, serviceId);
    await setManagedServiceApiState(db, {
      managedServiceId: serviceId,
      actorId: adminId,
      actorType: "admin",
      nextState: "ENABLED",
      reason: "integration_test_enable",
      expectedLockVersion: Number(state.lockVersion),
      correlationId: randomUUID()
    });
    await db.query("update managed_service set enabled=false where id=$1", [serviceId]);
    state = await managedServiceStateView(db, serviceId);
    expect(state).toMatchObject({ apiState: "ENABLED", enabled: false });
    await setManagedServiceApiState(db, {
      managedServiceId: serviceId,
      actorId: adminId,
      actorType: "admin",
      nextState: "ENABLED",
      reason: "integration_test_recover_enabled_flag",
      expectedLockVersion: Number(state.lockVersion),
      correlationId: randomUUID()
    });
    state = await managedServiceStateView(db, serviceId);
    expect(state).toMatchObject({ apiState: "ENABLED", enabled: true });

    const token = await issueAccessToken(db, {
      clientId: credential.publicId,
      clientSecret: credential.clientSecret,
      resource,
      hmacKey: config.ACCESS_TOKEN_HMAC_KEY_BASE64,
      keyId: config.ACCESS_TOKEN_HMAC_KEY_ID,
      correlationId: randomUUID()
    });

    const gatewayRead = await app.inject({
      method: "GET",
      url: "/v1/shifts/emp-42",
      headers: {
        host: new URL(resource).hostname,
        authorization: `Bearer ${token.access_token}`
      }
    });
    expect(gatewayRead.statusCode).toBe(200);
    expect(gatewayRead.json()).toMatchObject({ items: [{ employeeId: "emp-42" }] });

    const direct = await directHttpsRequest(backend.port, "/v1/shifts/emp-42", backend.certPem);
    expect(direct.status).toBe(403);
    expect(JSON.parse(direct.body)).toMatchObject({ code: "REFERENCE_DIRECT_BYPASS_BLOCKED" });

    state = await managedServiceStateView(db, serviceId);
    await setManagedServiceApiState(db, {
      managedServiceId: serviceId,
      actorId: adminId,
      actorType: "admin",
      nextState: "DISABLED",
      reason: "integration_test_disable",
      expectedLockVersion: Number(state.lockVersion),
      correlationId: randomUUID()
    });
    const disabled = await app.inject({
      method: "GET",
      url: "/v1/shifts/emp-42",
      headers: {
        host: new URL(resource).hostname,
        authorization: `Bearer ${token.access_token}`
      }
    });
    expect(disabled.statusCode).toBe(401);

    state = await managedServiceStateView(db, serviceId);
    await setManagedServiceApiState(db, {
      managedServiceId: serviceId,
      actorId: adminId,
      actorType: "admin",
      nextState: "ENABLED",
      reason: "integration_test_reenable",
      expectedLockVersion: Number(state.lockVersion),
      correlationId: randomUUID()
    });
    await replaceManagedServicePermissions(db, adminId, randomUUID(), credentialId, [{
      managedServiceId: serviceId,
      scopeNames: []
    }]);
    const stalePermissionToken = await issueAccessToken(db, {
      clientId: credential.publicId,
      clientSecret: credential.clientSecret,
      resource,
      hmacKey: config.ACCESS_TOKEN_HMAC_KEY_BASE64,
      keyId: config.ACCESS_TOKEN_HMAC_KEY_ID,
      correlationId: randomUUID()
    }).catch((error: unknown) => error);
    expect(stalePermissionToken).toBeInstanceOf(Error);

    await replaceManagedServicePermissions(db, adminId, randomUUID(), credentialId, [{
      managedServiceId: serviceId,
      scopeNames: ["reference.shifts.read", "reference.time_off.write"]
    }]);
    const restoredToken = await issueAccessToken(db, {
      clientId: credential.publicId,
      clientSecret: credential.clientSecret,
      resource,
      hmacKey: config.ACCESS_TOKEN_HMAC_KEY_BASE64,
      keyId: config.ACCESS_TOKEN_HMAC_KEY_ID,
      correlationId: randomUUID()
    });
    const restored = await app.inject({
      method: "POST",
      url: "/v1/time-off",
      headers: {
        host: new URL(resource).hostname,
        authorization: `Bearer ${restoredToken.access_token}`
      },
      payload: { employeeId: "emp-42", days: 2 }
    });
    expect(restored.statusCode).toBe(200);
    expect(restored.json()).toMatchObject({ accepted: true });

    const monitoringTarget = (await listExternalApiMonitoringTargets(db)).find((item) => item.managedServiceId === serviceId);
    expect(monitoringTarget).toBeTruthy();
    backend.state.ready = false;
    await runExternalApiMonitoringTarget(db, config, monitoringTarget!);
    await db.query(
      `update managed_service_probe_result
          set checked_at = checked_at - interval '20 seconds'
        where managed_service_id = $1
          and probe_type in ('health','readiness','acceptance')`,
      [serviceId]
    );
    await runExternalApiMonitoringTarget(db, config, monitoringTarget!);
    await db.query(
      `update managed_service_probe_result
          set checked_at = checked_at - interval '20 seconds'
        where managed_service_id = $1
          and probe_type in ('health','readiness','acceptance')`,
      [serviceId]
    );
    await runExternalApiMonitoringTarget(db, config, monitoringTarget!);
    const openAlerts = await db.query(
      `select count(*)::int as count
         from operational_alert
        where managed_service_id = $1
          and alert_type = 'managed_service.monitoring.readiness'
          and status = 'OPEN'`,
      [serviceId]
    );
    expect(Number(openAlerts.rows[0].count)).toBe(1);
    await db.query(
      `update managed_service_probe_result
          set checked_at = checked_at - interval '20 seconds'
        where managed_service_id = $1
          and probe_type in ('health','readiness','acceptance')`,
      [serviceId]
    );
    await runExternalApiMonitoringTarget(db, config, monitoringTarget!);
    const dedupedAlerts = await db.query(
      `select count(*)::int as count
         from operational_alert
        where managed_service_id = $1
          and alert_type = 'managed_service.monitoring.readiness'`,
      [serviceId]
    );
    expect(Number(dedupedAlerts.rows[0].count)).toBe(1);
    backend.state.ready = true;
    await db.query(
      `update managed_service_probe_result
          set checked_at = checked_at - interval '20 seconds'
        where managed_service_id = $1
          and probe_type in ('health','readiness','acceptance')`,
      [serviceId]
    );
    await runExternalApiMonitoringTarget(db, config, monitoringTarget!);
    const closedAlerts = await db.query(
      `select status
         from operational_alert
        where managed_service_id = $1
          and alert_type = 'managed_service.monitoring.readiness'`,
      [serviceId]
    );
    expect(closedAlerts.rows[0]?.status).toBe("CLOSED");

    await recordExternalApiMonitoringInternalError(db, monitoringTarget!, new Error("synthetic-monitor-error"));
    const internalError = await db.query(
      `select status
         from operational_alert
        where managed_service_id = $1
          and alert_type = 'managed_service.monitoring.internal_error'
        order by first_seen_at desc
        limit 1`,
      [serviceId]
    );
    expect(internalError.rows[0]?.status).toBe("OPEN");
  });

  it("rolls back token issuance when the legacy token insert fails", async () => {
    const mcp = await seedMcpManagedService(db, "KCML9100");
    const credential = await createKajaCredential(db, adminId, randomUUID(), "Rollback legacy insert", null);
    const credentialRow = await db.query("select id from kaja_credential where public_id = $1", [credential.publicId]);
    const credentialId = String(credentialRow.rows[0].id);
    await replaceManagedServicePermissions(db, adminId, randomUUID(), credentialId, [{
      managedServiceId: mcp.managedServiceId,
      scopeNames: ["mcp.invoke"]
    }]);
    await db.query(`
      create or replace function fail_access_token_insert() returns trigger language plpgsql as $$
      begin
        raise exception 'forced_access_token_failure';
      end $$;
      drop trigger if exists access_token_force_fail on access_token;
      create trigger access_token_force_fail before insert on access_token
      for each row execute function fail_access_token_insert();
    `);
    try {
      await expect(issueAccessToken(db, {
        clientId: credential.publicId,
        clientSecret: credential.clientSecret,
        resource: mcp.resourceUri,
        hmacKey: config.ACCESS_TOKEN_HMAC_KEY_BASE64,
        keyId: config.ACCESS_TOKEN_HMAC_KEY_ID,
        correlationId: randomUUID()
      })).rejects.toThrow(/forced_access_token_failure/);
    } finally {
      await db.query("drop trigger if exists access_token_force_fail on access_token");
      await db.query("drop function if exists fail_access_token_insert()");
    }
    const counts = await db.query(
      `select
          (select count(*) from managed_service_access_token where credential_id = $1)::int as managed_count,
          (select count(*) from access_token where credential_id = $1)::int as legacy_count`,
      [credentialId]
    );
    expect(counts.rows[0]).toMatchObject({ managed_count: 0, legacy_count: 0 });
  });

  it("rolls back credential creation when audit append fails", async () => {
    await db.query(`
      create or replace function fail_audit_event_insert() returns trigger language plpgsql as $$
      begin
        raise exception 'forced_audit_failure';
      end $$;
      drop trigger if exists audit_event_force_fail on audit_event;
      create trigger audit_event_force_fail before insert on audit_event
      for each row execute function fail_audit_event_insert();
    `);
    try {
      await expect(createKajaCredential(db, adminId, randomUUID(), "Audit rollback credential", null))
        .rejects.toThrow(/forced_audit_failure/);
    } finally {
      await db.query("drop trigger if exists audit_event_force_fail on audit_event");
      await db.query("drop function if exists fail_audit_event_insert()");
    }
    const count = await db.query("select count(*)::int as count from kaja_credential where label = $1", ["Audit rollback credential"]);
    expect(Number(count.rows[0].count)).toBe(0);
  });

  it("migrates legacy plaintext MFA secrets idempotently", async () => {
    await db.query("alter table admin_account drop constraint admin_account_mfa_secret_ciphertext_check");
    await db.query(
      "update admin_account set mfa_enabled=true, mfa_secret=$2 where id=$1",
      [adminId, "JBSWY3DPEHPK3PXP"]
    );
    await db.query(
      `alter table admin_account add constraint admin_account_mfa_secret_ciphertext_check
       check (mfa_secret is null or mfa_secret like 'enc:v2:%') not valid`
    );
    const migrated = await migrateLegacyMfaSecrets();
    expect(migrated.migrated).toBe(1);
    const account = await db.query("select mfa_secret from admin_account where id=$1", [adminId]);
    expect(String(account.rows[0].mfa_secret)).toMatch(/^enc:v2:/);
    const effectiveConfig = await loadConfigFromDb(db, loadBootstrapConfig(process.env));
    expect(decryptMfaSecret(String(account.rows[0].mfa_secret), effectiveConfig.MFA_ENCRYPTION_KEY_BASE64, {
      subjectId: adminId,
      purpose: "admin_totp"
    })).toBe("JBSWY3DPEHPK3PXP");
    const rerun = await migrateLegacyMfaSecrets();
    expect(rerun.migrated).toBe(0);
  });

  it("rolls back both token stores when audit append fails and keeps a single logical token on success", async () => {
    const mcp = await seedMcpManagedService(db, "KCML9101");
    const credential = await createKajaCredential(db, adminId, randomUUID(), "Audit rollback", null);
    const credentialRow = await db.query("select id from kaja_credential where public_id = $1", [credential.publicId]);
    const credentialId = String(credentialRow.rows[0].id);
    await replaceManagedServicePermissions(db, adminId, randomUUID(), credentialId, [{
      managedServiceId: mcp.managedServiceId,
      scopeNames: ["mcp.invoke"]
    }]);
    await db.query(`
      create or replace function fail_audit_event_insert() returns trigger language plpgsql as $$
      begin
        raise exception 'forced_audit_failure';
      end $$;
      drop trigger if exists audit_event_force_fail on audit_event;
      create trigger audit_event_force_fail before insert on audit_event
      for each row execute function fail_audit_event_insert();
    `);
    try {
      await expect(issueAccessToken(db, {
        clientId: credential.publicId,
        clientSecret: credential.clientSecret,
        resource: mcp.resourceUri,
        hmacKey: config.ACCESS_TOKEN_HMAC_KEY_BASE64,
        keyId: config.ACCESS_TOKEN_HMAC_KEY_ID,
        correlationId: randomUUID()
      })).rejects.toThrow(/forced_audit_failure/);
    } finally {
      await db.query("drop trigger if exists audit_event_force_fail on audit_event");
      await db.query("drop function if exists fail_audit_event_insert()");
    }
    const token = await issueAccessToken(db, {
      clientId: credential.publicId,
      clientSecret: credential.clientSecret,
      resource: mcp.resourceUri,
      hmacKey: config.ACCESS_TOKEN_HMAC_KEY_BASE64,
      keyId: config.ACCESS_TOKEN_HMAC_KEY_ID,
      correlationId: randomUUID()
    });
    expect(token.scope).toBe("mcp.invoke");
    const snapshots = await db.query(
      `select
          managed.lookup_digest = managed.legacy_access_token_digest as linked,
          managed.legacy_access_token_digest = legacy.lookup_digest as shared_digest,
          managed.permission_epoch_snapshot = service.permission_epoch as permission_epoch_match,
          managed.active_revision_epoch_snapshot = service.active_revision_epoch as revision_epoch_match
         from managed_service_access_token managed
         join access_token legacy on legacy.lookup_digest = managed.legacy_access_token_digest
         join managed_service service on service.id = managed.managed_service_id
        where managed.credential_id = $1`,
      [credentialId]
    );
    expect(snapshots.rowCount).toBe(1);
    expect(snapshots.rows[0]).toMatchObject({
      linked: true,
      shared_digest: true,
      permission_epoch_match: true,
      revision_epoch_match: true
    });
  });

  it("applies full replace semantics for managed-service permissions", async () => {
    const first = await seedMcpManagedService(db, "KCML9102");
    const second = await seedMcpManagedService(db, "KCML9103");
    const credential = await createKajaCredential(db, adminId, randomUUID(), "Permission replace", null);
    const credentialRow = await db.query("select id from kaja_credential where public_id = $1", [credential.publicId]);
    const credentialId = String(credentialRow.rows[0].id);
    await replaceManagedServicePermissions(db, adminId, randomUUID(), credentialId, [
      { managedServiceId: first.managedServiceId, scopeNames: ["mcp.invoke"] },
      { managedServiceId: second.managedServiceId, scopeNames: ["mcp.invoke"] }
    ]);
    const epochBefore = await db.query("select id, permission_epoch from managed_service where id = any($1::uuid[]) order by id", [[first.managedServiceId, second.managedServiceId]]);
    await replaceManagedServicePermissions(db, adminId, randomUUID(), credentialId, [
      { managedServiceId: first.managedServiceId, scopeNames: ["mcp.invoke"] }
    ]);
    const remaining = await listManagedServicePermissions(db, credentialId);
    expect(remaining.filter((permission) => permission.scopes.length > 0).map((permission) => permission.managedServiceId)).toEqual([first.managedServiceId]);
    await replaceManagedServicePermissions(db, adminId, randomUUID(), credentialId, []);
    const cleared = await listManagedServicePermissions(db, credentialId);
    expect(cleared.every((permission) => permission.scopes.length === 0)).toBe(true);
    const epochAfter = await db.query("select id, permission_epoch from managed_service where id = any($1::uuid[]) order by id", [[first.managedServiceId, second.managedServiceId]]);
    expect(epochAfter.rows.map((row, index) => row.permission_epoch !== epochBefore.rows[index]?.permission_epoch)).toEqual([true, true]);
  });

  it("applies a resumed EXTERNAL_API onboarding revision for an existing managed service", async () => {
    const initialInput = manifestFor(`https://127.0.0.1:${backend.port}`);
    const { manifest: initialManifest, digest: initialDigest } = validateExternalApiManifest(initialInput);
    const integration = await createIntegrationToken(db, config, adminId, randomUUID(), "External API integration", {
      summary: "Reference external API",
      businessPurpose: "Integration test",
      serviceOwner: "KCML Managed Services",
      technicalOwner: "KCML Managed Services",
      criticality: "HIGH"
    }, undefined, { serviceKind: "EXTERNAL_API", allowedPipeline: "EXTERNAL_API_REGISTRATION" });
    const principal = await authenticateIntegrationToken(db, integration.token, config);
    const receipt = await createExternalApiManagedService(
      db,
      config,
      principal,
      "external-api-db-resume-test",
      initialManifest,
      initialDigest,
      randomUUID()
    );
    expect(receipt.finalState).toBe("REGISTERED_DISABLED");

    const resumed = await createIntegrationToken(db, config, adminId, randomUUID(), "External API resumed integration", {
      summary: "Reference external API",
      businessPurpose: "Integration test",
      serviceOwner: "KCML Managed Services",
      technicalOwner: "KCML Managed Services",
      criticality: "HIGH"
    }, receipt.jobId, { serviceKind: "EXTERNAL_API", allowedPipeline: "EXTERNAL_API_REGISTRATION" });
    const resumedPrincipal = await authenticateIntegrationToken(db, resumed.token, config);
    const resumedJob = await db.query("select lock_version from onboarding_job where id=$1", [receipt.jobId]);
    const nextInput = {
      ...manifestFor(`https://127.0.0.1:${backend.port}`),
      registrationRevision: "test-reference-api-2",
      description: "Updated local HTTPS reference backend used by the integration test."
    };
    const { manifest: nextManifest, digest: nextDigest } = validateExternalApiManifest(nextInput);
    const updated = await updateExternalApiManagedService(
      db,
      config,
      resumedPrincipal,
      receipt.jobId,
      Number(resumedJob.rows[0].lock_version),
      "external-api-db-resume-test-revision",
      nextManifest,
      nextDigest,
      randomUUID()
    );

    expect(updated).toMatchObject({
      jobId: receipt.jobId,
      serviceId: receipt.serviceId,
      finalState: "REGISTERED_DISABLED"
    });
    const revisionCount = await db.query("select count(*)::int as count from managed_service_revision where managed_service_id=$1", [receipt.serviceId]);
    expect(revisionCount.rows[0].count).toBe(2);
    const activeRevision = await db.query("select revision from managed_service_revision where managed_service_id=$1 and active is true", [receipt.serviceId]);
    expect(activeRevision.rows[0].revision).toBe("test-reference-api-2");
  });
});
