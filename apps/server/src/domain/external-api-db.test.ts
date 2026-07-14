import { randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import https from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import Fastify, { type FastifyInstance } from "fastify";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { loadConfig, type AppConfig } from "../config.js";
import { createDb, type Db } from "../db.js";
import {
  createKajaCredential,
  issueAccessToken,
  replaceManagedServicePermissions
} from "./auth.js";
import {
  createExternalApiManagedService,
  listExternalApiMonitoringTargets,
  recordExternalApiMonitoringInternalError,
  runExternalApiMonitoringTarget,
  validateExternalApiManifest
} from "./external-api.js";
import { managedServiceStateView, setManagedServiceApiState } from "./managed-service.js";
import { authenticateIntegrationToken, createIntegrationToken } from "./onboarding.js";
import { buildEgressProxy, listenEgressProxy } from "../onboarding/egress-proxy.js";
import { registerAuthRoutes } from "../http/auth-routes.js";
import { registerExternalApiRoutes } from "../http/external-api-routes.js";

const enabled = process.env.KCML_TEST_DATABASE === "1";

const certPem = `-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUOKc9k+VP2wvPnJgjUMcc1sNDazswDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJMTI3LjAuMC4xMB4XDTI2MDcxNDIzMDc0N1oXDTI3MDcx
NDIzMDc0N1owFDESMBAGA1UEAwwJMTI3LjAuMC4xMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA4TYLFZKcyPmBWBtRBKK/9ItPArh/ewYpp2JcEkt64jFA
QbdxKwjAjKkAG6lnCfmDxHmQNMfBXuc1W9R0dYBzOEwWBM64ctSS4UjAMVqCKsEm
4gpc22kiLuq8tzt8Pxp2npwpXwrkZKxLoSaYvx8gwaOdrW4zkGKf/GRd26XeiWkj
hsW9TaOhp+wOwwmBviiFWKsRXYjVwIrs7B1ysUyOQ0D6mtepaSwmMZE1vBorK9Ew
lrvUOKSrCf8e7ansV3oXLTWbkMxB3pPYU53E/6IC9OgeHAx6yiGyZHTMiY8NWvfL
OPm7UEfr/0gQEmEjWdqzE887U659J53ZJX8F3Obv9QIDAQABo1MwUTAdBgNVHQ4E
FgQUnhADj/7ebFngjuhG9HHWFenHetEwHwYDVR0jBBgwFoAUnhADj/7ebFngjuhG
9HHWFenHetEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAn+l0
NDxGGerDe9uRnwsWHQ+SmuRAm8A7SSjjFFxqjE4inAjVV6Ykx2dBnd8OfUx9jV/5
iJnzDaxqiFW2eX4ZM5Z9hl83f3j5FYVXOg/HH1AuzZvN3drs4DyytP5dYaxmqNob
KpIIIYRmOOz0c04hgHZAIBoFctL2IQDZyhStENcj+ouLy2kZDeBknuPysdlsom2p
3bvdRqSDa7nCWMPkAtTUm3ShA/qckdLhI7WbviP38tNI6A06+j2cI+Da4sTtOi3E
5FU/QY3dQmYh4EaHIolXvbpwDo8CP1QuqxMAON7GpGmZLOgzjViYxvfdndikquum
nRDu2icpjGHdVxKfPQ==
-----END CERTIFICATE-----`;

const keyPem = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDhNgsVkpzI+YFY
G1EEor/0i08CuH97BimnYlwSS3riMUBBt3ErCMCMqQAbqWcJ+YPEeZA0x8Fe5zVb
1HR1gHM4TBYEzrhy1JLhSMAxWoIqwSbiClzbaSIu6ry3O3w/GnaenClfCuRkrEuh
Jpi/HyDBo52tbjOQYp/8ZF3bpd6JaSOGxb1No6Gn7A7DCYG+KIVYqxFdiNXAiuzs
HXKxTI5DQPqa16lpLCYxkTW8Gisr0TCWu9Q4pKsJ/x7tqexXehctNZuQzEHek9hT
ncT/ogL06B4cDHrKIbJkdMyJjw1a98s4+btQR+v/SBASYSNZ2rMTzztTrn0nndkl
fwXc5u/1AgMBAAECggEAFrtUvRWyW5rLknAXamdfBrj0/apPu8QweiO0dWhG/APK
n5d7hcN5Y/k++IvNybT0tuUqSBmNjB28RguYwa94cctEQbH37idEuBaWx6SCFPyw
BwrSupbPC3tIFxqa/OeX54SNrHk1+m9lptt1eX0T2lfAd5vy+nTp/xjGXIBOiQHy
SB1k2v/uTAKY+T3QR7KVzW65msIe5IwKTg2Bu66qpv3qsfAue/LTQF0KuprZSktv
wk69rm0w9LCbFKr6Y8ci2e92zIv+rL3JJnhKUxSpx0BHnevHcPxqcTij/Cz1WDaT
ghvd0JZdtY98SKZsbZnGgFaDeOsPH/Qd+fGKPh5g1QKBgQD0dNlqIkTTz4fW3sgG
WP8hgTDw6hGenBf8tU2XnCHJ5iwqcYYkZvrHzOVM2VVfOMSsr+iwipCHHRHlYkGL
VGJw+bVyBTLW8silskNX1K17vbLzbKzpCB8QUW5r2HrjqcsI/GO550m7TXcShJyi
lOUlAq46QD0rCdw2aL5r9l6ygwKBgQDr2IswcLqWvSab0jDv3LYBlPhdTqw1h6O0
uo3DvUOZdWbKq+9573M6bwggyDynhvh3cz9YREcrtXKrxrGY06okjbyVSRUEQqhB
hRXRxfLogrWANEDnrkdi5DHeUZu1ZGWydZOSA6F+Dv+Nb1JziHadgPib2+NAbgyj
jDPhjBrqJwKBgDA+l2Hw3XCH9qEbWpKWIdP08Tm6mDubRsii52tSbwCvomvF99lb
UYb5Ew/1nHmsdHQ4S038KsXfoNaKa7EZuEvfnEWibQQq6hp5cfz1hj9zksuj2QQs
jCTmTUqPcMFZky500SGxWcXTZfqLnXYguJBzVPs+DlReH83FIj+gYdQNAoGBANOA
OjKSpYIQ1tLeSGySrdX1VlW2+9B1d2XX9tIWpMy18BzI29Wp2tgIQm3DpEFIVQIq
JCBv+rND4TYS1amMCAUH5pqqE2LitCktxEd/ETtaHJKAScR7EiGpKt+Ip+6fvmOv
9Ur4XpbBtION1Y8uTdEpm8mKA93/0u3ICa63Clv5AoGBALsWfFpYcJfNj2JR8BUO
X+s4dhJ8SLM7F47l9DAbrkLIEe4b4x7oIOWtTZOAnT//vtbSzMVYETpu77Mpzv41
46lfYd14Wue9Ljp1P03lVI1R12dOilVvjr8+t/uwKKlwr8or0knr0+v80k++EC94
Zi2Z8/XUXgp+MsenM1baTQ0V
-----END PRIVATE KEY-----`;

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

function directHttpsRequest(port: number, path: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const request = https.request({
      host: "127.0.0.1",
      port,
      path,
      method: "GET",
      rejectUnauthorized: false
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

function sendJson(response: import("node:http").ServerResponse, status: number, body: Record<string, unknown>): void {
  const payload = JSON.stringify(body);
  response.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(payload)
  });
  response.end(payload);
}

async function startReferenceBackend(): Promise<{
  server: https.Server;
  port: number;
  state: { ready: boolean; recentRequests: Array<Record<string, unknown>> };
}> {
  const state = { ready: true, recentRequests: [] as Array<Record<string, unknown>> };
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
  return { server, port: (server.address() as AddressInfo).port, state };
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
    await db.query("truncate table onboarding_job, integration_token, managed_service, kaja_credential, operational_alert, audit_event restart identity cascade");
    await db.query("select setval('kcml_number_seq', 1, false)");
    await db.query("update audit_head set last_sequence=0,event_hash=null,updated_at=now() where singleton=true");
    backend.state.ready = true;
    backend.state.recentRequests.length = 0;
  });

  afterAll(async () => {
    await app.close();
    await new Promise<void>((resolve, reject) => egressServer.close((error) => error ? reject(error) : resolve()));
    await new Promise<void>((resolve, reject) => backend.server.close((error) => error ? reject(error) : resolve()));
    await db.end();
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

    const credential = await createKajaCredential(db, adminId, randomUUID(), "Gateway client", null);
    const credentialRow = await db.query("select id from kaja_credential where public_id = $1", [credential.publicId]);
    const credentialId = String(credentialRow.rows[0].id);
    await replaceManagedServicePermissions(db, adminId, randomUUID(), credentialId, [{
      managedServiceId: serviceId,
      scopeNames: ["reference.shifts.read", "reference.time_off.write"]
    }]);

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

    const direct = await directHttpsRequest(backend.port, "/v1/shifts/emp-42");
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
});
