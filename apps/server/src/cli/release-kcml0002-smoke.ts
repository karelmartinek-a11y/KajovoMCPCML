import { randomUUID } from "node:crypto";
import http from "node:http";
import { loadConfig } from "../config.js";
import { createDb, tx } from "../db.js";
import { createKajaCredential, replaceKajaPermissions, revokeKajaCredential } from "../domain/auth.js";
import { appendAudit } from "../domain/audit.js";
import { transitionServerState } from "../domain/server-state.js";
import { setManagedServiceApiState } from "../domain/managed-service.js";
import { loadConfigFromDb } from "../domain/operational-config.js";
import { matchesExpectedResult } from "../onboarding/activation.js";

type JsonRpcResponse = {
  error?: unknown;
  result?: {
    tools?: Array<{ name?: string }>;
    structuredContent?: unknown;
  };
};

type HttpJsonInit = {
  method?: string;
  headers: Record<string, string>;
  body?: string;
  expectedStatus?: number;
};

function writeReleaseCheck(message: string): void {
  process.stdout.write(`${message}\n`);
}

async function httpJson(url: string, init: HttpJsonInit): Promise<{
  body: unknown;
  status: number;
  correlationId: string | null;
}> {
  const expected = init.expectedStatus ?? 200;
  const parsed = new URL(url);
  return new Promise((resolve, reject) => {
    const bodyText = init.body ?? "";
    const headers: Record<string, string> = { ...init.headers };
    if (bodyText && !headers["content-length"]) headers["content-length"] = String(Buffer.byteLength(bodyText));
    const request = http.request({
      hostname: parsed.hostname,
      port: parsed.port,
      path: `${parsed.pathname}${parsed.search}`,
      method: init.method ?? "GET",
      headers,
      timeout: 10_000
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        if (response.statusCode !== expected) {
          reject(new Error(`http_status:${response.statusCode ?? "unknown"}:${text.slice(0, 500)}`));
          return;
        }
        let body: unknown = null;
        try {
          body = text ? JSON.parse(text) as unknown : null;
        } catch (error) {
          reject(new Error(`invalid_json_response:${error instanceof Error ? error.message : String(error)}:${text.slice(0, 500)}`));
          return;
        }
        resolve({
          body,
          status: response.statusCode ?? 0,
          correlationId: typeof response.headers["x-correlation-id"] === "string" ? response.headers["x-correlation-id"] : null
        });
      });
    });
    request.on("timeout", () => request.destroy(new Error("http_timeout")));
    request.on("error", reject);
    if (bodyText) request.write(bodyText);
    request.end();
  });
}

async function rpc(baseUrl: string, hostname: string, accessToken: string, method: string, params?: unknown): Promise<{
  body: JsonRpcResponse;
  correlationId: string | null;
}> {
  const response = await httpJson(`${baseUrl}/mcp`, {
    method: "POST",
    headers: {
      host: hostname,
      authorization: `Bearer ${accessToken}`,
      "content-type": "application/json",
      "idempotency-key": randomUUID()
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: randomUUID(), method, params })
  });
  return { body: response.body as JsonRpcResponse, correlationId: response.correlationId };
}

async function syncManagedServiceLifecycle(db: ReturnType<typeof createDb>, params: {
  serverId: string;
  lifecycleState: "TRIAL" | "ACTIVE";
  operationalState: "UNKNOWN" | "HEALTHY";
  correlationId: string;
  reason: string;
  evidence?: Record<string, unknown>;
}): Promise<void> {
  await tx(db, async (client) => {
    const result = await client.query(
      `update managed_service
          set lifecycle_state = $2::managed_service_state,
              operational_state = $3::operational_state,
              enabled = true,
              api_state = 'ENABLED'::managed_service_api_state,
              api_disabled_reason = null,
              lock_version = lock_version + 1,
              updated_at = now()
        where legacy_mcp_server_id = $1
          and service_kind = 'MCP'
          and (
            lifecycle_state is distinct from $2::managed_service_state
            or operational_state is distinct from $3::operational_state
            or enabled is distinct from true
            or api_state is distinct from 'ENABLED'::managed_service_api_state
            or api_disabled_reason is not null
          )
        returning id, lock_version`,
      [params.serverId, params.lifecycleState, params.operationalState]
    );
    if (!result.rowCount) return;
    const managedServiceId = String(result.rows[0].id);
    await client.query(
      `insert into managed_service_api_status(managed_service_id, api_state, disabled_reason, changed_by_type, changed_by_id, correlation_id, changed_at)
       values ($1, 'ENABLED', null, 'system', 'release-smoke', $2, now())
       on conflict (managed_service_id) do update
         set api_state = excluded.api_state,
             disabled_reason = excluded.disabled_reason,
             changed_by_type = excluded.changed_by_type,
             changed_by_id = excluded.changed_by_id,
             correlation_id = excluded.correlation_id,
             changed_at = excluded.changed_at`,
      [managedServiceId, params.correlationId]
    );
    await client.query(
      `insert into managed_service_policy_event(managed_service_id, event_type, correlation_id, detail)
       values ($1, 'lifecycle.release_smoke_sync', $2, $3)`,
      [managedServiceId, params.correlationId, JSON.stringify({ reason: params.reason, ...params.evidence })]
    );
    await appendAudit(client, {
      eventType: "managed_service.lifecycle.release_smoke_synced",
      actorType: "system",
      actorId: "release-smoke",
      objectType: "managed_service",
      objectId: managedServiceId,
      after: {
        lifecycleState: params.lifecycleState,
        operationalState: params.operationalState,
        lockVersion: Number(result.rows[0].lock_version),
        reason: params.reason,
        ...params.evidence
      },
      correlationId: params.correlationId
    });
  });
}

async function main(): Promise<void> {
  const bootstrapConfig = loadConfig();
  const db = createDb(bootstrapConfig);
  try {
    const config = await loadConfigFromDb(db, bootstrapConfig);
    const baseUrl = process.env.KCML_RELEASE_BASE_URL ?? `http://127.0.0.1:${process.env.PORT || "3010"}`;
    const correlationId = randomUUID();
    const serverResult = await db.query(
      `select
          ms.id, ms.code, ms.hostname, ms.tool_name, ms.registration_state, ms.operational_state,
          ms.contract_version, ms.handler_version, ms.manifest_digest, ms.artifact_digest,
          managed.id as managed_service_id, managed.lifecycle_state as managed_lifecycle_state,
          managed.api_state as managed_api_state, managed.lock_version as managed_lock_version,
          rr.manifest
         from mcp_server ms
         join registration_revision rr on rr.id=ms.active_revision_id and rr.server_id=ms.id and rr.active=true
         left join managed_service managed on managed.legacy_mcp_server_id=ms.id and managed.service_kind='MCP'
        where ms.code='KCML0002'`
    );
    if (!serverResult.rowCount) throw new Error("kcml0002_missing");
    const server = serverResult.rows[0] as Record<string, unknown>;
    const serverId = String(server.id);
    const hostname = String(server.hostname);
    const toolName = String(server.tool_name);
    const manifest = server.manifest as { testContract?: { safeInput?: unknown; expectedResult?: unknown } };
    const testContract = manifest.testContract;
    if (!testContract) throw new Error("kcml0002_test_contract_missing");

    const managedServiceId = typeof server.managed_service_id === "string" ? server.managed_service_id : null;
    if (managedServiceId && (String(server.managed_lifecycle_state) === "REGISTERED_DISABLED" || String(server.managed_api_state) === "DISABLED")) {
      await setManagedServiceApiState(db, {
        managedServiceId,
        actorType: "system",
        actorId: "release-smoke",
        nextState: "ENABLED",
        reason: "release_smoke_trial_started",
        expectedLockVersion: Number(server.managed_lock_version ?? 0),
        correlationId
      });
      writeReleaseCheck("release-check:mcp_kcml0002_managed_service_enabled=true");
    } else if (String(server.registration_state) === "REGISTERED_DISABLED") {
      await tx(db, (client) => transitionServerState(client, {
        serverId,
        to: "TRIAL",
        actorType: "system",
        actorId: "release-smoke",
        reason: "release_smoke_trial_started",
        correlationId
      }));
      await syncManagedServiceLifecycle(db, {
        serverId,
        lifecycleState: "TRIAL",
        operationalState: "UNKNOWN",
        correlationId,
        reason: "release_smoke_trial_started"
      });
      writeReleaseCheck("release-check:mcp_kcml0002_trial_started=true");
    }

    const credential = await createKajaCredential(
      db,
      "release-smoke",
      correlationId,
      `kcml0002-release-smoke-${process.env.BUILD_ID ?? "local"}`.slice(0, 120),
      new Date(Date.now() + 15 * 60_000).toISOString()
    );
    const credentialResult = await db.query(
      "select id from kaja_credential where public_id=$1 and deleted_at is null",
      [credential.publicId]
    );
    if (!credentialResult.rowCount) throw new Error("release_smoke_credential_missing");
    const credentialId = String(credentialResult.rows[0].id);
    try {
      await replaceKajaPermissions(db, "release-smoke", correlationId, credentialId, [{ serverId, accessLevel: "EXECUTE" }]);
      const basic = Buffer.from(`${encodeURIComponent(credential.publicId)}:${encodeURIComponent(credential.clientSecret)}`).toString("base64");
      const tokenResponse = await httpJson(`${baseUrl}/oauth/token`, {
        method: "POST",
        headers: {
          host: config.AUTH_HOST,
          authorization: `Basic ${basic}`,
          "content-type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({ grant_type: "client_credentials", resource: `https://${hostname}/mcp` }).toString()
      });
      const tokenBody = tokenResponse.body as { access_token?: unknown };
      const accessToken = typeof tokenBody.access_token === "string" ? tokenBody.access_token : "";
      if (!accessToken) throw new Error("release_smoke_token_missing");

      await rpc(baseUrl, hostname, accessToken, "initialize");
      const list = await rpc(baseUrl, hostname, accessToken, "tools/list");
      const toolNames = list.body.result?.tools?.map((tool) => tool.name).filter(Boolean) ?? [];
      if (toolNames.length !== 1 || toolNames[0] !== toolName) throw new Error("release_smoke_tool_catalog_mismatch");
      const call = await rpc(baseUrl, hostname, accessToken, "tools/call", {
        name: toolName,
        arguments: testContract.safeInput ?? {}
      });
      if (call.body.error) throw new Error(`release_smoke_tool_error:${JSON.stringify(call.body.error).slice(0, 500)}`);
      if (!matchesExpectedResult(call.body.result?.structuredContent, testContract.expectedResult ?? {})) {
        throw new Error("release_smoke_result_mismatch");
      }
      if (!call.correlationId) throw new Error("release_smoke_correlation_missing");
      const evidence = await db.query(
        `select
            exists(select 1 from audit_event where correlation_id=$1 and event_type='mcp.invocation.completed') as audit_ok,
            exists(select 1 from runtime_log_event where correlation_id=$1 and event_name='mcp.invocation.completed') as log_ok`,
        [call.correlationId]
      );
      if (!evidence.rows[0]?.audit_ok || !evidence.rows[0]?.log_ok) throw new Error("release_smoke_evidence_missing");

      const latestState = await db.query("select registration_state, operational_state from mcp_server where id=$1", [serverId]);
      if (String(latestState.rows[0]?.registration_state) !== "ACTIVE") {
        const activationEvidence = {
          code: String(server.code),
          hostname,
          toolName,
          contractVersion: String(server.contract_version),
          handlerVersion: String(server.handler_version),
          manifestDigest: String(server.manifest_digest),
          artifactDigest: String(server.artifact_digest),
          invocationCorrelationId: call.correlationId
        };
        await tx(db, (client) => transitionServerState(client, {
          serverId,
          to: "ACTIVE",
          actorType: "system",
          actorId: "release-smoke",
          reason: "release_smoke_gateway_passed",
          correlationId,
          activationEvidence
        }));
        await syncManagedServiceLifecycle(db, {
          serverId,
          lifecycleState: "ACTIVE",
          operationalState: "HEALTHY",
          correlationId,
          reason: "release_smoke_gateway_passed",
          evidence: activationEvidence
        });
      }
      await appendAudit(db, {
        eventType: "deployment.kcml0002_gateway_smoke.passed",
        actorType: "system",
        actorId: "release-smoke",
        objectType: "mcp_server",
        objectId: serverId,
        after: { hostname, toolName, invocationCorrelationId: call.correlationId },
        correlationId
      });
      writeReleaseCheck(`release-check:mcp_kcml0002_gateway_smoke=PASS correlation=${call.correlationId}`);
    } finally {
      await revokeKajaCredential(db, "release-smoke", correlationId, credentialId).catch(() => undefined);
    }
  } finally {
    await db.end();
  }
}

main().catch((error) => {
  console.error(`release-check:mcp_kcml0002_gateway_smoke=FAIL error=${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
