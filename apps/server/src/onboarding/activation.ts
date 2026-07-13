import { randomUUID } from "node:crypto";
import dns from "node:dns/promises";
import tls from "node:tls";
import { isDeepStrictEqual } from "node:util";
import type { AppConfig } from "../config.js";
import type { Db } from "../db.js";
import { tx } from "../db.js";
import { appendAudit } from "../domain/audit.js";
import type { OnboardingManifest } from "../domain/registration.js";
import { hashPasswordLikeSecret, issueOpaqueSecret } from "../security/secrets.js";

export type ActivationJob = {
  id: string;
  code: string;
  hostname: string;
  toolName: string;
  manifestDigest: string;
  sourceDigest: string;
  imageReference: string;
  imageDigest: string;
  sbomDigest: string;
  provenanceDigest: string;
  sourceCommit: string;
  buildId: string;
  manifest: OnboardingManifest;
};

function tlsCertificate(hostname: string): Promise<{ subjectaltname: string; fingerprint256: string }> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host: hostname, port: 443, servername: hostname, rejectUnauthorized: true, timeout: 8_000 }, () => {
      const certificate = socket.getPeerCertificate();
      const identityError = tls.checkServerIdentity(hostname, certificate);
      socket.end();
      if (identityError) reject(identityError);
      else resolve({ subjectaltname: String(certificate.subjectaltname ?? ""), fingerprint256: String(certificate.fingerprint256 ?? "") });
    });
    socket.on("timeout", () => socket.destroy(new Error("tls_timeout")));
    socket.on("error", reject);
  });
}

async function jsonRequest(url: string, init: RequestInit): Promise<{ response: Response; body: unknown }> {
  const response = await fetch(url, { ...init, signal: AbortSignal.timeout(65_000), redirect: "manual" });
  const text = await response.text();
  let body: unknown = null;
  if (text) {
    try { body = JSON.parse(text); } catch { body = text; }
  }
  return { response, body };
}

function assertStatus(response: Response, expected: number, code: string): void {
  if (response.status !== expected) throw new Error(`${code}:${response.status}`);
}

export function matchesExpectedResult(actual: unknown, expected: unknown): boolean {
  if (Array.isArray(expected)) {
    return Array.isArray(actual)
      && actual.length === expected.length
      && expected.every((item, index) => matchesExpectedResult(actual[index], item));
  }
  if (expected && typeof expected === "object") {
    if (!actual || typeof actual !== "object" || Array.isArray(actual)) return false;
    return Object.entries(expected as Record<string, unknown>).every(
      ([key, value]) => Object.hasOwn(actual, key)
        && matchesExpectedResult((actual as Record<string, unknown>)[key], value)
    );
  }
  return isDeepStrictEqual(actual, expected);
}

export async function registerDisabledServer(db: Db, job: ActivationJob, socketPath: string, correlationId: string): Promise<string> {
  return tx(db, async (client) => {
    const authorization = await client.query(
      `select oj.id
         from onboarding_job oj
         join integration_token it on it.id=oj.token_id
        where oj.id=$1 and oj.state='DEPLOYING' and it.onboarding_job_id=oj.id
          and it.revoked_at is null and it.deleted_at is null and it.expires_at>now()
        for update of oj,it`,
      [job.id]
    );
    if (!authorization.rowCount) throw new Error("integration_token_inactive");
    const existing = await client.query("select id from mcp_server where code=$1", [job.code]);
    if (existing.rowCount) return String(existing.rows[0].id);
    const server = await client.query(
      `insert into mcp_server
        (kcml_number,code,hostname,tool_name,display_name,description,enabled,registration_state,operational_state,
         input_schema,output_schema,handler_key,handler_version,contract_version,artifact_digest,manifest_digest,
         image_reference,image_digest,sbom_digest,provenance_digest,runtime_socket,timeout_ms,max_concurrency,request_max_bytes,response_max_bytes,
         rate_window_seconds,rate_max_requests)
       select kcml_number,code,hostname,tool_name,$2,$3,false,'REGISTERED_DISABLED','DISABLED',$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21
         from onboarding_job where id=$1
       returning id`,
      [job.id, job.manifest.displayName, job.manifest.businessPurpose, job.manifest.tool.inputSchema, job.manifest.tool.outputSchema,
        job.manifest.handlerKey, job.manifest.handlerVersion, job.manifest.registrationRevision, job.imageDigest, job.manifestDigest,
        job.imageReference, job.imageDigest, job.sbomDigest, job.provenanceDigest, socketPath, job.manifest.behavior.timeoutMs,
        job.manifest.behavior.maxConcurrency, job.manifest.behavior.requestMaxBytes, job.manifest.behavior.responseMaxBytes,
        job.manifest.behavior.rateLimit.windowSeconds, job.manifest.behavior.rateLimit.maxRequests]
    );
    if (!server.rowCount) throw new Error("onboarding_identity_missing");
    const serverId = String(server.rows[0].id);
    await client.query(
      `insert into registration_revision(server_id,revision,state,manifest,manifest_digest,artifact_digest,evidence)
       values ($1,$2,'REGISTERED_DISABLED',$3,$4,$5,$6)`,
      [serverId, job.manifest.registrationRevision, job.manifest, job.manifestDigest, job.imageDigest,
        JSON.stringify({ sourceDigest: job.sourceDigest, sourceCommit: job.sourceCommit, buildId: job.buildId, imageReference: job.imageReference, imageDigest: job.imageDigest, sbomDigest: job.sbomDigest, provenanceDigest: job.provenanceDigest })]
    );
    await client.query("insert into function_statistics(server_id) values ($1) on conflict do nothing", [serverId]);
    await client.query(
      "insert into monitoring_profile(server_id,profile,enabled) values ($1,$2,false) on conflict (server_id) do update set profile=excluded.profile",
      [serverId, job.manifest.monitoringProfile]
    );
    await appendAudit(client, {
      eventType: "mcp_server.registered_disabled", actorType: "system", objectType: "mcp_server", objectId: serverId,
      after: { code: job.code, hostname: job.hostname, imageDigest: job.imageDigest, manifestDigest: job.manifestDigest }, correlationId
    });
    return serverId;
  });
}

export async function runPublicPreflight(db: Db, config: AppConfig, serverId: string, job: ActivationJob, correlationId: string): Promise<Record<string, unknown>> {
  const addresses = await dns.lookup(job.hostname, { all: true });
  if (!addresses.length) throw new Error("dns_resolution_failed");
  const certificate = await tlsCertificate(job.hostname);
  const metadata = await jsonRequest(`https://${job.hostname}/.well-known/oauth-protected-resource/mcp`, { method: "GET" });
  assertStatus(metadata.response, 200, "host_routing_failed");
  const body = metadata.body as { resource?: string; authorization_servers?: string[] };
  if (body.resource !== `https://${job.hostname}/mcp`) throw new Error("protected_resource_mismatch");
  if (!body.authorization_servers?.includes(`https://${config.AUTH_HOST}`)) throw new Error("authorization_server_mismatch");
  await db.query(
    `insert into runtime_log_event(server_id,level,event_name,fields,correlation_id,image_digest)
     values ($1,'info','onboarding.preflight',$2,$3,$4)`,
    [serverId, JSON.stringify({ hostname: job.hostname, addresses: addresses.map((item) => item.address), certificateFingerprint: certificate.fingerprint256 }), correlationId, job.imageDigest]
  );
  return { addresses: addresses.map((item) => item.address), certificate };
}

async function createSystemCredential(db: Db, serverId: string): Promise<{ id: string; publicId: string; secret: string }> {
  const secret = issueOpaqueSecret();
  const hash = await hashPasswordLikeSecret(secret.value);
  return tx(db, async (client) => {
    const number = await client.query("select nextval('kaja_number_seq') as number");
    const publicId = `Kaja${String(Number(number.rows[0].number)).padStart(4, "0")}`;
    const inserted = await client.query(
      `insert into kaja_credential(public_id,label,secret_hash,secret_fingerprint,expires_at)
       values ($1,'System onboarding trial',$2,$3,now()+interval '15 minutes') returning id`,
      [publicId, hash, secret.fingerprint]
    );
    const id = String(inserted.rows[0].id);
    await client.query("insert into kaja_permission(credential_id,server_id,access_level) values ($1,$2,'EXECUTE')", [id, serverId]);
    return { id, publicId, secret: secret.value };
  });
}

async function revokeSystemCredential(db: Db, credentialId: string): Promise<void> {
  await tx(db, async (client) => {
    await client.query("update access_token set revoked_at=coalesce(revoked_at,now()) where credential_id=$1", [credentialId]);
    await client.query("update kaja_permission set revoked_at=coalesce(revoked_at,now()) where credential_id=$1", [credentialId]);
    await client.query("update kaja_credential set active=false,revoked_at=coalesce(revoked_at,now()),deleted_at=coalesce(deleted_at,now()),revocation_epoch=gen_random_uuid() where id=$1", [credentialId]);
  });
}

async function setAuthorizedServerState(
  db: Db,
  jobId: string,
  serverId: string,
  registrationState: "TRIAL" | "ACTIVE",
  operationalState: "UNKNOWN" | "HEALTHY",
  correlationId: string,
  audit?: { code: string; hostname: string; imageDigest: string }
): Promise<void> {
  await tx(db, async (client) => {
    const authorization = await client.query(
      `select oj.id
         from onboarding_job oj
         join integration_token it on it.id=oj.token_id
        where oj.id=$1 and oj.server_id=$2 and oj.state='TRIAL_TESTING'
          and it.onboarding_job_id=oj.id and it.revoked_at is null and it.deleted_at is null
          and it.expires_at>now()
        for update of oj,it`,
      [jobId, serverId]
    );
    if (!authorization.rowCount) throw new Error("integration_token_inactive");
    const updated = await client.query(
      `update mcp_server
          set enabled=true,registration_state=$2,operational_state=$3,
              lock_version=lock_version+1,updated_at=now()
        where id=$1 returning id`,
      [serverId, registrationState, operationalState]
    );
    if (!updated.rowCount) throw new Error("trial_server_missing");
    if (audit) {
      await appendAudit(client, {
        eventType: "mcp_server.activated", actorType: "system", objectType: "mcp_server", objectId: serverId,
        after: { code: audit.code, hostname: audit.hostname, imageDigest: audit.imageDigest, gates: "PASS" }, correlationId
      });
    }
  });
}

async function rpc(hostname: string, token: string | null, method: string, params?: unknown) {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (token) headers.authorization = `Bearer ${token}`;
  return jsonRequest(`https://${hostname}/mcp`, {
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "2.0", id: randomUUID(), method, params })
  });
}

export async function runTrialAndActivate(db: Db, config: AppConfig, serverId: string, job: ActivationJob, correlationId: string): Promise<Record<string, unknown>> {
  await setAuthorizedServerState(db, job.id, serverId, "TRIAL", "UNKNOWN", correlationId);
  const credential = await createSystemCredential(db, serverId);
  let accessToken = "";
  try {
    const resource = `https://${job.hostname}/mcp`;
    const token = await jsonRequest(`https://${config.AUTH_HOST}/oauth/token`, {
      method: "POST",
      headers: {
        authorization: `Basic ${Buffer.from(`${encodeURIComponent(credential.publicId)}:${encodeURIComponent(credential.secret)}`).toString("base64")}`,
        "content-type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({ grant_type: "client_credentials", resource }).toString()
    });
    assertStatus(token.response, 200, "oauth_token_failed");
    accessToken = String((token.body as { access_token?: string }).access_token ?? "");
    if (!accessToken) throw new Error("oauth_token_missing");

    const wrongAudience = await jsonRequest(`https://${config.AUTH_HOST}/oauth/token`, {
      method: "POST",
      headers: {
        authorization: `Basic ${Buffer.from(`${encodeURIComponent(credential.publicId)}:${encodeURIComponent(credential.secret)}`).toString("base64")}`,
        "content-type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({ grant_type: "client_credentials", resource: `https://kcml999999.${config.PUBLIC_BASE_DOMAIN}/mcp` }).toString()
    });
    assertStatus(wrongAudience.response, 400, "audience_binding_failed");

    const missing = await rpc(job.hostname, null, "initialize");
    assertStatus(missing.response, 401, "missing_token_not_rejected");
    const invalid = await rpc(job.hostname, "invalid-token", "initialize");
    assertStatus(invalid.response, 401, "invalid_token_not_rejected");

    const initialize = await rpc(job.hostname, accessToken, "initialize");
    assertStatus(initialize.response, 200, "mcp_initialize_failed");
    const initialized = await rpc(job.hostname, accessToken, "notifications/initialized");
    assertStatus(initialized.response, 202, "mcp_initialized_notification_failed");
    const list = await rpc(job.hostname, accessToken, "tools/list");
    assertStatus(list.response, 200, "mcp_tools_list_failed");
    const toolNames = (((list.body as { result?: { tools?: Array<{ name?: string }> } }).result?.tools) ?? []).map((item) => item.name);
    if (!toolNames.includes(job.toolName) || toolNames.length !== 1) throw new Error("mcp_tool_catalog_mismatch");
    const wrongTool = await rpc(job.hostname, accessToken, "tools/call", { name: `${job.toolName}_wrong`, arguments: job.manifest.testContract.safeInput });
    if (!(wrongTool.body as { error?: { code?: number } }).error) throw new Error("cross_tool_not_rejected");
    const other = await db.query("select hostname from mcp_server where id<>$1 and enabled=true and registration_state in ('ACTIVE','TRIAL') order by created_at limit 1", [serverId]);
    const crossHostname = other.rowCount ? String(other.rows[0].hostname) : `kcml999999.${config.PUBLIC_BASE_DOMAIN}`;
    const crossHost = await rpc(crossHostname, accessToken, "initialize");
    if (crossHost.response.status !== (other.rowCount ? 401 : 404)) throw new Error(`cross_host_not_rejected:${crossHost.response.status}`);
    const call = await rpc(job.hostname, accessToken, "tools/call", { name: job.toolName, arguments: job.manifest.testContract.safeInput });
    assertStatus(call.response, 200, "safe_tool_call_failed");
    const structured = (call.body as { result?: { structuredContent?: unknown }; error?: unknown }).result?.structuredContent;
    if ((call.body as { error?: unknown }).error) throw new Error("safe_tool_call_returned_error");
    if (!matchesExpectedResult(structured, job.manifest.testContract.expectedResult)) throw new Error("safe_tool_result_mismatch");
    const invocationCorrelation = call.response.headers.get("x-correlation-id");
    if (!invocationCorrelation) throw new Error("correlation_header_missing");

    const evidence = await db.query(
      `select
         exists(select 1 from audit_event where correlation_id=$1 and event_type='mcp.invocation.completed') as audit_ok,
         exists(select 1 from runtime_log_event where correlation_id=$1 and event_name='mcp.invocation.completed') as log_ok,
         exists(select 1 from function_statistics where server_id=$2 and success_count>0) as stats_ok,
         not exists(select 1 from audit_event where object_id=$2::text and (coalesce(before_json::text,'')||coalesce(after_json::text,'')) like '%'||$3||'%') as audit_access_token_free,
         not exists(select 1 from runtime_log_event where server_id=$2 and fields::text like '%'||$3||'%') as log_access_token_free,
         not exists(select 1 from audit_event where object_id=$2::text and (coalesce(before_json::text,'')||coalesce(after_json::text,'')) like '%'||$4||'%') as audit_kaja_secret_free,
         not exists(select 1 from runtime_log_event where server_id=$2 and fields::text like '%'||$4||'%') as log_kaja_secret_free,
         not exists(select 1 from audit_event where object_id=$2 and (coalesce(before_json::text,'')||coalesce(after_json::text,'')) ~ 'kc[ie]_[A-Za-z0-9_-]{40,}') as audit_integration_egress_secret_free,
         not exists(select 1 from runtime_log_event where server_id=$2 and fields::text ~ 'kc[ie]_[A-Za-z0-9_-]{40,}') as log_integration_egress_secret_free`,
      [invocationCorrelation, serverId, accessToken, credential.secret]
    );
    const checks = evidence.rows[0] as Record<string, boolean>;
    if (!Object.values(checks).every(Boolean)) throw new Error("observability_evidence_failed");

    const probes = ["readiness", "tls", "oauth_mcp", "synthetic_call", "artifact_integrity"];
    for (const probe of probes) {
      await db.query(
        `insert into monitoring_probe_result(server_id,probe_type,status,evidence,correlation_id)
         values ($1,$2,'PASS',$3,$4)`,
        [serverId, probe, JSON.stringify({ onboardingJobId: job.id, imageDigest: job.imageDigest }), correlationId]
      );
    }
    await db.query(
      "update monitoring_profile set enabled=true where server_id=$1",
      [serverId]
    );
    await setAuthorizedServerState(db, job.id, serverId, "ACTIVE", "HEALTHY", correlationId, {
      code: job.code,
      hostname: job.hostname,
      imageDigest: job.imageDigest
    });
    return { invocationCorrelation, toolName: job.toolName, probes };
  } finally {
    await revokeSystemCredential(db, credential.id);
    accessToken = "";
  }
}

export async function runSyntheticMonitoringProbe(
  db: Db,
  config: AppConfig,
  server: { id: string; hostname: string; toolName: string },
  manifest: OnboardingManifest
): Promise<{ correlationId: string }> {
  const credential = await createSystemCredential(db, server.id);
  let accessToken = "";
  try {
    const resource = `https://${server.hostname}/mcp`;
    const token = await jsonRequest(`https://${config.AUTH_HOST}/oauth/token`, {
      method: "POST",
      headers: {
        authorization: `Basic ${Buffer.from(`${encodeURIComponent(credential.publicId)}:${encodeURIComponent(credential.secret)}`).toString("base64")}`,
        "content-type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({ grant_type: "client_credentials", resource }).toString()
    });
    assertStatus(token.response, 200, "monitor_oauth_failed");
    accessToken = String((token.body as { access_token?: string }).access_token ?? "");
    if (!accessToken) throw new Error("monitor_access_token_missing");
    const call = await rpc(server.hostname, accessToken, "tools/call", { name: server.toolName, arguments: manifest.testContract.safeInput });
    assertStatus(call.response, 200, "monitor_synthetic_call_failed");
    const output = (call.body as { result?: { structuredContent?: unknown }; error?: unknown }).result?.structuredContent;
    if ((call.body as { error?: unknown }).error || !matchesExpectedResult(output, manifest.testContract.expectedResult)) throw new Error("monitor_synthetic_result_mismatch");
    const correlationId = call.response.headers.get("x-correlation-id");
    if (!correlationId) throw new Error("monitor_correlation_missing");
    return { correlationId };
  } finally {
    await revokeSystemCredential(db, credential.id);
    accessToken = "";
  }
}

export async function disableAfterFailure(db: Db, serverId: string | null, quarantine: boolean, correlationId: string, reason: string): Promise<void> {
  if (!serverId) return;
  await tx(db, async (client) => {
    await client.query(
      `update mcp_server
          set enabled=false, registration_state=$2, operational_state=$3,
              revocation_epoch=gen_random_uuid(), lock_version=lock_version+1, updated_at=now()
        where id=$1`,
      [serverId, quarantine ? "QUARANTINED" : "TEST_FAILED", quarantine ? "QUARANTINED" : "DISABLED"]
    );
    await client.query("update access_token set revoked_at=coalesce(revoked_at,now()) where server_id=$1", [serverId]);
    await client.query("update monitoring_profile set enabled=false where server_id=$1", [serverId]);
    await appendAudit(client, {
      eventType: quarantine ? "mcp_server.quarantined" : "mcp_server.test_failed", actorType: "system",
      objectType: "mcp_server", objectId: serverId, after: { reason }, correlationId
    });
  });
}
