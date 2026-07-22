import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { lookup } from "node:dns/promises";
import { request as httpsRequest } from "node:https";
import type { Db } from "../db.js";
import { tx } from "../db.js";
import { hmacToken, issueOpaqueSecret } from "../security/secrets.js";
import { appendAudit } from "./audit.js";

type JsonRecord = Record<string, unknown>;
const privateIpv4 = /^(10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|0\.)/;

function fail(code: string, statusCode: number): never {
  throw Object.assign(new Error(code), { statusCode });
}

function canonicalTargetUrl(value: string): URL {
  let url: URL;
  try { url = new URL(value); } catch { return fail("external_target_url_invalid", 400); }
  if (url.protocol !== "https:" || url.username || url.password || url.hash || url.search || url.port || url.hostname.endsWith(".")) {
    return fail("external_target_url_invalid", 400);
  }
  if (url.pathname !== "/" && url.pathname.endsWith("/")) url.pathname = url.pathname.slice(0, -1);
  return url;
}

function forbiddenIp(address: string): boolean {
  address = address.replace(/^\[|\]$/g, "");
  if (isIP(address) === 4) return privateIpv4.test(address);
  const normalized = address.toLowerCase();
  return normalized === "::1" || normalized.startsWith("fe80:") || normalized.startsWith("fc") || normalized.startsWith("fd") || normalized === "::";
}

export async function assertSafeExternalTarget(urlValue: string): Promise<URL> {
  const url = canonicalTargetUrl(urlValue);
  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  if (isIP(hostname) && forbiddenIp(hostname)) fail("external_target_ssrf_denied", 400);
  if (!isIP(hostname)) {
    let addresses: { address: string }[];
    try { addresses = await lookup(hostname, { all: true, verbatim: true }); } catch { fail("external_target_dns_unresolved", 400); }
    if (!addresses.length || addresses.some(({ address }) => forbiddenIp(address))) fail("external_target_ssrf_denied", 400);
  }
  return url;
}

async function pinnedHttpsPost(url: URL, body: string, headers: Record<string, string>, timeoutMs: number): Promise<{ status: number; body: string }> {
  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  const addresses = isIP(hostname) ? [{ address: hostname, family: isIP(hostname) }] : await lookup(hostname, { all: true, verbatim: true });
  if (!addresses.length || addresses.some(({ address }) => forbiddenIp(address))) fail("external_target_ssrf_denied", 400);
  const pinned = addresses[0]!;
  return new Promise((resolve, reject) => {
    const request = httpsRequest({ protocol: "https:", hostname, servername: hostname, port: 443, method: "POST", path: `${url.pathname}${url.search}`, headers: { ...headers, "content-length": Buffer.byteLength(body) }, rejectUnauthorized: true, timeout: timeoutMs, lookup: (_hostname, _options, callback) => callback(null, pinned.address, pinned.family) }, (response) => {
      const chunks: Buffer[] = [];
      let size = 0;
      response.on("data", (chunk: Buffer) => { size += chunk.length; if (size > 4 * 1024 * 1024) request.destroy(new Error("external_gateway_response_too_large")); else chunks.push(chunk); });
      response.on("end", () => resolve({ status: response.statusCode ?? 502, body: Buffer.concat(chunks).toString("utf8") }));
    });
    request.on("timeout", () => request.destroy(new Error("external_gateway_timeout")));
    request.on("error", reject);
    request.end(body);
  });
}

function principalView(row: Record<string, unknown>): JsonRecord {
  return { id: String(row.id), publicId: String(row.public_id), displayName: String(row.display_name), description: String(row.description), status: String(row.status), createdAt: String(row.created_at), revokedAt: row.revoked_at instanceof Date ? row.revoked_at.toISOString() : null, accessTokenCount: Number(row.access_token_count ?? 0) };
}
function targetView(row: Record<string, unknown>): JsonRecord {
  return { id: String(row.id), targetKey: String(row.target_key), displayName: String(row.display_name), baseUrl: String(row.base_url), auditRequired: Boolean(row.audit_required), allowedPathPrefixes: row.allowed_path_prefixes ?? ["/"], connectTimeoutMs: Number(row.connect_timeout_ms), requestTimeoutMs: Number(row.request_timeout_ms), maxRetries: Number(row.max_retries), circuitState: String(row.circuit_state), circuitFailureCount: Number(row.circuit_failure_count), circuitFailureThreshold: Number(row.circuit_failure_threshold), circuitOpenSeconds: Number(row.circuit_open_seconds), status: String(row.status), createdAt: String(row.created_at), revokedAt: row.revoked_at instanceof Date ? row.revoked_at.toISOString() : null };
}

function circuitCooldownActive(row: Record<string, unknown>): boolean {
  const openedAt = row.circuit_opened_at instanceof Date ? row.circuit_opened_at.getTime() : typeof row.circuit_opened_at === "string" ? Date.parse(row.circuit_opened_at) : Date.now();
  return (Date.now() - openedAt) / 1000 < Number(row.circuit_open_seconds);
}

export async function listExternalPrincipals(db: Db): Promise<JsonRecord[]> {
  const result = await db.query(`select external.*, (select count(*)::int from principal_access_token token where token.source_principal_id=external.principal_id and token.revoked_at is null) access_token_count from component_external_principal external order by external.created_at desc`);
  return result.rows.map(principalView);
}
export async function listExternalTargets(db: Db): Promise<JsonRecord[]> {
  const result = await db.query("select * from component_external_target order by created_at desc");
  return result.rows.map(targetView);
}
export async function listExternalPermissions(db: Db): Promise<JsonRecord[]> {
  const result = await db.query(`select permission.*, target.target_key, target.display_name as target_display_name, component.code as component_code, principal.public_id as external_principal_public_id from component_external_permission permission join component_external_target target on target.id=permission.external_target_id left join component on component.id=permission.component_id left join component_external_principal principal on principal.id=permission.external_principal_id order by permission.granted_at desc`);
  return result.rows.map((row: Record<string, unknown>) => ({ ...row }));
}
export async function listExternalInboundPermissions(db: Db): Promise<JsonRecord[]> {
  const result = await db.query(`
    select permission.id,external.id as external_principal_id,external.public_id as external_principal_public_id,
           component.id as target_component_id,component.code as target_component_code,
           permission.route_pattern,permission.scope_name,permission.granted_at,permission.revoked_at
      from principal_component_permission permission
      join component_external_principal external on external.principal_id=permission.source_principal_id
      join component on component.id=permission.target_component_id
     order by permission.granted_at desc`);
  return result.rows.map((row: Record<string, unknown>) => ({ ...row }));
}

export async function createExternalPrincipal(db: Db, params: { publicId: string; displayName: string; description?: string; actorId: string; correlationId: string }): Promise<JsonRecord> {
  return tx(db, async (client) => {
    const canonical = await client.query("insert into principal(kind,public_id,status,metadata) values ('EXTERNAL',$1,'ACTIVE',$2::jsonb) returning id", [params.publicId, JSON.stringify({ displayName: params.displayName })]);
    const created = await client.query(`insert into component_external_principal(principal_id,public_id,display_name,description) values ($1,$2,$3,$4) returning *`, [canonical.rows[0].id, params.publicId, params.displayName, params.description ?? ""]);
    await appendAudit(client, { eventType: "external_principal.created", actorType: "admin", actorId: params.actorId, objectType: "component_external_principal", objectId: String(created.rows[0].id), after: { publicId: params.publicId }, correlationId: params.correlationId });
    return principalView(created.rows[0]);
  });
}
export async function createExternalTarget(db: Db, params: { targetKey: string; displayName: string; baseUrl: string; allowedPathPrefixes?: string[]; requestTimeoutMs: number; maxRetries: number; circuitFailureThreshold: number; circuitOpenSeconds: number; actorId: string; correlationId: string }): Promise<JsonRecord> {
  const baseUrl = (await assertSafeExternalTarget(params.baseUrl)).toString().replace(/\/$/, "");
  const prefixes = (params.allowedPathPrefixes?.length ? params.allowedPathPrefixes : ["/"]).map((prefix) => prefix.startsWith("/") && !prefix.includes("//") ? prefix : fail("external_target_path_invalid", 400));
  return tx(db, async (client) => {
    const created = await client.query(`insert into component_external_target(target_key,display_name,base_url,allowed_path_prefixes,request_timeout_ms,max_retries,circuit_failure_threshold,circuit_open_seconds) values ($1,$2,$3,$4::text[],$5,$6,$7,$8) returning *`, [params.targetKey, params.displayName, baseUrl, prefixes, params.requestTimeoutMs, params.maxRetries, params.circuitFailureThreshold, params.circuitOpenSeconds]);
    await appendAudit(client, { eventType: "external_target.created", actorType: "admin", actorId: params.actorId, objectType: "component_external_target", objectId: String(created.rows[0].id), after: { targetKey: params.targetKey, baseUrl, prefixes }, correlationId: params.correlationId });
    return targetView(created.rows[0]);
  });
}
export async function setExternalEntityStatus(db: Db, params: { kind: "principal" | "target"; id: string; status: "ACTIVE" | "DISABLED" | "REVOKED"; actorId: string; correlationId: string }): Promise<JsonRecord> {
  const table = params.kind === "principal" ? "component_external_principal" : "component_external_target";
  return tx(db, async (client) => {
    const result = await client.query(`update ${table} set status=$2, revoked_at=case when $2='REVOKED' then now() else null end where id=$1 returning *`, [params.id, params.status]);
    if (!result.rowCount) fail("not_found", 404);
    if (params.kind === "principal") {
      await client.query(`update principal set status=$2,policy_epoch=policy_epoch+1,revocation_epoch=case when $2='ACTIVE' then revocation_epoch else revocation_epoch+1 end,updated_at=now()
        where id=(select principal_id from component_external_principal where id=$1)`, [params.id, params.status === "ACTIVE" ? "ACTIVE" : params.status === "REVOKED" ? "REVOKED" : "SUSPENDED"]);
      if (params.status !== "ACTIVE") await client.query("update principal_access_token set revoked_at=coalesce(revoked_at,now()) where source_principal_id=(select principal_id from component_external_principal where id=$1)", [params.id]);
    }
    await appendAudit(client, { eventType: `external_${params.kind}.status_changed`, actorType: "admin", actorId: params.actorId, objectType: table, objectId: params.id, after: { status: params.status }, correlationId: params.correlationId });
    return params.kind === "principal" ? principalView(result.rows[0]) : targetView(result.rows[0]);
  });
}
export async function rotateExternalPrincipalAccessToken(db: Db, params: { principalId: string; actorId: string; hmacKey: Buffer; hmacKeyId: string; correlationId: string }): Promise<{ principal: JsonRecord; accessToken: JsonRecord }> {
  return tx(db, async (client) => {
    const principal = await client.query("select * from component_external_principal where id=$1 for update", [params.principalId]);
    if (!principal.rowCount) fail("not_found", 404);
    if (principal.rows[0].status !== "ACTIVE") fail("external_principal_inactive", 409);
    await client.query("update principal_access_token set revoked_at=coalesce(revoked_at,now()),rotated_at=now(),rotation_reason='ADMIN_ROTATE' where source_principal_id=$1 and revoked_at is null", [principal.rows[0].principal_id]);
    const secret = issueOpaqueSecret();
    const scopes = await client.query("select distinct scope_name from principal_component_permission where source_principal_id=$1 and revoked_at is null order by scope_name", [principal.rows[0].principal_id]);
    const canonical = await client.query("select policy_epoch,revocation_epoch from principal where id=$1 for update", [principal.rows[0].principal_id]);
    await client.query(`insert into principal_access_token(lookup_digest,key_id,fingerprint,source_principal_id,target_component_id,audience,scope_names,issued_policy_epoch,issued_revocation_epoch,expires_at)
      values ($1,$2,$3,$4,null,'*',$5::text[],$6,$7,'infinity')`, [hmacToken(secret.value, params.hmacKey), params.hmacKeyId, secret.fingerprint, principal.rows[0].principal_id,
      scopes.rows.map((row) => String(row.scope_name)), canonical.rows[0].policy_epoch, canonical.rows[0].revocation_epoch]);
    await appendAudit(client, { eventType: "external_principal.access_token_rotated", actorType: "admin", actorId: params.actorId, objectType: "component_external_principal", objectId: params.principalId, after: { fingerprint: secret.fingerprint, expiresAt: "infinity" }, correlationId: params.correlationId });
    return { principal: principalView(principal.rows[0]), accessToken: { token: secret.value, fingerprint: secret.fingerprint } };
  });
}

export async function setExternalInboundPermission(db: Db, params: { externalPrincipalId: string; targetComponentId: string; routePattern: string; scopeName: string; enabled: boolean; actorId: string; correlationId: string }): Promise<void> {
  return tx(db, async (client) => {
    const principal = await client.query("select principal_id from component_external_principal where id=$1 for update", [params.externalPrincipalId]);
    if (!principal.rowCount) fail("not_found", 404);
    const existing = await client.query("select id from principal_component_permission where source_principal_id=$1 and target_component_id=$2 and route_pattern=$3 and scope_name=$4 for update",
      [principal.rows[0].principal_id, params.targetComponentId, params.routePattern, params.scopeName]);
    if (existing.rowCount) await client.query("update principal_component_permission set revoked_at=case when $2 then null else now() end where id=$1", [existing.rows[0].id, params.enabled]);
    else if (params.enabled) await client.query("insert into principal_component_permission(source_principal_id,target_component_id,route_pattern,scope_name) values ($1,$2,$3,$4)",
      [principal.rows[0].principal_id, params.targetComponentId, params.routePattern, params.scopeName]);
    await client.query("update principal set policy_epoch=policy_epoch+1 where id=$1", [principal.rows[0].principal_id]);
    await appendAudit(client, { eventType: "external_principal.component_permission_changed", actorType: "admin", actorId: params.actorId,
      objectType: "component", objectId: params.targetComponentId, after: { externalPrincipalId: params.externalPrincipalId, routePattern: params.routePattern, scopeName: params.scopeName, enabled: params.enabled }, correlationId: params.correlationId });
  });
}
export async function setExternalPermission(db: Db, params: { componentId?: string; externalPrincipalId?: string; externalTargetId: string; routePattern: string; scopeName: string; enabled: boolean; actorId: string; correlationId: string }): Promise<void> {
  if (!params.componentId && !params.externalPrincipalId) fail("external_permission_subject_required", 400);
  if (params.componentId && params.externalPrincipalId) fail("external_permission_subject_ambiguous", 400);
  return tx(db, async (client) => {
    const existing = await client.query(`select id from component_external_permission where component_id is not distinct from $1::uuid and external_principal_id is not distinct from $2::uuid and external_target_id=$3 and route_pattern=$4 and scope_name=$5 for update`, [params.componentId ?? null, params.externalPrincipalId ?? null, params.externalTargetId, params.routePattern, params.scopeName]);
    if (existing.rowCount) await client.query("update component_external_permission set revoked_at=case when $2 then null else now() end where id=$1", [existing.rows[0].id, params.enabled]);
    else if (params.enabled) await client.query(`insert into component_external_permission(component_id,external_principal_id,external_target_id,route_pattern,scope_name) values ($1,$2,$3,$4,$5)`, [params.componentId ?? null, params.externalPrincipalId ?? null, params.externalTargetId, params.routePattern, params.scopeName]);
    await appendAudit(client, { eventType: "external_permission.changed", actorType: "admin", actorId: params.actorId, objectType: "component_external_target", objectId: params.externalTargetId, after: { componentId: params.componentId ?? null, externalPrincipalId: params.externalPrincipalId ?? null, routePattern: params.routePattern, scopeName: params.scopeName, enabled: params.enabled }, correlationId: params.correlationId });
  });
}

export async function dispatchExternalComponentCall(db: Db, params: { sourceComponentId: string; targetKey: string; routePath: string; scopeName: string; payload: unknown; correlationId: string; accessToken: string; tokenFingerprint: string }): Promise<JsonRecord> {
  const targetResult = await db.query("select * from component_external_target where target_key=$1 and status='ACTIVE'", [params.targetKey]);
  if (!targetResult.rowCount) fail("external_target_not_available", 404);
  let target = targetResult.rows[0] as Record<string, unknown>;
  if (target.circuit_state === "OPEN" && circuitCooldownActive(target)) fail("external_gateway_circuit_open", 503);
  const permission = await db.query(`select id from component_external_permission where component_id=$1 and external_target_id=$2 and scope_name=$3 and revoked_at is null and ($4=route_pattern or (right(route_pattern,2)='/*' and $4 like left(route_pattern,length(route_pattern)-1)||'%'))`, [params.sourceComponentId, target.id, params.scopeName, params.routePath]);
  if (!permission.rowCount) fail("external_route_denied", 403);
  const baseUrl = await assertSafeExternalTarget(String(target.base_url));
  if (!(target.allowed_path_prefixes as string[]).some((prefix) => params.routePath.startsWith(prefix))) fail("external_route_denied", 403);
  const url = new URL(params.routePath, baseUrl);
  if (url.origin !== baseUrl.origin) fail("external_target_ssrf_denied", 400);

  target = await tx(db, async (client) => {
    const result = await client.query("select * from component_external_target where id=$1 and status='ACTIVE' for update", [target.id]);
    if (!result.rowCount) fail("external_target_not_available", 404);
    const row = result.rows[0] as Record<string, unknown>;
    if (row.circuit_state === "OPEN") {
      if (circuitCooldownActive(row)) fail("external_gateway_circuit_open", 503);
      await client.query("update component_external_target set circuit_state='HALF_OPEN',circuit_probe_in_flight=true where id=$1", [row.id]);
      row.circuit_state = "HALF_OPEN";
    } else if (row.circuit_state === "HALF_OPEN") {
      if (row.circuit_probe_in_flight) fail("external_gateway_circuit_open", 503);
      await client.query("update component_external_target set circuit_probe_in_flight=true where id=$1", [row.id]);
    }
    return row;
  });
  const requestDigest = `sha256:${createHash("sha256").update(JSON.stringify(params.payload)).digest("hex")}`;
  let call;
  try {
    call = await tx(db, async (client) => {
      const created = await client.query(`insert into component_external_gateway_call(source_component_id,external_target_id,external_permission_id,route_path,scope_name,correlation_id,request_digest,request_payload,status,attempt_count) values ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,'PENDING',1) returning id`, [params.sourceComponentId, target.id, permission.rows[0].id, params.routePath, params.scopeName, params.correlationId, requestDigest, JSON.stringify(params.payload)]);
      await appendAudit(client, { eventType: "component.external_gateway.authorized", actorType: "component", actorId: params.sourceComponentId, objectType: "component_external_target", objectId: String(target.id), after: { callId: created.rows[0].id, audience: baseUrl.origin, scopeName: params.scopeName, tokenFingerprint: params.tokenFingerprint }, correlationId: params.correlationId });
      return created;
    });
  } catch (error) {
    await db.query("update component_external_target set circuit_probe_in_flight=false where id=$1 and circuit_state='HALF_OPEN'", [target.id]);
    throw error;
  }
  let response: { status: number; body: string } | undefined;
  const attempts = Number(target.max_retries) + 1;
  let attemptsUsed = 0;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    attemptsUsed = attempt;
    try {
      response = await pinnedHttpsPost(url, JSON.stringify(params.payload), { "authorization": `Bearer ${params.accessToken}`, "content-type": "application/json", "x-kcml-correlation-id": params.correlationId, "x-kcml-access-token-fingerprint": params.tokenFingerprint }, Number(target.request_timeout_ms));
      if (response.status < 500 || attempt === attempts) break;
    } catch {
      if (attempt === attempts) break;
    }
  }
  if (!response) {
    await tx(db, async (client) => {
      await client.query("update component_external_gateway_call set status='FAILED',error_code='external_gateway_unreachable',attempt_count=$2,completed_at=now() where id=$1", [call.rows[0].id, attemptsUsed]);
      await client.query(`update component_external_target set circuit_failure_count=circuit_failure_count+1,circuit_state=case when circuit_failure_count+1>=circuit_failure_threshold then 'OPEN' else circuit_state end,circuit_opened_at=case when circuit_failure_count+1>=circuit_failure_threshold then now() else circuit_opened_at end,circuit_probe_in_flight=false where id=$1`, [target.id]);
    });
    fail("external_gateway_unreachable", 502);
  }
  const bodyText = response.body;
  let responsePayload: unknown = bodyText;
  try { responsePayload = JSON.parse(bodyText); } catch { /* audit raw text safely as a JSON string */ }
  const responseDigest = `sha256:${createHash("sha256").update(bodyText).digest("hex")}`;
  await tx(db, async (client) => {
    const succeeded = response.status >= 200 && response.status < 300;
    const circuitHealthy = response.status < 500;
    await client.query("update component_external_gateway_call set status=$2,http_status=$3,response_digest=$4,response_payload=$5::jsonb,attempt_count=$6,completed_at=now() where id=$1", [call.rows[0].id, succeeded ? "SUCCEEDED" : "FAILED", response.status, responseDigest, JSON.stringify(responsePayload), attemptsUsed]);
    await client.query(`update component_external_target set circuit_failure_count=case when $2 then 0 else circuit_failure_count+1 end,circuit_state=case when $2 then 'CLOSED' when circuit_failure_count+1>=circuit_failure_threshold then 'OPEN' else circuit_state end,circuit_opened_at=case when $2 then null when circuit_failure_count+1>=circuit_failure_threshold then now() else circuit_opened_at end,circuit_probe_in_flight=false where id=$1`, [target.id, circuitHealthy]);
    await appendAudit(client, { eventType: "component.external_gateway.completed", actorType: "component", actorId: params.sourceComponentId, objectType: "component_external_target", objectId: String(target.id), after: { callId: call.rows[0].id, routePath: params.routePath, scopeName: params.scopeName, status: response.status, requestDigest, responseDigest, attempts: attemptsUsed }, correlationId: params.correlationId });
  });
  return { accepted: response.status >= 200 && response.status < 300, statusCode: response.status, response: responsePayload, correlationId: params.correlationId };
}
