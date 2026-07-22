import http from "node:http";
import { createHash } from "node:crypto";
import { Ajv2020 } from "ajv/dist/2020.js";
import type { FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import type { AppServerConfig } from "../config.js";
import type { Db } from "../db.js";
import { tx } from "../db.js";
import { appendAudit } from "../domain/audit.js";
import { authorizeComponentCall } from "../domain/component-auth.js";
import { fetchThroughEgress } from "../domain/egress-client.js";
import { KCML_RELEASE } from "../domain/release.js";
import { jsonRpcError, jsonRpcResult, respondToJsonRpc, sendJsonRpc } from "./json-rpc.js";

const rpcSchema = z.object({
  jsonrpc: z.literal("2.0"),
  id: z.union([z.string(), z.number().finite(), z.null()]).optional(),
  method: z.string().min(1),
  params: z.unknown().optional()
}).strict();
const callSchema = z.object({ name: z.string().min(1), arguments: z.unknown().optional() }).strict();
const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: false });

type RuntimeComponent = {
  id: string;
  code: string;
  hostname: string;
  enabled: boolean;
  ingressEnabled: boolean;
  lifecycleState: string;
  activationState: string;
  operationalState: string;
  activeRevisionId: string;
  revision: string;
};

type ToolContract = {
  name: string;
  title: string;
  description: string;
  inputSchema: Record<string, unknown>;
  outputSchema: Record<string, unknown>;
  annotations: Record<string, unknown>;
  scopeName: string;
  timeoutMs: number;
  limits: Record<string, unknown>;
};

function sha256(value: string | Buffer): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function bearer(request: FastifyRequest): string | null {
  const value = request.headers.authorization;
  return value?.startsWith("Bearer ") ? value.slice("Bearer ".length) : null;
}

export async function canonicalMcpComponent(db: Db, hostname: string): Promise<RuntimeComponent | null> {
  const result = await db.query(
    `select c.id,c.code,c.hostname,c.enabled,c.ingress_enabled,c.lifecycle_state,c.activation_state,c.operational_state,
            c.active_revision_id,r.revision
       from component c
       join component_revision r on r.id=c.active_revision_id and r.component_id=c.id
      where lower(c.hostname::text)=lower($1)`,
    [hostname]
  );
  if (!result.rowCount) return null;
  const row = result.rows[0];
  return {
    id: String(row.id), code: String(row.code), hostname: String(row.hostname), enabled: Boolean(row.enabled),
    ingressEnabled: Boolean(row.ingress_enabled), lifecycleState: String(row.lifecycle_state),
    activationState: String(row.activation_state), operationalState: String(row.operational_state),
    activeRevisionId: String(row.active_revision_id), revision: String(row.revision)
  };
}

async function toolsForComponent(db: Db, component: RuntimeComponent): Promise<ToolContract[]> {
  const result = await db.query(
    `select name,title,description,input_schema,output_schema,annotations,scope_name,timeout_ms,limits
       from component_tool_contract
      where component_id=$1 and revision_id=$2 order by name`,
    [component.id, component.activeRevisionId]
  );
  return result.rows.map((row) => ({
    name: String(row.name), title: String(row.title), description: String(row.description),
    inputSchema: row.input_schema as Record<string, unknown>, outputSchema: row.output_schema as Record<string, unknown>,
    annotations: row.annotations as Record<string, unknown>, scopeName: String(row.scope_name),
    timeoutMs: Number(row.timeout_ms), limits: row.limits as Record<string, unknown>
  }));
}

function maxBytes(limits: Record<string, unknown>, key: string, fallback: number): number {
  const value = Number(limits[key]);
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

async function udsDispatch(socketPath: string, payload: Buffer, token: string, timeoutMs: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const request = http.request({
      socketPath, path: "/v1/kcml/runtime/tools/call", method: "POST", timeout: timeoutMs,
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json", "content-length": payload.length }
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
      response.on("error", reject);
      response.on("end", () => {
        const body = Buffer.concat(chunks);
        if (!response.statusCode || response.statusCode < 200 || response.statusCode >= 300) {
          reject(Object.assign(new Error("runtime_rejected"), { statusCode: response.statusCode ?? 502, responseBody: body }));
          return;
        }
        resolve(body);
      });
    });
    request.on("timeout", () => request.destroy(new Error("runtime_timeout")));
    request.on("error", reject);
    request.end(payload);
  });
}

async function dispatch(db: Db, config: AppServerConfig, component: RuntimeComponent, tool: ToolContract, args: unknown, token: string, correlationId: string, decisionId: string): Promise<unknown> {
  const target = await db.query(
    `select transport,upstream,expected_tls_identity,socket_path,status
       from component_runtime_target where component_id=$1 and revision_id=$2`,
    [component.id, component.activeRevisionId]
  );
  if (!target.rowCount || target.rows[0].status === "DISABLED") throw Object.assign(new Error("runtime_target_unavailable"), { statusCode: 503 });
  const payload = Buffer.from(JSON.stringify({
    operation: "tools/call", tool: tool.name, arguments: args ?? {},
    authorization: { authority: "KCML", decisionId, correlationId, targetComponent: component.code }
  }));
  if (payload.length > maxBytes(tool.limits, "requestMaxBytes", 1_048_576)) throw Object.assign(new Error("request_too_large"), { statusCode: 413 });
  let response: Buffer;
  if (target.rows[0].transport === "UDS") {
    response = await udsDispatch(String(target.rows[0].socket_path), payload, token, tool.timeoutMs);
  } else {
    const upstream = new URL(String(target.rows[0].upstream));
    if (upstream.protocol !== "https:" || upstream.hostname !== String(target.rows[0].expected_tls_identity)) {
      throw Object.assign(new Error("runtime_tls_identity_invalid"), { statusCode: 503 });
    }
    const fetched = await fetchThroughEgress(config, {
      url: new URL("/v1/kcml/runtime/tools/call", upstream).toString(), method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: payload,
      allowlist: [upstream.hostname], purpose: "component.runtime.tool", correlationId,
      ttlSeconds: Math.max(15, Math.ceil(tool.timeoutMs / 1000) + 5)
    });
    if (fetched.status < 200 || fetched.status >= 300) throw Object.assign(new Error("runtime_rejected"), { statusCode: fetched.status });
    response = fetched.body;
  }
  if (response.length > maxBytes(tool.limits, "responseMaxBytes", 5_242_880)) throw Object.assign(new Error("response_too_large"), { statusCode: 502 });
  const parsed = JSON.parse(response.toString("utf8")) as Record<string, unknown>;
  return Object.hasOwn(parsed, "result") ? parsed.result : parsed;
}

export async function handleCanonicalMcp(request: FastifyRequest, reply: FastifyReply, db: Db, config: AppServerConfig, component: RuntimeComponent, correlationId: string): Promise<FastifyReply> {
  if (Array.isArray(request.body)) return sendJsonRpc(reply, jsonRpcError(null, -32600, "Batch requests are not supported", correlationId));
  const parsed = rpcSchema.safeParse(request.body);
  if (!parsed.success) return sendJsonRpc(reply, jsonRpcError(null, -32600, "Invalid Request", correlationId));
  const body = parsed.data;
  const token = bearer(request);
  if (!token) return reply.code(401).header("www-authenticate", "Bearer").send({ code: "invalid_token", correlationId });
  const scope = body.method === "initialize" ? "mcp.initialize"
    : body.method === "notifications/initialized" ? "mcp.notifications.initialized"
      : body.method === "tools/list" ? "mcp.tools.list" : "mcp.tools.call";
  const route = body.method === "tools/call" && callSchema.safeParse(body.params).success
    ? `/mcp/tools/${callSchema.parse(body.params).name}` : "/mcp";
  const decision = await authorizeComponentCall(db, {
    token, audience: `https://${component.hostname}`, host: component.hostname, scope, route,
    hmacKey: config.ACCESS_TOKEN_HMAC_KEY_BASE64, correlationId
  });
  if (!decision.allow) return reply.code(decision.reasonCode === "invalid_token" || decision.reasonCode === "expired_token" || decision.reasonCode === "revoked_token" ? 401 : 403)
    .send({ code: decision.reasonCode, correlationId, decisionId: decision.decisionId });
  const respond = (payload: ReturnType<typeof jsonRpcResult> | ReturnType<typeof jsonRpcError>) => respondToJsonRpc(reply, body.id, payload);
  if (body.method === "initialize") return respond(jsonRpcResult(body.id, {
    protocolVersion: KCML_RELEASE.mcpProtocolVersion, capabilities: { tools: {} }, serverInfo: { name: component.code, version: component.revision }
  }));
  if (body.method === "notifications/initialized") return reply.code(202).send();
  const tools = await toolsForComponent(db, component);
  if (body.method === "tools/list") return respond(jsonRpcResult(body.id, {
    tools: tools.map((tool) => ({ name: tool.name, title: tool.title, description: tool.description, inputSchema: tool.inputSchema, outputSchema: tool.outputSchema, annotations: tool.annotations }))
  }));
  if (body.method !== "tools/call") return respond(jsonRpcError(body.id, -32601, "Method not found", correlationId));
  const call = callSchema.safeParse(body.params);
  if (!call.success) return respond(jsonRpcError(body.id, -32602, "Invalid params", correlationId));
  const tool = tools.find((candidate) => candidate.name === call.data.name);
  if (!tool) return respond(jsonRpcError(body.id, -32602, "Unknown tool", correlationId));
  const validateInput = ajv.compile(tool.inputSchema);
  if (!validateInput(call.data.arguments ?? {})) return respond(jsonRpcError(body.id, -32602, "Input schema validation failed", correlationId, { issues: validateInput.errors ?? [] }));
  const inputJson = JSON.stringify(call.data.arguments ?? {});
  let lease: string;
  try {
    lease = await tx(db, async (client) => {
    await client.query("select pg_advisory_xact_lock(hashtextextended($1,0))", [`${component.id}:${tool.name}`]);
    await client.query(
      `update component_operation_lease set success=false,finished_at=coalesce(finished_at,now()),process_trace=jsonb_build_object('error','operation_deadline_expired')
        where target_component_id=$1 and operation_kind='TOOL' and operation_name=$2 and finished_at is null and expires_at<=now()`,
      [component.id, tool.name]
    );
    const capacity = await client.query(
      `select coalesce((runtime_resources->>'maxConcurrency')::int,1) max_concurrency,
              (select count(*)::int from component_operation_lease lease
                where lease.target_component_id=$1 and lease.operation_kind='TOOL' and lease.operation_name=$2
                  and lease.finished_at is null and lease.expires_at>now()) active_count
         from component_runtime_target where component_id=$1 and revision_id=$3`,
      [component.id, tool.name, component.activeRevisionId]
    );
    const maxConcurrency = Math.max(1, Number(capacity.rows[0]?.max_concurrency ?? 1));
    if (Number(capacity.rows[0]?.active_count ?? 0) >= maxConcurrency) throw Object.assign(new Error("operation_concurrency_exceeded"), { statusCode: 429 });
    const inserted = await client.query(
      `insert into component_operation_lease(
        source_principal_id,target_component_id,operation_kind,operation_name,input_payload,input_digest,
        expires_at,correlation_id,token_fingerprint,permission_epoch
      ) select source.principal_id,$2,'TOOL',$3,$4::jsonb,
               'sha256:'||encode(sha256(convert_to(($4::jsonb)::text,'utf8')),'hex'),
               now()+($5||' milliseconds')::interval,$6,$7,$8
          from component source where source.id=$1 returning id`,
      [decision.sourceComponentId, component.id, tool.name, inputJson, tool.timeoutMs, correlationId, decision.tokenFingerprint, decision.policyEpoch]
    );
    if (!inserted.rowCount) throw Object.assign(new Error("source_principal_unavailable"), { statusCode: 403 });
    await appendAudit(client, { eventType: "component.operation.started", actorType: "component", actorId: decision.sourceComponentId,
      objectType: "component_operation_lease", objectId: String(inserted.rows[0].id), after: { targetComponentId: component.id, tool: tool.name, inputDigest: sha256(inputJson), decisionId: decision.decisionId }, correlationId });
    return String(inserted.rows[0].id);
    });
  } catch (error) {
    if (error instanceof Error && error.message === "operation_concurrency_exceeded") {
      return respond(jsonRpcError(body.id, -32004, "Component concurrency limit exceeded", correlationId, { retryable: true }));
    }
    throw error;
  }
  try {
    const output = await dispatch(db, config, component, tool, call.data.arguments ?? {}, token, correlationId, decision.decisionId);
    const validateOutput = ajv.compile(tool.outputSchema);
    if (!validateOutput(output)) throw Object.assign(new Error("output_schema_invalid"), { statusCode: 502, issues: validateOutput.errors });
    const outputJson = JSON.stringify(output);
    await tx(db, async (client) => {
      await client.query(
        `update component_operation_lease set output_payload=$2::jsonb,
          output_digest='sha256:'||encode(sha256(convert_to(($2::jsonb)::text,'utf8')),'hex'),success=true,finished_at=now() where id=$1`,
        [lease, outputJson]
      );
      await appendAudit(client, { eventType: "component.operation.succeeded", actorType: "component", actorId: decision.sourceComponentId,
        objectType: "component_operation_lease", objectId: lease, after: { outputDigest: sha256(outputJson), tool: tool.name }, correlationId });
    });
    return respond(jsonRpcResult(body.id, { structuredContent: output, content: [{ type: "text", text: outputJson }], isError: false }));
  } catch (error) {
    await tx(db, async (client) => {
      await client.query("update component_operation_lease set success=false,finished_at=now(),process_trace=$2::jsonb where id=$1", [lease, JSON.stringify({ error: error instanceof Error ? error.message : "runtime_failed" })]);
      await appendAudit(client, { eventType: "component.operation.failed", actorType: "component", actorId: decision.sourceComponentId,
        objectType: "component_operation_lease", objectId: lease, after: { errorCode: error instanceof Error ? error.message : "runtime_failed", tool: tool.name }, correlationId });
    });
    return respond(jsonRpcError(body.id, -32603, "Runtime operation failed", correlationId, { code: error instanceof Error ? error.message.toUpperCase() : "RUNTIME_FAILED" }));
  }
}
