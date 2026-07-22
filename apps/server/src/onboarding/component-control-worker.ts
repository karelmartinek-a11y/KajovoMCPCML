import http from "node:http";
import { randomInt } from "node:crypto";
import { Ajv2020 } from "ajv/dist/2020.js";
import type { WorkerConfig } from "../config.js";
import type { Db } from "../db.js";
import { tx } from "../db.js";
import { decryptVaultSecret } from "../security/secrets.js";
import { recordComponentControlAck } from "../domain/component.js";
import { appendAudit } from "../domain/audit.js";
import { fetchThroughEgress } from "../domain/egress-client.js";
import { authorizePlatformWorkerCall } from "../domain/platform-worker-access.js";

type ClaimedDispatch = {
  id: string;
  component_id: string;
  revision_id: string;
  command_type: "enable" | "disable" | "state" | "heartbeat";
  endpoint_path: string;
  target_hostname: string;
  request_body: Record<string, unknown>;
  requested_policy_epoch: number;
  correlation_id: string;
  attempt_count: number;
  retry_policy: { maxAttempts?: number };
  transport: "UDS" | "HTTPS";
  upstream: string | null;
  expected_tls_identity: string | null;
  socket_path: string | null;
  principal_public_id: string;
  state_query_id: string | null;
  state_query_nonce: string | null;
  heartbeat_challenge_id: string | null;
  heartbeat_nonce: string | null;
  response_schema: Record<string, unknown>;
  request_schema: Record<string, unknown>;
  onboarding_job_id: string | null;
  callback_token_ciphertext: string | null;
  callback_token_key_id: string | null;
};

const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: false });

function udsPost(socketPath: string, endpointPath: string, body: Buffer, token: string, callbackToken: string | null): Promise<{ status: number; body: Buffer }> {
  return new Promise((resolve, reject) => {
    const request = http.request({
      socketPath,
      path: endpointPath,
      method: "POST",
      timeout: 30_000,
      headers: { authorization: `Bearer ${token}`, ...(callbackToken ? { "x-kcml-callback-authorization": `Bearer ${callbackToken}` } : {}), "content-type": "application/json", "content-length": body.length }
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
      response.on("error", reject);
      response.on("end", () => resolve({ status: response.statusCode ?? 502, body: Buffer.concat(chunks) }));
    });
    request.on("timeout", () => request.destroy(new Error("component_control_timeout")));
    request.on("error", reject);
    request.end(body);
  });
}

async function claim(db: Db, workerId: string): Promise<ClaimedDispatch | null> {
  return tx(db, async (client) => {
    await client.query(
      `update component_control_dispatch
          set state='EXPIRED',final_error_code='control_deadline_expired',lease_owner=null,lease_until=null,updated_at=now()
        where state in ('QUEUED','CLAIMED','SENT','ACK_PENDING') and deadline_at <= now()`
    );
    const result = await client.query(
      `select d.*,rt.transport,rt.upstream,rt.expected_tls_identity,rt.socket_path,contract.request_schema,contract.response_schema,
              p.public_id as principal_public_id,
              onboarding.id onboarding_job_id,onboarding.principal_access_token_ciphertext callback_token_ciphertext,onboarding.principal_access_token_key_id callback_token_key_id,
              sq.id as state_query_id,sq.challenge_nonce as state_query_nonce,
              hb.id as heartbeat_challenge_id,hb.challenge_nonce as heartbeat_nonce
         from component_control_dispatch d
         join component c on c.id=d.component_id
         join principal p on p.id=c.principal_id
         join component_runtime_target rt on rt.component_id=d.component_id and rt.revision_id=d.revision_id
         join component_control_command contract on contract.id=d.command_contract_id
         left join component_state_query_run sq on sq.dispatch_id=d.id
         left join component_heartbeat_challenge hb on hb.dispatch_id=d.id
         left join lateral (
           select job.id,job.principal_access_token_ciphertext,job.principal_access_token_key_id
             from component_onboarding_job job where job.component_id=d.component_id and job.principal_access_token_handed_off_at is null
             order by job.created_at desc limit 1
         ) onboarding on true
        where d.state in ('QUEUED','CLAIMED')
          and d.deadline_at > now()
          and d.next_attempt_at <= now()
          and (rt.circuit_open_until is null or rt.circuit_open_until<=now())
          and (d.lease_until is null or d.lease_until < now())
        order by d.created_at
        for update of d skip locked
        limit 1`
    );
    if (!result.rowCount) return null;
    const row = result.rows[0];
    await client.query(
      `update component_control_dispatch
          set state='CLAIMED',lease_owner=$2,lease_until=now()+interval '45 seconds',updated_at=now()
        where id=$1`,
      [row.id, workerId]
    );
    return row as ClaimedDispatch;
  });
}

async function send(config: WorkerConfig, dispatch: ClaimedDispatch, token: string, callbackToken: string | null): Promise<{ status: number; body: Buffer }> {
  const requestBody = {
    ...dispatch.request_body,
    stateQuery: dispatch.state_query_id ? { id: dispatch.state_query_id, nonce: dispatch.state_query_nonce } : null,
    heartbeatChallenge: dispatch.heartbeat_challenge_id ? { id: dispatch.heartbeat_challenge_id, nonce: dispatch.heartbeat_nonce } : null
  };
  const validateRequest = ajv.compile(dispatch.request_schema);
  if (!validateRequest(requestBody)) throw new Error("control_request_schema_invalid");
  const body = Buffer.from(JSON.stringify(requestBody));
  if (dispatch.transport === "UDS") {
    if (!dispatch.socket_path) throw new Error("control_socket_missing");
    return udsPost(dispatch.socket_path, dispatch.endpoint_path, body, token, callbackToken);
  }
  if (!dispatch.upstream || !dispatch.expected_tls_identity) throw new Error("control_https_target_missing");
  const upstream = new URL(dispatch.upstream);
  if (upstream.protocol !== "https:" || upstream.hostname !== dispatch.expected_tls_identity) throw new Error("control_tls_identity_invalid");
  const response = await fetchThroughEgress(config, {
    url: new URL(dispatch.endpoint_path, upstream).toString(),
    method: "POST",
    headers: { authorization: `Bearer ${token}`, ...(callbackToken ? { "x-kcml-callback-authorization": `Bearer ${callbackToken}` } : {}), "content-type": "application/json" },
    body,
    allowlist: [upstream.hostname],
    purpose: "component.control.dispatch",
    correlationId: dispatch.correlation_id,
    ttlSeconds: 45
  });
  return { status: response.status, body: response.body };
}

async function failAttempt(db: Db, dispatch: ClaimedDispatch, errorCode: string): Promise<void> {
  await tx(db, async (client) => {
    const attempt = dispatch.attempt_count + 1;
    const maxAttempts = Math.max(1, Number(dispatch.retry_policy?.maxAttempts ?? 3));
    const terminal = attempt >= maxAttempts;
    const retryDelayMs = Math.min(60_000, (2 ** attempt) * 1_000) + randomInt(0, 1_001);
    await client.query(
      `insert into component_control_dispatch_attempt(
        dispatch_id,attempt_number,status,request_body,error_code,transport_status,request_digest,correlation_id
      ) values ($1,$2,'FAILED',$3::jsonb,$4,'FAILED',
        'sha256:'||encode(sha256(convert_to(($3::jsonb)::text,'utf8')),'hex'),$5)`,
      [dispatch.id, attempt, JSON.stringify(dispatch.request_body), errorCode.slice(0, 160), dispatch.correlation_id]
    );
    await client.query(
      `update component_control_dispatch
          set state=$2,attempt_count=$3,last_attempt_at=now(),next_attempt_at=now()+($4||' seconds')::interval,
              final_error_code=$5,lease_owner=null,lease_until=null,updated_at=now()
        where id=$1`,
      [dispatch.id, terminal ? "FAILED" : "QUEUED", attempt, retryDelayMs / 1000, errorCode.slice(0, 160)]
    );
    await client.query(
      `update component_runtime_target
          set circuit_failure_count=circuit_failure_count+1,
              circuit_open_until=case when circuit_failure_count+1>=3 then now()+interval '60 seconds' else circuit_open_until end,
              last_dispatch_error=$3,last_probe_at=now()
        where component_id=$1 and revision_id=$2`,
      [dispatch.component_id, dispatch.revision_id, errorCode.slice(0, 160)]
    );
    await appendAudit(client, { eventType: "component.control.dispatch_failed", actorType: "system",
      objectType: "component_control_dispatch", objectId: dispatch.id,
      after: { attempt, errorCode: errorCode.slice(0, 160), terminal, retryDelayMs }, correlationId: dispatch.correlation_id });
    if (terminal) {
      await client.query(
        `update component set enabled=false,ingress_enabled=false,pulse_enabled=false,egress_enabled=false,
                activation_state='BLOCKED',operational_state='UNHEALTHY',monitoring_state='FAILED',updated_at=now()
          where id=$1`,
        [dispatch.component_id]
      );
    }
  });
}

export async function processNextComponentControlDispatch(db: Db, config: WorkerConfig, workerId: string): Promise<boolean> {
  const dispatch = await claim(db, workerId);
  if (!dispatch) return false;
  try {
    const authorization = await authorizePlatformWorkerCall(db, config, {
      hostname: dispatch.target_hostname,
      scope: `platform.control.${dispatch.command_type}`,
      route: dispatch.endpoint_path,
      correlationId: dispatch.correlation_id
    });
    const callbackToken = dispatch.onboarding_job_id && dispatch.callback_token_ciphertext && dispatch.callback_token_key_id
      ? decryptVaultSecret(dispatch.callback_token_ciphertext, new Map([[dispatch.callback_token_key_id, config.CONFIG_VAULT_MASTER_KEY_BASE64]]), `component-onboarding:${dispatch.onboarding_job_id}`)
      : null;
    const response = await send(config, dispatch, authorization.token, callbackToken);
    if (response.status < 200 || response.status >= 300) throw new Error(`control_http_${response.status}`);
    let ackPayload: unknown = {};
    if (response.body.length) ackPayload = JSON.parse(response.body.toString("utf8"));
    const validateResponse = ajv.compile(dispatch.response_schema);
    if (!validateResponse(ackPayload)) throw new Error("control_response_schema_invalid");
    const attempt = dispatch.attempt_count + 1;
    await tx(db, async (client) => {
      await client.query(
        `insert into component_control_dispatch_attempt(
          dispatch_id,attempt_number,status,request_body,response_body,response_digest,transport_status,request_digest,correlation_id
        ) values ($1,$2,'ACKED',$3::jsonb,$4::jsonb,
          'sha256:'||encode(sha256(convert_to(($4::jsonb)::text,'utf8')),'hex'),'DELIVERED',
          'sha256:'||encode(sha256(convert_to(($3::jsonb)::text,'utf8')),'hex'),$5)`,
        [dispatch.id, attempt, JSON.stringify(dispatch.request_body), JSON.stringify(ackPayload), dispatch.correlation_id]
      );
      await client.query(
        "update component_runtime_target set circuit_failure_count=0,circuit_open_until=null,last_dispatch_error=null,last_probe_at=now(),status='HEALTHY' where component_id=$1 and revision_id=$2",
        [dispatch.component_id, dispatch.revision_id]
      );
      await appendAudit(client, { eventType: "component.control.dispatched", actorType: "system",
        objectType: "component_control_dispatch", objectId: dispatch.id,
        after: { attempt, httpStatus: response.status, responseBytes: response.body.length }, correlationId: dispatch.correlation_id });
      await client.query(
        `update component_control_dispatch
            set state='ACK_PENDING',attempt_count=$2,last_attempt_at=now(),lease_owner=null,lease_until=null,updated_at=now()
          where id=$1`,
        [dispatch.id, attempt]
      );
    });
    await recordComponentControlAck(db, dispatch.component_id, {
      commandId: dispatch.id,
      commandType: dispatch.command_type,
      status: "ACKED",
      ackPayload,
      correlationId: dispatch.correlation_id,
      declaredClientId: dispatch.principal_public_id,
      declaredComponentCode: typeof dispatch.request_body.componentCode === "string" ? dispatch.request_body.componentCode : "",
      policyEpoch: Number(dispatch.requested_policy_epoch)
    });
  } catch (error) {
    await failAttempt(db, dispatch, error instanceof Error ? error.message : "control_dispatch_failed");
  }
  return true;
}
