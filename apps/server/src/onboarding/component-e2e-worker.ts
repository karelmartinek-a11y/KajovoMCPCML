import { createHash } from "node:crypto";
import http from "node:http";
import { Ajv2020 } from "ajv/dist/2020.js";
import type { WorkerConfig } from "../config.js";
import type { Db } from "../db.js";
import { tx } from "../db.js";
import { decryptVaultSecret } from "../security/secrets.js";
import { canonicalJson } from "../domain/component.js";
import { authorizeComponentCall } from "../domain/component-auth.js";
import { fetchThroughEgress } from "../domain/egress-client.js";
import { authorizePlatformWorkerCall } from "../domain/platform-worker-access.js";
import { KCML_RELEASE } from "../domain/release.js";

type E2ERun = {
  id: string; component_id: string; revision_id: string; runtime_digest: string; correlation_id: string;
  transport: "UDS" | "HTTPS"; upstream: string | null; expected_tls_identity: string | null; socket_path: string | null;
  hostname: string;
  revision_digest: string;
  onboarding_job_id: string | null;
  callback_token_ciphertext: string | null;
  callback_token_key_id: string | null;
  deadline_at: string | Date;
};
type Fixture = {
  id: string; scenario_key: string; variant_key: string; input_content: Buffer; input_media_type: string;
  expected_content: Buffer; expected_media_type: string; expected_digest: string; invocation_kind: string;
  invocation_name: string; timeout_ms: number; cleanup_contract: { required?: boolean; operation?: string };
};

const digest = (value: Buffer) => `sha256:${createHash("sha256").update(value).digest("hex")}`;
const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: false });

function udsPost(socketPath: string, path: string, body: Buffer, mediaType: string, timeoutMs: number, token: string, callbackToken: string | null): Promise<{ status: number; body: Buffer }> {
  return new Promise((resolve, reject) => {
    const request = http.request({ socketPath, path, method: "POST", timeout: timeoutMs,
      headers: { authorization: `Bearer ${token}`, ...(callbackToken ? { "x-kcml-callback-authorization": `Bearer ${callbackToken}` } : {}), "content-type": mediaType, "content-length": body.length, "x-kcml-platform-operation": "e2e" } }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
      response.on("error", reject);
      response.on("end", () => resolve({ status: response.statusCode ?? 502, body: Buffer.concat(chunks) }));
    });
    request.on("timeout", () => request.destroy(new Error("e2e_timeout")));
    request.on("error", reject);
    request.end(body);
  });
}

async function claim(db: Db, workerId: string): Promise<E2ERun | null> {
  return tx(db, async (client) => {
    await client.query("update component_e2e_run set status='FAIL',final_error_code='e2e_deadline_expired',completed_at=now(),lease_owner=null,lease_until=null where status in ('QUEUED','RUNNING') and deadline_at<=now()");
    const result = await client.query(
      `select run.*,target.transport,target.upstream,target.expected_tls_identity,target.socket_path,component.hostname,revision.manifest_digest as revision_digest,
              onboarding.id onboarding_job_id,onboarding.principal_access_token_ciphertext callback_token_ciphertext,onboarding.principal_access_token_key_id callback_token_key_id
         from component_e2e_run run
         join component on component.id=run.component_id
         join component_revision revision on revision.id=run.revision_id
         join component_runtime_target target on target.component_id=run.component_id and target.revision_id=run.revision_id and target.runtime_digest=run.runtime_digest
         left join lateral (
           select job.id,job.principal_access_token_ciphertext,job.principal_access_token_key_id
             from component_onboarding_job job where job.component_id=run.component_id and job.principal_access_token_handed_off_at is null
             order by job.created_at desc limit 1
         ) onboarding on true
        where run.status in ('QUEUED','RUNNING') and run.deadline_at>now()
          and run.cancellation_requested_at is null and (run.lease_until is null or run.lease_until<now())
        order by run.created_at for update of run skip locked limit 1`
    );
    if (!result.rowCount) return null;
    await client.query("update component_e2e_run set status='RUNNING',started_at=coalesce(started_at,now()),lease_owner=$2,lease_until=now()+interval '45 seconds',worker_heartbeat_at=now(),attempt_count=attempt_count+1 where id=$1", [result.rows[0].id, workerId]);
    return result.rows[0] as E2ERun;
  });
}

function invocationRequest(run: E2ERun, fixture: Fixture, cleanup: boolean): { path: string; mediaType: string; body: Buffer } {
  if (cleanup) return {
    path: "/v1/kcml/runtime/e2e/cleanup",
    mediaType: "application/json",
    body: Buffer.from(JSON.stringify({ scenarioKey: fixture.scenario_key, variantKey: fixture.variant_key, operation: fixture.cleanup_contract.operation }))
  };
  if (fixture.invocation_kind === "TOOL") {
    if (fixture.input_media_type !== "application/json") throw new Error("e2e_tool_input_media_type_invalid");
    return {
      path: "/v1/kcml/runtime/tools/call",
      mediaType: "application/json",
      body: Buffer.from(JSON.stringify({
        operation: "tools/call",
        tool: fixture.invocation_name,
        arguments: JSON.parse(fixture.input_content.toString("utf8")),
        authorization: { authority: "KCML", correlationId: run.correlation_id, probe: true }
      }))
    };
  }
  if (fixture.invocation_kind === "PULSE") return { path: "/v1/kcml/runtime/pulse", mediaType: fixture.input_media_type, body: fixture.input_content };
  if (fixture.invocation_kind === "ENDPOINT") return { path: fixture.invocation_name, mediaType: fixture.input_media_type, body: fixture.input_content };
  throw new Error("e2e_invocation_kind_unsupported");
}

async function invoke(config: WorkerConfig, run: E2ERun, fixture: Fixture, token: string, callbackToken: string | null, cleanup = false): Promise<{ status: number; body: Buffer }> {
  const invocation = invocationRequest(run, fixture, cleanup);
  if (run.transport === "UDS") {
    if (!run.socket_path) throw new Error("e2e_socket_missing");
    return udsPost(run.socket_path, invocation.path, invocation.body, invocation.mediaType, Number(fixture.timeout_ms), token, callbackToken);
  }
  if (!run.upstream || !run.expected_tls_identity) throw new Error("e2e_https_target_missing");
  const upstream = new URL(run.upstream);
  if (upstream.protocol !== "https:" || upstream.hostname !== run.expected_tls_identity) throw new Error("e2e_tls_identity_invalid");
  const response = await fetchThroughEgress(config, { url: new URL(invocation.path, upstream).toString(), method: "POST",
    headers: { authorization: `Bearer ${token}`, ...(callbackToken ? { "x-kcml-callback-authorization": `Bearer ${callbackToken}` } : {}), "content-type": invocation.mediaType, "x-kcml-platform-operation": "e2e" }, body: invocation.body,
    allowlist: [upstream.hostname], purpose: "component.e2e.execute", correlationId: run.correlation_id,
    ttlSeconds: Math.max(15, Math.ceil(Number(fixture.timeout_ms) / 1000) + 5) });
  return { status: response.status, body: response.body };
}

function normalizedResponse(body: Buffer, mediaType: string): Buffer {
  if (mediaType !== "application/json") return body;
  return Buffer.from(canonicalJson(JSON.parse(body.toString("utf8"))));
}

export async function processNextComponentE2ERun(db: Db, config: WorkerConfig, workerId: string): Promise<boolean> {
  const run = await claim(db, workerId);
  if (!run) return false;
  const fixtures = await db.query("select * from component_e2e_fixture where revision_id=$1 order by scenario_key,variant_key", [run.revision_id]);
  const toolContracts = await db.query("select name,output_schema from component_tool_contract where component_id=$1 and revision_id=$2 order by name", [run.component_id, run.revision_id]);
  const endpointContracts = await db.query("select endpoint_id,path from component_endpoint_contract where component_id=$1 and revision_id=$2 order by endpoint_id", [run.component_id, run.revision_id]);
  const pulseContracts = await db.query("select direction,pulse_type from component_pulse_mask where component_id=$1 and revision_id=$2 order by direction,pulse_type", [run.component_id, run.revision_id]);
  const outputValidators = new Map(toolContracts.rows.map((contract) => [String(contract.name), ajv.compile(contract.output_schema)]));
  const callbackToken = run.onboarding_job_id && run.callback_token_ciphertext && run.callback_token_key_id
    ? decryptVaultSecret(run.callback_token_ciphertext, new Map([[run.callback_token_key_id, config.CONFIG_VAULT_MASTER_KEY_BASE64]]), `component-onboarding:${run.onboarding_job_id}`)
    : null;
  let passed = Number(fixtures.rowCount ?? 0) > 0;
  let registeredDispatchPassed = false;
  const gateEvidence: Array<Record<string, unknown>> = [];
  for (const raw of fixtures.rows as Fixture[]) {
    const startedAt = new Date();
    let responseContent: Buffer | null = null;
    let status: "PASS" | "FAIL" | "ERROR" = "ERROR";
    let errorCode: string | null = null;
    try {
      const invocation = invocationRequest(run, raw, false);
      if (callbackToken && raw.invocation_kind === "TOOL") {
        const componentDecision = await authorizeComponentCall(db, {
          token: callbackToken,
          audience: `https://${run.hostname}`,
          host: run.hostname,
          scope: "mcp.tools.call",
          route: `/mcp/tools/${raw.invocation_name}`,
          hmacKey: config.ACCESS_TOKEN_HMAC_KEY_BASE64,
          correlationId: run.correlation_id,
          allowOnboardingProbe: true
        });
        if (!componentDecision.allow) throw new Error(`e2e_component_authorization_${componentDecision.reasonCode}`);
        registeredDispatchPassed = true;
      }
      const authorization = await authorizePlatformWorkerCall(db, config, {
        hostname: run.hostname,
        scope: "platform.e2e.execute",
        route: invocation.path,
        correlationId: run.correlation_id
      });
      const response = await invoke(config, run, raw, authorization.token, callbackToken);
      if (response.status < 200 || response.status >= 300) throw new Error(`e2e_http_${response.status}`);
      responseContent = normalizedResponse(response.body, raw.expected_media_type);
      const outputSchemaValid = raw.invocation_kind !== "TOOL" || Boolean(outputValidators.get(raw.invocation_name)?.(JSON.parse(responseContent.toString("utf8"))));
      status = responseContent.equals(raw.expected_content) && digest(responseContent) === raw.expected_digest && outputSchemaValid ? "PASS" : "FAIL";
      if (status === "FAIL") errorCode = "e2e_exact_mismatch";
      if (raw.cleanup_contract?.required) {
        const cleanup = await invoke(config, run, raw, authorization.token, callbackToken, true);
        if (cleanup.status < 200 || cleanup.status >= 300) throw new Error(`e2e_cleanup_http_${cleanup.status}`);
      }
    } catch (error) {
      status = "ERROR";
      errorCode = error instanceof Error ? error.message : "e2e_execution_failed";
    }
    if (status !== "PASS") passed = false;
    gateEvidence.push({ scenarioKey: raw.scenario_key, variantKey: raw.variant_key, invocationKind: raw.invocation_kind, invocationName: raw.invocation_name, status, errorCode,
      requestDigest: digest(raw.input_content), responseDigest: responseContent ? digest(responseContent) : null });
    await db.query(
      `insert into component_e2e_run_result(run_id,fixture_id,response_content,response_digest,exact_match,status,error_code,started_at,completed_at)
       values ($1,$2,$3,$4,$5,$6,$7,$8,now()) on conflict (run_id,fixture_id) do update set response_content=excluded.response_content,
       response_digest=excluded.response_digest,exact_match=excluded.exact_match,status=excluded.status,error_code=excluded.error_code,started_at=excluded.started_at,completed_at=now()`,
      [run.id, raw.id, responseContent, responseContent ? digest(responseContent) : null, status === "PASS", status, errorCode, startedAt]
    );
    await db.query("update component_e2e_run set worker_heartbeat_at=now(),lease_until=now()+interval '45 seconds' where id=$1", [run.id]);
  }
  await db.query("update component_e2e_run set status=$2,completed_at=now(),lease_owner=null,lease_until=null,final_error_code=$3 where id=$1", [run.id, passed ? "PASS" : "FAIL", passed ? null : "e2e_scenario_failed"]);
  const evidence = { runId: run.id, scenarios: gateEvidence, checkedAt: new Date().toISOString() };
  const requestDigest = digest(Buffer.from(canonicalJson(gateEvidence.map((item) => ({ scenarioKey: item.scenarioKey, variantKey: item.variantKey, requestDigest: item.requestDigest })))));
  const responseDigest = digest(Buffer.from(canonicalJson(gateEvidence.map((item) => ({ scenarioKey: item.scenarioKey, variantKey: item.variantKey, responseDigest: item.responseDigest, status: item.status })))));
  const passedInvocation = (kind: string, name: string) => gateEvidence.some((item) => item.invocationKind === kind && item.invocationName === name && item.status === "PASS");
  const toolCoverage = toolContracts.rows.map((contract) => ({ name: String(contract.name), pass: passedInvocation("TOOL", String(contract.name)) }));
  const endpointCoverage = endpointContracts.rows.map((contract) => ({ id: String(contract.endpoint_id), route: String(contract.path), pass: passedInvocation("ENDPOINT", String(contract.endpoint_id)) || passedInvocation("ENDPOINT", String(contract.path)) }));
  const incomingPulseCoverage = pulseContracts.rows.filter((contract) => contract.direction === "INCOMING").map((contract) => ({ pulseType: String(contract.pulse_type), pass: passedInvocation("PULSE", String(contract.pulse_type)) }));
  const outgoingPulseCoverage = pulseContracts.rows.filter((contract) => contract.direction === "OUTGOING").map((contract) => ({ pulseType: String(contract.pulse_type), pass: passedInvocation("PULSE", String(contract.pulse_type)) }));
  const gates = [
    { gate: "E2E_ALL_SCENARIOS", pass: passed, reason: passed ? "e2e_all_scenarios_exact_match" : "e2e_scenario_failed", variant: "all_declared_scenarios", detail: evidence },
    { gate: "EACH_TOOL_POSITIVE_CALL", pass: toolCoverage.every((item) => item.pass), reason: "each_tool_fixture_executed", variant: "all_declared_tools", detail: { coverage: toolCoverage } },
    { gate: "EACH_TOOL_OUTPUT_SCHEMA", pass: toolCoverage.every((item) => item.pass), reason: "each_tool_output_schema_validated", variant: "all_declared_tools", detail: { coverage: toolCoverage } },
    { gate: "EACH_ENDPOINT_VARIANT", pass: endpointCoverage.every((item) => item.pass), reason: "each_endpoint_fixture_executed", variant: "all_declared_endpoints", detail: { coverage: endpointCoverage } },
    { gate: "EACH_INCOMING_PULSE_VARIANT", pass: incomingPulseCoverage.every((item) => item.pass), reason: "each_incoming_pulse_fixture_executed", variant: "all_declared_incoming_pulses", detail: { coverage: incomingPulseCoverage } },
    { gate: "EACH_OUTGOING_PULSE_VARIANT", pass: outgoingPulseCoverage.every((item) => item.pass), reason: "each_outgoing_pulse_fixture_executed", variant: "all_declared_outgoing_pulses", detail: { coverage: outgoingPulseCoverage } },
    { gate: "OPERATION_LEASE_ENFORCEMENT", pass: passed && Date.now() < new Date(run.deadline_at).getTime(), reason: "e2e_worker_lease_and_deadline_enforced", variant: "durable_worker_lease", detail: { runId: run.id, deadlineAt: new Date(run.deadline_at).toISOString(), completedBeforeDeadline: Date.now() < new Date(run.deadline_at).getTime() } },
    { gate: "REGISTERED_TO_REGISTERED_DISPATCH", pass: registeredDispatchPassed && passed, reason: "pending_component_token_authorized_and_runtime_executed", variant: "component_self_dispatch_probe", detail: { componentId: run.component_id, authorized: registeredDispatchPassed, runtimePassed: passed } }
  ];
  for (const gate of gates) {
    const gateEvidenceBody = { ...gate.detail, checkedAt: new Date().toISOString() };
    await db.query(`insert into component_readiness_gate_evidence(
      component_id,revision_id,gate_key,evaluator_version,status,reason_code,evidence,evidence_digest,correlation_id,expires_at,
      revision_digest,runtime_digest,artifact_digest,request_digest,response_digest,variant
    ) values ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,now()+interval '15 minutes',$10,$11,$11,$12,$13,$14)`,
    [run.component_id, run.revision_id, gate.gate, KCML_RELEASE.catalogVersion, gate.pass ? "PASS" : "FAIL",
      gate.pass ? gate.reason : `${gate.gate.toLowerCase()}_failed`, JSON.stringify(gateEvidenceBody), digest(Buffer.from(canonicalJson(gateEvidenceBody))),
      run.correlation_id, run.revision_digest, run.runtime_digest, requestDigest, responseDigest, gate.variant]);
  }
  return true;
}
