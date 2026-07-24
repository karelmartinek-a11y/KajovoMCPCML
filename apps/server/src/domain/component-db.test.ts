import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadConfig, type AppConfig } from "../config.js";
import { createDb, type Db } from "../db.js";
import { hmacToken } from "../security/secrets.js";
import { ingestComponentAuditEvent } from "./component-audit.js";
import { authorizeComponentCall } from "./component-auth.js";
import {
  createComponentOnboarding,
  evaluateComponentReadiness,
  markStaleComponentHeartbeats,
  queueComponentE2ERun,
  revokeComponentAccessToken,
  rotateComponentAccessToken,
  setComponentLifecycle,
  setComponentPermissionEnabled,
  validateComponentOnboardingSubmission,
  validateComponentManifest
} from "./component.js";
import { KCML_RELEASE } from "./release.js";
import { authorizePlatformWorkerCall, ensurePlatformWorkerAccessToken, rotatePlatformWorkerAccessToken } from "./platform-worker-access.js";
import { issueRepositoryComponentRuntimeSecretToken } from "./repository-component-runtime-auth.js";

const sourceId = "91000000-0000-4000-8000-000000000001";
const targetId = "91000000-0000-4000-8000-000000000002";
const accessTokenId = "91000000-0000-4000-8000-000000000003";
const permissionId = "91000000-0000-4000-8000-000000000004";
const revisionId = "91000000-0000-4000-8000-000000000005";
const auditComponentId = "91000000-0000-4000-8000-000000000006";
const auditRevisionId = "91000000-0000-4000-8000-000000000007";
const sourcePrincipalId = "91000000-0000-4000-8000-000000000008";
const targetPrincipalId = "91000000-0000-4000-8000-000000000009";
const auditPrincipalId = "91000000-0000-4000-8000-000000000010";
const clientSecret = "component-secret-for-current-policy-tests";
const enabled = process.env.KCML_TEST_DATABASE === "1";
const exampleManifest = JSON.parse(readFileSync(new URL(`../../../../docs/onboarding-manifest-${KCML_RELEASE.manifestSchemaVersion}.example.json`, import.meta.url), "utf8")) as Record<string, unknown>;
const repositoryComponentDescriptor = JSON.parse(readFileSync(new URL(`../../../../components/mail-vectorizace/component.kcml.json`, import.meta.url), "utf8")) as Record<string, unknown>;
let db: Db;
let accessHmacKey: Buffer;
let config: AppConfig;

describe.skipIf(!enabled)("component authorization and audit persistence", () => {
  beforeAll(async () => {
    config = loadConfig(process.env);
    accessHmacKey = config.ACCESS_TOKEN_HMAC_KEY_BASE64;
    db = createDb(config);
    await db.query("delete from principal_access_token where source_principal_id=$1", [sourcePrincipalId]);
    await db.query("delete from component_permission where source_component_id=$1 or target_component_id=$2", [sourceId, targetId]);
    await db.query(`insert into principal(id,kind,public_id,status,policy_epoch,revocation_epoch) values
      ($1,'COMPONENT','KCML91001','ACTIVE',1,1),($2,'COMPONENT','KCML91002','ACTIVE',1,1),($3,'COMPONENT','KCML91003','ACTIVE',1,1)
      on conflict (id) do update set status='ACTIVE'`, [sourcePrincipalId, targetPrincipalId, auditPrincipalId]);
    await db.query(`
      insert into component(id,principal_id,kcml_number,code,hostname,display_name,category,registration_type,component_role,lifecycle_state,activation_state,operational_state,monitoring_state,enabled,ingress_enabled,pulse_enabled,egress_enabled,release_version)
      values
        ($1,$4,91001,'KCML91001','kcml91001.kajovocml.hcasc.cz','Zdroj','EXTERNAL_SERVICE','GENERIC_COMPONENT','SERVICE','ACTIVE','ACTIVE','HEALTHY','HEALTHY',true,true,true,true,$3),
        ($2,$5,91002,'KCML91002','kcml91002.kajovocml.hcasc.cz','Cíl','EXTERNAL_SERVICE','GENERIC_COMPONENT','SERVICE','ACTIVE','ACTIVE','HEALTHY','HEALTHY',true,true,true,true,$3)
      on conflict (id) do update set lifecycle_state='ACTIVE',activation_state='ACTIVE',operational_state='HEALTHY',monitoring_state='HEALTHY',
        enabled=true,ingress_enabled=true,pulse_enabled=true,egress_enabled=true,release_version=excluded.release_version`,
      [sourceId, targetId, KCML_RELEASE.catalogVersion, sourcePrincipalId, targetPrincipalId]
    );
    await db.query(
      `insert into component(id,principal_id,kcml_number,code,hostname,display_name,category,registration_type,component_role,lifecycle_state,activation_state,operational_state,monitoring_state,enabled,ingress_enabled,pulse_enabled,egress_enabled,release_version)
      values
        ($1,$3,91003,'KCML91003','kcml91003.kajovocml.hcasc.cz','Auditní cíl','EXTERNAL_SERVICE','GENERIC_COMPONENT','SERVICE','ACTIVE','ACTIVE','HEALTHY','HEALTHY',true,true,true,true,$2)
      on conflict (id) do update set lifecycle_state='ACTIVE',activation_state='ACTIVE',operational_state='HEALTHY',monitoring_state='HEALTHY',
        enabled=true,ingress_enabled=true,pulse_enabled=true,egress_enabled=true,release_version=excluded.release_version`,
      [auditComponentId, KCML_RELEASE.catalogVersion, auditPrincipalId]
    );
    await db.query(`insert into component_revision(id,component_id,revision,validation_state,manifest,manifest_digest,capabilities,protocols,transports)
      values ($1,$2,'1.0.0','APPROVED','{}','sha256:test',array['component.pulse','component.audit.write'],array['HTTPS'],array['HTTPS'])
      on conflict (id) do update set validation_state='APPROVED'`, [revisionId, targetId]);
    await db.query(`insert into component_revision(id,component_id,revision,validation_state,manifest,manifest_digest,capabilities,protocols,transports)
      values ($1,$2,'1.0.0','APPROVED','{}','sha256:test-audit',array['component.audit.write'],array['HTTPS'],array['HTTPS'])
      on conflict (id) do update set validation_state='APPROVED'`, [auditRevisionId, auditComponentId]);
    await db.query("update component set active_revision_id=$2 where id=$1", [targetId, revisionId]);
    await db.query("update component set active_revision_id=$2 where id=$1", [auditComponentId, auditRevisionId]);
    await db.query("insert into component_audit_stream(component_id) values ($1),($2),($3) on conflict (component_id) do nothing", [sourceId, targetId, auditComponentId]);
    await db.query(`insert into principal_access_token(id,lookup_digest,fingerprint,source_principal_id,target_component_id,audience,scope_names,issued_policy_epoch,issued_revocation_epoch,expires_at)
      values ($1,$2,'fingerprint-test',$3,null,'*',array['component.pulse','component.audit.write'],1,1,'infinity')`,
      [accessTokenId, hmacToken(clientSecret, accessHmacKey), sourcePrincipalId]);
    await db.query(`insert into component_permission(id,source_component_id,target_component_id,route_pattern,scope_name)
      values ($1,$2,$3,'/v2/*','component.pulse'),(gen_random_uuid(),$2,$3,'/v2/*','component.audit.write')`, [permissionId, sourceId, targetId]);
    await db.query(`insert into principal_component_permission(source_principal_id,target_component_id,route_pattern,scope_name)
      select id,$1,'/v1/kcml/runtime/*','platform.e2e.execute' from principal where public_id='KCML-PLATFORM-WORKER'
      on conflict (source_principal_id,target_component_id,route_pattern,scope_name) do update set revoked_at=null`, [targetId]);
  });

  afterAll(async () => {
    if (!db) return;
    await db.query("delete from principal_access_token where source_principal_id=$1", [sourcePrincipalId]);
    await db.query("delete from component_permission where source_component_id=$1 or target_component_id=$2", [sourceId, targetId]);
    await db.query("update component set enabled=false,ingress_enabled=false,pulse_enabled=false,egress_enabled=false,activation_state='INACTIVE',operational_state='RETIRED',lifecycle_state='DEREGISTERED',deregistered_at=now() where id=any($1::uuid[])", [[sourceId, targetId, auditComponentId]]);
    await db.end();
  });

  it("checks current route, scope and component state without revoking a token on deactivation", async () => {
    const accessToken = `kca_${randomUUID()}${randomUUID()}`;
    await db.query(`insert into principal_access_token(lookup_digest,key_id,fingerprint,source_principal_id,target_component_id,audience,scope_names,expires_at,issued_policy_epoch,issued_revocation_epoch)
      values ($1,'test','principal-token-test',$2,null,'*',array['component.pulse'],'infinity',1,1)`, [hmacToken(accessToken, accessHmacKey), sourcePrincipalId]);
    const parameters = {
      token: accessToken, audience: "https://kcml91002.kajovocml.hcasc.cz", host: "kcml91002.kajovocml.hcasc.cz",
      scope: "component.pulse", route: "/v2/component-pulse", hmacKey: accessHmacKey
    };
    expect((await authorizeComponentCall(db, { ...parameters, correlationId: randomUUID() })).reasonCode).toBe("allowed");
    expect((await authorizeComponentCall(db, {
      ...parameters,
      audience: "https://kcml91001.kajovocml.hcasc.cz",
      correlationId: randomUUID()
    })).reasonCode).toBe("invalid_audience");
    expect((await authorizeComponentCall(db, {
      ...parameters,
      scope: "component.scope.not.granted",
      correlationId: randomUUID()
    })).reasonCode).toBe("insufficient_scope");
    expect((await authorizeComponentCall(db, {
      ...parameters,
      route: "/mcp",
      correlationId: randomUUID()
    })).reasonCode).toBe("route_denied");
    await db.query("update component_permission set revoked_at=now() where id=$1", [permissionId]);
    expect((await authorizeComponentCall(db, { ...parameters, correlationId: randomUUID() })).reasonCode).toBe("insufficient_scope");
    await db.query("update component_permission set revoked_at=null where id=$1", [permissionId]);
    await db.query("update component set enabled=false,ingress_enabled=false,pulse_enabled=false,egress_enabled=false,activation_state='READY',operational_state='DISABLED' where id=$1", [targetId]);
    expect((await authorizeComponentCall(db, { ...parameters, correlationId: randomUUID() })).reasonCode).toBe("component_disabled");
    expect((await db.query("select revoked_at from principal_access_token where fingerprint='principal-token-test'")).rows[0].revoked_at).toBeNull();
    await db.query("update component set enabled=true,ingress_enabled=true,pulse_enabled=true,egress_enabled=true,activation_state='ACTIVE',operational_state='HEALTHY' where id=$1", [targetId]);
    expect((await authorizeComponentCall(db, { ...parameters, correlationId: randomUUID() })).reasonCode).toBe("allowed");
  });

  it("locks active components separately before aggregating stale heartbeat evidence", async () => {
    await db.query(
      `update component
          set activated_at=now()-interval '30 seconds',operational_state='HEALTHY',monitoring_state='HEALTHY',
              enabled=true,ingress_enabled=true,pulse_enabled=true,egress_enabled=true
        where id=$1`,
      [targetId]
    );
    await db.query("delete from component_heartbeat where component_id=$1", [targetId]);
    expect(await markStaleComponentHeartbeats(db, 1, 10, randomUUID())).toBeGreaterThanOrEqual(1);
    const disabled = await db.query(
      "select operational_state,monitoring_state,enabled,ingress_enabled,pulse_enabled,egress_enabled from component where id=$1",
      [targetId]
    );
    expect(disabled.rows[0]).toMatchObject({
      operational_state: "DISABLED",
      monitoring_state: "FAILED",
      enabled: false,
      ingress_enabled: false,
      pulse_enabled: false,
      egress_enabled: false
    });
    await db.query(
      `update component
          set activated_at=now(),operational_state='HEALTHY',monitoring_state='HEALTHY',
              enabled=true,ingress_enabled=true,pulse_enabled=true,egress_enabled=true
        where id=$1`,
      [targetId]
    );
  });

  it("detects an audit gap and accepts a contiguous replay", async () => {
    const stream = await db.query("select expected_next_sequence from component_audit_stream where component_id=$1", [targetId]);
    const base = Number(stream.rows[0].expected_next_sequence);
    const event = (sequenceNumber: number) => ({
      sequenceNumber, eventType: "workflow.step", initiatedByType: "component", occurredAt: new Date().toISOString(),
      correlationId: randomUUID(), catalogVersion: KCML_RELEASE.catalogVersion
    });
    expect((await ingestComponentAuditEvent(db, targetId, event(base))).accepted).toBe(true);
    const gap = await ingestComponentAuditEvent(db, targetId, event(base + 2));
    expect(gap).toMatchObject({ accepted: false, gapState: "GAP_DETECTED", replayFromSequence: base + 1 });
    expect((await ingestComponentAuditEvent(db, targetId, event(base + 1))).expectedNextSequence).toBe(base + 2);
    expect((await ingestComponentAuditEvent(db, targetId, event(base + 2))).expectedNextSequence).toBe(base + 3);
  });

  it("accepts an exact duplicate audit event idempotently and fail-closes on conflicting duplicate content", async () => {
    const beforeStream = await db.query(
      `select coalesce(max(event.sequence_number),0)::bigint+1 expected_next_sequence,
              (array_agg(event.event_hash order by event.sequence_number desc))[1] current_event_hash
         from component_audit_stream stream
         left join component_audit_event event on event.stream_id=stream.id
        where stream.component_id=$1`,
      [auditComponentId]
    );
    const sequenceNumber = Number(beforeStream.rows[0].expected_next_sequence);
    await db.query(
      `update component_audit_stream
          set expected_next_sequence=$2::bigint,
              highest_received_sequence=$2::bigint-1,
              highest_acknowledged_sequence=$2::bigint-1,
              current_event_hash=$3,
              gap_state='CONTIGUOUS',
              gap_from_sequence=null,
              gap_to_sequence=null,
              integrity_state='VALID',
              integrity_reason=null,
              broken_at=null,
              updated_at=now(),
              lock_version=lock_version+1
        where component_id=$1`,
      [auditComponentId, sequenceNumber, beforeStream.rows[0].current_event_hash]
    );
    await db.query(
      `update component
          set lifecycle_state='ACTIVE',
              activation_state='ACTIVE',
              operational_state='HEALTHY',
              enabled=true,
              ingress_enabled=true,
              pulse_enabled=true,
              egress_enabled=true,
              updated_at=now()
        where id=$1`,
      [auditComponentId]
    );
    const exact = {
      sequenceNumber,
      eventType: "runtime.ack",
      initiatedByType: "component",
      occurredAt: "2026-07-24T12:00:00.000Z",
      correlationId: "91000000-0000-4000-8000-000000000010",
      catalogVersion: KCML_RELEASE.catalogVersion,
      payload: { state: "ok", counter: 1 }
    };
    const first = await ingestComponentAuditEvent(db, auditComponentId, exact);
    expect(first).toMatchObject({ accepted: true, duplicate: false, expectedNextSequence: sequenceNumber + 1 });
    const duplicate = await ingestComponentAuditEvent(db, auditComponentId, exact);
    expect(duplicate).toMatchObject({ accepted: true, duplicate: true, expectedNextSequence: sequenceNumber + 1 });

    const stored = await db.query(
      `select event_hash,previous_event_hash,canonical_payload_digest,revision_id
         from component_audit_event
        where stream_id=(select id from component_audit_stream where component_id=$1)
          and sequence_number=$2`,
      [auditComponentId, sequenceNumber]
    );
    expect(stored.rows[0].event_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(stored.rows[0].previous_event_hash).toBe(beforeStream.rows[0].current_event_hash);
    expect(stored.rows[0].canonical_payload_digest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(String(stored.rows[0].revision_id)).toBe(auditRevisionId);

    await expect(ingestComponentAuditEvent(db, auditComponentId, {
      ...exact,
      payload: { state: "tampered", counter: 1 }
    })).rejects.toThrow("audit_stream_conflict");

    const stream = await db.query(
      "select integrity_state,integrity_reason,current_event_hash from component_audit_stream where component_id=$1",
      [auditComponentId]
    );
    expect(stream.rows[0]).toMatchObject({
      integrity_state: "CONFLICT",
      integrity_reason: "duplicate_event_hash_conflict"
    });
    expect(stream.rows[0].current_event_hash).toMatch(/^sha256:[a-f0-9]{64}$/);

    const component = await db.query(
      "select lifecycle_state,activation_state,operational_state,enabled,ingress_enabled,pulse_enabled,egress_enabled from component where id=$1",
      [auditComponentId]
    );
    expect(component.rows[0]).toMatchObject({
      lifecycle_state: "QUARANTINED",
      activation_state: "BLOCKED",
      operational_state: "QUARANTINED",
      enabled: false,
      ingress_enabled: false,
      pulse_enabled: false,
      egress_enabled: false
    });
  });

  it("keeps onboarding idempotent and queues KCML-executed E2E before token handoff", async () => {
    const integrationTokenId = randomUUID();
    const admin = await db.query("select id from admin_account order by created_at limit 1");
    await db.query(`insert into integration_token(
      id,label,lookup_digest,key_id,fingerprint,created_by,initial_expires_at,expires_at,max_expires_at,descriptor,
      token_kind,release_version,max_child_jobs
    ) values ($1,'Component DB test',$2,'test','component-db-test',$3,now()+interval '24 hours',now()+interval '24 hours',now()+interval '24 hours',$4::jsonb,
      'SINGLE_COMPONENT',$5,1)`,
    [integrationTokenId, hmacToken(integrationTokenId, accessHmacKey), admin.rows[0].id, JSON.stringify({ summary: "Component test", businessPurpose: "Validate component onboarding access token handoff safely.", serviceOwner: "KCML", technicalOwner: "KCML", criticality: "LOW" }), KCML_RELEASE.catalogVersion]);
    const manifest = validateComponentManifest({
      ...structuredClone(exampleManifest),
      displayName: "Self-service test",
      businessPurpose: "Validate component onboarding access token handoff safely."
    });
    const input = {
      integrationTokenId,
      idempotencyKey: `component-${integrationTokenId}`,
      manifest: { phase: "FINAL" as const, manifest },
      correlationId: randomUUID()
    };
    const created = await createComponentOnboarding(db, input);
    expect((await createComponentOnboarding(db, input)).id).toBe(created.id);
    const mcpPermissions = await db.query("select route_pattern,scope_name from component_permission where source_component_id=$1 and target_component_id=$1 and scope_name like 'mcp.%' and revoked_at is null order by scope_name", [created.componentId]);
    expect(mcpPermissions.rows.map((row) => [String(row.scope_name), String(row.route_pattern)])).toEqual([
      ["mcp.initialize", "/mcp"], ["mcp.notifications.initialized", "/mcp"], ["mcp.tools.call", "/mcp/*"], ["mcp.tools.list", "/mcp"]
    ]);
    await db.query("update component set monitoring_state='HEALTHY', recertification_state='NOT_DUE' where id=$1", [created.componentId]);
    const run = await queueComponentE2ERun(db, { jobId: String(created.id), integrationTokenId, correlationId: randomUUID() });
    expect(run.status).toBe("QUEUED");
    const evaluation = await evaluateComponentReadiness(db, {
      jobId: String(created.id), integrationTokenId, accessTokenHmacKey: accessHmacKey,
      accessTokenHmacKeyId: config.ACCESS_TOKEN_HMAC_KEY_ID, vaultMasterKey: config.CONFIG_VAULT_MASTER_KEY_BASE64,
      vaultMasterKeyId: config.CONFIG_VAULT_MASTER_KEY_ID, integrationTokenHmacKey: config.INTEGRATION_TOKEN_HMAC_KEY_BASE64,
      integrationTokenHmacKeyId: config.INTEGRATION_TOKEN_HMAC_KEY_ID, correlationId: randomUUID()
    });
    expect(evaluation.accessToken).toBeUndefined();
    expect(evaluation.job.state).toBe("BLOCKED");
    const authorizationGates = await db.query(
      `select distinct on (gate_key) gate_key,status from component_readiness_gate_evidence
        where component_id=$1 and (gate_key like 'NEGATIVE_AUTH_%' or gate_key='TOKEN_EPOCH_INVALIDATION')
        order by gate_key,executed_at desc`,
      [created.componentId]
    );
    expect(authorizationGates.rows).toHaveLength(7);
    expect(authorizationGates.rows.every((gate) => gate.status === "PASS")).toBe(true);
    const secondEvaluation = await evaluateComponentReadiness(db, {
      jobId: String(created.id), integrationTokenId, accessTokenHmacKey: accessHmacKey,
      accessTokenHmacKeyId: config.ACCESS_TOKEN_HMAC_KEY_ID, vaultMasterKey: config.CONFIG_VAULT_MASTER_KEY_BASE64,
      vaultMasterKeyId: config.CONFIG_VAULT_MASTER_KEY_ID, integrationTokenHmacKey: config.INTEGRATION_TOKEN_HMAC_KEY_BASE64,
      integrationTokenHmacKeyId: config.INTEGRATION_TOKEN_HMAC_KEY_ID, correlationId: randomUUID()
    });
    expect(secondEvaluation.accessToken).toBeUndefined();
    const secretGates = await db.query(
      `select distinct on (gate_key) gate_key,status from component_readiness_gate_evidence
        where component_id=$1 and gate_key in ('SECRET_ALLOWED','SECRET_DENIED') order by gate_key,executed_at desc`,
      [created.componentId]
    );
    expect(secretGates.rows).toHaveLength(2);
    expect(secretGates.rows.every((gate) => gate.status === "PASS")).toBe(true);
    const pendingToken = await db.query("select principal_access_token_ciphertext,principal_access_token_handed_off_at from component_onboarding_job where id=$1", [created.id]);
    expect(String(pendingToken.rows[0].principal_access_token_ciphertext)).toMatch(/^vault:v1:/);
    expect(pendingToken.rows[0].principal_access_token_handed_off_at).toBeNull();
    expect(Number((await db.query("select count(*)::int count from principal where public_id like 'KCML-READINESS-%'")).rows[0].count)).toBe(0);
    expect((await db.query("select revoked_at is null as reusable from integration_token where id=$1", [integrationTokenId])).rows[0].reusable).toBe(true);
  });

  it("reserves repository component identity from source-phase onboarding and resolves runtime bootstrap by repository key", async () => {
    const integrationTokenId = randomUUID();
    const admin = await db.query("select id from admin_account order by created_at limit 1");
    await db.query(`insert into integration_token(
      id,label,lookup_digest,key_id,fingerprint,created_by,initial_expires_at,expires_at,max_expires_at,descriptor,
      token_kind,release_version,max_child_jobs
    ) values ($1,'Repository source onboarding test',$2,'test','repository-source-test',$3,now()+interval '24 hours',now()+interval '24 hours',now()+interval '24 hours',$4::jsonb,
      'SINGLE_COMPONENT',$5,1)`,
    [integrationTokenId, hmacToken(integrationTokenId, accessHmacKey), admin.rows[0].id, JSON.stringify({
      summary: "Repository component bootstrap test",
      businessPurpose: "Validate source-phase onboarding reservation for repository components.",
      serviceOwner: "KCML",
      technicalOwner: "KCML",
      criticality: "LOW"
    }), KCML_RELEASE.catalogVersion]);
    const submission = validateComponentOnboardingSubmission(repositoryComponentDescriptor);
    expect(submission.phase).toBe("SOURCE");
    const created = await createComponentOnboarding(db, {
      integrationTokenId,
      idempotencyKey: `repository-source-${integrationTokenId}`,
      manifest: submission,
      correlationId: randomUUID()
    });
    const component = await db.query(
      `select c.active_revision_id,p.metadata
         from component c join principal p on p.id=c.principal_id
        where c.id=$1`,
      [created.componentId]
    );
    expect(component.rows[0]?.active_revision_id ?? null).toBeNull();
    expect(component.rows[0]?.metadata).toMatchObject({ repositoryKey: "mail-vectorizace", onboardingPhase: "SOURCE" });
    const runtimeToken = await issueRepositoryComponentRuntimeSecretToken(db, {
      repositoryKey: "mail-vectorizace",
      accessTokenHmacKey: accessHmacKey,
      accessTokenHmacKeyId: config.ACCESS_TOKEN_HMAC_KEY_ID
    });
    expect(runtimeToken.componentId).toBe(created.componentId);
    expect(runtimeToken.token.length).toBeGreaterThanOrEqual(80);
  });

  it("keeps lifecycle, permission and access-token revocation as separate audited operations", async () => {
    const actorId = String((await db.query("select id from admin_account order by created_at limit 1")).rows[0].id);
    const before = await db.query("select policy_epoch from component where id=$1", [targetId]);
    await setComponentLifecycle(db, { componentId: targetId, action: "QUARANTINE", actorId, correlationId: randomUUID() });
    const quarantined = await db.query("select lifecycle_state,enabled from component where id=$1", [targetId]);
    expect(quarantined.rows[0]).toMatchObject({ lifecycle_state: "QUARANTINED", enabled: false });
    expect((await db.query("select revoked_at from principal_access_token where id=$1", [accessTokenId])).rows[0].revoked_at).toBeNull();
    await setComponentLifecycle(db, { componentId: targetId, action: "RESTORE", actorId, correlationId: randomUUID() });

    await setComponentPermissionEnabled(db, { componentId: sourceId, permissionId, enabled: false, actorId, correlationId: randomUUID() });
    expect((await db.query("select revoked_at is not null as revoked from component_permission where id=$1", [permissionId])).rows[0].revoked).toBe(true);
    await setComponentPermissionEnabled(db, { componentId: sourceId, permissionId, enabled: true, actorId, correlationId: randomUUID() });
    expect(Number((await db.query("select policy_epoch from component where id=$1", [targetId])).rows[0].policy_epoch)).toBeGreaterThan(Number(before.rows[0].policy_epoch));

    const rotated = await rotateComponentAccessToken(db, {
      componentId: sourceId, tokenId: accessTokenId, actorId, accessTokenHmacKey: accessHmacKey,
      accessTokenHmacKeyId: config.ACCESS_TOKEN_HMAC_KEY_ID, correlationId: randomUUID()
    });
    expect(rotated.accessToken.token).toBeTypeOf("string");
    expect((await db.query("select revoked_at is not null as revoked from principal_access_token where id=$1", [accessTokenId])).rows[0].revoked).toBe(true);
    const newToken = await db.query("select id from principal_access_token where fingerprint=$1", [rotated.accessToken.fingerprint]);
    await revokeComponentAccessToken(db, {
      componentId: sourceId, tokenId: String(newToken.rows[0].id), actorId, correlationId: randomUUID()
    });
    expect((await db.query("select revoked_at is not null as revoked from principal_access_token where id=$1", [newToken.rows[0].id])).rows[0].revoked).toBe(true);
  });

  it("stores the platform worker access token encrypted and checks its current permission", async () => {
    const actorId = String((await db.query("select id from admin_account order by created_at limit 1")).rows[0].id);
    const platformPrincipalId = String((await db.query("select principal_id from platform_worker_access_identity where singleton=true")).rows[0].principal_id);
    await db.query(`update platform_worker_access_identity set access_token_id=null,token_ciphertext=null,key_id=null,fingerprint=null,
      rotated_by=null,rotated_at=null,updated_at=now() where singleton=true`);
    await db.query("delete from principal_access_token where source_principal_id=$1", [platformPrincipalId]);
    const provisioned = await ensurePlatformWorkerAccessToken(db, config, { actorId, correlationId: randomUUID() });
    expect(provisioned).toMatchObject({ created: true, status: { configured: true } });
    const firstIdentity = await db.query("select access_token_id,fingerprint,token_ciphertext from platform_worker_access_identity where singleton=true");
    const unchanged = await ensurePlatformWorkerAccessToken(db, config, { actorId, correlationId: randomUUID() });
    expect(unchanged).toMatchObject({ created: false, status: { configured: true, fingerprint: firstIdentity.rows[0].fingerprint } });
    expect((await db.query("select access_token_id from platform_worker_access_identity where singleton=true")).rows[0].access_token_id)
      .toBe(firstIdentity.rows[0].access_token_id);
    expect(String(firstIdentity.rows[0].token_ciphertext)).toMatch(/^vault:v1:/);
    await db.query("update principal_access_token set revoked_at=now() where id=$1", [firstIdentity.rows[0].access_token_id]);
    await expect(ensurePlatformWorkerAccessToken(db, config, { actorId, correlationId: randomUUID() }))
      .rejects.toThrow("platform_worker_access_token_invalid_requires_admin_rotation");
    expect((await db.query("select access_token_id from platform_worker_access_identity where singleton=true")).rows[0].access_token_id)
      .toBe(firstIdentity.rows[0].access_token_id);
    const rotated = await rotatePlatformWorkerAccessToken(db, config, { actorId, correlationId: randomUUID() });
    expect(rotated.status).toMatchObject({ configured: true, fingerprint: rotated.accessToken.fingerprint });
    const stored = await db.query("select token_ciphertext from platform_worker_access_identity where singleton=true");
    expect(String(stored.rows[0].token_ciphertext)).toMatch(/^vault:v1:/);
    expect(String(stored.rows[0].token_ciphertext)).not.toContain(rotated.accessToken.token);
    await expect(authorizePlatformWorkerCall(db, config, {
      hostname: "kcml91002.kajovocml.hcasc.cz", scope: "platform.e2e.execute", route: "/v1/kcml/runtime/tools/call", correlationId: randomUUID()
    })).resolves.toMatchObject({ token: rotated.accessToken.token, decision: { allow: true } });
    await db.query("update principal_component_permission set revoked_at=now() where target_component_id=$1 and scope_name='platform.e2e.execute'", [targetId]);
    await expect(authorizePlatformWorkerCall(db, config, {
      hostname: "kcml91002.kajovocml.hcasc.cz", scope: "platform.e2e.execute", route: "/v1/kcml/runtime/tools/call", correlationId: randomUUID()
    })).rejects.toThrow("platform_worker_authorization_insufficient_scope");
  });
});
