import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadConfig } from "../config.js";
import { createDb, type Db } from "../db.js";
import { hmacToken } from "../security/secrets.js";
import { ingestComponentAuditEvent } from "./component-audit.js";
import { authorizeComponentCall, issueComponentAccessToken } from "./component-auth.js";
import {
  claimComponentCredential,
  createComponentOnboarding,
  evaluateComponentReadiness,
  revokeComponentCredential,
  rotateComponentCredential,
  setComponentLifecycle,
  setComponentPermissionEnabled,
  validateComponentManifest
} from "./component.js";
import { KCML_RELEASE } from "./release.js";

const sourceId = "91000000-0000-4000-8000-000000000001";
const targetId = "91000000-0000-4000-8000-000000000002";
const credentialId = "91000000-0000-4000-8000-000000000003";
const permissionId = "91000000-0000-4000-8000-000000000004";
const revisionId = "91000000-0000-4000-8000-000000000005";
const clientSecret = "component-secret-for-current-policy-tests";
const enabled = process.env.KCML_TEST_DATABASE === "1";
let db: Db;
let accessHmacKey: Buffer;

describe.skipIf(!enabled)("component authorization and audit persistence", () => {
  beforeAll(async () => {
    const config = loadConfig(process.env);
    accessHmacKey = config.ACCESS_TOKEN_HMAC_KEY_BASE64;
    db = createDb(config);
    await db.query("delete from component_access_token where source_component_id=$1 or target_component_id=$2", [sourceId, targetId]);
    await db.query("delete from component_permission where source_component_id=$1 or target_component_id=$2", [sourceId, targetId]);
    await db.query("delete from component_credential where component_id=$1", [sourceId]);
    await db.query(`
      insert into component(id,kcml_number,code,hostname,display_name,category,registration_type,component_role,lifecycle_state,activation_state,operational_state,monitoring_state,enabled,ingress_enabled,pulse_enabled,egress_enabled,release_version)
      values
        ($1,91001,'KCML91001','kcml91001.component.test','Zdroj','AI_CLIENT','GENERIC_COMPONENT','CLIENT','ACTIVE','ACTIVE','HEALTHY','HEALTHY',true,true,true,true,$3),
        ($2,91002,'KCML91002','kcml91002.component.test','Cíl','MANAGED_RUNTIME','GENERIC_COMPONENT','RUNTIME','ACTIVE','ACTIVE','HEALTHY','HEALTHY',true,true,true,true,$3)
      on conflict (id) do update set lifecycle_state='ACTIVE',activation_state='ACTIVE',operational_state='HEALTHY',monitoring_state='HEALTHY',
        enabled=true,ingress_enabled=true,pulse_enabled=true,egress_enabled=true,release_version=excluded.release_version`,
      [sourceId, targetId, KCML_RELEASE.catalogVersion]
    );
    await db.query(`insert into component_revision(id,component_id,revision,validation_state,manifest,manifest_digest,capabilities,protocols,transports)
      values ($1,$2,'1.0.0','APPROVED','{}','sha256:test',array['component.pulse','component.audit.write'],array['HTTPS'],array['HTTPS'])
      on conflict (id) do update set validation_state='APPROVED'`, [revisionId, targetId]);
    await db.query("update component set active_revision_id=$2 where id=$1", [targetId, revisionId]);
    await db.query("insert into component_audit_stream(component_id) values ($1),($2) on conflict (component_id) do nothing", [sourceId, targetId]);
    await db.query(`insert into component_credential(id,component_id,public_id,key_id,secret_digest,secret_fingerprint)
      values ($1,$2,'KCML91001-C01','test',$3,'fingerprint-test')`, [credentialId, sourceId, hmacToken(clientSecret, accessHmacKey)]);
    await db.query(`insert into component_permission(id,source_component_id,target_component_id,route_pattern,scope_name)
      values ($1,$2,$3,'/v2/*','component.pulse'),(gen_random_uuid(),$2,$3,'/v2/*','component.audit.write')`, [permissionId, sourceId, targetId]);
  });

  afterAll(async () => {
    if (!db) return;
    await db.query("delete from component_access_token where source_component_id=$1 or target_component_id=$2", [sourceId, targetId]);
    await db.query("delete from component_permission where source_component_id=$1 or target_component_id=$2", [sourceId, targetId]);
    await db.query("delete from component_credential where component_id=$1", [sourceId]);
    await db.query("update component set enabled=false,ingress_enabled=false,pulse_enabled=false,egress_enabled=false,activation_state='INACTIVE',operational_state='RETIRED',lifecycle_state='DEREGISTERED',deregistered_at=now() where id=any($1::uuid[])", [[sourceId, targetId]]);
    await db.end();
  });

  it("checks current route, scope and component state without revoking a token on deactivation", async () => {
    const issued = await issueComponentAccessToken(db, {
      clientId: "KCML91001-C01", clientSecret, resource: "https://kcml91002.component.test",
      hmacKey: accessHmacKey, keyId: "test", correlationId: randomUUID()
    });
    const parameters = {
      token: issued.access_token, audience: "https://kcml91002.component.test", host: "kcml91002.component.test",
      scope: "component.pulse", route: "/v2/component-pulse", hmacKey: accessHmacKey
    };
    expect((await authorizeComponentCall(db, { ...parameters, correlationId: randomUUID() })).reasonCode).toBe("allowed");
    await db.query("update component_permission set revoked_at=now() where id=$1", [permissionId]);
    expect((await authorizeComponentCall(db, { ...parameters, correlationId: randomUUID() })).reasonCode).toBe("route_denied");
    await db.query("update component_permission set revoked_at=null where id=$1", [permissionId]);
    await db.query("update component set enabled=false,ingress_enabled=false,pulse_enabled=false,egress_enabled=false,activation_state='READY',operational_state='DISABLED' where id=$1", [targetId]);
    expect((await authorizeComponentCall(db, { ...parameters, correlationId: randomUUID() })).reasonCode).toBe("component_disabled");
    expect((await db.query("select revoked_at from component_access_token where fingerprint=$1", ["fingerprint-test"])).rowCount).toBe(0);
    const stored = await db.query("select revoked_at from component_access_token where target_component_id=$1", [targetId]);
    expect(stored.rows[0].revoked_at).toBeNull();
    await db.query("update component set enabled=true,ingress_enabled=true,pulse_enabled=true,egress_enabled=true,activation_state='ACTIVE',operational_state='HEALTHY' where id=$1", [targetId]);
    expect((await authorizeComponentCall(db, { ...parameters, correlationId: randomUUID() })).reasonCode).toBe("allowed");
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

  it("keeps onboarding idempotent and reveals a component credential exactly once", async () => {
    const integrationTokenId = randomUUID();
    const admin = await db.query("select id from admin_account order by created_at limit 1");
    await db.query(`insert into integration_token(
      id,label,lookup_digest,key_id,fingerprint,created_by,initial_expires_at,expires_at,max_expires_at,descriptor,release_version
    ) values ($1,'Component DB test',$2,'test','component-db-test',$3,now()+interval '1 hour',now()+interval '1 hour',now()+interval '1 day',$4::jsonb,'2026.07.21')`,
    [integrationTokenId, hmacToken(integrationTokenId, accessHmacKey), admin.rows[0].id, JSON.stringify({ summary: "Component test", businessPurpose: "Validate component onboarding credential issuance safely.", serviceOwner: "KCML", technicalOwner: "KCML", criticality: "LOW" })]);
    const manifest = validateComponentManifest({
      schemaVersion: KCML_RELEASE.catalogVersion, name: "Self-service test", category: "MANAGED_RUNTIME", registrationType: "GENERIC_COMPONENT", role: "RUNTIME", revision: "1.0.0",
      capabilities: ["component.discovery"], protocols: ["HTTPS"], transports: ["HTTPS"], owners: { service: "KCML" }, contacts: {},
      monitoring: { enabled: true }, audit: { enabled: true, replaySupported: true }, authorization: { mode: "OAUTH2_CLIENT_CREDENTIALS" }, endpoint: { public: true }, technicalDisable: { supported: true }
    });
    const input = { integrationTokenId, idempotencyKey: `component-${integrationTokenId}`, manifest, claimHmacKey: accessHmacKey, baseDomain: "component.test", correlationId: randomUUID() };
    const created = await createComponentOnboarding(db, input);
    expect((await createComponentOnboarding(db, input)).id).toBe(created.id);
    const readiness = await evaluateComponentReadiness(db, { jobId: String(created.id), integrationTokenId, claimHmacKey: accessHmacKey, correlationId: randomUUID() });
    expect(readiness.job.state).toBe("READY");
    expect(readiness.credentialClaimToken).toBeTypeOf("string");
    const credential = await claimComponentCredential(db, {
      jobId: String(created.id), integrationTokenId, claimToken: readiness.credentialClaimToken!, claimHmacKey: accessHmacKey,
      credentialHmacKey: accessHmacKey, keyId: "test", correlationId: randomUUID()
    });
    expect(credential.clientId).toMatch(/^KCML[0-9]+-C01$/);
    await expect(claimComponentCredential(db, {
      jobId: String(created.id), integrationTokenId, claimToken: readiness.credentialClaimToken!, claimHmacKey: accessHmacKey,
      credentialHmacKey: accessHmacKey, keyId: "test", correlationId: randomUUID()
    })).rejects.toThrow("credential_claim_invalid");
  });

  it("keeps lifecycle, permission and credential revocation as separate audited operations", async () => {
    const actorId = String((await db.query("select id from admin_account order by created_at limit 1")).rows[0].id);
    const before = await db.query("select policy_epoch from component where id=$1", [targetId]);
    await setComponentLifecycle(db, { componentId: targetId, action: "QUARANTINE", actorId, correlationId: randomUUID() });
    const quarantined = await db.query("select lifecycle_state,enabled from component where id=$1", [targetId]);
    expect(quarantined.rows[0]).toMatchObject({ lifecycle_state: "QUARANTINED", enabled: false });
    expect((await db.query("select status from component_credential where id=$1", [credentialId])).rows[0].status).toBe("ACTIVE");
    await setComponentLifecycle(db, { componentId: targetId, action: "RESTORE", actorId, correlationId: randomUUID() });

    await setComponentPermissionEnabled(db, { componentId: sourceId, permissionId, enabled: false, actorId, correlationId: randomUUID() });
    expect((await db.query("select revoked_at is not null as revoked from component_permission where id=$1", [permissionId])).rows[0].revoked).toBe(true);
    await setComponentPermissionEnabled(db, { componentId: sourceId, permissionId, enabled: true, actorId, correlationId: randomUUID() });
    expect(Number((await db.query("select policy_epoch from component where id=$1", [targetId])).rows[0].policy_epoch)).toBeGreaterThan(Number(before.rows[0].policy_epoch));

    const rotated = await rotateComponentCredential(db, {
      componentId: sourceId, credentialId, actorId, credentialHmacKey: accessHmacKey, keyId: "test", correlationId: randomUUID()
    });
    expect(rotated.credential.clientId).toBe("KCML91001-C02");
    expect(rotated.credential.clientSecret).toBeTypeOf("string");
    expect((await db.query("select status from component_credential where id=$1", [credentialId])).rows[0].status).toBe("REVOKED");
    const newCredential = await db.query("select id from component_credential where public_id=$1", [rotated.credential.clientId]);
    await revokeComponentCredential(db, {
      componentId: sourceId, credentialId: String(newCredential.rows[0].id), actorId, correlationId: randomUUID()
    });
    expect((await db.query("select status from component_credential where id=$1", [newCredential.rows[0].id])).rows[0].status).toBe("REVOKED");
  });
});
