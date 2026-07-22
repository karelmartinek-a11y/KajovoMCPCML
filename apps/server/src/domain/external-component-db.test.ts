import { beforeAll, afterAll, describe, expect, it } from "vitest";
import { loadConfig } from "../config.js";
import { createDb, type Db } from "../db.js";
import { dispatchExternalComponentCall } from "./external-component.js";
import { KCML_RELEASE } from "./release.js";

const enabled = process.env.KCML_TEST_DATABASE === "1";
const componentId = "92000000-0000-4000-8000-000000000001";
const targetId = "92000000-0000-4000-8000-000000000002";
const principalId = "92000000-0000-4000-8000-000000000003";
let db: Db;

describe.skipIf(!enabled)("external component circuit persistence", () => {
  beforeAll(async () => {
    db = createDb(loadConfig(process.env));
    await db.query("insert into principal(id,kind,public_id,status) values ($1,'COMPONENT','KCML92001','ACTIVE') on conflict (id) do update set status='ACTIVE'", [principalId]);
    await db.query(`insert into component(id,principal_id,kcml_number,code,hostname,display_name,category,registration_type,component_role,lifecycle_state,activation_state,operational_state,monitoring_state,enabled,ingress_enabled,pulse_enabled,egress_enabled,release_version) values ($1,$2,92001,'KCML92001','kcml92001.kajovocml.hcasc.cz','Circuit source','EXTERNAL_SERVICE','GENERIC_COMPONENT','SERVICE','ACTIVE','ACTIVE','HEALTHY','HEALTHY',true,true,true,true,$3) on conflict (id) do update set lifecycle_state='ACTIVE',activation_state='ACTIVE',operational_state='HEALTHY',monitoring_state='HEALTHY',enabled=true,ingress_enabled=true,pulse_enabled=true,egress_enabled=true,deregistered_at=null`, [componentId, principalId, KCML_RELEASE.catalogVersion]);
    await db.query(`insert into component_external_target(id,target_key,display_name,base_url,status,circuit_state,circuit_failure_count,circuit_failure_threshold,circuit_opened_at) values ($1,'circuit-test','Circuit target','https://example.com','ACTIVE','OPEN',5,5,now()) on conflict (id) do update set status='ACTIVE',circuit_state='OPEN',circuit_failure_count=5,circuit_failure_threshold=5,circuit_opened_at=now()`, [targetId]);
  });
  afterAll(async () => {
    if (!db) return;
    await db.query("delete from component_external_target where id=$1", [targetId]);
    await db.query("update component set lifecycle_state='DEREGISTERED',enabled=false,ingress_enabled=false,pulse_enabled=false,egress_enabled=false,deregistered_at=now() where id=$1", [componentId]);
    await db.end();
  });
  it("rejects an open circuit before permission lookup and network dispatch", async () => {
    await expect(dispatchExternalComponentCall(db, { sourceComponentId: componentId, targetKey: "circuit-test", routePath: "/mcp", scopeName: "component.outbound.pulse", payload: {}, correlationId: "92000000-0000-4000-8000-000000000003", accessToken: "long-lived-test-token", tokenFingerprint: "test-fingerprint" })).rejects.toMatchObject({ message: "external_gateway_circuit_open", statusCode: 503 });
  });

  it("does not reserve a half-open probe for a denied request after cooldown", async () => {
    await db.query("update component_external_target set circuit_state='OPEN',circuit_opened_at=now()-interval '10 minutes',circuit_probe_in_flight=false where id=$1", [targetId]);
    await expect(dispatchExternalComponentCall(db, { sourceComponentId: componentId, targetKey: "circuit-test", routePath: "/mcp", scopeName: "component.outbound.pulse", payload: {}, correlationId: "92000000-0000-4000-8000-000000000004", accessToken: "long-lived-test-token", tokenFingerprint: "test-fingerprint" })).rejects.toMatchObject({ message: "external_route_denied", statusCode: 403 });
    const target = await db.query("select circuit_state,circuit_probe_in_flight from component_external_target where id=$1", [targetId]);
    expect(target.rows[0]).toMatchObject({ circuit_state: "OPEN", circuit_probe_in_flight: false });
  });
});
