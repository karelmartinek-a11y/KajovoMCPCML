import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { loadConfig } from "../config.js";
import { createDb, tx, type Db } from "../db.js";
import { setServerEnabled, transitionServerState } from "./server-state.js";

const enabled = process.env.KCML_TEST_DATABASE === "1";

describe.skipIf(!enabled)("server state PostgreSQL transitions", () => {
  let db: Db;

  async function createCanonicalComponent(kcmlNumber: number, code: string): Promise<string> {
    const principal = await db.query("insert into principal(kind,public_id,status) values ('COMPONENT',$1,'ACTIVE') returning id", [`${code}-${randomUUID()}`]);
    const component = await db.query(
      `insert into component(principal_id,kcml_number,code,hostname,display_name,category,registration_type,component_role,lifecycle_state,activation_state,operational_state,monitoring_state,enabled,release_version)
       values ($1,$2,$3,$4,'Legacy adapter test','EXTERNAL_SERVICE','GENERIC_COMPONENT','SERVICE','ACTIVE','ACTIVE','HEALTHY','HEALTHY',true,'2026.07.22-compliance.1') returning id`,
      [principal.rows[0].id, kcmlNumber, code, `${code.toLowerCase()}.kajovocml.hcasc.cz`]
    );
    return String(component.rows[0].id);
  }

  beforeAll(() => {
    db = createDb(loadConfig(process.env));
  });

  beforeEach(async () => {
    await db.query("truncate table kaja_credential,mcp_server,audit_event restart identity cascade");
    await db.query("update audit_head set last_sequence=0,event_hash=null,updated_at=now() where singleton=true");
  });

  afterAll(async () => db.end());

  it("binds registration state parameters without PostgreSQL type ambiguity", async () => {
    const kcmlNumber = Number((await db.query("select nextval('kcml_number_seq') as value")).rows[0].value);
    const code = `KCML${String(kcmlNumber).padStart(4, "0")}`;
    const hostname = `kcml${String(kcmlNumber).padStart(4, "0")}.example.invalid`;
    const audience = `https://${hostname}/mcp`;
    const componentId = await createCanonicalComponent(kcmlNumber, code);
    const server = await db.query(
      `insert into mcp_server(
         component_id,kcml_number,code,hostname,tool_name,display_name,description,enabled,
         registration_state,operational_state,input_schema,output_schema,handler_key,
         handler_version,contract_version,artifact_digest,manifest_digest
       ) values ($6,$3,$4,$5,'test_tool','Test','Test',true,
         'ACTIVE','HEALTHY','{}','{}','test','1.0.0','1.0.0',$1,$2) returning id`,
      [`sha256:${"a".repeat(64)}`, `sha256:${"b".repeat(64)}`, kcmlNumber, code, hostname, componentId]
    );
    const serverId = String(server.rows[0].id);
    const revision = await db.query(
      `insert into registration_revision(
         server_id,revision,state,manifest,manifest_digest,artifact_digest,schema_version,
         approved_at,review_due_at,review_interval_days,certification_digest,validation_state,active
       ) values ($1,'test-1','ACTIVE','{}',$2,$3,'1.5',now(),now()+interval '180 days',180,$2,'VALID',true)
       returning id`,
      [serverId, `sha256:${"b".repeat(64)}`, `sha256:${"a".repeat(64)}`]
    );
    await db.query("update mcp_server set active_revision_id=$2 where id=$1", [serverId, revision.rows[0].id]);
    await db.query(
      "insert into monitoring_profile(server_id,profile,enabled,registration_revision_id,profile_digest) values ($1,'{}',true,$2,$3)",
      [serverId, revision.rows[0].id, `sha256:${"c".repeat(64)}`]
    );
    const credential = await db.query(
      "insert into kaja_credential(public_id,secret_hash,secret_fingerprint,label) values ('Kaja9001','hash','fingerprint','State test') returning id,revocation_epoch,principal_token_epoch"
    );
    await db.query(
      `insert into access_token(lookup_digest,key_id,fingerprint,credential_id,server_id,audience,expires_at,credential_revocation_epoch,server_revocation_epoch)
       select decode('01','hex'),'v1','access-fingerprint',$1,id,$4,now()+interval '1 hour',$2,revocation_epoch
         from mcp_server where id=$3`,
      [credential.rows[0].id, credential.rows[0].revocation_epoch, serverId, audience]
    );
    const managed = await db.query(
      `insert into managed_service(component_id,legacy_mcp_server_id,code,slug,display_name,description,service_kind,lifecycle_state,operational_state,enabled,public_hostname,base_url,resource_uri,api_state)
       values ($7,$1,$2,$3,'Test','Test','MCP','ACTIVE','HEALTHY',true,$4,$5,$6,'ENABLED') returning id,revocation_epoch,service_token_epoch,permission_epoch,active_revision_epoch`,
      [serverId, code, hostname.split(".")[0], hostname, `https://${hostname}`, audience, componentId]
    );
    await db.query(
      `insert into managed_service_access_token(lookup_digest,key_id,fingerprint,credential_id,managed_service_id,audience,expires_at,credential_revocation_epoch,service_revocation_epoch,principal_token_epoch,service_token_epoch,permission_epoch_snapshot,active_revision_epoch_snapshot)
       values (decode('02','hex'),'v1','managed-fingerprint',$1,$2,'https://kcml0001.example.invalid/mcp',now()+interval '1 hour',$3,$4,$5,$6,$7,$8)`,
      [credential.rows[0].id, managed.rows[0].id, credential.rows[0].revocation_epoch, managed.rows[0].revocation_epoch,
        credential.rows[0].principal_token_epoch, managed.rows[0].service_token_epoch, managed.rows[0].permission_epoch, managed.rows[0].active_revision_epoch]
    );
    const previousEpoch = String((await db.query("select revocation_epoch from mcp_server where id=$1", [serverId])).rows[0].revocation_epoch);

    await tx(db, (client) => transitionServerState(client, {
      serverId,
      to: "SUSPENDED",
      actorType: "system",
      reason: "db_parameter_regression_test",
      correlationId: randomUUID()
    }));

    const state = await db.query("select registration_state,operational_state,enabled,revocation_epoch from mcp_server where id=$1", [serverId]);
    expect(state.rows[0]).toMatchObject({ registration_state: "SUSPENDED", operational_state: "DISABLED", enabled: false });
    expect(String(state.rows[0].revocation_epoch)).toBe(previousEpoch);
    await expect(db.query("select revoked_at is not null as revoked from access_token where server_id=$1", [serverId]))
      .resolves.toMatchObject({ rows: [{ revoked: false }] });
    await expect(db.query("select lifecycle_state,operational_state,enabled,api_state from managed_service where id=$1", [managed.rows[0].id]))
      .resolves.toMatchObject({ rows: [{ lifecycle_state: "SUSPENDED", operational_state: "DISABLED", enabled: false, api_state: "DISABLED" }] });
    await expect(db.query("select revoked_at is not null as revoked from managed_service_access_token where managed_service_id=$1", [managed.rows[0].id]))
      .resolves.toMatchObject({ rows: [{ revoked: false }] });
  });

  it("serializes concurrent disable requests into one effective transition", async () => {
    const kcmlNumber = Number((await db.query("select nextval('kcml_number_seq') as value")).rows[0].value);
    const code = `KCML${String(kcmlNumber).padStart(4, "0")}`;
    const hostname = `kcml${String(kcmlNumber).padStart(4, "0")}.example.invalid`;
    const componentId = await createCanonicalComponent(kcmlNumber, code);
    const server = await db.query(
      `insert into mcp_server(
         component_id,kcml_number,code,hostname,tool_name,display_name,description,enabled,
         registration_state,operational_state,input_schema,output_schema,handler_key,
         handler_version,contract_version,artifact_digest,manifest_digest
       ) values ($6,$3,$4,$5,'concurrent_disable','Concurrent','Concurrent',true,
         'ACTIVE','HEALTHY','{}','{}','test','1.0.0','1.0.0',$1,$2) returning id`,
      [`sha256:${"d".repeat(64)}`, `sha256:${"e".repeat(64)}`, kcmlNumber, code, hostname, componentId]
    );
    const serverId = String(server.rows[0].id);

    await Promise.all([
      setServerEnabled(db, "admin-1", randomUUID(), serverId, false),
      setServerEnabled(db, "admin-1", randomUUID(), serverId, false)
    ]);

    await expect(db.query("select registration_state,operational_state,enabled from mcp_server where id=$1", [serverId]))
      .resolves.toMatchObject({ rows: [{ registration_state: "REGISTERED_DISABLED", operational_state: "DISABLED", enabled: false }] });
    await expect(db.query("select count(*)::int as count from server_state_history where server_id=$1 and reason='manual_disable'", [serverId]))
      .resolves.toMatchObject({ rows: [{ count: 1 }] });
    await expect(db.query("select count(*)::int as count from audit_event where object_id=$1 and event_type='mcp_server.state.registered_disabled'", [serverId]))
      .resolves.toMatchObject({ rows: [{ count: 1 }] });
  });
});
