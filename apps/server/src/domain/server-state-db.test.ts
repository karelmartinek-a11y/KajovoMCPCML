import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { loadConfig } from "../config.js";
import { createDb, tx, type Db } from "../db.js";
import { transitionServerState } from "./server-state.js";

const enabled = process.env.KCML_TEST_DATABASE === "1";

describe.skipIf(!enabled)("server state PostgreSQL transitions", () => {
  let db: Db;

  beforeAll(() => {
    db = createDb(loadConfig(process.env));
  });

  beforeEach(async () => {
    await db.query("truncate table mcp_server,audit_event restart identity cascade");
    await db.query("update audit_head set last_sequence=0,event_hash=null,updated_at=now() where singleton=true");
  });

  afterAll(async () => db.end());

  it("binds registration state parameters without PostgreSQL type ambiguity", async () => {
    const server = await db.query(
      `insert into mcp_server(
         kcml_number,code,hostname,tool_name,display_name,description,enabled,
         registration_state,operational_state,input_schema,output_schema,handler_key,
         handler_version,contract_version,artifact_digest,manifest_digest
       ) values (1,'KCML0001','kcml0001.hcasc.cz','test_tool','Test','Test',true,
         'ACTIVE','HEALTHY','{}','{}','test','1.0.0','1.0.0',$1,$2) returning id`,
      [`sha256:${"a".repeat(64)}`, `sha256:${"b".repeat(64)}`]
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

    await tx(db, (client) => transitionServerState(client, {
      serverId,
      to: "SUSPENDED",
      actorType: "system",
      reason: "db_parameter_regression_test",
      correlationId: randomUUID()
    }));

    const state = await db.query("select registration_state,operational_state,enabled from mcp_server where id=$1", [serverId]);
    expect(state.rows[0]).toMatchObject({ registration_state: "SUSPENDED", operational_state: "DISABLED", enabled: false });
  });
});
