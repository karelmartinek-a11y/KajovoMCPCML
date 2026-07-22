import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { loadConfig } from "../config.js";
import { createDb, type Db } from "../db.js";
import { acquireServerExecutionLease, releaseServerExecutionLease } from "./mcp-policy.js";

const enabled = process.env.KCML_TEST_DATABASE === "1";

describe.skipIf(!enabled)("MCP concurrency PostgreSQL lease", () => {
  let db: Db;

  beforeAll(() => { db = createDb(loadConfig(process.env)); });
  beforeEach(async () => {
    await db.query("truncate table function_concurrency_lease,mcp_server restart identity cascade");
    await db.query("delete from component where kcml_number=$1", [9002]);
    await db.query("delete from principal where public_id='KCML9002'");
  });
  afterAll(async () => db.end());

  it("allows exactly one of two concurrent acquisitions at maxConcurrency one", async () => {
    const principal = await db.query("insert into principal(kind,public_id,status) values ('COMPONENT','KCML9002','ACTIVE') returning id");
    const component = await db.query(
      `insert into component(principal_id,kcml_number,code,hostname,display_name,category,registration_type,component_role,lifecycle_state,activation_state,operational_state,monitoring_state,enabled,release_version)
       values ($1,9002,'KCML9002','kcml9002.kajovocml.hcasc.cz','Lease','EXTERNAL_SERVICE','GENERIC_COMPONENT','SERVICE','ACTIVE','ACTIVE','HEALTHY','HEALTHY',true,'2026.07.22-compliance.1') returning id`,
      [principal.rows[0].id]
    );
    const inserted = await db.query(
      `insert into mcp_server(component_id,kcml_number,code,hostname,tool_name,display_name,description,enabled,registration_state,operational_state,input_schema,output_schema,handler_key,handler_version,contract_version,artifact_digest,manifest_digest,max_concurrency,timeout_ms)
       values ($3,9002,'KCML9002','kcml9002.example.invalid','lease_test','Lease','Lease',true,'ACTIVE','HEALTHY','{}','{}','test','1','1',$1,$2,1,1000) returning id`,
      [`sha256:${"a".repeat(64)}`, `sha256:${"b".repeat(64)}`, component.rows[0].id]
    );
    const server = { id: String(inserted.rows[0].id), maxConcurrency: 1, timeoutMs: 1000 };
    const results = await Promise.allSettled([
      acquireServerExecutionLease(db, server),
      acquireServerExecutionLease(db, server)
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    const fulfilled = results.find((result): result is PromiseFulfilledResult<string> => result.status === "fulfilled");
    expect(fulfilled).toBeDefined();
    await releaseServerExecutionLease(db, fulfilled!.value);
    const nextLease = await acquireServerExecutionLease(db, server);
    expect(nextLease).toEqual(expect.any(String));
    await releaseServerExecutionLease(db, nextLease);
  });
});
