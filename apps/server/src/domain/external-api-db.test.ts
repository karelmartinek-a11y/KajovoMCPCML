import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadConfig } from "../config.js";
import { createDb, type Db } from "../db.js";

const enabled = process.env.KCML_TEST_DATABASE === "1";

describe.skipIf(!enabled)("retired external API registry PostgreSQL compatibility", () => {
  let db: Db;
  beforeAll(() => { db = createDb(loadConfig(process.env)); });
  afterAll(async () => db.end());

  it("rejects a managed-service row that is not backed by a canonical component", async () => {
    await expect(db.query(
      `insert into managed_service(code,slug,display_name,description,service_kind,lifecycle_state,operational_state,enabled,public_hostname,base_url,resource_uri,api_state)
       values ('KCML99001','legacy-orphan','Legacy orphan','Must fail','EXTERNAL_API','REGISTERED_DISABLED','DISABLED',false,
         'kcml99001.kajovocml.hcasc.cz','https://example.invalid','https://kcml99001.kajovocml.hcasc.cz','DISABLED')`
    )).rejects.toMatchObject({ code: "23502" });
  });

  it("rejects an MCP compatibility row that is not backed by a canonical component", async () => {
    await expect(db.query(
      `insert into mcp_server(kcml_number,code,hostname,tool_name,display_name,description,enabled,registration_state,operational_state,input_schema,output_schema,handler_key,handler_version,contract_version,artifact_digest,manifest_digest)
       values (99002,'KCML99002','kcml99002.kajovocml.hcasc.cz','legacy_orphan','Legacy orphan','Must fail',false,'REGISTERED_DISABLED','DISABLED','{}','{}','none','0','0',$1,$2)`,
      [`sha256:${"a".repeat(64)}`, `sha256:${"b".repeat(64)}`]
    )).rejects.toMatchObject({ code: "23502" });
  });
});
