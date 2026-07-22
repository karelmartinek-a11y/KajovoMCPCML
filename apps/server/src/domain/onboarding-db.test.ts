import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadConfig } from "../config.js";
import { createDb, type Db } from "../db.js";

const enabled = process.env.KCML_TEST_DATABASE === "1";

describe.skipIf(!enabled)("integration token PostgreSQL invariants", () => {
  let db: Db;
  beforeAll(() => { db = createDb(loadConfig(process.env)); });
  afterAll(async () => db.end());

  it("enforces exactly 24 hours and one component job", async () => {
    const admin = await db.query("select id from admin_account order by created_at limit 1");
    await expect(db.query(
      `insert into integration_token(label,lookup_digest,key_id,fingerprint,created_by,initial_expires_at,expires_at,max_expires_at,descriptor,max_child_jobs)
       values ('invalid ttl',decode('9901','hex'),'test','invalid-ttl',$1,now()+interval '23 hours',now()+interval '23 hours',now()+interval '23 hours','{}',1)`,
      [admin.rows[0].id]
    )).rejects.toMatchObject({ code: "23514" });
    await expect(db.query(
      `insert into integration_token(label,lookup_digest,key_id,fingerprint,created_by,initial_expires_at,expires_at,max_expires_at,descriptor,max_child_jobs)
       values ('invalid jobs',decode('9902','hex'),'test','invalid-jobs',$1,now()+interval '24 hours',now()+interval '24 hours',now()+interval '24 hours','{}',2)`,
      [admin.rows[0].id]
    )).rejects.toMatchObject({ code: "23514" });
  });
});
