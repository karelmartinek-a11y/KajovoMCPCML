import { randomUUID } from "node:crypto";
import { loadBootstrapConfig } from "../config.js";
import { createDb } from "../db.js";
import { loadConfigFromDb } from "../domain/operational-config.js";
import { ensurePlatformWorkerAccessToken } from "../domain/platform-worker-access.js";

const bootstrapConfig = loadBootstrapConfig();
const db = createDb(bootstrapConfig);

try {
  const config = await loadConfigFromDb(db, bootstrapConfig);
  const actor = await db.query(
    "select id from admin_account where username=$1 and active=true",
    [config.ADMIN_BOOTSTRAP_USERNAME]
  );
  if (!actor.rowCount) throw new Error("active_bootstrap_admin_required_for_platform_worker_access");
  const result = await ensurePlatformWorkerAccessToken(db, config, {
    actorId: String(actor.rows[0].id),
    correlationId: randomUUID()
  });
  process.stdout.write(`platform-worker-access:CONFIGURED created=${result.created}\n`);
} finally {
  await db.end();
}
