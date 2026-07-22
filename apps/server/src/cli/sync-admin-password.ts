import { randomUUID } from "node:crypto";
import { loadBootstrapConfig } from "../config.js";
import { createDb } from "../db.js";
import { tx } from "../db.js";
import {
  requireDeploymentManagedAdminPassword,
  syncDeploymentManagedAdmin,
  verifyDeploymentManagedAdminPassword
} from "../domain/deployment-managed-admin.js";
import { loadConfigFromDb } from "../domain/operational-config.js";

const bootstrapConfig = loadBootstrapConfig();
const db = createDb(bootstrapConfig);
const config = await loadConfigFromDb(db, bootstrapConfig);
const pass = process.env.PASS;

try {
  const password = requireDeploymentManagedAdminPassword(pass);
  const accountId = await tx(db, async (client) => {
    const result = await syncDeploymentManagedAdmin(client, {
      username: config.ADMIN_BOOTSTRAP_USERNAME,
      password,
      mfaEncryptionKey: config.MFA_ENCRYPTION_KEY_BASE64,
      configuredTotpSecret: config.ADMIN_TOTP_SECRET,
      actorType: "deployment",
      eventType: "admin.password.synced",
      correlationId: randomUUID()
    });
    return result.accountId;
  });
  await tx(db, async (client) => {
    await verifyDeploymentManagedAdminPassword(client, accountId, password, "deployment", randomUUID());
  });
  if (config.ADMIN_TOTP_SECRET) {
    process.stderr.write("Admin password synchronized from PASS; MFA is configured; sessions and trusted devices are invalidated.\n");
  } else {
    process.stderr.write("Admin password synchronized from PASS; sessions and trusted devices are invalidated.\n");
  }
} finally {
  await db.end();
}
