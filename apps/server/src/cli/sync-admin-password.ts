import argon2 from "argon2";
import { randomUUID } from "node:crypto";
import { loadConfig } from "../config.js";
import { createDb } from "../db.js";
import { tx } from "../db.js";
import { appendAudit } from "../domain/audit.js";
import { encryptMfaSecret } from "../security/secrets.js";

const config = loadConfig();
const db = createDb(config);
const pass = process.env.PASS;

try {
  if (pass === undefined || pass.length === 0) throw new Error("PASS must not be empty");
  const hash = await argon2.hash(pass, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 1 });
  const encryptedTotpSecret = config.ADMIN_TOTP_SECRET
    ? encryptMfaSecret(config.ADMIN_TOTP_SECRET, config.MFA_ENCRYPTION_KEY_BASE64)
    : null;
  await tx(db, async (client) => {
    const account = await client.query(
      `insert into admin_account(username, mfa_enabled)
       values ($1,false)
       on conflict (username) do update set username=excluded.username
       returning id`,
      [config.ADMIN_BOOTSTRAP_USERNAME]
    );
    const accountId = String(account.rows[0].id);
    await client.query(
      "update admin_account set password_hash=$1, password_changed_at=now(), mfa_enabled=$2, mfa_secret=$3 where id=$4",
      [hash, Boolean(config.ADMIN_TOTP_SECRET), encryptedTotpSecret, accountId]
    );
    await client.query("update admin_session set revoked_at=now() where account_id=$1 and revoked_at is null", [accountId]);
    await appendAudit(client, { eventType: "admin.password.synced", actorType: "deployment", objectType: "admin_account", objectId: accountId, correlationId: randomUUID() });
  });
  if (config.ADMIN_TOTP_SECRET) {
    process.stderr.write("Admin password synchronized from PASS; MFA is configured; existing admin sessions revoked.\n");
  } else {
    process.stderr.write("Admin password synchronized from PASS; existing admin sessions revoked.\n");
  }
} finally {
  await db.end();
}
