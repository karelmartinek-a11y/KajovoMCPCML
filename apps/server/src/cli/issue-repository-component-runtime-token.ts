import { loadBootstrapConfig } from "../config.js";
import { createDb } from "../db.js";
import { loadConfigFromDb } from "../domain/operational-config.js";
import { issueRepositoryComponentRuntimeSecretToken } from "../domain/repository-component-runtime-auth.js";

const repositoryKey = process.argv[2];
if (!repositoryKey) {
  process.stderr.write("repository key required\n");
  process.exit(2);
}

const bootstrapConfig = loadBootstrapConfig();
const db = createDb(bootstrapConfig);

try {
  const config = await loadConfigFromDb(db, bootstrapConfig);
  const issued = await issueRepositoryComponentRuntimeSecretToken(db, {
    repositoryKey,
    accessTokenHmacKey: config.ACCESS_TOKEN_HMAC_KEY_BASE64,
    accessTokenHmacKeyId: config.ACCESS_TOKEN_HMAC_KEY_ID
  });
  process.stdout.write(`${issued.token}\n`);
} finally {
  await db.end();
}
