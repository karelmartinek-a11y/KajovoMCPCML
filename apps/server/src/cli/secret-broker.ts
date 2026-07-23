import { loadBootstrapConfig } from "../config.js";
import { createDb } from "../db.js";
import { loadConfigFromDb } from "../domain/operational-config.js";
import { buildSecretBroker, listenSecretBroker } from "../onboarding/secret-broker.js";

const bootstrapConfig = loadBootstrapConfig();
const db = createDb(bootstrapConfig);
const config = await loadConfigFromDb(db, bootstrapConfig);
const server = await buildSecretBroker(db, config);
await listenSecretBroker(server, config.SECRET_BROKER_SOCKET_PATH);

async function shutdown(): Promise<void> {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await db.end();
}

process.on("SIGTERM", () => { void shutdown(); });
process.on("SIGINT", () => { void shutdown(); });
