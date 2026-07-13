import { loadConfig } from "../config.js";
import { createDb } from "../db.js";
import { buildEgressProxy, listenEgressProxy } from "../onboarding/egress-proxy.js";

const config = loadConfig();
const db = createDb(config);
const server = await buildEgressProxy(db, config);
await listenEgressProxy(server, config.EGRESS_PROXY_SOCKET_PATH);

async function shutdown(): Promise<void> {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await db.end();
}
process.on("SIGTERM", () => { void shutdown(); });
process.on("SIGINT", () => { void shutdown(); });
