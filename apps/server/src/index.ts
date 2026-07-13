import { loadConfig } from "./config.js";
import { createDb } from "./db.js";
import { buildApp } from "./app.js";
import "./handlers/home-assistant-device-inventory.js";

const config = loadConfig();
const db = createDb(config);
const app = await buildApp(config, db);

try {
  await app.listen({ port: config.PORT, host: "127.0.0.1" });
} catch (error) {
  app.log.error({ error }, "startup failed");
  process.exit(1);
}
