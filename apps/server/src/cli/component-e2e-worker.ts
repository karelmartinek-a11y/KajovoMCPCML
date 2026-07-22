import { randomUUID } from "node:crypto";
import { loadBootstrapConfig } from "../config.js";
import { createDb } from "../db.js";
import { loadConfigFromDb } from "../domain/operational-config.js";
import { processNextComponentE2ERun } from "../onboarding/component-e2e-worker.js";
import { recordPlatformWorkerHeartbeat } from "../onboarding/platform-worker-heartbeat.js";

const bootstrapConfig = loadBootstrapConfig();
const db = createDb(bootstrapConfig);
const config = await loadConfigFromDb(db, bootstrapConfig);
const workerId = `component-e2e-${randomUUID()}`;
const controller = new AbortController();
process.on("SIGTERM", () => controller.abort());
process.on("SIGINT", () => controller.abort());
try {
  await recordPlatformWorkerHeartbeat(db, { workerKind: "COMPONENT_E2E", workerId, buildId: config.BUILD_ID, completed: false });
  while (!controller.signal.aborted) {
    let worked = false;
    try {
      worked = await processNextComponentE2ERun(db, config, workerId);
      await recordPlatformWorkerHeartbeat(db, { workerKind: "COMPONENT_E2E", workerId, buildId: config.BUILD_ID, completed: worked });
    } catch (error) {
      await recordPlatformWorkerHeartbeat(db, { workerKind: "COMPONENT_E2E", workerId, buildId: config.BUILD_ID, completed: false,
        error: error instanceof Error ? error.message : "component_e2e_worker_failed" });
      throw error;
    }
    if (!worked) await new Promise((resolve) => setTimeout(resolve, config.ONBOARDING_WORKER_INTERVAL_MS));
  }
} finally {
  await db.end();
}
