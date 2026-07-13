import { loadConfig } from "../config.js";
import { createDb } from "../db.js";
import { OnboardingWorker } from "../onboarding/worker.js";

const config = loadConfig();
if (!config.ONBOARDING_WORKER_ENABLED) throw new Error("ONBOARDING_WORKER_ENABLED must be true for the worker process");
const db = createDb(config);
const worker = new OnboardingWorker(db, config);
const controller = new AbortController();
process.on("SIGTERM", () => controller.abort());
process.on("SIGINT", () => controller.abort());
try {
  await worker.run(controller.signal);
} finally {
  await db.end();
}
