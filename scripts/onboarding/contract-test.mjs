import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";
import path from "node:path";

const directory = process.argv[2];
if (!directory) throw new Error("handler directory is required");
const module = await import(pathToFileURL(path.resolve(directory, "dist/index.js")).href);
assert.equal(typeof module.invoke, "function", "src/index.ts must export async function invoke(input, context)");
const result = module.invoke({}, {
  correlationId: "00000000-0000-4000-8000-000000000000",
  serverCode: "KCML0000",
  toolName: "contract_test",
  handlerVersion: "0.0.0",
  imageDigest: `sha256:${"0".repeat(64)}`,
  logger: { info() {}, error() {} }
});
assert.equal(typeof result?.then, "function", "invoke must return a Promise");
await result.catch(() => undefined);
