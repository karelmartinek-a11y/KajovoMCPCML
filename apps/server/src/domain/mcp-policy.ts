import { Ajv2020, type AnySchema, type ValidateFunction } from "ajv/dist/2020.js";
import type { Db } from "../db.js";
import { tx } from "../db.js";
import { digestCanonicalJson } from "./registration.js";
import type { McpServer } from "./types.js";

export type McpRuntimeEffectClass = McpServer["effectClass"];
export type McpIdempotencyMode = "NOT_REQUIRED" | "REPLAY_COMPLETED" | "REJECT_REPLAY";

export class BoundedValidatorCache {
  private readonly entries = new Map<string, ValidateFunction>();

  constructor(private readonly maximumSize = 256) {
    if (!Number.isInteger(maximumSize) || maximumSize < 1) throw new Error("invalid_validator_cache_size");
  }

  get(server: McpServer, kind: "input" | "output", schema: unknown): ValidateFunction {
    const revision = server.activeRevisionId ?? server.contractVersion;
    const key = `${server.id}:${revision}:${server.manifestDigest}:${digestCanonicalJson(schema)}:${kind}`;
    const cached = this.entries.get(key);
    if (cached) {
      this.entries.delete(key);
      this.entries.set(key, cached);
      return cached;
    }
    const compiled = compileSchemaValidator(schema);
    this.entries.set(key, compiled);
    while (this.entries.size > this.maximumSize) {
      const oldest = this.entries.keys().next().value;
      if (!oldest) break;
      this.entries.delete(oldest);
    }
    return compiled;
  }

  invalidateServer(serverId: string): void {
    for (const key of this.entries.keys()) {
      if (key.startsWith(`${serverId}:`)) this.entries.delete(key);
    }
  }

  get size(): number {
    return this.entries.size;
  }
}

export function requiresIdempotencyKey(effectClass: McpRuntimeEffectClass): boolean {
  return effectClass !== "READ_ONLY";
}

export function idempotencyMode(effectClass: McpRuntimeEffectClass): McpIdempotencyMode {
  if (effectClass === "READ_ONLY") return "NOT_REQUIRED";
  if (effectClass === "IDEMPOTENT_WRITE") return "REPLAY_COMPLETED";
  return "REJECT_REPLAY";
}

export function abortOnTimeout(shutdownPolicy: McpServer["shutdownPolicy"]): boolean {
  return shutdownPolicy !== "COMPLETE_IN_FLIGHT";
}

export async function invokeWithDeadline<T>(
  timeoutMs: number,
  shutdownPolicy: McpServer["shutdownPolicy"],
  invoke: (signal: AbortSignal) => Promise<T>,
  externalSignal?: AbortSignal
): Promise<T> {
  const controller = new AbortController();
  let timeoutHandle: NodeJS.Timeout | undefined;
  const abortFromExternalSignal = (): void => controller.abort(externalSignal?.reason);
  if (externalSignal?.aborted) controller.abort(externalSignal.reason);
  else externalSignal?.addEventListener("abort", abortFromExternalSignal, { once: true });
  try {
    return await Promise.race([
      invoke(controller.signal),
      new Promise<never>((_resolve, reject) => {
        timeoutHandle = setTimeout(() => {
          if (abortOnTimeout(shutdownPolicy)) controller.abort();
          reject(Object.assign(new Error("handler_timeout"), { classification: "timeout" }));
        }, timeoutMs);
      })
    ]);
  } finally {
    externalSignal?.removeEventListener("abort", abortFromExternalSignal);
    if (timeoutHandle) clearTimeout(timeoutHandle);
  }
}

export async function acquireServerExecutionLease(db: Db, server: Pick<McpServer, "id" | "maxConcurrency" | "timeoutMs">): Promise<string> {
  return tx(db, async (client) => {
    await client.query("delete from function_concurrency_lease where expires_at <= now()");
    const locked = await client.query("select max_concurrency, timeout_ms from mcp_server where id=$1 for update", [server.id]);
    if (!locked.rowCount) throw Object.assign(new Error("server_missing"), { classification: "configuration" });
    const active = await client.query(
      "select count(*)::int as count from function_concurrency_lease where server_id=$1 and expires_at > now()",
      [server.id]
    );
    if (Number(active.rows[0].count) >= Number(locked.rows[0].max_concurrency)) {
      throw Object.assign(new Error("concurrency_limit_exceeded"), { classification: "saturation" });
    }
    const inserted = await client.query(
      "insert into function_concurrency_lease(server_id, expires_at) values ($1, now() + (($2 + 5000) || ' milliseconds')::interval) returning lease_id",
      [server.id, Number(locked.rows[0].timeout_ms)]
    );
    return String(inserted.rows[0].lease_id);
  });
}

export async function releaseServerExecutionLease(db: Db, leaseId: string): Promise<void> {
  await db.query("delete from function_concurrency_lease where lease_id=$1", [leaseId]);
}

export function serializeWithinLimit(value: unknown, maximumBytes: number, errorCode: string): string {
  const serialized = JSON.stringify(value);
  if (serialized === undefined || Buffer.byteLength(serialized) > maximumBytes) {
    throw Object.assign(new Error(errorCode), { classification: "size" });
  }
  return serialized;
}

export function compileSchemaValidator(schema: unknown): ValidateFunction {
  // Keep ownership of compiled validators in the bounded cache instead of AJV's
  // process-wide schema map, which otherwise retains every historical revision.
  return new Ajv2020({ strict: true, allErrors: true }).compile(schema as AnySchema);
}
