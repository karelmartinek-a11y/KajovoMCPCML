import Fastify from "fastify";
import rateLimit from "@fastify/rate-limit";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { loadConfig } from "../config.js";
import { createDb, type Db } from "../db.js";
import { createPostgresRateLimitStore } from "./postgres-rate-limit-store.js";

const enabled = process.env.KCML_TEST_DATABASE === "1";

type RateStore = {
  incr(key: string, callback: (error: Error | null, result?: { current: number; ttl: number }) => void): void;
  child(options: unknown): RateStore;
};

function increment(store: RateStore, key: string): Promise<{ current: number; ttl: number }> {
  return new Promise((resolve, reject) => {
    store.incr(key, (error, result) => {
      if (error) reject(error);
      else if (!result) reject(new Error("rate_limit_result_missing"));
      else resolve(result);
    });
  });
}

describe.skipIf(!enabled)("PostgreSQL HTTP rate-limit store", () => {
  let db: Db;

  beforeAll(() => {
    db = createDb(loadConfig(process.env));
  });

  beforeEach(async () => {
    await db.query("truncate table http_rate_bucket");
  });

  afterAll(async () => db.end());

  it("atomically serializes 100 concurrent increments and isolates route groups", async () => {
    const Store = createPostgresRateLimitStore(db, Buffer.alloc(32, 9));
    const globalStore = new Store({ timeWindow: 60_000, groupId: "concurrency-test" });
    const results = await Promise.all(Array.from({ length: 100 }, () => increment(globalStore, "198.51.100.10")));

    expect(results.map((result) => result.current).sort((left, right) => left - right))
      .toEqual(Array.from({ length: 100 }, (_, index) => index + 1));
    expect(results.every((result) => result.ttl > 0 && result.ttl <= 60_000)).toBe(true);

    const isolatedStore = globalStore.child({ timeWindow: 60_000, groupId: "different-route" });
    await expect(increment(isolatedStore, "198.51.100.10")).resolves.toMatchObject({ current: 1 });
  });

  it("enforces the shared store through Fastify while allowing liveness bypass", async () => {
    const app = Fastify();
    await app.register(rateLimit, {
      max: 2,
      timeWindow: "1 minute",
      store: createPostgresRateLimitStore(db, Buffer.alloc(32, 7)),
      skipOnError: false
    });
    app.get("/limited", async () => ({ ok: true }));
    app.get("/health", { config: { rateLimit: false } }, async () => ({ status: "ok" }));
    await app.ready();
    try {
      expect((await app.inject({ method: "GET", url: "/limited" })).statusCode).toBe(200);
      expect((await app.inject({ method: "GET", url: "/limited" })).statusCode).toBe(200);
      expect((await app.inject({ method: "GET", url: "/limited" })).statusCode).toBe(429);
      expect((await app.inject({ method: "GET", url: "/health" })).statusCode).toBe(200);
    } finally {
      await app.close();
    }
  });
});
