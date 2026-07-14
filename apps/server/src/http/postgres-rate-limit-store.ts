import { createHmac } from "node:crypto";
import type { Db } from "../db.js";

type StoreOptions = {
  groupId?: string;
  routeInfo?: {
    method?: string | string[];
    url?: string;
    path?: string;
  };
  timeWindow?: number;
};

type IncrementCallback = (error: Error | null, result?: { current: number; ttl: number }) => void;

function normalizedOptions(options: unknown): StoreOptions {
  return typeof options === "object" && options !== null ? options : {};
}

function scopeFor(options: StoreOptions): string {
  if (options.groupId) return options.groupId;
  const method = Array.isArray(options.routeInfo?.method)
    ? options.routeInfo.method.join(",")
    : options.routeInfo?.method ?? "GLOBAL";
  return `${method}:${options.routeInfo?.url ?? options.routeInfo?.path ?? "*"}`;
}

export function createPostgresRateLimitStore(db: Db, hmacKey: Buffer) {
  return class PostgresRateLimitStore {
    private readonly options: StoreOptions;

    constructor(options: unknown) {
      this.options = normalizedOptions(options);
    }

    incr(key: string, callback: IncrementCallback): void {
      const timeWindow = Math.max(1, Math.trunc(this.options.timeWindow ?? 60_000));
      const bucketKey = createHmac("sha256", hmacKey)
        .update(`kcml:http-rate:${scopeFor(this.options)}:${key}`)
        .digest();
      db.query(
        `insert into http_rate_bucket(bucket_key,window_started_at,request_count,updated_at)
         values ($1,statement_timestamp(),1,statement_timestamp())
         on conflict (bucket_key) do update
           set window_started_at=case
                 when http_rate_bucket.window_started_at <= statement_timestamp()-($2::bigint * interval '1 millisecond')
                   then statement_timestamp()
                 else http_rate_bucket.window_started_at
               end,
               request_count=case
                 when http_rate_bucket.window_started_at <= statement_timestamp()-($2::bigint * interval '1 millisecond')
                   then 1
                 else least(http_rate_bucket.request_count+1,2147483647)
               end,
               updated_at=statement_timestamp()
         returning request_count,
                   greatest(0,ceil(extract(epoch from (
                     window_started_at+($2::bigint * interval '1 millisecond')-statement_timestamp()
                   ))*1000))::bigint as ttl`,
        [bucketKey, timeWindow]
      ).then((result) => {
        callback(null, {
          current: Number(result.rows[0]?.request_count ?? 1),
          ttl: Number(result.rows[0]?.ttl ?? timeWindow)
        });
      }).catch((error: unknown) => {
        callback(error instanceof Error ? error : new Error("rate_limit_store_failed"));
      });
    }

    child(routeOptions: unknown): PostgresRateLimitStore {
      return new PostgresRateLimitStore({ ...this.options, ...normalizedOptions(routeOptions) });
    }
  };
}
