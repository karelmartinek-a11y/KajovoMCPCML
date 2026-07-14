import http from "node:http";
import { createEphemeralEgressCapability } from "./egress.js";
import type { AppConfig } from "../config.js";

type EgressResponse = {
  status: number;
  headers: Record<string, string | string[]>;
  body: string;
};

export type EgressFetchParams = {
  url: string;
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD";
  headers?: Record<string, string>;
  body?: Buffer;
  allowlist: string[];
  purpose: string;
  correlationId: string;
  managedServiceId?: string | null;
  ttlSeconds?: number;
};

export async function fetchThroughEgress(
  config: AppConfig,
  params: EgressFetchParams
): Promise<{ status: number; headers: Record<string, string | string[]>; body: Buffer }> {
  const capability = createEphemeralEgressCapability(config, {
    allowlist: params.allowlist,
    managedServiceId: params.managedServiceId ?? null,
    correlationId: params.correlationId,
    purpose: params.purpose,
    ttlSeconds: params.ttlSeconds ?? 90
  });
  const payload = JSON.stringify({
    url: params.url,
    method: params.method,
    headers: params.headers ?? {},
    body: params.body?.length ? params.body.toString("base64") : undefined
  });
  const response = await new Promise<EgressResponse>((resolve, reject) => {
    const request = http.request({
      socketPath: config.EGRESS_PROXY_SOCKET_PATH,
      path: "/fetch",
      method: "POST",
      headers: {
        authorization: `Bearer ${capability}`,
        "content-type": "application/json",
        "content-length": Buffer.byteLength(payload)
      },
      timeout: 30_000
    }, (reply) => {
      const chunks: Buffer[] = [];
      reply.on("data", (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
      reply.on("error", reject);
      reply.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf8");
        if (reply.statusCode !== 200) {
          reject(Object.assign(new Error("egress_proxy_rejected"), {
            statusCode: 502,
            detail: body ? JSON.parse(body) as Record<string, unknown> : null
          }));
          return;
        }
        resolve(JSON.parse(body) as EgressResponse);
      });
    });
    request.on("timeout", () => request.destroy(new Error("egress_proxy_timeout")));
    request.on("error", reject);
    request.write(payload);
    request.end();
  });
  return {
    status: response.status,
    headers: response.headers,
    body: Buffer.from(response.body, "base64")
  };
}
