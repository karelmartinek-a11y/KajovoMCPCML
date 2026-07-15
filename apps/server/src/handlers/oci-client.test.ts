import { mkdtemp, rm } from "node:fs/promises";
import http from "node:http";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ociHandler } from "./oci-client.js";

describe("ociHandler", () => {
  let socketDir: string | null = null;
  let socketPath: string | null = null;
  let server: http.Server | null = null;

  afterEach(async () => {
    await new Promise<void>((resolve) => server?.close(() => resolve()) ?? resolve());
    server = null;
    if (socketDir) await rm(socketDir, { recursive: true, force: true });
    socketDir = null;
    socketPath = null;
  });

  it("surfaces the worker error message for admin and release diagnostics", async () => {
    socketDir = await mkdtemp(join(tmpdir(), "kcml-oci-client-"));
    socketPath = join(socketDir, "worker.sock");
    server = http.createServer((request, reply) => {
      const body = JSON.stringify({
        error: {
          code: "handler_failed",
          message: "home_assistant_catalog_contract_mismatch"
        },
        logs: [{ level: "info", message: "catalog.requested", fields: { operation: "list_home_assistant_devices" } }]
      });
      reply.writeHead(200, { "content-type": "application/json", "content-length": Buffer.byteLength(body) });
      reply.end(body);
      request.resume();
    });
    await new Promise<void>((resolve, reject) => server!.listen(socketPath!, (error?: Error) => error ? reject(error) : resolve()));

    const handler = ociHandler();
    const info = vi.fn();
    const error = vi.fn();

    await expect(handler.invoke({}, {
      correlationId: "00000000-0000-4000-8000-000000000000",
      server: {
        id: "server-id",
        code: "KCML0002",
        kcmlNumber: 2,
        hostname: "kcml0002.hcasc.cz",
        toolName: "home_assistant_inventory",
        displayName: "Home Assistant inventory",
        description: "Production compatibility fixture",
        enabled: true,
        registrationState: "TRIAL",
        operationalState: "DEGRADED",
        inputSchema: { type: "object", additionalProperties: false },
        outputSchema: { type: "object", additionalProperties: false },
        handlerKey: "home-assistant-inventory",
        handlerVersion: "1.0.0",
        contractVersion: "prod-1",
        artifactDigest: "sha256:artifact",
        manifestDigest: "sha256:manifest",
        registrationRevision: "prod-1",
        activeRevisionId: "revision-id",
        registrationSchemaVersion: "1.4",
        registrationValidationState: "VALID",
        reviewApprovedAt: "2026-01-01T00:00:00.000Z",
        reviewDueAt: "2027-01-01T00:00:00.000Z",
        reviewIntervalDays: 365,
        monitoringEnabled: true,
        monitoringProfileDigest: "sha256:monitoring",
        imageReference: null,
        imageDigest: "sha256:image",
        sbomDigest: null,
        provenanceDigest: null,
        runtimeSocket: socketPath,
        timeoutMs: 1000,
        maxConcurrency: 1,
        requestMaxBytes: 1024,
        responseMaxBytes: 1024,
        rateWindowSeconds: 60,
        rateMaxRequests: 10,
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
        effectClass: "READ_ONLY",
        shutdownPolicy: "COMPLETE_IN_FLIGHT",
        idempotencyPolicy: "read only",
        revocationEpoch: "epoch",
        successCount: 0,
        unauthorizedCount: 0,
        failureCount: 0,
        lastLatencyMs: null,
        averageLatencyMs: null,
        p95LatencyMs: null,
        lastSuccessAt: null,
        lastFailureAt: null,
        lastUnauthorizedAt: null,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      },
      logger: { info, error }
    })).rejects.toThrow("home_assistant_catalog_contract_mismatch");

    expect(info).toHaveBeenCalledWith(
      expect.objectContaining({
        operation: "list_home_assistant_devices",
        serverCode: "KCML0002",
        imageDigest: "sha256:image",
        correlationId: "00000000-0000-4000-8000-000000000000"
      }),
      "catalog.requested"
    );
    expect(error).not.toHaveBeenCalled();
  });
});
