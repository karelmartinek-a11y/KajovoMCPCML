import { createHash } from "node:crypto";
import { Ajv2020 } from "ajv/dist/2020.js";
import { z } from "zod";
import type { Db } from "../db.js";

const manifestSchema = z.object({
  schemaVersion: z.literal("1.3"),
  registrationRevision: z.string().min(1),
  environment: z.enum(["production", "staging"]),
  handlerKey: z.string().regex(/^[a-z0-9_-]+$/),
  handlerVersion: z.string().min(1),
  displayName: z.string().min(1),
  businessPurpose: z.string().min(10),
  owners: z.object({
    service: z.string().min(1),
    technical: z.string().min(1),
    security: z.string().min(1),
    operations: z.string().min(1)
  }),
  tool: z.object({
    name: z.string().regex(/^[a-z0-9_-]+$/),
    title: z.string().min(1),
    description: z.string().min(1),
    inputSchema: z.record(z.unknown()),
    outputSchema: z.record(z.unknown()),
    annotations: z.object({
      readOnlyHint: z.boolean(),
      destructiveHint: z.boolean(),
      idempotentHint: z.boolean(),
      openWorldHint: z.boolean(),
      taskSupport: z.literal("forbidden")
    })
  }),
  behavior: z.object({
    effectClass: z.enum(["READ_ONLY", "IDEMPOTENT_WRITE", "NON_IDEMPOTENT_WRITE"]),
    timeoutMs: z.number().int().min(100).max(60_000),
    maxConcurrency: z.number().int().min(1).max(100),
    requestMaxBytes: z.number().int().min(1),
    responseMaxBytes: z.number().int().min(1),
    rateLimit: z.object({ windowSeconds: z.number().int().min(1), maxRequests: z.number().int().min(1) }),
    shutdownPolicy: z.enum(["COMPLETE_IN_FLIGHT", "CANCEL_SAFE", "COMPENSATE"]),
    idempotencyPolicy: z.string().min(1),
    retryPolicy: z.object({ automaticRetry: z.literal(false) })
  }),
  testContract: z.object({
    safeInput: z.record(z.unknown()),
    expectedResult: z.record(z.unknown()),
    cleanupOrCompensation: z.string().min(1)
  }),
  monitoringProfile: z.object({
    sloTargets: z.record(z.unknown()),
    probeIntervals: z.record(z.unknown()),
    alertRules: z.array(z.record(z.unknown())).min(1),
    runbookRef: z.string().min(1),
    primaryAlertChannel: z.string().min(1),
    backupAlertChannel: z.string().min(1)
  }),
  approvals: z.object({
    architecture: z.string().min(1),
    security: z.string().min(1),
    operations: z.string().min(1)
  }),
  artifact: z.object({
    digest: z.string().regex(/^sha256:[a-f0-9]{64}$/),
    sbomDigest: z.string().regex(/^sha256:[a-f0-9]{64}$/)
  }),
  change: z.object({
    rollbackRef: z.string().min(1),
    decommissionRef: z.string().min(1),
    reviewDueAt: z.string().datetime()
  })
}).strict();

export type RegistrationManifest = z.infer<typeof manifestSchema>;

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nested]) => [key, canonicalize(nested)])
    );
  }
  return value;
}

export function validateManifest(input: unknown): { manifest: RegistrationManifest; digest: string } {
  const manifest = manifestSchema.parse(input);
  const ajv = new Ajv2020({ strict: true, allErrors: true });
  ajv.compile(manifest.tool.inputSchema);
  ajv.compile(manifest.tool.outputSchema);
  const canonical = JSON.stringify(canonicalize(manifest));
  return {
    manifest,
    digest: `sha256:${createHash("sha256").update(canonical).digest("hex")}`
  };
}

export async function allocateKcml(db: Db): Promise<{ code: string; hostname: string; number: number }> {
  const result = await db.query("select nextval('kcml_number_seq') as number");
  const number = Number(result.rows[0].number);
  const code = `KCML${String(number).padStart(4, "0")}`;
  return { number, code, hostname: `${code.toLowerCase()}.hcasc.cz` };
}
