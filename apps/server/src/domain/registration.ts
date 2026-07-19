import { createHash } from "node:crypto";
import { Ajv2020 } from "ajv/dist/2020.js";
import { z } from "zod";
import type { Db } from "../db.js";
import componentManifestSchema from "../contracts/component-manifest-2026.07.21.schema.json" with { type: "json" };
import { kcmlCodeFromNumber, kcmlHostnameForCode } from "./hostnames.js";
import { KCML_MCP_COMPONENTS, KCML_RELEASE } from "./release.js";

const sha256Schema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const evidenceRefSchema = z.string().regex(/^evidence\/[a-z0-9][a-z0-9_./-]{1,240}$/i);
const ownerSchema = z.string().trim().min(2).max(160);
const timestampSchema = z.string().datetime({ offset: true });

const errorCatalogEntrySchema = z.object({
  code: z.string().regex(/^[A-Z][A-Z0-9_]{1,119}$/),
  description: z.string().trim().min(5).max(500),
  classification: z.enum(["VALIDATION", "AUTHORIZATION", "DEPENDENCY", "TIMEOUT", "CONFLICT", "INTERNAL"]),
  retryable: z.literal(false)
}).strict();

const protocolSchema = z.object({
  protocolVersion: z.literal("2025-11-25"),
  transport: z.literal("streamable-http"),
  capabilities: z.tuple([z.literal("tools")]),
  errorCatalog: z.array(errorCatalogEntrySchema).min(1).max(50)
}).strict();

const annotationsSchema = z.object({
  readOnlyHint: z.boolean(),
  destructiveHint: z.boolean(),
  idempotentHint: z.boolean(),
  openWorldHint: z.boolean(),
  taskSupport: z.literal("forbidden")
}).strict();

const behaviorSchema = z.object({
  effectClass: z.enum(["READ_ONLY", "IDEMPOTENT_WRITE", "NON_IDEMPOTENT_WRITE"]),
  timeoutMs: z.number().int().min(100).max(60_000),
  maxConcurrency: z.number().int().min(1).max(32),
  requestMaxBytes: z.number().int().min(1).max(1_048_576),
  responseMaxBytes: z.number().int().min(1).max(5_242_880),
  rateLimit: z.object({
    windowSeconds: z.number().int().min(1).max(86_400),
    maxRequests: z.number().int().min(1).max(100_000)
  }).strict(),
  shutdownPolicy: z.enum(["COMPLETE_IN_FLIGHT", "CANCEL_SAFE", "COMPENSATE"]),
  idempotencyPolicy: z.string().trim().min(5).max(500),
  compensationPolicy: z.string().trim().min(5).max(1_000),
  retryPolicy: z.object({ automaticRetry: z.literal(false) }).strict()
}).strict();

const legacyErrorCatalogEntrySchema = z.object({
  code: z.string().min(1).max(120),
  description: z.string().min(1).max(500)
}).strict();

const legacyProtocolSchema = z.object({
  protocolVersion: z.literal("2025-11-25"),
  transport: z.literal("streamable-http"),
  capabilities: z.array(z.literal("tools")).min(1).max(1),
  errorCatalog: z.array(legacyErrorCatalogEntrySchema).min(1).max(50)
}).strict();

const legacyNetworkPolicySchema = z.object({
  outboundAllowlist: z.array(z.string().min(1).max(200)).max(20),
  dnsPolicy: z.enum(["strict", "none"]),
  databaseRole: z.string().min(1).max(120),
  filesystemPolicy: z.string().min(1).max(200)
}).strict();

const legacyDataClassificationSchema = z.object({
  input: z.string().min(1).max(120),
  output: z.string().min(1).max(120),
  containsPersonalData: z.boolean(),
  loggingPolicy: z.string().min(1).max(500),
  redactionFields: z.array(z.string().min(1).max(80)).max(50),
  retentionPolicy: z.string().min(1).max(500)
}).strict();

const legacyDependenciesSchema = z.object({
  runtime: z.array(z.object({
    name: z.string().min(1).max(120),
    version: z.string().min(1).max(120)
  }).strict()).max(50),
  externalServices: z.array(z.string().min(1).max(200)).max(50),
  secretRefs: z.array(z.string().min(1).max(200)).max(50),
  networkPolicy: legacyNetworkPolicySchema,
  dataClassification: legacyDataClassificationSchema
}).strict();

const legacyChangeSchema = z.object({
  changeClass: z.enum(["INITIAL", "PATCH", "MINOR", "MAJOR"]).optional(),
  migrationRef: z.string().min(1).max(500).optional(),
  rollbackRef: z.string().min(1).max(500),
  decommissionRef: z.string().min(1).max(500),
  previousApprovedRevision: z.string().min(1).max(80).nullable().optional(),
  reviewDueAt: z.string().datetime()
}).strict();

const legacyOnboardingManifestSchema = z.object({
  schemaVersion: z.literal("1.4"),
  registrationRevision: z.string().min(1).max(80),
  environment: z.enum(["production", "staging"]),
  handlerKey: z.string().regex(/^[a-z0-9][a-z0-9_-]{1,62}$/),
  handlerVersion: z.string().regex(/^\d+\.\d+\.\d+(?:-[a-z0-9.-]+)?$/i),
  displayName: z.string().min(1).max(120),
  businessPurpose: z.string().min(10).max(2_000),
  owners: z.object({
    service: z.string().min(1).max(160),
    technical: z.string().min(1).max(160),
    security: z.string().min(1).max(160),
    operations: z.string().min(1).max(160)
  }).strict(),
  source: z.object({
    runtime: z.enum(["nodejs22-typescript", "nodejs24-typescript"]),
    entrypoint: z.literal("src/index.ts"),
    testCommand: z.literal("pnpm test")
  }).strict(),
  runtime: z.object({
    memoryMb: z.number().int().min(64).max(512),
    cpuCores: z.number().min(0.1).max(2),
    pidsLimit: z.number().int().min(16).max(256),
    egressAllowlist: z.array(z.string().regex(/^[a-z0-9.-]+(?::\d+)?$/i)).max(20)
  }).strict(),
  tool: z.object({
    title: z.string().min(1).max(120),
    description: z.string().min(1).max(2_000),
    inputSchema: z.record(z.string(), z.unknown()),
    outputSchema: z.record(z.string(), z.unknown()),
    annotations: annotationsSchema
  }).strict(),
  behavior: z.object({
    effectClass: z.enum(["READ_ONLY", "IDEMPOTENT_WRITE", "NON_IDEMPOTENT_WRITE"]),
    timeoutMs: z.number().int().min(100).max(60_000),
    maxConcurrency: z.number().int().min(1).max(32),
    requestMaxBytes: z.number().int().min(1).max(1_048_576),
    responseMaxBytes: z.number().int().min(1).max(5_242_880),
    rateLimit: z.object({ windowSeconds: z.number().int().min(1), maxRequests: z.number().int().min(1) }).strict(),
    shutdownPolicy: z.enum(["COMPLETE_IN_FLIGHT", "CANCEL_SAFE", "COMPENSATE"]),
    idempotencyPolicy: z.string().min(1).max(500),
    retryPolicy: z.object({ automaticRetry: z.literal(false) }).strict()
  }).strict(),
  testContract: z.object({
    safeInput: z.record(z.string(), z.unknown()),
    expectedResult: z.record(z.string(), z.unknown()),
    cleanupOrCompensation: z.string().min(1).max(1_000),
    executionMode: z.enum(["READ_ONLY", "SANDBOX", "COMPENSATED"]).optional()
  }).strict(),
  protocol: legacyProtocolSchema.optional(),
  dependencies: legacyDependenciesSchema.optional(),
  monitoringProfile: z.object({
    sloTargets: z.record(z.string(), z.unknown()),
    probeIntervals: z.record(z.string(), z.unknown()),
    alertRules: z.array(z.record(z.string(), z.unknown())).min(1).max(50),
    runbookRef: z.string().min(1).max(500),
    primaryAlertChannel: z.string().min(1).max(200),
    backupAlertChannel: z.string().min(1).max(200)
  }).strict(),
  errorCatalog: z.array(legacyErrorCatalogEntrySchema).min(1).max(50).optional(),
  change: legacyChangeSchema
}).strict();

const registrationManifest15Schema = z.object({
  schemaVersion: z.literal("1.5"),
  registrationRevision: z.string().regex(/^[a-z0-9][a-z0-9._-]{2,79}$/i),
  environment: z.enum(["production", "staging"]),
  handlerKey: z.string().regex(/^[a-z0-9][a-z0-9_-]{1,62}$/),
  handlerVersion: z.string().regex(/^\d+\.\d+\.\d+(?:-[a-z0-9.-]+)?$/i),
  displayName: z.string().trim().min(3).max(120),
  businessPurpose: z.string().trim().min(20).max(2_000),
  owners: z.object({
    service: ownerSchema,
    technical: ownerSchema,
    security: ownerSchema,
    operations: ownerSchema
  }).strict(),
  contacts: z.object({
    serviceEmail: z.string().email().max(254),
    technicalEmail: z.string().email().max(254),
    securityEmail: z.string().email().max(254),
    operationsOnCall: z.string().trim().min(5).max(300)
  }).strict(),
  criticality: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
  review: z.object({
    intervalDays: z.number().int().min(1).max(365),
    approvedAt: timestampSchema,
    reviewDueAt: timestampSchema
  }).strict(),
  source: z.object({
    runtime: z.literal("nodejs24-typescript"),
    entrypoint: z.literal("src/index.ts"),
    testCommand: z.literal("pnpm test")
  }).strict(),
  runtime: z.object({
    memoryMb: z.number().int().min(64).max(512),
    cpuCores: z.number().min(0.1).max(2),
    pidsLimit: z.number().int().min(16).max(256),
    egressAllowlist: z.array(z.string().regex(/^[a-z0-9.-]+(?::\d+)?$/i)).max(20)
  }).strict(),
  tool: z.object({
    title: z.string().trim().min(3).max(120),
    description: z.string().trim().min(20).max(2_000),
    inputSchema: z.record(z.string(), z.unknown()),
    outputSchema: z.record(z.string(), z.unknown()),
    annotations: annotationsSchema
  }).strict(),
  contractDigests: z.object({
    inputSchema: sha256Schema,
    outputSchema: sha256Schema
  }).strict(),
  behavior: behaviorSchema,
  testContract: z.object({
    safeInput: z.record(z.string(), z.unknown()),
    expectedResult: z.record(z.string(), z.unknown()),
    cleanupOrCompensation: z.string().trim().min(5).max(1_000),
    executionMode: z.enum(["READ_ONLY", "SANDBOX", "COMPENSATED"]).optional(),
    positiveEvidenceRef: evidenceRefSchema,
    negativeTests: z.array(z.object({
      name: z.string().trim().min(3).max(120),
      input: z.record(z.string(), z.unknown()),
      expectedErrorCode: z.string().min(2).max(120),
      evidenceRef: evidenceRefSchema
    }).strict()).min(1).max(50),
    failureScenarios: z.array(z.object({
      dependency: z.string().min(2).max(120),
      expectedFailureClass: z.string().min(2).max(120),
      evidenceRef: evidenceRefSchema
    }).strict()).min(1).max(50),
    loadProfile: z.object({
      expectedConcurrency: z.number().int().min(1).max(32),
      expectedDurationMinutes: z.number().int().min(30).max(240),
      stressMultiplier: z.literal(2),
      stressDurationMinutes: z.number().int().min(10).max(120),
      maxP95LatencyMs: z.number().int().min(1).max(60_000),
      maxErrorRatePercent: z.number().min(0).max(100),
      evidenceRef: evidenceRefSchema
    }).strict()
  }).strict(),
  protocol: protocolSchema,
  dependencies: z.object({
    runtime: z.array(z.object({
      name: z.string().min(2).max(120),
      version: z.string().min(1).max(120),
      checksum: sha256Schema,
      evidenceRef: evidenceRefSchema
    }).strict()).min(1).max(50),
    externalServices: z.array(z.object({
      name: z.string().min(2).max(120),
      endpoint: z.string().url().startsWith("https://"),
      criticality: z.enum(["OPTIONAL", "REQUIRED"]),
      timeoutMs: z.number().int().min(100).max(60_000),
      contractRef: evidenceRefSchema
    }).strict()).max(50),
    secretReferences: z.array(z.object({
      reference: z.string().regex(/^(?:systemd-creds|vault|file):\/\/[A-Za-z0-9._/-]+$/),
      owner: ownerSchema,
      rotationDays: z.number().int().min(1).max(365),
      lastRotatedAt: timestampSchema
    }).strict()).max(50),
    networkPolicy: z.object({
      outboundAllowlist: z.array(z.string().regex(/^[a-z0-9.-]+(?::\d+)?$/i)).max(20),
      dnsPolicy: z.literal("strict"),
      databaseRole: z.string().min(2).max(120),
      filesystemPolicy: z.enum(["read-only", "isolated-runtime-only"]),
      evidenceRef: evidenceRefSchema
    }).strict()
  }).strict(),
  dataGovernance: z.object({
    classification: z.enum(["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]),
    containsPersonalData: z.boolean(),
    residencyCountries: z.array(z.string().regex(/^[A-Z]{2}$/)).min(1).max(20),
    exportAllowed: z.boolean(),
    exportDestinations: z.array(z.string().regex(/^[A-Z]{2}$/)).max(20),
    loggingPolicy: z.string().trim().min(5).max(500),
    redactionFields: z.array(z.string().min(1).max(80)).max(50),
    retentionDays: z.number().int().min(1).max(3_650),
    evidenceRef: evidenceRefSchema
  }).strict(),
  monitoringProfile: z.object({
    sloTargets: z.object({
      availabilityPercent: z.number().min(90).max(100),
      p95LatencyMs: z.number().int().min(1).max(60_000),
      maxErrorRatePercent: z.number().min(0).max(100)
    }).strict(),
    probeIntervals: z.object({
      readinessSeconds: z.number().int().min(15).max(300),
      tlsSeconds: z.number().int().min(60).max(3_600),
      routingSeconds: z.number().int().min(15).max(300),
      oauthMcpSeconds: z.number().int().min(30).max(600),
      syntheticCallSeconds: z.number().int().min(60).max(900),
      integritySeconds: z.number().int().min(60).max(900),
      dependenciesSeconds: z.number().int().min(30).max(900)
    }).strict(),
    staleAfterSeconds: z.number().int().min(30).max(7_200),
    alertRules: z.array(z.object({
      probeType: z.string().min(2).max(120),
      severity: z.enum(["WARNING", "HIGH", "CRITICAL"]),
      consecutiveFailures: z.number().int().min(1).max(20)
    }).strict()).min(1).max(50),
    runbookRef: evidenceRefSchema,
    primaryAlertChannel: z.literal("PRIMARY_WEBHOOK"),
    backupAlertChannel: z.literal("BACKUP_WEBHOOK")
  }).strict(),
  maintenance: z.object({
    window: z.string().trim().min(5).max(200),
    runbookRef: evidenceRefSchema,
    rollbackRef: evidenceRefSchema,
    recoveryTimeObjectiveMinutes: z.number().int().min(1).max(10_080),
    recoveryPointObjectiveMinutes: z.number().int().min(0).max(10_080)
  }).strict(),
  autoQuarantine: z.object({
    enabled: z.literal(true),
    rules: z.array(z.enum(["CROSS_HOST", "AUDIENCE_MISMATCH", "ARTIFACT_DRIFT", "CONTRACT_DRIFT", "ROUTING_DRIFT"])).min(5).max(5)
  }).strict(),
  errorCatalog: z.array(errorCatalogEntrySchema).min(1).max(50),
  evidence: z.object({
    architectureRef: evidenceRefSchema,
    threatModelRef: evidenceRefSchema,
    sastRef: evidenceRefSchema,
    scaRef: evidenceRefSchema,
    secretScanRef: evidenceRefSchema,
    containerScanRef: evidenceRefSchema,
    sbomRef: evidenceRefSchema,
    provenanceRef: evidenceRefSchema,
    rollbackTestRef: evidenceRefSchema,
    compatibilityWindowEndsAt: timestampSchema
  }).strict(),
  approvals: z.object({
    architecture: z.object({ approver: ownerSchema, approvedAt: timestampSchema, evidenceRef: evidenceRefSchema }).strict(),
    security: z.object({ approver: ownerSchema, approvedAt: timestampSchema, evidenceRef: evidenceRefSchema }).strict(),
    operations: z.object({ approver: ownerSchema, approvedAt: timestampSchema, evidenceRef: evidenceRefSchema }).strict(),
    dataOwner: z.object({ approver: ownerSchema, approvedAt: timestampSchema, evidenceRef: evidenceRefSchema }).strict(),
    changeManagement: z.object({ approver: ownerSchema, approvedAt: timestampSchema, evidenceRef: evidenceRefSchema }).strict()
  }).strict(),
  change: z.object({
    changeClass: z.enum(["INITIAL", "PATCH", "MINOR", "MAJOR"]),
    migrationRef: evidenceRefSchema,
    rollbackRef: evidenceRefSchema,
    decommissionRef: evidenceRefSchema,
    previousApprovedRevision: z.string().min(3).max(80).nullable()
  }).strict()
}).strict();

const storedRegistrationManifest15Schema = registrationManifest15Schema.extend({
  source: registrationManifest15Schema.shape.source.extend({
    runtime: z.enum(["nodejs22-typescript", "nodejs24-typescript"])
  })
});

export type LegacyOnboardingManifest = z.infer<typeof legacyOnboardingManifestSchema>;
export type RegistrationManifest15 = z.infer<typeof registrationManifest15Schema>;
export type RuntimeRegistrationManifest = Omit<RegistrationManifest15, "schemaVersion"> & {
  schemaVersion: typeof KCML_RELEASE.manifestSchemaVersion;
  releaseVersion: typeof KCML_RELEASE.applicationVersion;
  componentType: "MCP_SERVER";
  registrationType: "MCP_SERVER";
  blueprint: { componentId: string; version: typeof KCML_RELEASE.blueprintVersion };
  pulseEnvelopeVersion: typeof KCML_RELEASE.pulseEnvelopeVersion;
  publicEndpoints: unknown[];
  pulseContract: unknown;
  normalizedFromComponentManifest: true;
};
export type StoredRuntimeRegistrationManifest20260720 = Omit<RuntimeRegistrationManifest, "schemaVersion" | "releaseVersion" | "blueprint" | "pulseEnvelopeVersion"> & {
  schemaVersion: "2026.07.20";
  releaseVersion: "2026.07.20";
  blueprint: { componentId: string; version: "2026.07.20" };
  pulseEnvelopeVersion: "2026.07.20";
};
export type OnboardingManifest = LegacyOnboardingManifest | RegistrationManifest15 | StoredRuntimeRegistrationManifest20260720 | RuntimeRegistrationManifest;
export type RegistrationManifest = RuntimeRegistrationManifest;

export function isStructuredOnboardingManifest(manifest: OnboardingManifest): manifest is Exclude<OnboardingManifest, LegacyOnboardingManifest> {
  return ["1.5", "2026.07.20", KCML_RELEASE.manifestSchemaVersion].includes(manifest.schemaVersion);
}

function parseStoredRuntimeRegistrationManifest20260720(input: unknown): StoredRuntimeRegistrationManifest20260720 | null {
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  const value = input as Record<string, unknown>;
  const blueprint = value.blueprint as Record<string, unknown> | undefined;
  const protocol = value.protocol as Record<string, unknown> | undefined;
  if (value.schemaVersion !== "2026.07.20" || value.releaseVersion !== "2026.07.20"
    || value.componentType !== "MCP_SERVER" || value.registrationType !== "MCP_SERVER"
    || value.pulseEnvelopeVersion !== "2026.07.20" || value.normalizedFromComponentManifest !== true
    || !blueprint || blueprint.version !== "2026.07.20" || typeof blueprint.componentId !== "string"
    || !KCML_MCP_COMPONENTS.some(([componentId]) => componentId === blueprint.componentId)
    || !protocol || protocol.protocolVersion !== KCML_RELEASE.mcpProtocolVersion
    || !Array.isArray(value.publicEndpoints) || value.publicEndpoints.length === 0
    || !value.tool || typeof value.tool !== "object" || !value.behavior || typeof value.behavior !== "object"
    || !value.dependencies || typeof value.dependencies !== "object" || !value.monitoringProfile || typeof value.monitoringProfile !== "object"
    || !value.review || typeof value.review !== "object" || !value.pulseContract || typeof value.pulseContract !== "object") return null;
  return structuredClone(value) as unknown as StoredRuntimeRegistrationManifest20260720;
}

const componentManifestValidator = new Ajv2020({ strict: false, allErrors: true, validateFormats: false }).compile(componentManifestSchema);

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(([left], [right]) => left.localeCompare(right));
    return `{${entries.map(([key, child]) => `${JSON.stringify(key)}:${canonicalJson(child)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function validateJsonSchemas(inputSchema: Record<string, unknown>, outputSchema: Record<string, unknown>): void {
  const ajv = new Ajv2020({ strict: true, allErrors: true });
  ajv.compile(inputSchema);
  ajv.compile(outputSchema);
}

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

export function digestCanonicalJson(value: unknown): string {
  return `sha256:${createHash("sha256").update(JSON.stringify(canonicalize(value))).digest("hex")}`;
}

function exactComponentType(input: unknown): string | null {
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  const value = (input as Record<string, unknown>).componentType;
  return typeof value === "string" ? value : null;
}

function assertNoPlatformGeneratedFields(input: Record<string, unknown>): void {
  for (const key of ["code", "kcmlCode", "hostname", "resource", "toolName", "credentialId", "secret", "authorizationSnapshot"]) {
    if (Object.hasOwn(input, key)) throw new Error("component_identity_forbidden");
  }
}

function normalizeComponentMcpManifest(input: unknown): RuntimeRegistrationManifest {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("invalid_manifest");
  const raw = input as Record<string, unknown>;
  if (raw.schemaVersion !== KCML_RELEASE.manifestSchemaVersion) throw new Error("old_manifest_schema_not_accepted");
  assertNoPlatformGeneratedFields(raw);
  if (!componentManifestValidator(raw)) throw new Error("invalid_manifest");
  if (raw.componentType !== "MCP_SERVER" || raw.registrationType !== "MCP_SERVER") throw new Error("component_type_not_supported");

  const blueprint = raw.blueprint as { componentId: string; version: typeof KCML_RELEASE.blueprintVersion };
  if (!KCML_MCP_COMPONENTS.some(([componentId]) => componentId === blueprint.componentId)) throw new Error("blueprint_component_not_allowed");
  const facadeTools = raw.facadeTools as Array<{ name: string; inputSchema: Record<string, unknown>; outputSchema: Record<string, unknown> }>;
  if (facadeTools.length !== 1) throw new Error("facade_tool_count_mismatch");
  const endpoint = (raw.publicEndpoints as Array<Record<string, unknown>>)[0];
  if (!endpoint) throw new Error("public_endpoint_required_for_mcp");
  const rateLimit = endpoint.rateLimit as { windowSeconds: number; maxRequests: number };
  const limits = endpoint.limits as { requestBytes: number; responseBytes: number };
  const runtime = raw.runtime as { memoryMb: number; cpuCores: number; pidsLimit: number };
  const networkPolicy = raw.networkPolicy as { outboundAllowlist: string[] };
  const review = raw.review as { intervalDays: number; approvedAt: string; reviewDueAt: string };
  const firstTool = facadeTools[0]!;
  const manifest: RuntimeRegistrationManifest = {
    schemaVersion: KCML_RELEASE.manifestSchemaVersion,
    releaseVersion: KCML_RELEASE.applicationVersion,
    componentType: "MCP_SERVER",
    registrationType: "MCP_SERVER",
    blueprint,
    pulseEnvelopeVersion: KCML_RELEASE.pulseEnvelopeVersion,
    normalizedFromComponentManifest: true,
    registrationRevision: String(raw.registrationRevision),
    environment: raw.environment as "production" | "staging",
    handlerKey: String(raw.handlerKey),
    handlerVersion: String(raw.handlerVersion),
    displayName: String(raw.displayName),
    businessPurpose: String(raw.businessPurpose),
    owners: { service: "component-owner", technical: "component-owner", security: "component-owner", operations: "component-owner" },
    contacts: { serviceEmail: "service@example.invalid", technicalEmail: "technical@example.invalid", securityEmail: "security@example.invalid", operationsOnCall: "component:oncall" },
    criticality: raw.criticality as RegistrationManifest15["criticality"],
    review,
    source: { runtime: "nodejs24-typescript", entrypoint: "src/index.ts", testCommand: "pnpm test" },
    runtime: { memoryMb: runtime.memoryMb, cpuCores: runtime.cpuCores, pidsLimit: runtime.pidsLimit, egressAllowlist: networkPolicy.outboundAllowlist },
    tool: {
      title: firstTool.name,
      description: String(raw.businessPurpose),
      inputSchema: firstTool.inputSchema,
      outputSchema: firstTool.outputSchema,
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false, taskSupport: "forbidden" }
    },
    contractDigests: { inputSchema: digestCanonicalJson(firstTool.inputSchema), outputSchema: digestCanonicalJson(firstTool.outputSchema) },
    behavior: {
      effectClass: "READ_ONLY",
      timeoutMs: Number(endpoint.timeoutMs),
      maxConcurrency: 4,
      requestMaxBytes: limits.requestBytes,
      responseMaxBytes: limits.responseBytes,
      rateLimit,
      shutdownPolicy: "COMPLETE_IN_FLIGHT",
      idempotencyPolicy: "Platform enforces the declared component idempotency contract.",
      compensationPolicy: "Side effects require status check or compensation declared in pulse contract.",
      retryPolicy: { automaticRetry: false }
    },
    testContract: {
      safeInput: {},
      expectedResult: {},
      cleanupOrCompensation: "No central business implementation is executed by the registry contract test.",
      positiveEvidenceRef: "evidence/contract/positive.json",
      negativeTests: [{ name: "Reject invalid token", input: {}, expectedErrorCode: "invalid_integration_token", evidenceRef: "evidence/contract/negative-token.json" }],
      failureScenarios: [{ dependency: "platform", expectedFailureClass: "DEPENDENCY", evidenceRef: "evidence/contract/platform-failure.json" }],
      loadProfile: { expectedConcurrency: 1, expectedDurationMinutes: 30, stressMultiplier: 2, stressDurationMinutes: 10, maxP95LatencyMs: 2_000, maxErrorRatePercent: 1, evidenceRef: "evidence/contract/load.json" }
    },
    protocol: { protocolVersion: KCML_RELEASE.mcpProtocolVersion, transport: "streamable-http", capabilities: ["tools"], errorCatalog: [{ code: "INVALID_INPUT", description: "Input failed the declared schema.", classification: "VALIDATION", retryable: false }] },
    dependencies: {
      runtime: [{ name: "node", version: "24.0.0", checksum: `sha256:${"0".repeat(64)}`, evidenceRef: "evidence/dependencies/node.json" }],
      externalServices: [],
      secretReferences: [],
      networkPolicy: { outboundAllowlist: networkPolicy.outboundAllowlist, dnsPolicy: "strict", databaseRole: "kcml_handler_none", filesystemPolicy: "isolated-runtime-only", evidenceRef: "evidence/policies/network.json" }
    },
    dataGovernance: { classification: "INTERNAL", containsPersonalData: false, residencyCountries: ["CZ"], exportAllowed: false, exportDestinations: [], loggingPolicy: "Platform redaction policy applies.", redactionFields: [], retentionDays: 365, evidenceRef: "evidence/data/governance.json" },
    monitoringProfile: { sloTargets: { availabilityPercent: 99.5, p95LatencyMs: 2000, maxErrorRatePercent: 1 }, probeIntervals: { readinessSeconds: 60, tlsSeconds: 3600, routingSeconds: 60, oauthMcpSeconds: 60, syntheticCallSeconds: 300, integritySeconds: 300, dependenciesSeconds: 300 }, staleAfterSeconds: 3600, alertRules: [{ probeType: "runtime", severity: "CRITICAL", consecutiveFailures: 2 }], runbookRef: "evidence/runbook.md", primaryAlertChannel: "PRIMARY_WEBHOOK", backupAlertChannel: "BACKUP_WEBHOOK" },
    maintenance: { window: "platform-controlled", runbookRef: "evidence/runbook.md", rollbackRef: "evidence/rollback.md", recoveryTimeObjectiveMinutes: 60, recoveryPointObjectiveMinutes: 0 },
    autoQuarantine: { enabled: true, rules: ["CROSS_HOST", "AUDIENCE_MISMATCH", "ARTIFACT_DRIFT", "CONTRACT_DRIFT", "ROUTING_DRIFT"] },
    errorCatalog: [{ code: "INVALID_INPUT", description: "Input failed the declared schema.", classification: "VALIDATION", retryable: false }],
    evidence: { architectureRef: "evidence/architecture.md", threatModelRef: "evidence/threat-model.md", sastRef: "evidence/sast.json", scaRef: "evidence/sca.json", secretScanRef: "evidence/secret-scan.json", containerScanRef: "evidence/container-scan.json", sbomRef: "evidence/sbom.json", provenanceRef: "evidence/provenance.json", rollbackTestRef: "evidence/rollback-test.json", compatibilityWindowEndsAt: "2027-07-20T00:00:00.000Z" },
    approvals: { architecture: { approver: "platform", approvedAt: review.approvedAt, evidenceRef: "evidence/approvals/architecture.json" }, security: { approver: "platform", approvedAt: review.approvedAt, evidenceRef: "evidence/approvals/security.json" }, operations: { approver: "platform", approvedAt: review.approvedAt, evidenceRef: "evidence/approvals/operations.json" }, dataOwner: { approver: "platform", approvedAt: review.approvedAt, evidenceRef: "evidence/approvals/data-owner.json" }, changeManagement: { approver: "platform", approvedAt: review.approvedAt, evidenceRef: "evidence/approvals/change.json" } },
    change: { changeClass: "INITIAL", migrationRef: "evidence/change/migration.json", rollbackRef: "evidence/change/rollback.json", decommissionRef: "evidence/change/decommission.json", previousApprovedRevision: null },
    publicEndpoints: raw.publicEndpoints as unknown[],
    pulseContract: raw.pulseContract
  };
  return manifest;
}

function assertAnnotationPolicy(annotations: z.infer<typeof annotationsSchema>, effectClass: OnboardingManifest["behavior"]["effectClass"]): void {
  if (effectClass === "READ_ONLY") {
    if (!annotations.readOnlyHint || annotations.destructiveHint || !annotations.idempotentHint) throw new Error("effect_class_annotations_mismatch");
    return;
  }
  if (effectClass === "IDEMPOTENT_WRITE") {
    if (annotations.readOnlyHint || annotations.destructiveHint || !annotations.idempotentHint) throw new Error("effect_class_annotations_mismatch");
    return;
  }
  if (annotations.readOnlyHint || annotations.idempotentHint || !annotations.destructiveHint) throw new Error("effect_class_annotations_mismatch");
}

function assertManifest15Invariants(manifest: RegistrationManifest15): void {
  assertAnnotationPolicy(manifest.tool.annotations, manifest.behavior.effectClass);
  if (manifest.contractDigests.inputSchema !== digestCanonicalJson(manifest.tool.inputSchema)) throw new Error("input_schema_digest_mismatch");
  if (manifest.contractDigests.outputSchema !== digestCanonicalJson(manifest.tool.outputSchema)) throw new Error("output_schema_digest_mismatch");
  if (canonicalJson(manifest.protocol.errorCatalog) !== canonicalJson(manifest.errorCatalog)) throw new Error("error_catalog_mismatch");
  if (canonicalJson([...manifest.runtime.egressAllowlist].sort()) !== canonicalJson([...manifest.dependencies.networkPolicy.outboundAllowlist].sort())) {
    throw new Error("egress_allowlist_mismatch");
  }
  if (!manifest.dataGovernance.exportAllowed && manifest.dataGovernance.exportDestinations.length > 0) throw new Error("data_export_policy_mismatch");
  if (new Set(manifest.autoQuarantine.rules).size !== manifest.autoQuarantine.rules.length) throw new Error("duplicate_auto_quarantine_rule");
  if (manifest.testContract.loadProfile.expectedConcurrency > manifest.behavior.maxConcurrency) throw new Error("load_profile_exceeds_concurrency");
  if (manifest.monitoringProfile.staleAfterSeconds < Math.max(...Object.values(manifest.monitoringProfile.probeIntervals))) {
    throw new Error("monitoring_stale_window_too_short");
  }

  const approvedAt = new Date(manifest.review.approvedAt).getTime();
  const reviewDueAt = new Date(manifest.review.reviewDueAt).getTime();
  const expectedDueAt = approvedAt + manifest.review.intervalDays * 86_400_000;
  if (Math.abs(reviewDueAt - expectedDueAt) > 1_000) throw new Error("review_interval_mismatch");
  const sensitive = manifest.behavior.effectClass === "NON_IDEMPOTENT_WRITE"
    || manifest.criticality === "CRITICAL"
    || manifest.dataGovernance.containsPersonalData
    || ["CONFIDENTIAL", "RESTRICTED"].includes(manifest.dataGovernance.classification);
  if (manifest.review.intervalDays > (sensitive ? 180 : 365)) throw new Error("review_interval_exceeds_policy");
  if (new Date(manifest.evidence.compatibilityWindowEndsAt).getTime() < approvedAt) throw new Error("compatibility_window_invalid");
  const secretRefs = manifest.dependencies.secretReferences.map((item) => item.reference);
  if (new Set(secretRefs).size !== secretRefs.length) throw new Error("duplicate_secret_reference");
  if ((manifest.change.changeClass === "INITIAL") !== (manifest.change.previousApprovedRevision === null)) {
    throw new Error("previous_revision_mismatch");
  }
}

function validateParsedManifest(manifest: OnboardingManifest): void {
  validateJsonSchemas(manifest.tool.inputSchema, manifest.tool.outputSchema);
  assertAnnotationPolicy(manifest.tool.annotations, manifest.behavior.effectClass);
  if (manifest.schemaVersion === "1.5") assertManifest15Invariants(manifest);
  if (manifest.schemaVersion === "2026.07.20" || manifest.schemaVersion === KCML_RELEASE.manifestSchemaVersion) {
    if (!manifest.publicEndpoints.length) throw new Error("public_endpoint_required_for_mcp");
    if (manifest.protocol.protocolVersion !== KCML_RELEASE.mcpProtocolVersion) throw new Error("mcp_protocol_mismatch");
  }
}

function resultFor<T extends OnboardingManifest>(manifest: T): { manifest: T; digest: string } {
  validateParsedManifest(manifest);
  return {
    manifest,
    digest: `sha256:${createHash("sha256").update(canonicalJson(manifest)).digest("hex")}`
  };
}

export function validateOnboardingManifest(input: unknown): { manifest: RuntimeRegistrationManifest; digest: string } {
  if (exactComponentType(input) === "MCP_SERVER") {
    const manifest = normalizeComponentMcpManifest(input);
    validateParsedManifest(manifest);
    return {
      manifest,
      digest: `sha256:${createHash("sha256").update(canonicalJson(input)).digest("hex")}`
    };
  }
  if (input && typeof input === "object" && !Array.isArray(input) && (input as Record<string, unknown>).schemaVersion !== KCML_RELEASE.manifestSchemaVersion) {
    throw new Error("old_manifest_schema_not_accepted");
  }
  throw new Error("invalid_manifest");
}

export function validateStoredOnboardingManifest(input: unknown): { manifest: OnboardingManifest; digest: string } {
  const storedRuntime20260720 = parseStoredRuntimeRegistrationManifest20260720(input);
  if (storedRuntime20260720) return resultFor(storedRuntime20260720);
  const current = registrationManifest15Schema.safeParse(input);
  if (current.success) return resultFor(current.data);
  const storedCurrent = storedRegistrationManifest15Schema.safeParse(input);
  if (storedCurrent.success) {
    const normalized = {
      ...storedCurrent.data,
      source: { ...storedCurrent.data.source, runtime: "nodejs24-typescript" as const }
    };
    return resultFor(normalized);
  }
  return resultFor(legacyOnboardingManifestSchema.parse(input));
}

export function validateManifest(input: unknown, baseDomain: string): { manifest: RuntimeRegistrationManifest; digest: string } {
  void baseDomain;
  return validateOnboardingManifest(input);
}

export function reviewMetadataForManifest(manifest: OnboardingManifest): { schemaVersion: string; approvedAt: string; reviewDueAt: string; intervalDays: number } {
  if (isStructuredOnboardingManifest(manifest)) {
    return {
      schemaVersion: manifest.schemaVersion,
      approvedAt: manifest.review.approvedAt,
      reviewDueAt: manifest.review.reviewDueAt,
      intervalDays: manifest.review.intervalDays
    };
  }
  const legacy = manifest;
  const reviewDueAt = new Date(legacy.change.reviewDueAt);
  const intervalDays = manifest.behavior.effectClass === "NON_IDEMPOTENT_WRITE"
    || legacy.dependencies?.dataClassification.containsPersonalData ? 180 : 365;
  return {
    schemaVersion: manifest.schemaVersion,
    approvedAt: new Date(reviewDueAt.getTime() - intervalDays * 86_400_000).toISOString(),
    reviewDueAt: reviewDueAt.toISOString(),
    intervalDays
  };
}

export function evidenceReferencesForManifest(manifest: OnboardingManifest): string[] {
  const references = new Set<string>();
  const visit = (value: unknown, key = ""): void => {
    if (typeof value === "string" && (key.endsWith("Ref") || key.endsWith("evidenceRef")) && value.startsWith("evidence/")) references.add(value);
    else if (Array.isArray(value)) value.forEach((item) => visit(item, key));
    else if (value && typeof value === "object") {
      for (const [nestedKey, nestedValue] of Object.entries(value as Record<string, unknown>)) visit(nestedValue, nestedKey);
    }
  };
  visit(manifest);
  return [...references].sort();
}

export async function allocateKcml(db: Db, baseDomain: string): Promise<{ code: string; hostname: string; number: number }> {
  const result = await db.query("select nextval('kcml_number_seq') as number");
  const number = Number(result.rows[0].number);
  const code = kcmlCodeFromNumber(number);
  return { number, code, hostname: kcmlHostnameForCode(code, baseDomain) };
}
