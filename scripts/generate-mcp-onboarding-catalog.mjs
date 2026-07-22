import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const release = "2026.07.22-compliance.1";
const schemaPath = path.join(root, `apps/server/src/contracts/component-manifest-${release}.schema.json`);
const examplePath = path.join(root, `docs/onboarding-manifest-${release}.example.json`);
const catalogPath = path.join(root, `docs/onboarding-catalogs/component-${release}.json`);
const digest = (value) => `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
const sha = { type: "string", pattern: "^sha256:[a-f0-9]{64}$" };
const objectSchema = { type: "object", minProperties: 1 };
const content = {
  oneOf: [
    { type: "object", required: ["mediaType", "json"], additionalProperties: false, properties: { mediaType: { const: "application/json" }, json: {} } },
    { type: "object", required: ["mediaType", "base64"], additionalProperties: false, properties: { mediaType: { type: "string", minLength: 3 }, base64: { type: "string", minLength: 1, contentEncoding: "base64" } } }
  ]
};
const schema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: `https://register.hcasc.cz/schemas/component-manifest-${release}.schema.json`,
  title: "KCML generic component onboarding manifest",
  type: "object",
  additionalProperties: false,
  required: ["schemaVersion", "registrationRevision", "displayName", "businessPurpose", "kind", "owners", "contacts", "criticality", "artifact", "runtime", "capabilities", "tools", "endpoints", "pulses", "states", "controlPlane", "e2eScenarios", "documentationEvidence", "secretPolicy", "outboundPolicies", "monitoring", "auditPolicy"],
  properties: {
    schemaVersion: { const: release },
    registrationRevision: { type: "string", pattern: "^[0-9]+\\.[0-9]+\\.[0-9]+$" },
    displayName: { type: "string", minLength: 2, maxLength: 200 },
    businessPurpose: { type: "string", minLength: 10, maxLength: 4000 },
    kind: { type: "string", minLength: 2, maxLength: 120 },
    owners: { type: "array", minItems: 1, items: { type: "object", required: ["name"], additionalProperties: false, properties: { name: { type: "string", minLength: 2 }, team: { type: "string" } } } },
    contacts: { type: "array", minItems: 1, items: { type: "object", required: ["type", "value"], additionalProperties: false, properties: { type: { enum: ["EMAIL", "SLACK", "URL"] }, value: { type: "string", minLength: 3 } } } },
    criticality: { type: "object", required: ["level", "reviewIntervalDays"], additionalProperties: false, properties: { level: { enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"] }, reviewIntervalDays: { type: "integer", minimum: 1, maximum: 365 } } },
    artifact: { type: "object", required: ["type", "digest", "provenance"], additionalProperties: false, properties: { type: { enum: ["OCI_IMAGE", "SOURCE_PACKAGE", "REMOTE_RUNTIME"] }, digest: sha, provenance: objectSchema, imageReference: { type: "string" }, sourceBundleDigest: sha, buildContract: { type: "object" } } },
    runtime: { type: "object", required: ["transport", "runtimeDigest", "resources"], additionalProperties: false, properties: { transport: { enum: ["UDS", "HTTPS"] }, runtimeDigest: sha, upstream: { type: "string", format: "uri" }, socketPath: { type: "string", pattern: "^/" }, tlsIdentity: { type: "string" }, container: { type: "object" }, resources: { type: "object", required: ["cpuMillis", "memoryMiB", "maxConcurrency"], additionalProperties: false, properties: { cpuMillis: { type: "integer", minimum: 10 }, memoryMiB: { type: "integer", minimum: 16 }, maxConcurrency: { type: "integer", minimum: 1 } } } } },
    capabilities: { type: "array", uniqueItems: true, items: { type: "string", minLength: 2, maxLength: 160 } },
    tools: { type: "array", items: { type: "object", required: ["name", "title", "description", "inputSchema", "outputSchema", "scope", "timeoutMs", "limits"], additionalProperties: false, properties: { name: { type: "string", pattern: "^[a-zA-Z0-9._-]+$" }, title: { type: "string", minLength: 2 }, description: { type: "string", minLength: 5 }, inputSchema: objectSchema, outputSchema: objectSchema, scope: { type: "string", minLength: 2 }, timeoutMs: { type: "integer", minimum: 100, maximum: 300000 }, limits: { type: "object", required: ["requestMaxBytes", "responseMaxBytes"], additionalProperties: false, properties: { requestMaxBytes: { type: "integer", minimum: 1 }, responseMaxBytes: { type: "integer", minimum: 1 } } }, annotations: { type: "object" } } } },
    endpoints: { type: "array", items: { type: "object", required: ["key", "method", "path", "scope", "requestSchema", "responseSchema"], additionalProperties: false, properties: { key: { type: "string", minLength: 2 }, method: { enum: ["GET", "POST", "PUT", "PATCH", "DELETE"] }, path: { type: "string", pattern: "^/" }, scope: { type: "string", minLength: 2 }, requestSchema: objectSchema, responseSchema: objectSchema } } },
    pulses: { type: "object", required: ["incoming", "outgoing"], additionalProperties: false, properties: { incoming: { type: "array", items: { $ref: "#/$defs/pulse" } }, outgoing: { type: "array", items: { $ref: "#/$defs/pulse" } } } },
    states: { type: "object", required: ["states", "transitions"], additionalProperties: false, properties: { states: { type: "array", minItems: 1, items: { type: "object", required: ["key", "category", "schema"], additionalProperties: false, properties: { key: { type: "string", minLength: 2 }, category: { type: "string", minLength: 2 }, schema: objectSchema, terminal: { type: "boolean" } } } }, transitions: { type: "array", items: { type: "object", required: ["from", "to", "trigger"], additionalProperties: false, properties: { from: { type: "string" }, to: { type: "string" }, trigger: { type: "string" } } } } } },
    controlPlane: { type: "object", required: ["enable", "disable", "state", "heartbeat"], additionalProperties: false, properties: Object.fromEntries(["enable", "disable", "state", "heartbeat"].map((key) => [key, { type: "object", required: ["path", "requestSchema", "responseSchema"], additionalProperties: false, properties: { path: { type: "string", pattern: "^/" }, requestSchema: objectSchema, responseSchema: objectSchema } }])) },
    e2eScenarios: { type: "array", minItems: 1, items: { type: "object", required: ["scenarioKey", "variantKey", "invocation", "input", "expected", "timeoutMs", "deterministic", "cleanup"], additionalProperties: false, properties: { scenarioKey: { type: "string", minLength: 2 }, variantKey: { type: "string", minLength: 1 }, invocation: { type: "object", required: ["kind", "name"], additionalProperties: false, properties: { kind: { enum: ["TOOL", "PULSE", "ENDPOINT"] }, name: { type: "string", minLength: 1 } } }, input: content, expected: content, timeoutMs: { type: "integer", minimum: 100, maximum: 600000 }, deterministic: { const: true }, cleanup: { type: "object", required: ["required"], additionalProperties: false, properties: { required: { type: "boolean" }, operation: { type: "string" } } } } } },
    documentationEvidence: { type: "array", minItems: 1, items: { type: "object", required: ["key", "path", "digest", "content"], additionalProperties: false, properties: { key: { type: "string", minLength: 2 }, path: { type: "string", pattern: "^(?!/)(?!.*\\.\\.).+$" }, digest: sha, content } } },
    secretPolicy: { type: "object", required: ["authorizationAuthority", "allSecretsRequireGrant", "auditLevel"], additionalProperties: false, properties: { authorizationAuthority: { const: "KCML" }, allSecretsRequireGrant: { const: true }, auditLevel: { const: "FULL" } } },
    outboundPolicies: { type: "array", items: { type: "object", required: ["target", "pathPrefix", "scope"], additionalProperties: false, properties: { target: { type: "string", minLength: 2 }, pathPrefix: { type: "string", pattern: "^/" }, scope: { type: "string", minLength: 2 } } } },
    monitoring: { type: "object", required: ["probes", "staleAfterSeconds", "disableAfterSeconds"], additionalProperties: false, properties: { probes: { type: "array", minItems: 1, items: { type: "object", required: ["kind", "intervalSeconds"], additionalProperties: false, properties: { kind: { type: "string", minLength: 2 }, intervalSeconds: { type: "integer", minimum: 5 } } } }, staleAfterSeconds: { type: "integer", minimum: 10 }, disableAfterSeconds: { type: "integer", minimum: 10 } } },
    auditPolicy: { type: "object", required: ["technicalAudit", "payloadProtection", "retentionDays"], additionalProperties: false, properties: { technicalAudit: { const: "PLATFORM" }, payloadProtection: { const: "ENCRYPTED" }, retentionDays: { type: "integer", minimum: 1 } } }
  },
  $defs: { pulse: { type: "object", required: ["type", "schema", "scope"], additionalProperties: false, properties: { type: { type: "string", minLength: 2 }, schema: objectSchema, scope: { type: "string", minLength: 2 } } } }
};

const example = {
  schemaVersion: release, registrationRevision: "1.0.0", displayName: "Inventory lookup", businessPurpose: "Returns authoritative inventory availability.", kind: "inventory-api",
  owners: [{ name: "Inventory Platform", team: "Commerce" }], contacts: [{ type: "EMAIL", value: "inventory@example.com" }], criticality: { level: "HIGH", reviewIntervalDays: 90 },
  artifact: { type: "REMOTE_RUNTIME", digest: digest("inventory-runtime-artifact-v1"), provenance: { issuer: "https://github.com" } },
  runtime: { transport: "HTTPS", runtimeDigest: digest("inventory-runtime-v1"), upstream: "https://inventory-runtime.example.com", tlsIdentity: "inventory-runtime.example.com", resources: { cpuMillis: 500, memoryMiB: 256, maxConcurrency: 20 } },
  capabilities: ["mcp.initialize", "mcp.notifications.initialized", "mcp.tools.list", "mcp.tools.call", "component.control.ack", "component.state.query", "component.heartbeat", "component.audit.write"],
  tools: [{ name: "inventory.lookup", title: "Inventory lookup", description: "Looks up inventory by SKU.", inputSchema: { type: "object", required: ["sku"], additionalProperties: false, properties: { sku: { type: "string" } } }, outputSchema: { type: "object", required: ["available"], additionalProperties: false, properties: { available: { type: "boolean" } } }, scope: "inventory.lookup", timeoutMs: 5000, limits: { requestMaxBytes: 65536, responseMaxBytes: 65536 }, annotations: { readOnlyHint: true } }],
  endpoints: [], pulses: { incoming: [], outgoing: [] },
  states: { states: [{ key: "LIFECYCLE", category: "OPERATIONAL", schema: { type: "object", required: ["enabled", "activationState", "operationalState"], additionalProperties: false, properties: { enabled: { type: "boolean" }, activationState: { type: "string" }, operationalState: { type: "string" } } }, terminal: false }], transitions: [] },
  controlPlane: Object.fromEntries(["enable", "disable", "state", "heartbeat"].map((key) => [key, { path: `/v1/kcml/control/${key}`, requestSchema: { type: "object", required: ["commandId"], properties: { commandId: { type: "string" } } }, responseSchema: { type: "object", required: ["accepted"], properties: { accepted: { type: "boolean" } } } }])),
  e2eScenarios: [{ scenarioKey: "lookup", variantKey: "known-sku", invocation: { kind: "TOOL", name: "inventory.lookup" }, input: { mediaType: "application/json", json: { sku: "SKU-1" } }, expected: { mediaType: "application/json", json: { available: true } }, timeoutMs: 5000, deterministic: true, cleanup: { required: false } }],
  documentationEvidence: [{ key: "runbook", path: "docs/runbook.md", digest: digest(Buffer.from("IyBSdW5ib29r", "base64")), content: { mediaType: "text/markdown", base64: "IyBSdW5ib29r" } }],
  secretPolicy: { authorizationAuthority: "KCML", allSecretsRequireGrant: true, auditLevel: "FULL" }, outboundPolicies: [],
  monitoring: { probes: [{ kind: "runtime", intervalSeconds: 60 }], staleAfterSeconds: 180, disableAfterSeconds: 600 },
  auditPolicy: { technicalAudit: "PLATFORM", payloadProtection: "ENCRYPTED", retentionDays: 365 }
};

const catalog = {
  version: release, normativeLabel: "2026.07.22-COMPLIANCE.1", serviceKind: "COMPONENT",
  manifestSchemaVersion: release, pulseEnvelopeVersion: release, policyBaseline: "2026-07-22", mcpProtocolVersion: "2025-11-25",
  manifestSchemaPath: `apps/server/src/contracts/component-manifest-${release}.schema.json`,
  manifestExamplePath: `docs/onboarding-manifest-${release}.example.json`,
  documentationArtifacts: [`docs/releases/${release}/README.md`, `docs/releases/${release}/compatibility-matrix.md`],
  jsonSchema: schema,
  identityAssignment: { authority: "KCML", codePattern: "KCML####", hostnamePattern: "kcml####.kajovocml.hcasc.cz", clientSuppliedIdentityForbidden: true },
  tokens: { integration: { ttlHours: 24, consumedOn: "SUCCESSFUL_REGISTRATION", reusableAfterFailedAttempt: true }, access: { expires: false, rotatedOrRevokedOnly: true }, permittedTokenClasses: ["INTEGRATION", "ACCESS"] },
  runtime: { canonicalMcpPath: "/mcp", transports: ["UDS", "HTTPS"], internalControlExcludedFromBusinessTools: true },
  compatibility: { classification: "BREAKING", migration: "Re-submit a generic manifest and evidence bundle against the canonical pre-production baseline.", rollback: "Restore the last verified pre-production release and re-run baseline verification." },
  compatibilityMatrix: [{ kind: "ANY_API_CAPABLE_COMPONENT", UDS: "SUPPORTED", HTTPS: "SUPPORTED" }],
  pipelineGates: ["manifest_schema", "artifact_provenance", "runtime_probe", "authorization", "control_plane", "state_contract", "e2e_all_scenarios", "monitoring", "audit_continuity", "recertification"],
  programmerApi: { openapi: "3.1.0", paths: { "/v2/component-onboardings": { post: {} }, "/v2/component-onboardings/{id}": { get: {} }, "/v2/component-onboardings/{id}/revisions": { post: {} }, "/v2/component-onboardings/{id}/readiness": { post: {} }, "/v2/component-onboardings/{id}/e2e-results": { post: { deprecated: true, responses: { 410: { description: "Client supplied E2E evidence is forbidden" } } } } } }
};

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort((left, right) => left.localeCompare(right)).map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}
const digestInput = structuredClone(catalog);
catalog.canonicalDigest = `sha256:${crypto.createHash("sha256").update(canonical(digestInput)).digest("hex")}`;

const outputs = [[schemaPath, schema], [examplePath, example], [catalogPath, catalog]];
const check = process.argv.includes("--check");
let stale = false;
for (const [file, value] of outputs) {
  const rendered = `${JSON.stringify(value, null, 2)}\n`;
  if (check) {
    if (!fs.existsSync(file) || fs.readFileSync(file, "utf8") !== rendered) { console.error(`stale generated artifact: ${path.relative(root, file)}`); stale = true; }
  } else {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, rendered);
  }
}
if (stale) process.exitCode = 1;
