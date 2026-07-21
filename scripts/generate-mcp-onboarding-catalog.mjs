import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const releaseArgument = process.argv.find((argument) => argument.startsWith("--release="));
const release = releaseArgument?.slice("--release=".length) ?? "2026.07.23";
if (!/^20[0-9]{2}[.](0[1-9]|1[0-2])[.](0[1-9]|[12][0-9]|3[01])$/.test(release)) throw new Error(`Unsupported catalog release: ${release}`);
if (release <= "2026.07.20") throw new Error(`Historical catalog is immutable: ${release}`);
const protocol = "2025-11-25";
const outputPath = path.join(root, `docs/onboarding-catalogs/component-${release}.json`);
const schemaPath = path.join(root, `apps/server/src/contracts/component-manifest-${release}.schema.json`);
const examplePath = path.join(root, `docs/onboarding-manifest-${release}.example.json`);
const flowFabricBlueprintPath = path.join(root, `docs/blueprints/flowfabric-first-wave-${release}.json`);
const flowFabricBlueprint = fs.existsSync(flowFabricBlueprintPath)
  ? JSON.parse(fs.readFileSync(flowFabricBlueprintPath, "utf8"))
  : null;
if (flowFabricBlueprint && flowFabricBlueprint.releaseVersion !== release) throw new Error(`FlowFabric blueprint release mismatch: ${flowFabricBlueprint.releaseVersion}`);

const aiComponents = [
  ["AI-CLS-001", "AGENT_ROUTER"],
  ["AI-QRP-002", "AGENT_WORKER"],
  ["AI-LYL-003", "AGENT_WORKER"],
  ["AI-GRP-004", "AGENT_WORKER"],
  ["AI-BIZ-005", "AGENT_WORKER"],
  ["AI-IND-006", "AGENT_WORKER"],
  ["AI-HIS-007", "AGENT_CONTEXT"],
  ["AI-BRD-008", "AGENT_REVIEW"],
  ["AI-QA-009", "AGENT_QA"]
];
const mcpComponents = [
  ["MCP-RX-WA-001", "EVENT_INGRESS"],
  ["MCP-RX-MS-002", "EVENT_INGRESS"],
  ["MCP-RX-EM-003", "EVENT_INGRESS"],
  ["MCP-RX-BC-004", "EVENT_INGRESS"],
  ["MCP-PMS-RO-005", "ISOLATED_HANDLER"],
  ["MCP-PMS-RW-006", "STATEFUL_HANDLER"],
  ["MCP-TX-WA-007", "ASYNC_EGRESS"],
  ["MCP-TX-MS-008", "ASYNC_EGRESS"],
  ["MCP-TX-EM-009", "ASYNC_EGRESS"],
  ["MCP-TX-BC-010", "ASYNC_EGRESS"],
  ["MCP-WFC-011", "STATEFUL_SERVICE"]
];
const managedServices = ["KCML-AUTH-001", "KCML-CTL-002", "KCML-MON-003", "KCML-AUD-004", "KCML-SEC-005"];
const releaseWaveKey = "baseline-2026-07-23";
const generatedBlueprintIds = [...aiComponents, ...mcpComponents].map(([componentId]) => componentId);
const blueprintIds = generatedBlueprintIds.concat(managedServices);

const gatesByStage = {
  intake: ["archive_policy", "manifest_schema", "token_scope", "authorization_snapshot", "secret_scan", "dependency_policy"],
  ci: ["path_policy", "lint", "typecheck", "unit_tests", "contract_tests", "sast", "sca", "license", "sbom", "reproducible_build"],
  supply_chain: ["source_commit", "artifact_digest", "artifact_signature", "provenance"],
  deploy: ["runtime_isolation", "worker_readiness", "agent_runtime_profile", "mcp_runtime_profile"],
  preflight: ["dns", "tls_san", "host_path_method_endpoint", "route_acl"],
  trial: ["negative_auth", "mcp_initialize", "pulse_acl", "ack_then_event", "schema_contract", "correlation_chain", "logging_redaction", "technical_audit", "business_audit", "monitoring_probes", "recertification"]
};
const componentActivationGates = [
  "FULL_SCHEMA", "PULSE_CONTRACT", "STATE_CONTRACT", "CALL_MASKS", "E2E_SCENARIOS", "DOCUMENTATION",
  "CONTROL_PLANE", "SECRET_POLICY", "OUTBOUND_AUTH", "AUTHORIZATION", "PUBLIC_ENDPOINT", "TECHNICAL_DISABLE",
  "MONITORING", "AUDIT_CONTINUITY", "RECERTIFICATION"
];

const requiredChecks = [
  "path-policy", "manifest-schema", "lint", "typecheck", "unit-tests", "contract-tests",
  "secret-scan", "sast", "sca-license", "sbom", "reproducible-build", "artifact-signature"
];

const errorCodes = [
  "invalid_integration_token", "integration_token_kind_mismatch", "integration_token_scope_mismatch",
  "blueprint_component_not_allowed", "duplicate_blueprint_component", "max_child_jobs_exceeded",
  "invalid_idempotency_key", "idempotency_key_reused", "multipart_required", "invalid_manifest_json",
  "manifest_and_source_required", "invalid_source_part", "source_must_be_zip", "invalid_manifest",
  "manifest_evidence_missing", "old_manifest_schema_not_accepted", "component_identity_forbidden",
  "handler_retry_must_be_false", "audit_policy_mismatch", "public_endpoint_forbidden_for_ai",
  "public_endpoint_required_for_mcp", "facade_tool_count_mismatch", "mcp_protocol_mismatch",
  "ack_then_event_contract_invalid", "route_acl_invalid", "archive_too_large", "expanded_archive_too_large",
  "too_many_files", "unsafe_archive_path", "secret_detected", "dependency_version_must_be_exact",
  "source_revision_not_allowed", "idempotency_key_and_if_match_required", "lock_version_conflict",
  "job_terminal", "not_found", "gone", "invalid_token", "expired_token", "revoked_token",
  "insufficient_scope", "invalid_audience", "component_disabled", "component_quarantined",
  "route_denied", "catalog_incompatible", "audit_gap", "audit_stream_unavailable"
];

const ref = (name) => ({ $ref: `#/$defs/${name}` });
const strictObjectSchema = {
  type: "object",
  required: ["type", "required", "properties"],
  additionalProperties: true,
  properties: {
    type: { const: "object" },
    required: { type: "array", minItems: 1, items: { type: "string", minLength: 1 } },
    properties: { type: "object", minProperties: 1 }
  }
};
const schema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: `urn:kcml:schema:component-manifest:${release}`,
  title: `KajovoCML component manifest ${release}`,
  oneOf: [{ $ref: "#/$defs/aiAgentManifest" }, { $ref: "#/$defs/mcpServerManifest" }, { $ref: "#/$defs/managedServiceManifest" }, { $ref: "#/$defs/genericComponentManifest" }],
  discriminator: { propertyName: "componentType" },
  $defs: {
    sha256: { type: "string", pattern: "^sha256:[a-f0-9]{64}$" },
    timestamp: { type: "string", format: "date-time" },
    email: { type: "string", format: "email", maxLength: 254 },
    blueprintId: { enum: [...blueprintIds, ...managedServices] },
    contact: {
      type: "object", additionalProperties: false, required: ["name", "email"],
      properties: { name: { type: "string", minLength: 2, maxLength: 160 }, email: ref("email") }
    },
    strictObjectSchema,
    endpoint: {
      type: "object", additionalProperties: false,
      required: ["endpointId", "path", "methods", "authMode", "requestSchema", "responseSchema", "limits", "timeoutMs", "rateLimit", "idempotency", "signatureProfile", "eventMapping"],
      properties: {
        endpointId: { type: "string", pattern: "^[A-Z0-9][A-Z0-9_-]{2,63}$" },
        path: { type: "string", pattern: "^/" },
        methods: { type: "array", minItems: 1, uniqueItems: true, items: { enum: ["GET", "POST", "PUT", "PATCH", "DELETE"] } },
        authMode: { enum: ["KCML_BEARER", "SIGNED_WEBHOOK", "MUTUAL_TLS"] },
        requestSchema: ref("strictObjectSchema"),
        responseSchema: ref("strictObjectSchema"),
        limits: { type: "object", additionalProperties: false, required: ["requestBytes", "responseBytes"], properties: { requestBytes: { type: "integer", minimum: 1, maximum: 1048576 }, responseBytes: { type: "integer", minimum: 1, maximum: 5242880 } } },
        timeoutMs: { type: "integer", minimum: 100, maximum: 60000 },
        rateLimit: { type: "object", additionalProperties: false, required: ["windowSeconds", "maxRequests"], properties: { windowSeconds: { type: "integer", minimum: 1, maximum: 86400 }, maxRequests: { type: "integer", minimum: 1, maximum: 100000 } } },
        idempotency: { enum: ["REQUIRED", "OPTIONAL", "FORBIDDEN"] },
        signatureProfile: { type: "string", minLength: 3, maxLength: 120 },
        eventMapping: { type: "object", additionalProperties: false, required: ["pulseType", "correlationIdSource"], properties: { pulseType: { type: "string", minLength: 3, maxLength: 160 }, correlationIdSource: { type: "string", minLength: 3, maxLength: 160 } } }
      }
    },
    pulse: {
      type: "object", additionalProperties: false,
      required: ["pulseType", "direction", "schema", "routeAcl", "scopes", "executionMode", "timeoutMs", "resultPulseTypes", "deadlineMs", "retry", "idempotency"],
      properties: {
        pulseType: { type: "string", minLength: 3, maxLength: 160 },
        direction: { enum: ["INCOMING", "OUTGOING"] },
        schema: ref("strictObjectSchema"),
        routeAcl: { type: "array", minItems: 1, items: { type: "string", minLength: 3, maxLength: 160 } },
        scopes: { type: "array", items: { type: "string", minLength: 3, maxLength: 160 } },
        executionMode: { enum: ["SYNC", "ACK_THEN_EVENT", "ASYNC"] },
        timeoutMs: { type: "integer", minimum: 100, maximum: 60000 },
        resultPulseTypes: { type: "array", items: { type: "string", minLength: 3, maxLength: 160 } },
        deadlineMs: { type: "integer", minimum: 100, maximum: 86400000 },
        retry: { type: "object", additionalProperties: false, required: ["transportRetry", "retryable", "requiresIdempotencyKey"], properties: { transportRetry: { type: "boolean" }, retryable: { type: "boolean" }, requiresIdempotencyKey: { type: "boolean" } } },
        idempotency: { enum: ["REQUIRED", "OPTIONAL", "FORBIDDEN"] }
      }
    },
    common: {
      type: "object",
      required: [
        "schemaVersion", "releaseVersion", "registrationRevision", "environment", "componentType",
        "registrationType", "blueprint", "pulseEnvelopeVersion", "displayName", "businessPurpose",
        "owners", "contacts", "criticality", "review", "source", "runtime", "dependencies",
        "networkPolicy", "dataGovernance", "pulseContract", "retryPolicy", "auditPolicy",
        "monitoringProfile", "maintenance", "autoQuarantine", "evidence", "change", "integrity",
        "stateContract", "e2eScenarios", "documentationEvidence", "controlPlane", "outboundAuthorization", "secretPolicy"
      ],
      properties: {
        schemaVersion: { const: release },
        releaseVersion: { const: release },
        registrationRevision: { type: "string", pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{2,79}$" },
        environment: { enum: ["production", "staging"] },
        componentType: { enum: ["AI_AGENT", "MCP_SERVER", "KCML_MANAGED_SERVICE", "GENERIC_COMPONENT"] },
        registrationType: { type: "string", pattern: "^[A-Z][A-Z0-9_]{2,79}$" },
        blueprint: {
          type: "object",
          additionalProperties: false,
          required: ["componentId", "version", "releaseWaveKey"],
          properties: { componentId: ref("blueprintId"), version: { const: release }, releaseWaveKey: { const: releaseWaveKey } }
        },
        pulseEnvelopeVersion: { const: release },
        displayName: { type: "string", minLength: 3, maxLength: 120 },
        businessPurpose: { type: "string", minLength: 20, maxLength: 2000 },
        owners: { type: "array", minItems: 1, maxItems: 8, items: ref("contact") },
        contacts: { type: "array", minItems: 1, maxItems: 8, items: ref("contact") },
        criticality: { enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"] },
        review: { type: "object", additionalProperties: false, required: ["intervalDays", "approvedAt", "reviewDueAt", "recertificationEvaluator"], properties: { intervalDays: { type: "integer", minimum: 1, maximum: 365 }, approvedAt: ref("timestamp"), reviewDueAt: ref("timestamp"), recertificationEvaluator: { const: "KCML-SEC-005" } } },
        source: { type: "object", additionalProperties: false, required: ["runtime", "entrypoint", "testCommand"], properties: { runtime: { const: "nodejs24-typescript" }, entrypoint: { const: "src/index.ts" }, testCommand: { const: "pnpm kcml:contract-test" } } },
        runtime: { type: "object", additionalProperties: true, required: ["memoryMb", "cpuCores", "pidsLimit"], properties: { memoryMb: { type: "integer", minimum: 64, maximum: 1024 }, cpuCores: { type: "number", minimum: 0.1, maximum: 4 }, pidsLimit: { type: "integer", minimum: 16, maximum: 512 } } },
        dependencies: { type: "array", items: { type: "object", additionalProperties: false, required: ["name", "version", "checksum"], properties: { name: { type: "string" }, version: { type: "string", pattern: "^[0-9][0-9A-Za-z.+-]*$" }, checksum: ref("sha256") } } },
        networkPolicy: { type: "object", additionalProperties: false, required: ["outboundAllowlist", "dnsPolicy", "filesystemPolicy"], properties: { outboundAllowlist: { type: "array", items: { type: "string" } }, dnsPolicy: { const: "strict" }, filesystemPolicy: { enum: ["read-only", "isolated-runtime-only"] } } },
        dataGovernance: { type: "object", additionalProperties: false, required: ["classification", "containsPersonalData", "retentionDays"], properties: { classification: { enum: ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"] }, containsPersonalData: { type: "boolean" }, retentionDays: { type: "integer", minimum: 1, maximum: 3650 } } },
        pulseContract: { type: "object", additionalProperties: false, required: ["incoming", "outgoing"], properties: { incoming: { type: "array", minItems: 1, items: ref("pulse") }, outgoing: { type: "array", minItems: 1, items: ref("pulse") } } },
        retryPolicy: { type: "object", additionalProperties: false, required: ["handlerRetry"], properties: { handlerRetry: { const: false } } },
        auditPolicy: { type: "object", additionalProperties: false, required: ["technicalAudit", "businessAudit"], properties: { technicalAudit: { const: "PLATFORM" }, businessAudit: { const: "COMPONENT" } } },
        monitoringProfile: { type: "object", additionalProperties: true, required: ["slo", "probes"], properties: { slo: { type: "object" }, probes: { type: "array", minItems: 1, items: { type: "string" } } } },
        maintenance: { type: "object", additionalProperties: true },
        autoQuarantine: { type: "object", additionalProperties: false, required: ["enabled", "rules"], properties: { enabled: { const: true }, rules: { type: "array", minItems: 1, items: { type: "string" } } } },
        evidence: { type: "object", minProperties: 1, additionalProperties: true },
        change: { type: "object", additionalProperties: true, required: ["changeClass"], properties: { changeClass: { enum: ["INITIAL", "PATCH", "MINOR", "MAJOR"] } } },
        integrity: { type: "object", additionalProperties: false, required: ["manifestDigest", "sourceDigest"], properties: { manifestDigest: ref("sha256"), sourceDigest: ref("sha256") } },
        stateContract: {
          type: "object", additionalProperties: false, required: ["states", "transitions"],
          properties: {
            states: { type: "array", minItems: 1, items: { type: "object", additionalProperties: false, required: ["stateKey", "category", "schema", "terminal"], properties: { stateKey: { type: "string", minLength: 2, maxLength: 160 }, category: { enum: ["OPERATIONAL", "BUSINESS", "CONTROL", "ERROR"] }, schema: ref("strictObjectSchema"), terminal: { type: "boolean" } } } },
            transitions: { type: "array", minItems: 1, items: { type: "object", additionalProperties: false, required: ["from", "to", "triggerMask"], properties: { from: { type: "string", minLength: 2 }, to: { type: "string", minLength: 2 }, triggerMask: { type: "string", minLength: 2 } } } }
          }
        },
        e2eScenarios: {
          type: "array", minItems: 1,
          items: { type: "object", additionalProperties: false, required: ["scenarioId", "variant", "inputRef", "inputDigest", "expectedOutputRef", "expectedOutputDigest", "expectedOutput", "testCommands"], properties: {
            scenarioId: { type: "string", minLength: 2, maxLength: 160 }, variant: { type: "string", minLength: 2, maxLength: 160 },
            inputRef: { type: "string", pattern: "^(?!.*(?:TODO|TBD|placeholder|sample|stub)).{3,}$" }, inputDigest: ref("sha256"),
            expectedOutputRef: { type: "string", pattern: "^(?!.*(?:TODO|TBD|placeholder|sample|stub)).{3,}$" }, expectedOutputDigest: ref("sha256"),
            expectedOutput: { type: "object", minProperties: 1 },
            testCommands: { type: "array", minItems: 3, contains: { const: "pnpm kcml:contract-test" }, items: { enum: ["pnpm test", "pnpm e2e", "pnpm kcml:contract-test"] } }
          } }
        },
        documentationEvidence: {
          type: "array", minItems: 1,
          items: { type: "object", additionalProperties: false, required: ["evidenceKey", "evidenceRef", "evidenceDigest", "mediaType", "required"], properties: {
            evidenceKey: { type: "string", minLength: 2, maxLength: 120 }, evidenceRef: { type: "string", pattern: "^(?!.*(?:TODO|TBD|placeholder|sample|stub)).{3,}$" },
            evidenceDigest: ref("sha256"), mediaType: { type: "string", minLength: 3, maxLength: 120 }, required: { const: true }
          } }
        },
        controlPlane: {
          type: "object", additionalProperties: false, required: ["enable", "disable", "state", "heartbeat"],
          properties: Object.fromEntries(["enable", "disable", "state", "heartbeat"].map((name) => [name, {
            type: "object", additionalProperties: false, required: ["supported", "path", "method", "requestSchema", "responseSchema"],
            properties: { supported: { const: true }, path: { type: "string", pattern: "^/" }, method: { const: "POST" }, requestSchema: ref("strictObjectSchema"), responseSchema: ref("strictObjectSchema") }
          }]))
        },
        outboundAuthorization: {
          type: "object", additionalProperties: false, required: ["required", "tokenRequired", "gatewayRequired", "verifyEachPulse"],
          properties: { required: { const: true }, tokenRequired: { const: true }, gatewayRequired: { const: true }, verifyEachPulse: { const: true } }
        },
        secretPolicy: {
          type: "object", additionalProperties: false, required: ["mode", "authorizationAuthority", "allSecretsRequiresGrant", "auditLevel"],
          properties: { mode: { enum: ["GRANTED_SECRETS", "ALL_SECRETS"] }, authorizationAuthority: { const: "KCML" }, allSecretsRequiresGrant: { const: true }, auditLevel: { const: "FULL" } }
        }
      }
    },
    aiAgentManifest: {
      allOf: [
        { $ref: "#/$defs/common" },
        {
          type: "object",
          required: ["componentType", "registrationType", "agentKey", "agentVersion", "executionProfile", "modelPolicy", "promptPolicy", "toolScopesAllowlist", "memoryPolicy", "fallbackPolicy", "publicEndpoints"],
          properties: {
            componentType: { const: "AI_AGENT" }, registrationType: { const: "KCML_ACCESS_CLIENT" },
            agentKey: { type: "string", pattern: "^[a-z0-9][a-z0-9_-]{1,62}$" },
            agentVersion: { type: "string", pattern: "^\\d+\\.\\d+\\.\\d+(?:-[A-Za-z0-9.-]+)?$" },
            executionProfile: { type: "object" }, modelPolicy: { type: "object" }, promptPolicy: { type: "object" },
            toolScopesAllowlist: { type: "array", items: { type: "string" } },
            memoryPolicy: { type: "object" }, fallbackPolicy: { type: "object" },
            publicEndpoints: { type: "array", maxItems: 0 }
          }
        }
      ]
    },
    mcpServerManifest: {
      allOf: [
        { $ref: "#/$defs/common" },
        {
          type: "object",
          required: ["componentType", "registrationType", "handlerKey", "handlerVersion", "facadeTools", "protocol", "publicEndpoints", "handlerContract"],
          properties: {
            componentType: { const: "MCP_SERVER" }, registrationType: { const: "MCP_SERVER" },
            handlerKey: { type: "string", pattern: "^[a-z0-9][a-z0-9_-]{1,62}$" },
            handlerVersion: { type: "string", pattern: "^\\d+\\.\\d+\\.\\d+(?:-[A-Za-z0-9.-]+)?$" },
            facadeTools: { type: "array", minItems: 1, maxItems: 1, items: { type: "object", additionalProperties: false, required: ["name", "inputSchema", "outputSchema"], properties: { name: { type: "string" }, inputSchema: ref("strictObjectSchema"), outputSchema: ref("strictObjectSchema") } } },
            protocol: { type: "object", additionalProperties: false, required: ["protocolVersion", "transport", "capabilities"], properties: { protocolVersion: { const: protocol }, transport: { const: "streamable-http" }, capabilities: { type: "array", prefixItems: [{ const: "tools" }], minItems: 1, maxItems: 1 } } },
            publicEndpoints: { type: "array", minItems: 1, items: ref("endpoint") },
            handlerContract: { type: "object", additionalProperties: true }
          }
        }
      ]
    },
    managedServiceManifest: {
      allOf: [
        { $ref: "#/$defs/common" },
        { type: "object", required: ["componentType", "registrationType", "managedServiceId"], properties: { componentType: { const: "KCML_MANAGED_SERVICE" }, registrationType: { const: "MANAGED_PLATFORM_SERVICE" }, managedServiceId: { enum: managedServices } } }
      ]
    },
    genericComponentManifest: {
      allOf: [
        { $ref: "#/$defs/common" },
        { type: "object", required: ["componentType", "registrationType", "publicEndpoints"], properties: { componentType: { const: "GENERIC_COMPONENT" }, registrationType: { const: "KCML_ACCESS_CLIENT" }, publicEndpoints: { type: "array", minItems: 1, items: ref("endpoint") } } }
      ]
    }
  }
};

const example = {
  schemaVersion: release,
  releaseVersion: release,
  registrationRevision: `${release.replaceAll(".", "-")}.1`,
  environment: "production",
  componentType: "MCP_SERVER",
  registrationType: "MCP_SERVER",
  blueprint: { componentId: "MCP-RX-WA-001", version: release, releaseWaveKey },
  pulseEnvelopeVersion: release,
  displayName: "WhatsApp event ingress",
  businessPurpose: "Receives approved WhatsApp ingress events and maps them into strict KCML pulses.",
  owners: [{ name: "Example Service Owner", email: "service@example.com" }],
  contacts: [{ name: "Example Operations", email: "ops@example.com" }],
  criticality: "HIGH",
  review: { intervalDays: 180, approvedAt: `${release.replaceAll(".", "-")}T00:00:00.000Z`, reviewDueAt: "2027-01-17T00:00:00.000Z", recertificationEvaluator: "KCML-SEC-005" },
  source: { runtime: "nodejs24-typescript", entrypoint: "src/index.ts", testCommand: "pnpm kcml:contract-test" },
  runtime: { memoryMb: 256, cpuCores: 0.5, pidsLimit: 64 },
  dependencies: [{ name: "node", version: "24.0.0", checksum: "sha256:61df8c17ef87f64d8bea5e68e6f19ed9bdaf904cbc70c9b2597e9293758d9944" }],
  networkPolicy: { outboundAllowlist: [], dnsPolicy: "strict", filesystemPolicy: "isolated-runtime-only" },
  dataGovernance: { classification: "CONFIDENTIAL", containsPersonalData: true, retentionDays: 365 },
  pulseContract: {
    incoming: [{ pulseType: "wa.message.received", direction: "INCOMING", schema: { type: "object", required: ["payload"], additionalProperties: false, properties: { payload: { type: "object", minProperties: 1 } } }, routeAcl: ["AI-CLS-001"], scopes: ["component.pulse"], executionMode: "ACK_THEN_EVENT", timeoutMs: 3000, resultPulseTypes: ["wa.message.accepted"], deadlineMs: 60000, retry: { transportRetry: true, retryable: true, requiresIdempotencyKey: true }, idempotency: "REQUIRED" }],
    outgoing: [{ pulseType: "wa.message.accepted", direction: "OUTGOING", schema: { type: "object", required: ["payload"], additionalProperties: false, properties: { payload: { type: "object", minProperties: 1 } } }, routeAcl: ["AI-CLS-001"], scopes: ["component.outbound.pulse"], executionMode: "ASYNC", timeoutMs: 3000, resultPulseTypes: [], deadlineMs: 60000, retry: { transportRetry: false, retryable: false, requiresIdempotencyKey: true }, idempotency: "REQUIRED" }]
  },
  retryPolicy: { handlerRetry: false },
  auditPolicy: { technicalAudit: "PLATFORM", businessAudit: "COMPONENT" },
  monitoringProfile: { slo: { availabilityPercent: 99.9 }, probes: ["runtime", "route_acl", "artifact_drift", "recertification"] },
  maintenance: { rollbackRef: "evidence/rollback.md" },
  autoQuarantine: { enabled: true, rules: ["CROSS_HOST", "ARTIFACT_DRIFT", "ROUTE_ACL_DRIFT"] },
  evidence: { architectureRef: "evidence/architecture.md", securityRef: "evidence/security.md" },
  change: { changeClass: "INITIAL" },
  integrity: { manifestDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000", sourceDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111" },
  stateContract: {
    states: [{ stateKey: "HEALTHY", category: "OPERATIONAL", schema: { type: "object", required: ["payload"], additionalProperties: false, properties: { payload: { type: "object", minProperties: 1 } } }, terminal: false }],
    transitions: [{ from: "HEALTHY", to: "UNHEALTHY", triggerMask: "heartbeat.missed" }]
  },
  e2eScenarios: [{
    scenarioId: "wa-ingress-happy-path",
    variant: "message",
    inputRef: "fixtures/wa-message.input.json",
    inputDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
    expectedOutputRef: "fixtures/wa-message.expected.json",
    expectedOutputDigest: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
    expectedOutput: { payload: { accepted: true, nextPulseType: "wa.message.accepted" } },
    testCommands: ["pnpm test", "pnpm e2e", "pnpm kcml:contract-test"]
  }],
  documentationEvidence: [
    { evidenceKey: "architecture", evidenceRef: "evidence/architecture.md", evidenceDigest: "sha256:4444444444444444444444444444444444444444444444444444444444444444", mediaType: "text/markdown", required: true },
    { evidenceKey: "contract", evidenceRef: "evidence/contract.md", evidenceDigest: "sha256:5555555555555555555555555555555555555555555555555555555555555555", mediaType: "text/markdown", required: true }
  ],
  controlPlane: {
    enable: { supported: true, path: "/v2/control/enable", method: "POST", requestSchema: { type: "object", required: ["payload"], additionalProperties: false, properties: { payload: { type: "object", minProperties: 1 } } }, responseSchema: { type: "object", required: ["payload"], additionalProperties: false, properties: { payload: { type: "object", minProperties: 1 } } } },
    disable: { supported: true, path: "/v2/control/disable", method: "POST", requestSchema: { type: "object", required: ["payload"], additionalProperties: false, properties: { payload: { type: "object", minProperties: 1 } } }, responseSchema: { type: "object", required: ["payload"], additionalProperties: false, properties: { payload: { type: "object", minProperties: 1 } } } },
    state: { supported: true, path: "/v2/control/state", method: "POST", requestSchema: { type: "object", required: ["payload"], additionalProperties: false, properties: { payload: { type: "object", minProperties: 1 } } }, responseSchema: { type: "object", required: ["payload"], additionalProperties: false, properties: { payload: { type: "object", minProperties: 1 } } } },
    heartbeat: { supported: true, path: "/v2/control/heartbeat", method: "POST", requestSchema: { type: "object", required: ["payload"], additionalProperties: false, properties: { payload: { type: "object", minProperties: 1 } } }, responseSchema: { type: "object", required: ["payload"], additionalProperties: false, properties: { payload: { type: "object", minProperties: 1 } } } }
  },
  outboundAuthorization: { required: true, tokenRequired: true, gatewayRequired: true, verifyEachPulse: true },
  secretPolicy: { mode: "GRANTED_SECRETS", authorizationAuthority: "KCML", allSecretsRequiresGrant: true, auditLevel: "FULL" },
  handlerKey: "whatsapp_ingress",
  handlerVersion: "1.0.0",
  facadeTools: [{ name: "ingress", inputSchema: { type: "object", required: ["payload"], additionalProperties: false, properties: { payload: { type: "object", minProperties: 1 } } }, outputSchema: { type: "object", required: ["payload"], additionalProperties: false, properties: { payload: { type: "object", minProperties: 1 } } } }],
  protocol: { protocolVersion: protocol, transport: "streamable-http", capabilities: ["tools"] },
  publicEndpoints: [{
    endpointId: "WA_INGRESS", path: "/events/whatsapp", methods: ["POST"], authMode: "SIGNED_WEBHOOK",
    requestSchema: { type: "object", required: ["payload"], additionalProperties: false, properties: { payload: { type: "object", minProperties: 1 } } }, responseSchema: { type: "object", required: ["payload"], additionalProperties: false, properties: { payload: { type: "object", minProperties: 1 } } },
    limits: { requestBytes: 262144, responseBytes: 65536 }, timeoutMs: 3000,
    rateLimit: { windowSeconds: 60, maxRequests: 600 }, idempotency: "REQUIRED",
    signatureProfile: "whatsapp-hmac-v1", eventMapping: { pulseType: "wa.message.received", correlationIdSource: "header:x-correlation-id" }
  }],
  handlerContract: { export: "handle", listener: "forbidden" }
};

const catalog = {
  version: release,
  normativeLabel: "2026.07.19-NR",
  auditedBaselineCommit: "e2589ca4dc0b4ecb442aa8ef36141609b3b4dd76",
  serviceKind: "COMPONENT",
  publishedAt: release.replaceAll(".", "-"),
  blueprintVersion: release,
  catalogVersion: release,
  manifestSchemaVersion: release,
  pulseEnvelopeVersion: release,
  policyBaseline: release.replaceAll(".", "-"),
  mcpProtocolVersion: protocol,
  canonicalDigest: "",
  manifestExamplePath: `docs/onboarding-manifest-${release}.example.json`,
  humanCatalogFiles: [
    `docs/releases/${release}/KajovoCML_Onboarding_Catalog_${release}.docx`,
    `docs/releases/${release}/KajovoCML_Onboarding_Catalog_${release}.pdf`
  ],
  compatibility: {
    supersedesCatalogVersions: ["1.7", "1.8"],
    acceptedNewManifestSchemaVersions: [release],
    acceptedStoredManifestSchemaVersions: ["1.4", "1.5", release],
    breakingManifestChange: false,
    catalogChange: "MINOR",
    legacyAdapters: ["/v1/onboardings", "/v1/service-onboardings", "/api/mcp-servers", "/api/managed-services"],
    legacyOnboardingPath: { path: "/v1/onboardings", status: 202 }
  },
  releaseWaves: [{
    releaseVersion: release,
    waveKey: releaseWaveKey,
    displayName: "Prvni release vlna 9 AI / 11 MCP / 5 managed",
    baseline: true,
    baselineCounts: { aiAgents: aiComponents.length, mcpServers: mcpComponents.length, managedServices: managedServices.length },
    notFinalTargetScope: true,
    allowedBlueprintComponentIds: blueprintIds,
    platformPrerequisiteComponentIds: managedServices
  }],
  compatibilityMatrix: [
    { profile: "legacy-ai-client", category: "AI_CLIENT", catalog: "2026.07.20", manifestSchemas: ["1.4", "1.5"], intake: "/v1/onboardings", authorization: "ACCESS_TOKEN_COMPATIBILITY_ADAPTER", endpoint: "KCML_HOSTNAME", result: "SUPPORTED_ADAPTED" },
    { profile: "component-ai-client", category: "AI_CLIENT", catalog: release, manifestSchemas: [release], intake: "/v2/component-onboardings", authorization: "OAUTH2_CLIENT_CREDENTIALS", endpoint: "KCML_HOSTNAME", result: "SUPPORTED_NATIVE" },
    { profile: "legacy-ai-agent", category: "AI_AGENT", catalog: "2026.07.20", manifestSchemas: ["1.4", "1.5"], intake: "/v1/onboardings", authorization: "ACCESS_TOKEN_COMPATIBILITY_ADAPTER", endpoint: "KCML_HOSTNAME", result: "SUPPORTED_ADAPTED" },
    { profile: "component-ai-agent", category: "AI_AGENT", catalog: release, manifestSchemas: [release], intake: "/v2/component-onboardings", authorization: "OAUTH2_CLIENT_CREDENTIALS", endpoint: "KCML_HOSTNAME", result: "SUPPORTED_NATIVE" },
    { profile: "legacy-mcp-server", category: "MCP_SERVER", catalog: "2026.07.20", manifestSchemas: ["1.4", "1.5"], intake: "/v1/onboardings", authorization: "MCP_OAUTH_ADAPTER", endpoint: "KCML_HOSTNAME_MCP_RESOURCE", result: "SUPPORTED_ADAPTED" },
    { profile: "component-mcp-server", category: "MCP_SERVER", catalog: release, manifestSchemas: [release], intake: "/v2/component-onboardings", authorization: "OAUTH2_CLIENT_CREDENTIALS", endpoint: "KCML_HOSTNAME", result: "SUPPORTED_NATIVE" },
    { profile: "legacy-managed-runtime", category: "MANAGED_RUNTIME", catalog: "external-api-1.0", manifestSchemas: ["external-api-1.0"], intake: "/v1/service-onboardings", authorization: "MANAGED_SERVICE_ADAPTER", endpoint: "KCML_HOSTNAME_RESOURCE", result: "SUPPORTED_ADAPTED" },
    { profile: "component-managed-runtime", category: "MANAGED_RUNTIME", catalog: release, manifestSchemas: [release], intake: "/v2/component-onboardings", authorization: "OAUTH2_CLIENT_CREDENTIALS", endpoint: "KCML_HOSTNAME", result: "SUPPORTED_NATIVE" },
    { profile: "legacy-external-service", category: "EXTERNAL_SERVICE", catalog: "external-api-1.0", manifestSchemas: ["external-api-1.0"], intake: "/v1/service-onboardings", authorization: "MANAGED_SERVICE_ADAPTER", endpoint: "KCML_HOSTNAME_RESOURCE", result: "SUPPORTED_ADAPTED" },
    { profile: "component-external-service", category: "EXTERNAL_SERVICE", catalog: release, manifestSchemas: [release], intake: "/v2/component-onboardings", authorization: "OAUTH2_CLIENT_CREDENTIALS", endpoint: "KCML_HOSTNAME", result: "SUPPORTED_NATIVE" },
    { profile: "legacy-platform-service", category: "PLATFORM_SERVICE", catalog: "2026.07.20", manifestSchemas: ["1.4", "1.5"], intake: "/api/managed-services", authorization: "MANAGED_SERVICE_ADAPTER", endpoint: "KCML_HOSTNAME_RESOURCE", result: "SUPPORTED_ADAPTED" },
    { profile: "component-platform-service", category: "PLATFORM_SERVICE", catalog: release, manifestSchemas: [release], intake: "/v2/component-onboardings", authorization: "OAUTH2_CLIENT_CREDENTIALS", endpoint: "KCML_HOSTNAME", result: "SUPPORTED_NATIVE" }
  ],
  runtimeCompatibility: {
    pulse: { legacyBlueprintPulseTypes: "SUPPORTED_ADAPTED", componentPulse: "SUPPORTED_NATIVE", unknownPulseType: "REJECTED_CATALOG_INCOMPATIBLE" },
    scopesAndAcl: { currentDatabaseScope: "REQUIRED_EACH_CALL", currentRouteAcl: "REQUIRED_EACH_CALL", removedPermission: "REJECTED_ROUTE_DENIED" },
    endpointAndAudience: { canonicalHostname: "kcmlNNNN.kajovocml.hcasc.cz", matchingHostSniAudience: "REQUIRED", alternateHostname: "REJECTED_INVALID_AUDIENCE", ipLocalhostDirectPortServiceName: "REJECTED_INVALID_COMPONENT_HOSTNAME" }
  },
  ...(flowFabricBlueprint ? { flowFabricBlueprint } : {}),
  componentContracts: {
    AI_CLIENT: { manifestContract: "aiAgentManifest", requiredCapabilities: [], gates: componentActivationGates, endpoint: "kcmlNNNN.kajovocml.hcasc.cz", authorization: "OAUTH2_CLIENT_CREDENTIALS", deactivation: "REVOCATION_EPOCH_AND_TOKEN_REVOKE", recertification: "REQUIRED" },
    AI_AGENT: { manifestContract: "aiAgentManifest", requiredCapabilities: [], gates: componentActivationGates, endpoint: "kcmlNNNN.kajovocml.hcasc.cz", authorization: "OAUTH2_CLIENT_CREDENTIALS", deactivation: "REVOCATION_EPOCH_AND_TOKEN_REVOKE", recertification: "REQUIRED" },
    MCP_SERVER: { manifestContract: "mcpServerManifest", requiredCapabilities: ["mcp.initialize", "mcp.notifications.initialized", "mcp.tools.list", "mcp.tools.call"], gates: componentActivationGates, endpoint: "kcmlNNNN.kajovocml.hcasc.cz", authorization: "OAUTH2_CLIENT_CREDENTIALS", deactivation: "REVOCATION_EPOCH_AND_TOKEN_REVOKE", recertification: "REQUIRED" },
    MANAGED_RUNTIME: { manifestContract: "genericComponentManifest", requiredCapabilities: [], gates: componentActivationGates, endpoint: "kcmlNNNN.kajovocml.hcasc.cz", authorization: "OAUTH2_CLIENT_CREDENTIALS", deactivation: "REVOCATION_EPOCH_AND_TOKEN_REVOKE", recertification: "REQUIRED" },
    EXTERNAL_SERVICE: { manifestContract: "genericComponentManifest", requiredCapabilities: [], gates: componentActivationGates, endpoint: "kcmlNNNN.kajovocml.hcasc.cz", authorization: "OAUTH2_CLIENT_CREDENTIALS", deactivation: "REVOCATION_EPOCH_AND_TOKEN_REVOKE", recertification: "REQUIRED" },
    PLATFORM_SERVICE: { manifestContract: "managedServiceManifest", requiredCapabilities: [], gates: componentActivationGates, endpoint: "kcmlNNNN.kajovocml.hcasc.cz", authorization: "OAUTH2_CLIENT_CREDENTIALS", deactivation: "REVOCATION_EPOCH_AND_TOKEN_REVOKE", recertification: "REQUIRED" }
  },
  capabilityContracts: {
    "mcp.initialize": { protocol: "MCP", transport: "streamable-http", requiredFor: ["MCP_SERVER"], audit: true, monitoring: true },
    "mcp.notifications.initialized": { protocol: "MCP", transport: "streamable-http", requiredFor: ["MCP_SERVER"], audit: true, monitoring: true },
    "mcp.tools.list": { protocol: "MCP", transport: "streamable-http", requiredFor: ["MCP_SERVER"], audit: true, monitoring: true },
    "mcp.tools.call": { protocol: "MCP", transport: "streamable-http", requiredFor: ["MCP_SERVER"], audit: true, monitoring: true },
    "component.discovery": { protocol: "HTTPS", transport: "https", requiredFor: [], audit: true, monitoring: true },
    "component.pulse": { protocol: "KCML_PULSE", transport: "https", requiredFor: [], audit: true, monitoring: true },
    "component.audit.write": { protocol: "KCML_AUDIT", transport: "https", requiredFor: [], audit: true, monitoring: true },
    "component.heartbeat": { protocol: "KCML_CONTROL", transport: "https", requiredFor: [], audit: true, monitoring: true },
    "component.state.query": { protocol: "KCML_CONTROL", transport: "https", requiredFor: [], audit: true, monitoring: true },
    "component.control.ack": { protocol: "KCML_CONTROL", transport: "https", requiredFor: [], audit: true, monitoring: true },
    "component.outbound.pulse": { protocol: "KCML_PULSE", transport: "https", requiredFor: [], audit: true, monitoring: true }
  },
  blueprintComponents: {
    aiAgents: aiComponents.map(([componentId, role]) => ({ componentId, role, registrationType: "KCML_ACCESS_CLIENT" })),
    mcpServers: mcpComponents.map(([componentId, role]) => ({ componentId, role, registrationType: "MCP_SERVER" })),
    managedServices: managedServices.map((componentId) => ({ componentId, registrationType: "MANAGED_PLATFORM_SERVICE" }))
  },
  integrationTokens: {
    secretApiCompatibility: {
      acceptedTokenTypes: ["INTEGRATION_TOKEN"],
      rejectedTokenTypes: ["CONSUMED", "EXPIRED", "REVOKED"],
      grantIdentity: "Secret API accepts any unconsumed, unexpired integration token during the integration procedure and requires an explicit secret grant bound to component UUID, token UUID, or token fingerprint."
    },
    blueprintRelease: {
      releaseVersion: release,
      releaseWave: releaseWaveKey,
      allowedBlueprintComponentIds: blueprintIds,
      platformPrerequisiteComponentIds: managedServices,
      allowedRegistrationTypes: ["KCML_ACCESS_CLIENT", "MCP_SERVER", "MANAGED_PLATFORM_SERVICE"],
      maxChildJobs: 1,
      autoActivateAfterPass: false,
      manualApprovalRequiredAfterIssuance: false,
      ttlHours: 24,
      lifecycle: {
        initialExpiresInHours: 24,
        maxExpiresInHours: 24,
        currentExpiryField: "expiresAt",
        maximumExpiryField: "maxExpiresAt",
        successfulUseLimit: 1,
        consumedBy: "successful access-token handoff / client_secret claim",
        incompleteIntegrationCleanup: "expired, cancelled or retryable failed onboarding jobs are removed from runtime-visible state; redacted audit remains",
        revocation: "administrator revoke/delete, successful access-token handoff, expiry, cancellation, quarantine release, or server archival"
      },
      secret: { bytes: 64, prefix: "kci_", storage: "HMAC digest only" }
    }
  },
  secretManager: {
    serviceId: "KCML-SEC-005",
    catalogVersion: release,
    publicApi: {
      hostPattern: "secrets.{PUBLIC_BASE_DOMAIN}",
      resolveEndpoint: "/v1/secrets/resolve",
      request: { method: "POST", contentType: "application/json", schema: { type: "object", required: ["name"], additionalProperties: false, properties: { name: { type: "string", pattern: "^[A-Z][A-Z0-9_]{2,127}$" } } } },
      response: { contentType: "application/json", fields: ["name", "value", "version", "fingerprint", "correlationId"], cache: "no-store" },
      auth: {
        integrationToken: { header: "Authorization: Bearer <integration_token>", acceptedTokenTypes: ["INTEGRATION_TOKEN"], lifecycleIndependent: true },
        clientSecret: { header: "Authorization: Basic base64(client_id:client_secret)", tokenField: "client_secret", directCredentialVerification: true, lifecycleIndependent: false },
        oauthAccessToken: { accepted: false, reason: "Secret API does not issue or require short-lived OAuth access tokens for resolve" },
        scopeAudienceLifecycleEvaluation: { appliedInsideSecretApi: true, replacementGate: "access-token authenticity plus explicit secret grant or audited ALL_SECRETS grant" },
        componentLifecycleEvaluation: { appliedInsideSecretApi: true, blockedStatesRejectedForCredentialValidity: ["DISABLED", "INACTIVE", "QUARANTINED", "DEREGISTERED"] },
        allSecretsGrant: { accepted: true, grantName: "ALL_SECRETS", explicitAdminApprovalRequired: true, audited: true }
      },
      errorModel: {
        missingUngrantInactiveDeleted: "secret_unavailable",
        ambiguity: "invalid_client",
        correlationId: "always returned"
      },
      limits: { requestBytes: 4096, responseCache: "forbidden", rateLimit: { windowSeconds: 60, maxRequests: 30 } }
    },
    adminGui: {
      location: "KCML admin Secrets page",
      capabilities: ["create", "rotate", "deactivate", "activate", "soft-delete", "restore-disabled", "version-history", "grant", "revoke-grant", "two-phase-reveal", "reveal-ui-event-audit"],
      reveal: { requiresFreshPassword: true, requiresCurrentTotp: true, oneTimeGrantSeconds: 15, boundTo: ["admin", "session", "secret", "version", "purpose"], persistentStorage: false }
    },
    storage: {
      databaseAuthority: "PostgreSQL",
      encryption: "AES-256-GCM envelope with HKDF-SHA-256 key derivation from CONFIG_VAULT_MASTER_KEY_BASE64",
      aad: ["secretId", "stableName", "versionId", "versionNumber", "ownerKind", "ownerId", "algorithm", "keyId"],
      operationalSecretDependencies: ["CONFIG_VAULT_MASTER_KEY_BASE64", "CONFIG_VAULT_MASTER_KEY_ID"]
    }
  },
  submittedArtifacts: [
    { name: "manifest", mediaType: "application/json", required: true },
    { name: "source", mediaType: "application/zip", required: true },
    { name: "evidence", location: "evidence/** inside source ZIP", required: true }
  ],
  generatedArtifacts: ["child onboarding jobs", "authorization snapshot", "GitHub pull request", "required CI check receipts", "immutable artifact", "SBOM", "provenance attestation", "artifact signature"],
  pipelineGates: Object.entries(gatesByStage).flatMap(([stage, names]) => names.map((name) => ({ name, stage }))),
  requiredCiChecks: requiredChecks,
  semanticRules: errorCodes.map((code) => ({ code, description: code.replaceAll("_", " ") })),
  errorCodes,
  jsonSchema: schema,
  programmerApi: {
    openapi: "3.1.0",
    info: { title: "KajovoCML component onboarding programmer API", version: release },
    servers: [{ url: "https://{registerHost}", variables: { registerHost: { default: "register.example.invalid" } } }],
    security: [{ bearerAuth: [] }],
    paths: {
      "/v2/component-onboardings": { post: { operationId: "createComponentOnboarding", parameters: [{ name: "Idempotency-Key", in: "header", required: true, schema: { type: "string" } }], responses: { "202": { description: "Accepted" } } } },
      "/v2/component-onboardings/{id}": {
        get: { operationId: "getComponentOnboarding", responses: { "200": { description: "Current job" } } },
        delete: { operationId: "cancelComponentOnboarding", responses: { "200": { description: "Cancelled" } } }
      },
      "/v2/component-onboardings/{id}/revisions": {
        post: {
          operationId: "reviseComponentOnboarding",
          parameters: [
            { name: "Idempotency-Key", in: "header", required: true, schema: { type: "string" } },
            { name: "If-Match", in: "header", required: true, schema: { type: "string" } }
          ],
          responses: { "200": { description: "Revised" } }
        }
      },
      "/v2/component-onboardings/{id}/readiness": { post: { operationId: "evaluateComponentReadiness", responses: { "200": { description: "Readiness result" } } } },
      "/v2/component-onboardings/{id}/credential-claims": { post: { operationId: "claimComponentCredential", responses: { "200": { description: "Credential shown once" } } } },
      "/v2/component-onboardings/{id}/e2e-results": { post: { operationId: "recordComponentE2EResult", responses: { "202": { description: "Scenario output matches expected output" }, "409": { description: "Scenario output differs from expected output" } } } },
      "/v2/component-pulse": { post: { operationId: "ingestComponentPulse", responses: { "202": { description: "Full inbound PULS envelope accepted" } } } },
      "/v2/component-outbound-pulse": { post: { operationId: "dispatchComponentOutboundPulse", responses: { "202": { description: "Outbound PULS envelope authorized and audited" } } } },
      "/v2/component-heartbeat": { post: { operationId: "recordComponentHeartbeat", responses: { "202": { description: "Heartbeat accepted and policy snapshot returned" } } } },
      "/v2/component-state-query": { post: { operationId: "recordComponentStateQueryResponse", responses: { "202": { description: "State snapshot accepted" } } } },
      "/v2/component-control-ack": { post: { operationId: "recordComponentControlAck", responses: { "202": { description: "Control-plane acknowledgement accepted" } } } },
      "/v2/component-audit-events": { post: { operationId: "ingestComponentOperationAuditEvent", responses: { "202": { description: "Full operation audit accepted" } } } },
      "/v1/service-onboardings": { post: { operationId: "createServiceOnboarding", parameters: [{ name: "Idempotency-Key", in: "header", required: true, schema: { type: "string" } }], responses: { "202": { description: "Accepted" } } } },
      "/v1/service-onboardings/{id}": { get: { operationId: "getServiceOnboarding", responses: { "200": { description: "Current job" } } } },
      "/v1/service-onboardings/{id}/revision": { put: { operationId: "putServiceOnboardingRevision", parameters: [{ name: "Idempotency-Key", in: "header", required: true, schema: { type: "string" } }, { name: "If-Match", in: "header", required: true, schema: { type: "string" } }], responses: { "202": { description: "Accepted" } } } },
      "/v1/service-onboardings/{id}/cancel": { post: { operationId: "cancelServiceOnboarding", responses: { "200": { description: "Cancelled" } } } },
      "/v1/integration-intent": {
        get: {
          operationId: "getIntegrationIntent",
          responses: {
            "200": {
              description: "Token scope and release intent",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    required: ["release", "token", "blueprintRelease", "intakeUrl", "intakeUrls", "catalogUrl", "correlationId"],
                    properties: {
                      intakeUrl: { type: "string", format: "uri", description: "Recommended intake URL for this token." },
                      intakeUrls: {
                        type: "object",
                        required: ["recommendedIntakeUrl", "nativeComponentIntakeUrl", "legacyServiceIntakeUrl", "externalApiIntakeUrl", "componentCatalogUrl", "externalApiCatalogUrl"],
                        properties: {
                          recommendedIntakeUrl: { type: "string", format: "uri" },
                          nativeComponentIntakeUrl: { type: "string", format: "uri" },
                          legacyServiceIntakeUrl: { type: "string", format: "uri" },
                          externalApiIntakeUrl: { type: "string", format: "uri" },
                          componentCatalogUrl: { type: "string", format: "uri" },
                          externalApiCatalogUrl: { type: "string", format: "uri" }
                        }
                      },
                      blueprintRelease: {
                        type: "object",
                        required: ["allowedBlueprintComponentIds", "allowedBlueprintComponents"],
                        properties: {
                          allowedBlueprintComponentIds: { type: "array", items: { type: "string" } },
                          allowedBlueprintComponents: {
                            type: "array",
                            items: {
                              type: "object",
                              required: ["componentId", "registrationType", "releaseVersion"],
                              properties: {
                                componentId: { type: "string" },
                                registrationType: { type: "string" },
                                releaseVersion: { type: "string" },
                                releaseWaveKey: { type: ["string", "null"] }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    components: { securitySchemes: { bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "KCML integration token" } } }
  }
};

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value)
      .filter(([key]) => key !== "canonicalDigest")
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => [key, canonicalize(nested)]));
  }
  return value;
}

function render(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

catalog.canonicalDigest = `sha256:${createHash("sha256").update(JSON.stringify(canonicalize(catalog))).digest("hex")}`;

const outputs = new Map([
  [outputPath, render(catalog)],
  [schemaPath, render(schema)],
  [examplePath, render(example)]
]);

if (process.argv.includes("--check")) {
  let stale = false;
  for (const [file, rendered] of outputs) {
    if (!fs.existsSync(file) || fs.readFileSync(file, "utf8") !== rendered) {
      console.error(`Generated onboarding artifact is stale: ${path.relative(root, file)}`);
      stale = true;
    }
  }
  if (stale) process.exitCode = 1;
} else {
  for (const [file, rendered] of outputs) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, rendered);
  }
}
