import { readFileSync } from "node:fs";
import { Ajv2020, type AnySchema } from "ajv/dist/2020.js";
import { describe, expect, it } from "vitest";
import { MCP_ONBOARDING_GATES, nextHeartbeatExpiry, tokenDeadlines } from "./onboarding.js";
import { onboardingCatalogDigest } from "./onboarding-catalog.js";
import { validateOnboardingManifest } from "./registration.js";
import { REQUIRED_ONBOARDING_CHECKS } from "../onboarding/github.js";
import { KCML_AI_COMPONENTS, KCML_GENERATED_BLUEPRINT_COMPONENT_IDS, KCML_MANAGED_SERVICE_IDS, KCML_MCP_COMPONENTS, KCML_RELEASE } from "./release.js";

const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: false });

function readJson(path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8")) as Record<string, unknown>;
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

const catalog = readJson(`../../../../docs/onboarding-catalogs/component-${KCML_RELEASE.catalogVersion}.json`);
const schema = readJson(`../contracts/component-manifest-${KCML_RELEASE.manifestSchemaVersion}.schema.json`);
const example = readJson(`../../../../docs/onboarding-manifest-${KCML_RELEASE.manifestSchemaVersion}.example.json`);

describe(`component onboarding catalog ${KCML_RELEASE.catalogVersion}`, () => {
  it("publishes one component catalog with the required release and protocol versions", () => {
    expect(catalog).toMatchObject({
      version: KCML_RELEASE.catalogVersion,
      normativeLabel: KCML_RELEASE.normativeLabel,
      auditedBaselineCommit: KCML_RELEASE.auditedBaselineCommit,
      serviceKind: "COMPONENT",
      blueprintVersion: KCML_RELEASE.blueprintVersion,
      manifestSchemaVersion: KCML_RELEASE.manifestSchemaVersion,
      pulseEnvelopeVersion: KCML_RELEASE.pulseEnvelopeVersion,
      policyBaseline: KCML_RELEASE.policyBaseline,
      mcpProtocolVersion: KCML_RELEASE.mcpProtocolVersion,
      programmerApi: { openapi: "3.1.0" }
    });
    expect(catalog.jsonSchema).toEqual(schema);
    expect((catalog.programmerApi as { paths: Record<string, unknown> }).paths).toEqual(expect.objectContaining({
      "/v1/service-onboardings": expect.any(Object),
      "/v1/service-onboardings/{id}": expect.any(Object),
      "/v1/service-onboardings/{id}/revision": expect.any(Object),
      "/v1/service-onboardings/{id}/cancel": expect.any(Object),
      "/v1/integration-intent": expect.any(Object),
      "/v2/component-onboardings": expect.any(Object),
      "/v2/component-onboardings/{id}": expect.any(Object)
    }));
  });

  it("binds the published digest to canonical catalog content", () => {
    expect(catalog.canonicalDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(catalog.canonicalDigest).toBe(onboardingCatalogDigest(catalog));
    const tampered = clone(catalog);
    tampered.version = "2026.07.21-tampered";
    expect(onboardingCatalogDigest(tampered)).not.toBe(catalog.canonicalDigest);
  });

  it("contains exactly the 9 AI agents, 11 MCP servers and 5 managed services for the release", () => {
    const components = catalog.blueprintComponents as {
      aiAgents: Array<{ componentId: string; registrationType: string }>;
      mcpServers: Array<{ componentId: string; registrationType: string }>;
      managedServices: Array<{ componentId: string; registrationType: string }>;
    };
    expect(components.aiAgents.map((item) => [item.componentId, item.registrationType])).toEqual(KCML_AI_COMPONENTS.map(([id]) => [id, "KAJA_CLIENT"]));
    expect(components.mcpServers.map((item) => [item.componentId, item.registrationType])).toEqual(KCML_MCP_COMPONENTS.map(([id]) => [id, "MCP_SERVER"]));
    expect(components.managedServices.map((item) => [item.componentId, item.registrationType])).toEqual(KCML_MANAGED_SERVICE_IDS.map((id) => [id, "MANAGED_PLATFORM_SERVICE"]));
  });

  it("publishes the forensic FlowFabric first-wave blueprint without runtime identities", () => {
    const blueprint = catalog.flowFabricBlueprint as {
      source: { repositoryName: string; status: string; commit: string };
      scope: { aiAgents: number; mcpServers: number; managedServicePrerequisites: number; implementerChildJobs: number; managedServicesAsChildJobs: number };
      runtimeIdentityPolicy: { assignedBy: string; forbiddenInFactoryArtifacts: string[] };
      dependencyWaves: Array<{ wave: number; componentIds: string[] }>;
      readiness: { releaseDryRunStatus: string; actualSubmitEnabled: boolean; networkAttemptsInDryRun: number; readyForOnboardingCriteriaMet: boolean; blockingBeforeRealOnboarding: string[] };
      components: Array<{ componentId: string; componentType: string; registrationType: string; dependencyWave: number; zipSha256: string; manifestSha256: string }>;
    };

    expect(blueprint.source).toMatchObject({
      repositoryName: "KajovoFlowFabric",
      status: "READY_FOR_DRY_RUN_ONLY",
      commit: expect.stringMatching(/^[a-f0-9]{40}$/)
    });
    expect(blueprint.scope).toEqual({
      aiAgents: 9,
      mcpServers: 11,
      managedServicePrerequisites: 5,
      implementerChildJobs: 20,
      managedServicesAsChildJobs: 0
    });
    expect(blueprint.runtimeIdentityPolicy).toMatchObject({
      assignedBy: "KajovoCML onboarding only",
      forbiddenInFactoryArtifacts: expect.arrayContaining(["KCML code", "hostname", "credential secret", "authorization snapshot"])
    });
    expect(blueprint.dependencyWaves.map((wave) => wave.wave)).toEqual([0, 1, 2, 3, 4, 5]);
    expect(blueprint.dependencyWaves[0]?.componentIds).toEqual([...KCML_MANAGED_SERVICE_IDS]);
    expect(blueprint.components).toHaveLength(20);
    expect(blueprint.components.filter((item) => item.componentType === "AI_AGENT").map((item) => item.componentId)).toEqual(KCML_AI_COMPONENTS.map(([id]) => id));
    expect(blueprint.components.filter((item) => item.componentType === "MCP_SERVER").map((item) => item.componentId).sort()).toEqual(KCML_MCP_COMPONENTS.map(([id]) => id).sort());
    expect(blueprint.components.every((item) => item.registrationType === "KAJA_CLIENT" || item.registrationType === "MCP_SERVER")).toBe(true);
    expect(blueprint.components.every((item) => /^([a-f0-9]{64})$/.test(item.zipSha256) && /^([a-f0-9]{64})$/.test(item.manifestSha256))).toBe(true);
    expect(blueprint.readiness).toMatchObject({
      releaseDryRunStatus: "PASS",
      actualSubmitEnabled: false,
      networkAttemptsInDryRun: 0,
      readyForOnboardingCriteriaMet: false
    });
    expect(blueprint.readiness.blockingBeforeRealOnboarding).toEqual(expect.arrayContaining([
      expect.stringContaining("onboarding release token"),
      expect.stringContaining("Booking.com provider integration")
    ]));
  });

  it("documents release token scope and executable gates", () => {
    const releaseWave = (catalog.releaseWaves as Array<{ allowedBlueprintComponentIds: string[]; platformPrerequisiteComponentIds: string[] }>)[0];
    expect(releaseWave).toBeDefined();
    if (!releaseWave) throw new Error("release_wave_missing");
    expect(releaseWave.allowedBlueprintComponentIds).toEqual([...KCML_GENERATED_BLUEPRINT_COMPONENT_IDS]);
    expect(releaseWave.platformPrerequisiteComponentIds).toEqual([...KCML_MANAGED_SERVICE_IDS]);
    expect((catalog.implementationTokens as { blueprintRelease: { maxChildJobs: number; allowedBlueprintComponentIds: string[]; platformPrerequisiteComponentIds: string[]; allowedRegistrationTypes: string[]; autoActivateAfterPass: boolean; manualApprovalRequiredAfterIssuance: boolean } }).blueprintRelease).toMatchObject({
      maxChildJobs: 20,
      allowedBlueprintComponentIds: [...KCML_GENERATED_BLUEPRINT_COMPONENT_IDS],
      platformPrerequisiteComponentIds: [...KCML_MANAGED_SERVICE_IDS],
      allowedRegistrationTypes: ["KAJA_CLIENT", "MCP_SERVER"],
      autoActivateAfterPass: true,
      manualApprovalRequiredAfterIssuance: false
    });
    expect(catalog.pipelineGates).toEqual(expect.arrayContaining([
      { name: "manifest_schema", stage: "intake" },
      { name: "contract_tests", stage: "ci" },
      { name: "artifact_signature", stage: "supply_chain" },
      { name: "route_acl", stage: "preflight" },
      { name: "recertification", stage: "trial" }
    ]));
    expect(MCP_ONBOARDING_GATES.length).toBeGreaterThan(0);
    expect(catalog.requiredCiChecks).toEqual(expect.arrayContaining([...REQUIRED_ONBOARDING_CHECKS, "artifact-signature"]));
  });

  it("keeps implementation token lifecycle metadata aligned with runtime deadlines", () => {
    const issuedAt = new Date("2026-07-19T10:29:45.182Z");
    const deadlines = tokenDeadlines(issuedAt);
    const maximum = deadlines.maxExpiresAt;
    const extended = nextHeartbeatExpiry(new Date("2026-07-20T10:29:45.182Z"), deadlines.expiresAt, maximum);
    const tokenPolicy = (catalog.implementationTokens as {
      blueprintRelease: {
        ttlHours: number;
        maxTtlDays: number;
        lifecycle: {
          initialExpiresInHours: number;
          heartbeatExtensionHours: number;
          maxExpiresInDays: number;
          currentExpiryField: string;
          maximumExpiryField: string;
          terminalStatesStopExtension: string[];
          pausedStatesStopExtension: string[];
        };
      };
    }).blueprintRelease;

    expect(tokenPolicy.ttlHours).toBe(24);
    expect(tokenPolicy.maxTtlDays).toBe(30);
    expect(tokenPolicy.lifecycle).toMatchObject({
      initialExpiresInHours: 24,
      heartbeatExtensionHours: 24,
      maxExpiresInDays: 30,
      currentExpiryField: "expiresAt",
      maximumExpiryField: "maxExpiresAt",
      terminalStatesStopExtension: ["ACTIVE", "FAILED", "QUARANTINED", "CANCELLED"],
      pausedStatesStopExtension: ["AWAITING_REVISION"]
    });
    expect(deadlines.expiresAt.getTime() - issuedAt.getTime()).toBe(tokenPolicy.lifecycle.initialExpiresInHours * 60 * 60 * 1000);
    expect(maximum.getTime() - issuedAt.getTime()).toBe(tokenPolicy.lifecycle.maxExpiresInDays * 24 * 60 * 60 * 1000);
    expect(extended.getTime() - deadlines.expiresAt.getTime()).toBe(tokenPolicy.lifecycle.heartbeatExtensionHours * 60 * 60 * 1000);
  });

  it("publishes general component and capability contract registries without removing legacy adapters", () => {
    expect(catalog.componentContracts).toEqual(expect.objectContaining({ AI_AGENT: expect.any(Object), MCP_SERVER: expect.any(Object), EXTERNAL_SERVICE: expect.any(Object) }));
    expect(catalog.capabilityContracts).toEqual(expect.objectContaining({
      "mcp.initialize": expect.any(Object), "mcp.tools.call": expect.any(Object), "component.audit.write": expect.any(Object)
    }));
    expect((catalog.compatibility as { breakingManifestChange: boolean; legacyAdapters: string[] })).toMatchObject({
      breakingManifestChange: false,
      legacyAdapters: expect.arrayContaining(["/v1/onboardings", "/v1/service-onboardings", "/api/mcp-servers", "/api/managed-services"])
    });
    const matrix = catalog.compatibilityMatrix as Array<{ category: string; result: string }>;
    for (const category of ["AI_CLIENT", "AI_AGENT", "MCP_SERVER", "MANAGED_RUNTIME", "EXTERNAL_SERVICE", "PLATFORM_SERVICE"]) {
      expect(matrix.filter((entry) => entry.category === category).map((entry) => entry.result).sort()).toEqual(["SUPPORTED_ADAPTED", "SUPPORTED_NATIVE"]);
    }
    expect(catalog.runtimeCompatibility).toMatchObject({
      pulse: { unknownPulseType: "REJECTED_CATALOG_INCOMPATIBLE" },
      scopesAndAcl: { removedPermission: "REJECTED_ROUTE_DENIED" },
      endpointAndAudience: { alternateHostname: "REJECTED_INVALID_AUDIENCE" }
    });
  });

  it("validates the published MCP component example against catalog schema and runtime", () => {
    const validate = ajv.compile(catalog.jsonSchema as AnySchema);
    expect(validate(example), JSON.stringify(validate.errors)).toBe(true);
    const accepted = validateOnboardingManifest(example);
    expect(accepted.manifest.schemaVersion).toBe(KCML_RELEASE.manifestSchemaVersion);
    expect(accepted.manifest.blueprint.componentId).toBe("MCP-RX-WA-001");
    expect(accepted.manifest.protocol.protocolVersion).toBe(KCML_RELEASE.mcpProtocolVersion);
  });

  it.each([
    ["old schema", (manifest: Record<string, unknown>) => { manifest.schemaVersion = "1.5"; }],
    ["platform hostname", (manifest: Record<string, unknown>) => { manifest.hostname = "kcml0001.example.invalid"; }],
    ["handler retry", (manifest: Record<string, unknown>) => { manifest.retryPolicy = { handlerRetry: true }; }],
    ["unsupported blueprint id", (manifest: Record<string, unknown>) => { manifest.blueprint = { componentId: "MCP-UNKNOWN-999", version: KCML_RELEASE.blueprintVersion }; }]
  ])("rejects %s in new intake", (_name, mutate) => {
    const invalid = clone(example);
    mutate(invalid);
    expect(() => validateOnboardingManifest(invalid)).toThrow();
  });
});
