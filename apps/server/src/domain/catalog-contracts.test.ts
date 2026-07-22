import { readFileSync } from "node:fs";
import { Ajv2020, type AnySchema } from "ajv/dist/2020.js";
import { describe, expect, it } from "vitest";
import { onboardingCatalogDigest } from "./onboarding-catalog.js";
import { KCML_RELEASE } from "./release.js";
import { validateComponentManifest } from "./component.js";

function readJson(path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8")) as Record<string, unknown>;
}

const catalog = readJson(`../../../../docs/onboarding-catalogs/component-${KCML_RELEASE.catalogVersion}.json`);
const schema = readJson(`../contracts/component-manifest-${KCML_RELEASE.manifestSchemaVersion}.schema.json`);
const example = readJson(`../../../../docs/onboarding-manifest-${KCML_RELEASE.manifestSchemaVersion}.example.json`);

describe(`generic component onboarding catalog ${KCML_RELEASE.catalogVersion}`, () => {
  it("publishes the generated schema and canonical digest", () => {
    expect(catalog).toMatchObject({
      version: KCML_RELEASE.catalogVersion,
      normativeLabel: KCML_RELEASE.normativeLabel,
      serviceKind: "COMPONENT",
      manifestSchemaVersion: KCML_RELEASE.manifestSchemaVersion,
      mcpProtocolVersion: KCML_RELEASE.mcpProtocolVersion,
      programmerApi: { openapi: "3.1.0" }
    });
    expect(catalog.jsonSchema).toEqual(schema);
    expect(catalog.canonicalDigest).toBe(onboardingCatalogDigest(catalog));
  });

  it("declares only the two approved token classes", () => {
    expect(catalog.tokens).toMatchObject({
      permittedTokenClasses: ["INTEGRATION", "ACCESS"],
      integration: { ttlHours: 24, consumedOn: "SUCCESSFUL_REGISTRATION", reusableAfterFailedAttempt: true },
      access: { expires: false, rotatedOrRevokedOnly: true }
    });
  });

  it("has no preferred identities or fixed allowlists", () => {
    const serialized = JSON.stringify(catalog);
    const forbidden = ["release" + "Wave", "allowed" + "Blueprint", "blueprint" + "Components", "Flow" + "Fabric", "AI" + "-CLS-", "MCP" + "-RX-", "MCP" + "-TX-"];
    expect(forbidden.some((value) => serialized.toLowerCase().includes(value.toLowerCase()))).toBe(false);
  });

  it("validates a generic 0..N tool manifest with real embedded evidence", () => {
    const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: false });
    const validate = ajv.compile(schema as AnySchema);
    expect(validate(example), JSON.stringify(validate.errors)).toBe(true);
    expect(validateComponentManifest(example).kind).toBe("inventory-api");
  });

  it("rejects platform-assigned identity fields and missing evidence content", () => {
    const identity = { ...example, code: "KCML9999" };
    expect(() => validateComponentManifest(identity)).toThrow("invalid_manifest");
    const missingContent = structuredClone(example);
    (missingContent.documentationEvidence as Array<Record<string, unknown>>)[0]!.content = {};
    expect(() => validateComponentManifest(missingContent)).toThrow();
  });
});
