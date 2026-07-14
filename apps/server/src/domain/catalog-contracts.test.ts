import { readFileSync } from "node:fs";
import { Ajv2020, type AnySchema } from "ajv/dist/2020.js";
import { describe, expect, it } from "vitest";

const ajv = new Ajv2020({ strict: true, validateFormats: false });

function readJson(path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8")) as Record<string, unknown>;
}

const mcpCatalog = readJson("../../../../docs/onboarding-catalogs/mcp-1.6.json");
const externalCatalog = readJson("../../../../docs/onboarding-catalogs/external-api-1.0.json");
const mcpExample = readJson("../../../../docs/onboarding-manifest-v1.5.example.json");
const externalExample = readJson("../../../../docs/service-manifest-external-api-v1.0.example.json");

describe("machine-readable onboarding catalogs", () => {
  it("publish JSON Schema and programmer API contracts for both service kinds", () => {
    expect(mcpCatalog).toMatchObject({
      version: "1.6",
      serviceKind: "MCP",
      programmerApi: { openapi: "3.1.0" }
    });
    expect(externalCatalog).toMatchObject({
      version: "1.0",
      serviceKind: "EXTERNAL_API",
      programmerApi: { openapi: "3.1.0" }
    });
    expect(Array.isArray(mcpCatalog.gateRules)).toBe(true);
    expect(Array.isArray(externalCatalog.gateRules)).toBe(true);
  });

  it("validate the published MCP example against the v1.6 catalog schema", () => {
    const validate = ajv.compile(mcpCatalog.jsonSchema as AnySchema);
    expect(validate(mcpExample), JSON.stringify(validate.errors)).toBe(true);
  });

  it("validate the published EXTERNAL_API example against the v1.0 catalog schema", () => {
    const validate = ajv.compile(externalCatalog.jsonSchema as AnySchema);
    expect(validate(externalExample), JSON.stringify(validate.errors)).toBe(true);
  });
});
