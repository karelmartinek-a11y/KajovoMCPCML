import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  externalApiScopeCatalog,
  matchExternalApiOperation,
  validateExternalApiManifest,
  validateExternalApiRequest,
  validateExternalApiResponse
} from "./external-api.js";

const manifestFixture = JSON.parse(
  readFileSync(new URL("../../../../docs/service-manifest-external-api-v1.0.example.json", import.meta.url), "utf8")
) as Record<string, unknown>;

function manifest(): Record<string, unknown> {
  return structuredClone(manifestFixture);
}

describe("external API manifest 1.0", () => {
  it("accepts the published strict example", () => {
    expect(validateExternalApiManifest(manifest()).digest).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it("rejects unknown fields at intake", () => {
    expect(() => validateExternalApiManifest({ ...manifest(), unexpected: true })).toThrow();
  });

  it("matches templated operations and validates request and response schemas", () => {
    const parsed = validateExternalApiManifest(manifest()).manifest;
    const listShifts = matchExternalApiOperation(parsed, "GET", "/v1/shifts/emp-42");
    expect(listShifts).not.toBeNull();
    expect(listShifts?.params).toEqual({ employeeId: "emp-42" });
    expect(() => validateExternalApiRequest(listShifts!.operation, {})).not.toThrow();
    expect(() => validateExternalApiResponse(listShifts!.operation, { items: [] })).not.toThrow();

    const requestTimeOff = matchExternalApiOperation(parsed, "POST", "/v1/time-off");
    expect(requestTimeOff).not.toBeNull();
    expect(() => validateExternalApiRequest(requestTimeOff!.operation, { employeeId: "emp-42", days: 2 })).not.toThrow();
    expect(() => validateExternalApiRequest(requestTimeOff!.operation, { employeeId: "emp-42" })).toThrow("request_schema_invalid");
    expect(() => validateExternalApiResponse(requestTimeOff!.operation, { accepted: true })).toThrow("response_schema_invalid");
  });

  it("builds a stable unique scope catalog", () => {
    const parsed = validateExternalApiManifest(manifest()).manifest;
    expect(externalApiScopeCatalog(parsed)).toEqual([
      "reference.shifts.read",
      "reference.time_off.write"
    ]);
  });
});
