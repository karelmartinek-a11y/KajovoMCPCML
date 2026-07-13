import { describe, expect, it } from "vitest";
import { matchesExpectedResult } from "./activation.js";

describe("onboarding expected result invariants", () => {
  it("accepts a strict recursive object subset as the declared invariant", () => {
    expect(matchesExpectedResult(
      {
        schema: "ha_device_catalog.v3",
        summary: { device_count: 225, entity_count: 628 },
        devices: [{ device_key: "dev_0123456789" }]
      },
      { schema: "ha_device_catalog.v3", summary: { device_count: 225 } }
    )).toBe(true);
  });

  it("rejects a missing or mismatched invariant", () => {
    expect(matchesExpectedResult({ schema: "other" }, { schema: "ha_device_catalog.v3" })).toBe(false);
    expect(matchesExpectedResult({}, { schema: "ha_device_catalog.v3" })).toBe(false);
  });

  it("keeps arrays exact so order and cardinality cannot be silently weakened", () => {
    expect(matchesExpectedResult(["a", "b"], ["a", "b"])).toBe(true);
    expect(matchesExpectedResult(["a", "b", "c"], ["a", "b"])).toBe(false);
  });
});
