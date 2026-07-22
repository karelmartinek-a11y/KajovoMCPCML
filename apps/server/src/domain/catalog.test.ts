import { describe, expect, it } from "vitest";
import { isKcmlHostname, resourceFor } from "./catalog.js";
import { kcmlCodeFromNumber, kcmlHostnameForCode } from "./hostnames.js";

describe("host routing invariants", () => {
  it("accepts only canonical kcml hostnames under the configured base domain", () => {
    expect(isKcmlHostname("kcml0001.kajovocml.hcasc.cz")).toBe(true);
    expect(isKcmlHostname("KCML10000.kajovocml.hcasc.cz")).toBe(true);
    expect(isKcmlHostname("kcml1.kajovocml.hcasc.cz")).toBe(false);
    expect(isKcmlHostname("admin.hcasc.cz")).toBe(false);
    expect(isKcmlHostname("kcml0001.hcasc.cz")).toBe(false);
  });

  it("binds OAuth resource to exact MCP URI", () => {
    expect(resourceFor("kcml0001.hcasc.cz")).toBe("https://kcml0001.hcasc.cz/mcp");
  });

  it("builds KCML code and hostname through the shared helper", () => {
    expect(kcmlCodeFromNumber(7)).toBe("KCML0007");
    expect(kcmlHostnameForCode("KCML0007")).toBe("kcml0007.kajovocml.hcasc.cz");
  });
});
