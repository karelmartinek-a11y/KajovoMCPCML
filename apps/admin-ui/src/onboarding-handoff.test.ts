import { describe, expect, it } from "vitest";
import { onboardingHandoffText } from "./onboarding-handoff.js";

describe("onboarding handoff", () => {
  it("contains the existing catalog instruction, token, deadline and automatic outcome", () => {
    const text = onboardingHandoffText({
      note: "Fakturační MCP",
      token: "kci_example",
      initialExpiresAt: "2026-07-13T14:00:00.000Z",
      programmerApiUrl: "https://register.hcasc.cz/v1/onboardings"
    });

    expect(text).toContain("Poznámka k serveru: Fakturační MCP");
    expect(text).toContain("Integrační token: kci_example");
    expect(text).toContain("Connect in Catalog v1.4");
    expect(text).toContain("https://register.hcasc.cz/v1/onboardings");
    expect(text).toContain("sám přidělí KCML identitu a HTTPS adresu");
    expect(text).toContain("UPLOAD_REVISION");
  });
});
