import { describe, expect, it } from "vitest";
import { onboardingHandoffText } from "./onboarding-handoff.js";

describe("onboarding handoff", () => {
  it("contains the existing catalog instruction, token, deadline and automatic outcome", () => {
    const text = onboardingHandoffText({
      label: "Fakturační MCP",
      descriptor: {
        summary: "Zpracování faktur",
        businessPurpose: "Automatizace fakturačního workflow",
        serviceOwner: "Finance Ops",
        technicalOwner: "Platform Engineering",
        criticality: "HIGH"
      },
      token: "kci_example",
      initialExpiresAt: "2026-07-13T14:00:00.000Z",
      programmerApiUrl: "https://register.hcasc.cz/v1/service-onboardings"
    });

    expect(text).toContain("Označení integračního toku: Fakturační MCP");
    expect(text).toContain("Shrnutí serveru: Zpracování faktur");
    expect(text).toContain("Kritičnost: HIGH");
    expect(text).toContain("Integrační token: kci_example");
    expect(text).toContain("KajovoCML 2026.07.21");
    expect(text).toContain("https://register.hcasc.cz/v1/service-onboardings");
    expect(text).toContain("sám přidělí KCML identitu a HTTPS adresu");
    expect(text).toContain("UPLOAD_REVISION");
  });
});
