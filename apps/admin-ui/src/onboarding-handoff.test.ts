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
      programmerApiUrl: "https://register.hcasc.cz/v1/service-onboardings",
      catalogVersion: "2026.07.22-compliance.1"
    });

    expect(text).toContain("Označení integračního toku: Fakturační MCP");
    expect(text).toContain("Shrnutí serveru: Zpracování faktur");
    expect(text).toContain("Kritičnost: HIGH");
    expect(text).toContain("Integrační token: kci_example");
    expect(text).toContain("KajovoCML 2026.07.22-compliance.1");
    expect(text).not.toContain("KajovoCML 2026.07.24");
    expect(text).toContain("https://register.hcasc.cz/v1/service-onboardings");
    expect(text).toContain("sám přidělí KCML identitu, hostname, authorization snapshot");
    expect(text).toContain("UPLOAD_REVISION");
  });

  it("points generic handoff to the canonical component intake", () => {
    const text = onboardingHandoffText({
      label: "Obecná integrace",
      descriptor: {
        summary: "Integrace prvku",
        businessPurpose: "Registrace aplikačního prvku",
        serviceOwner: "KCML",
        technicalOwner: "Platform Engineering",
        criticality: "HIGH"
      },
      token: "kci_generic",
      initialExpiresAt: "2026-07-24T14:00:00.000Z",
      programmerApiUrl: "https://register.hcasc.cz/v2/component-onboardings",
      intakeUrls: {
        recommendedIntakeUrl: "https://register.hcasc.cz/v2/component-onboardings",
        nativeComponentIntakeUrl: "https://register.hcasc.cz/v2/component-onboardings",
        componentCatalogUrl: "https://register.hcasc.cz/api/onboarding-catalogs/component/2026.07.22-compliance.1"
      },
      catalogVersion: "2026.07.22-compliance.1"
    });

    expect(text).toContain("Automatická integrace prvku");
    expect(text).toContain("Doporučené programátorské API: https://register.hcasc.cz/v2/component-onboardings");
    expect(text).toContain("Rozsah tokenu: registrace jednoho libovolného prvku");
    expect(text).toContain("Kanonický component intake: https://register.hcasc.cz/v2/component-onboardings");
  });
});
