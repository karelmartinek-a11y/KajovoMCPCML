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
      catalogVersion: "2026.07.22"
    });

    expect(text).toContain("Označení integračního toku: Fakturační MCP");
    expect(text).toContain("Shrnutí serveru: Zpracování faktur");
    expect(text).toContain("Kritičnost: HIGH");
    expect(text).toContain("Integrační token: kci_example");
    expect(text).toContain("KajovoCML 2026.07.22");
    expect(text).not.toContain("KajovoCML 2026.07.21");
    expect(text).toContain("https://register.hcasc.cz/v1/service-onboardings");
    expect(text).toContain("sám přidělí KCML identitu, hostname, authorization snapshot");
    expect(text).toContain("UPLOAD_REVISION");
  });

  it("points blueprint release handoff to native component intake with scoped components", () => {
    const text = onboardingHandoffText({
      label: "FlowFabric first wave",
      descriptor: {
        summary: "První vlna komponent",
        businessPurpose: "Generování a registrace baseline komponent FlowFabric",
        serviceOwner: "KCML",
        technicalOwner: "Platform Engineering",
        criticality: "HIGH"
      },
      token: "kci_blueprint",
      initialExpiresAt: "2026-07-23T14:00:00.000Z",
      programmerApiUrl: "https://register.hcasc.cz/v2/component-onboardings",
      releaseWaveKey: "baseline-2026-07-23",
      allowedBlueprintComponents: [
        { componentId: "AI-CLS-001", registrationType: "KCML_ACCESS_CLIENT", releaseVersion: "2026.07.23", releaseWaveKey: "baseline-2026-07-23" },
        { componentId: "MCP-RX-WA-001", registrationType: "MCP_SERVER", releaseVersion: "2026.07.23", releaseWaveKey: "baseline-2026-07-23" }
      ],
      intakeUrls: {
        recommendedIntakeUrl: "https://register.hcasc.cz/v2/component-onboardings",
        nativeComponentIntakeUrl: "https://register.hcasc.cz/v2/component-onboardings",
        legacyServiceIntakeUrl: "https://register.hcasc.cz/v1/service-onboardings",
        externalApiIntakeUrl: "https://register.hcasc.cz/v1/service-onboardings",
        componentCatalogUrl: "https://register.hcasc.cz/api/onboarding-catalogs/component/2026.07.23",
        externalApiCatalogUrl: "https://register.hcasc.cz/api/onboarding-catalogs/external-api/1.0"
      },
      catalogVersion: "2026.07.23"
    });

    expect(text).toContain("Automatická integrace prvku");
    expect(text).toContain("Doporučené programátorské API: https://register.hcasc.cz/v2/component-onboardings");
    expect(text).toContain("Release wave: baseline-2026-07-23");
    expect(text).toContain("AI-CLS-001:KCML_ACCESS_CLIENT");
    expect(text).toContain("MCP-RX-WA-001:MCP_SERVER");
    expect(text).toContain("Legacy service intake pouze pro kompatibilitu: https://register.hcasc.cz/v1/service-onboardings");
  });
});
