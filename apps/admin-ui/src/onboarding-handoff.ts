import { formatDate } from "./ui-helpers.js";

export type OnboardingHandoff = {
  label: string;
  descriptor: {
    summary: string;
    businessPurpose: string;
    serviceOwner: string;
    technicalOwner: string;
    criticality: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  };
  token: string;
  initialExpiresAt: string;
  programmerApiUrl: string;
  tokenKind?: "SINGLE_COMPONENT" | "BLUEPRINT_RELEASE";
  releaseWaveKey?: string | null;
  allowedBlueprintComponents?: Array<{
    componentId: string;
    registrationType: string;
    releaseVersion: string;
    releaseWaveKey: string | null;
  }>;
  intakeUrls?: {
    recommendedIntakeUrl: string;
    nativeComponentIntakeUrl: string;
    legacyServiceIntakeUrl: string;
    externalApiIntakeUrl: string;
    componentCatalogUrl: string;
    externalApiCatalogUrl: string;
  };
  catalogVersion: string;
};

export function onboardingHandoffText(handoff: OnboardingHandoff): string {
  const expiresAt = formatDate(handoff.initialExpiresAt);
  const intakeUrl = handoff.intakeUrls?.recommendedIntakeUrl ?? handoff.programmerApiUrl;
  const componentScope = handoff.allowedBlueprintComponents?.map((component) => `${component.componentId}:${component.registrationType}`).join(", ");
  const blueprintLines = handoff.tokenKind === "BLUEPRINT_RELEASE"
    ? [
      `Release wave: ${handoff.releaseWaveKey ?? "neuvedeno"}`,
      `Povolené blueprint komponenty: ${componentScope || "žádné"}`,
      `Native component intake: ${handoff.intakeUrls?.nativeComponentIntakeUrl ?? intakeUrl}`,
      `Legacy service intake pouze pro kompatibilitu: ${handoff.intakeUrls?.legacyServiceIntakeUrl ?? handoff.programmerApiUrl}`
    ]
    : [];
  return [
    handoff.tokenKind === "BLUEPRINT_RELEASE"
      ? "Automatická integrace release blueprint komponent do KajovoMCPCML"
      : "Automatická integrace nového MCP serveru do KajovoMCPCML",
    "",
    `Označení integračního toku: ${handoff.label}`,
    `Shrnutí serveru: ${handoff.descriptor.summary}`,
    `Účel: ${handoff.descriptor.businessPurpose}`,
    `Vlastník služby: ${handoff.descriptor.serviceOwner}`,
    `Technický vlastník: ${handoff.descriptor.technicalOwner}`,
    `Kritičnost: ${handoff.descriptor.criticality}`,
    `Integrační token: ${handoff.token}`,
    `První upload proveďte nejpozději do: ${expiresAt}`,
    `Doporučené programátorské API: ${intakeUrl}`,
    ...blueprintLines,
    "",
    `Postupujte přesně podle přiloženého dokumentu KajovoCML ${handoff.catalogVersion}.`,
    handoff.tokenKind === "BLUEPRINT_RELEASE"
      ? "Pro každou povolenou blueprint komponentu pošlete samostatný manifest 2026.07.23 na native component intake; systém sám přidělí KCML identitu, hostname, authorization snapshot a credential claim."
      : "Po přijetí manifestu a zdrojového ZIPu systém sám přidělí KCML identitu a HTTPS adresu a spustí PR/CI, nasazení, autorizaci, logging, monitoring, testy a aktivaci.",
    "Stav jobu průběžně načítejte přes programátorské API. Pokud vrátí UPLOAD_REVISION, opravte uvedenou chybu a nahrajte novou revizi podle katalogu; opakujte až do COMPLETE / ACTIVE."
  ].join("\n");
}
