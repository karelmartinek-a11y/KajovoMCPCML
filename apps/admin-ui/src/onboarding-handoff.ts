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
  intakeUrls?: {
    recommendedIntakeUrl: string;
    nativeComponentIntakeUrl: string;
    componentCatalogUrl: string;
  };
  catalogVersion: string;
};

export function onboardingHandoffText(handoff: OnboardingHandoff): string {
  const expiresAt = formatDate(handoff.initialExpiresAt);
  const intakeUrl = handoff.intakeUrls?.recommendedIntakeUrl ?? handoff.programmerApiUrl;
  return [
    "Automatická integrace prvku do KajovoMCPCML",
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
    `Kanonický component intake: ${handoff.intakeUrls?.nativeComponentIntakeUrl ?? intakeUrl}`,
    "Rozsah tokenu: registrace jednoho libovolného prvku; token se spotřebuje až po úplném úspěchu.",
    "",
    `Postupujte přesně podle přiloženého dokumentu KajovoCML ${handoff.catalogVersion}.`,
    "Po přijetí manifestu systém sám přidělí KCML identitu, hostname, authorization snapshot a po úspěšném ověření předá přístupový token.",
    "Stav jobu průběžně načítejte přes programátorské API. Pokud vrátí UPLOAD_REVISION, opravte uvedenou chybu a nahrajte novou revizi podle katalogu; opakujte až do COMPLETE / ACTIVE."
  ].join("\n");
}
