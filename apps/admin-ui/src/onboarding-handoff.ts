export type OnboardingHandoff = {
  note: string;
  token: string;
  initialExpiresAt: string;
  programmerApiUrl: string;
};

export function onboardingHandoffText(handoff: OnboardingHandoff): string {
  return [
    "Automatická integrace nového MCP serveru do KajovoMCPCML",
    "",
    `Poznámka k serveru: ${handoff.note}`,
    `Integrační token: ${handoff.token}`,
    `První upload proveďte nejpozději do: ${new Date(handoff.initialExpiresAt).toLocaleString("cs-CZ")}`,
    `Programátorské API: ${handoff.programmerApiUrl}`,
    "",
    "Postupujte přesně podle přiloženého dokumentu Connect in Catalog v1.4.",
    "Po přijetí manifestu a zdrojového ZIPu systém sám přidělí KCML identitu a HTTPS adresu a spustí PR/CI, nasazení, autorizaci, logging, monitoring, testy a aktivaci.",
    "Stav jobu průběžně načítejte přes programátorské API. Pokud vrátí UPLOAD_REVISION, opravte uvedenou chybu a nahrajte novou revizi podle katalogu; opakujte až do COMPLETE / ACTIVE.",
    "Token nevkládejte do repozitáře, logu, ticketu ani screenshotu."
  ].join("\n");
}
