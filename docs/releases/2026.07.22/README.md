# KCML 2026.07.22

Katalogová změna `MINOR` s klasifikací `COMPATIBLE IMPACT`.

Release zachovává kanonický komponentový model a doplňuje centrální Secret Manager pro GUI-first správu tajemství, šifrované verze, rotaci, granty, jednorázové auditované reveal operace a Secret API. Dlouhodobý token komponenty je `client_secret`; pro Secret API je jeho platnost nezávislá na lifecycle stavu komponenty a rozhoduje autenticita credentialu společně s explicitním secret grantem.

Implementační token katalogu `2026.07.22` má aktuální expirační okno 24 hodin a pevný prodlužovací strop 30 dní od vydání. Worker smí posouvat `expiresAt` po heartbeat prodlouženích, nikdy ne za `maxExpiresAt`; terminální, pozastavené, revokované a nahrazené tokeny se dále neprodlužují.

Stávající MCP, managed-service, Kaja a onboarding adaptéry zůstávají zachované. Migrace `001-044` jsou forward-only a historické katalogové artefakty se nepřepisují.

Strojově čitelné artefakty:

- `docs/onboarding-catalogs/component-2026.07.22.json`
- `apps/server/src/contracts/component-manifest-2026.07.22.schema.json`
- `docs/onboarding-manifest-2026.07.22.example.json`

Lidsky čitelný katalog je v tomto adresáři ve formátech DOCX a PDF.

Úplný výsledek podporovaných legacy a nových profilů, Pulse, scope/ACL, endpoint/audience a Secret Manager kombinací je v `compatibility-matrix.md`; stejná data jsou strojově čitelná v `compatibilityMatrix`, `runtimeCompatibility` a `secretManager` katalogu.
