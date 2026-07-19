# KCML 2026.07.21

Katalogová změna `MINOR` s klasifikací `COMPATIBLE IMPACT`.

Release zavádí kanonický komponentový model, dopřednou migraci `041`, komponentové onboarding API v2, OAuth component credentials, aktuální route/scope autorizaci, sekvenční auditní streamy a katalog komponent v administračním UI. Historické katalogy, migrace a kompatibilní MCP, managed-service, Kaja a onboarding adaptéry zůstávají zachované.

Strojově čitelné artefakty:

- `docs/onboarding-catalogs/component-2026.07.21.json`
- `apps/server/src/contracts/component-manifest-2026.07.21.schema.json`
- `docs/onboarding-manifest-2026.07.21.example.json`

Lidsky čitelný katalog je v tomto adresáři ve formátech DOCX a PDF.

Úplný výsledek podporovaných legacy a nových profilů, Pulse, scope/ACL a endpoint/audience kombinací je v `compatibility-matrix.md`; stejná data jsou strojově čitelná v `compatibilityMatrix` a `runtimeCompatibility` katalogu.
