# Kompatibilitní matice KCML 2026.07.22

Katalogová změna je `MINOR`, klasifikace `COMPATIBLE IMPACT`. Historické manifesty se nepřepisují; existující identity, endpointy a tokenová semantika vstupují do komponentového modelu přes adaptéry.

| Profil | Katalog / manifest | Intake / adaptér | Výsledek |
| --- | --- | --- | --- |
| `legacy-ai-client` | `2026.07.20` | `/v1/onboardings` | `SUPPORTED_ADAPTED` |
| `component-ai-client` | `2026.07.22` | `/v2/component-onboardings` | `SUPPORTED_NATIVE` |
| `legacy-ai-agent` | `2026.07.20` | `/v1/onboardings` | `SUPPORTED_ADAPTED` |
| `component-ai-agent` | `2026.07.22` | `/v2/component-onboardings` | `SUPPORTED_NATIVE` |
| `legacy-mcp-server` | `2026.07.20` | `/v1/onboardings` | `SUPPORTED_ADAPTED` |
| `component-mcp-server` | `2026.07.22` | `/v2/component-onboardings` | `SUPPORTED_NATIVE` |
| `legacy-managed-runtime` | `external-api-1.0` | `/v1/service-onboardings` | `SUPPORTED_ADAPTED` |
| `component-managed-runtime` | `2026.07.22` | `/v2/component-onboardings` | `SUPPORTED_NATIVE` |
| `legacy-external-service` | `external-api-1.0` | `/v1/service-onboardings` | `SUPPORTED_ADAPTED` |
| `component-external-service` | `2026.07.22` | `/v2/component-onboardings` | `SUPPORTED_NATIVE` |
| `legacy-platform-service` | `2026.07.20` | `/api/managed-services` | `SUPPORTED_ADAPTED` |
| `component-platform-service` | `2026.07.22` | `/v2/component-onboardings` | `SUPPORTED_NATIVE` |

| Implementační token | Pravidlo | Výsledek |
| --- | --- | --- |
| `expiresAt` | Aktuální použitelnost tokenu po vydání nebo heartbeat prodloužení | 24 hodin od posledního prodloužení, pokud token není revokovaný/smazaný a job je v prodlužovatelném stavu |
| `maxExpiresAt` | Pevný horní strop od vydání tokenu | 30 dní; worker jej nesmí překročit |
| `AWAITING_REVISION` | Job čeká na opravu nebo novou revizi | Automatické prodloužení neběží; pokračování vyžaduje resume token |
| `ACTIVE`, `FAILED`, `QUARANTINED`, `CANCELLED` | Terminální nebo zastavené stavy | Automatické prodloužení neběží |

| Runtime oblast | Kombinace | Výsledek |
| --- | --- | --- |
| `pulse` | `legacyBlueprintPulseTypes` | `SUPPORTED_ADAPTED` |
| `pulse` | `componentPulse` | `SUPPORTED_NATIVE` |
| `pulse` | `unknownPulseType` | `REJECTED_CATALOG_INCOMPATIBLE` |
| `scopesAndAcl` | `currentDatabaseScope` | `REQUIRED_EACH_CALL` |
| `scopesAndAcl` | `currentRouteAcl` | `REQUIRED_EACH_CALL` |
| `scopesAndAcl` | `removedPermission` | `REJECTED_ROUTE_DENIED` |
| `endpointAndAudience` | `canonicalHostname` | `REQUIRED` |
| `endpointAndAudience` | `matchingHostSniAudience` | `REQUIRED` |
| `endpointAndAudience` | `alternateHostname` | `REJECTED_INVALID_AUDIENCE` |
| `endpointAndAudience` | `ipLocalhostDirectPortServiceName` | `REJECTED_INVALID_COMPONENT_HOSTNAME` |

| Secret Manager oblast | Výsledek |
| --- | --- |
| `integration_token` | Bearer tokeny `SINGLE_COMPONENT` a `BLUEPRINT_RELEASE` mohou volat Secret API, pokud existuje explicitní grant. |
| `client_secret` | Dlouhodobý token `client_secret` je ověřen přímo přes Basic `client_id:client_secret` a pro Secret API není nahrazen OAuth access tokenem. |
| `component_lifecycle` | `DISABLED`, `INACTIVE`, `QUARANTINED` a `DEREGISTERED` samy o sobě credential pro Secret API neruší; chybějící grant nebo credential selže fail-closed. |
| `admin_reveal` | Vyžaduje čerstvé heslo, aktuální TOTP a jednorázový grant vázaný na admina, session, secret, verzi a účel. |
