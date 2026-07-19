# Kompatibilitní matice KCML 2026.07.21

Katalogová změna je `MINOR`, klasifikace `COMPATIBLE IMPACT`. Historické manifesty se nepřepisují; existující identity, endpointy a tokenová semantika vstupují do komponentového modelu přes adaptéry migrace `041`.

| Profil | Starý katalog / manifest | Nový katalog / manifest | Intake / adaptér | Výsledek |
| --- | --- | --- | --- | --- |
| AI klient | `2026.07.20`, schema `1.4/1.5` | `2026.07.21` | `/v1/onboardings` / Kaja adaptér | podporováno adaptérem |
| AI klient | – | `2026.07.21` | `/v2/component-onboardings` | nativně podporováno |
| AI agent | `2026.07.20`, schema `1.4/1.5` | `2026.07.21` | `/v1/onboardings` / Kaja adaptér | podporováno adaptérem |
| AI agent | – | `2026.07.21` | `/v2/component-onboardings` | nativně podporováno |
| MCP server | `2026.07.20`, schema `1.4/1.5` | `2026.07.21` | `/v1/onboardings`, `/api/mcp-servers` | podporováno adaptérem; `initialize`, `notifications/initialized`, `tools/list`, `tools/call` zůstávají povinné |
| MCP server | – | `2026.07.21` | `/v2/component-onboardings` | nativně podporováno |
| Managed runtime | `external-api-1.0` | `2026.07.21` | `/v1/service-onboardings`, `/api/managed-services` | podporováno adaptérem |
| Managed runtime | – | `2026.07.21` | `/v2/component-onboardings` | nativně podporováno |
| Externí služba | `external-api-1.0` | `2026.07.21` | `/v1/service-onboardings` | podporováno adaptérem |
| Externí služba | – | `2026.07.21` | `/v2/component-onboardings` | nativně podporováno |
| Platformní služba | `2026.07.20`, schema `1.4/1.5` | `2026.07.21` | `/api/managed-services` | podporováno adaptérem |
| Platformní služba | – | `2026.07.21` | `/v2/component-onboardings` | nativně podporováno |

| Runtime kombinace | Výsledek |
| --- | --- |
| Známý legacy Pulse typ + existující ACL | podporováno adaptérem |
| `component.pulse` + aktuální route/scope permission | nativně podporováno |
| Neznámý Pulse typ | `catalog_incompatible` |
| Odebraný scope | `insufficient_scope` nebo `route_denied` podle rozhodovacího kroku |
| Odebraná route | `route_denied` |
| Kanonický hostname + shodný Host/SNI/audience | povoleno při splnění aktuálního stavu a gates |
| Alternativní hostname nebo nesprávná audience | `invalid_audience` |
| IP, localhost, přímý port nebo service name | `invalid_component_hostname` / fail-closed gateway rejection |
| Deaktivovaná komponenta se stále platným credentialem | `component_disabled`; credential zůstává nerevokovaný |
| Karanténa | `component_quarantined`; credential se mění jen explicitní revokací/rotací |
