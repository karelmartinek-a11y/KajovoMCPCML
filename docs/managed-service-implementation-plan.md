# Managed Service Implementation Plan

Tento dokument rozpracovává implementaci v ideálním pořadí. Cílem je rozšířit
současný systém tak, aby:

- podporoval `managed_service` nad MCP i dalšími API službami,
- zavedl samostatné řízení `api_state`,
- dal KCML explicitní operator scopes,
- rozšířil onboarding katalog a přidal `EXTERNAL_API` pipeline,
- zachoval kompatibilitu současného MCP provozu.

## Fáze 0: Sjednocení rozhodnutí a slovníku

1. Schválit, že cílová SSOT entita je `managed_service`, nikoli další větev vedle `mcp_server`.
2. Schválit oddělení:
   - `lifecycle_state`
   - `operational_state`
   - `api_state`
3. Schválit základní operator scopes:
   - `service.read_state`
   - `service.read_logs`
   - `service.monitor.read`
   - `service.api.enable`
   - `service.api.disable`
4. Schválit, že API disable nikdy neznamená vypnutí celé služby.

Výstup:

- potvrzená ADR,
- odsouhlasený scope model,
- odsouhlasená terminologie do katalogu v1.6.

## Fáze 1: Datový model bez změny runtime

1. Zavést nové tabulky `managed_service`, `managed_service_revision`, `managed_service_scope`, `managed_service_permission`, `managed_service_access_token`, `managed_service_api_status`, `managed_service_usage_event`, `managed_service_runtime_log_event`, `managed_service_probe_result`, `external_api_service_profile`, `service_pipeline_run`, `service_pipeline_event`.
2. Udělat backfill existujících MCP serverů.
3. Zapsat i samostatný `api_state` backfill.
4. Seednout standardní operator scopes pro všechny managed services.

Výstup:

- nové schéma připravené vedle stávajícího,
- žádná změna produkčního chování MCP.

## Fáze 2: Read model a administrace služeb

1. Přidat repository/domain vrstvu pro čtení `managed_service`.
2. Přidat admin API pro:
   - list/detail managed services,
   - scopes,
   - API state,
   - runtime logs,
   - monitoring evidence.
3. Zavést auditované operace:
   - `service.api.disabled`
   - `service.api.enabled`
4. Přidat kontrolu, že disable/enable mění jen API expozici a revokaci tokenů, ne interní business běh služby.

Výstup:

- centrální service admin API,
- auditovaný API interface control.

## Fáze 3: Scope model a token authority

1. Zobecnit dnešní `EXECUTE` na scope-based permission model.
2. Rozšířit vydávání tokenů z MCP audience na obecné service audience.
3. Přidat tokeny s `scope_names[]`.
4. Zavést jednotnou validaci:
   - credential revocation epoch,
   - service revocation epoch,
   - API state,
   - monitoring gate,
   - recertification gate.
5. Zavést KCML operator credential/profile s explicitními scopes.

Výstup:

- jedna autorizační autorita pro MCP i jiné služby,
- řízený operator access bez implicitního bypassu.

## Fáze 4: Monitoring, state a logging unification

1. Přesměrovat probe výsledky na `managed_service_probe_result`.
2. Přesměrovat runtime log evidence na `managed_service_runtime_log_event`.
3. Zavést jednotný state view:
   - lifecycle,
   - operational,
   - API state,
   - monitoring freshness,
   - recertification phase.
4. Doplnit API disable smoke test:
   - backend běží,
   - API vrací fail-closed,
   - tokeny jsou neplatné,
   - stav a logy jsou čitelné.

Výstup:

- společný monitoring a observability model.

## Fáze 5: Admin UI

1. Přidat novou obrazovku `Managed services`.
2. Zobrazovat odděleně:
   - service state,
   - API state,
   - monitoring state,
   - recertification state.
3. Přidat akce:
   - `Disable API interface`
   - `Enable API interface`
4. Přidat log viewer a state inspector.
5. Přidat editor scope-based permissions.

Výstup:

- UI připravené pro MCP i EXTERNAL_API služby.

## Fáze 6: Onboarding katalog v1.6

1. Vydat `Connect in Catalog v1.6`.
2. Upravit terminologii z MCP-only na managed service model.
3. Výslovně přidat `api_state`.
4. Výslovně přidat KCML operator scopes.
5. Rozdělit manifestový kontrakt:
   - MCP manifest 1.5
   - EXTERNAL_API manifest 1.0
6. Rozšířit akceptační důkazy o:
   - API disable bez odstavení backendu,
   - čtení stavu a logů,
   - operator scopes,
   - EXTERNAL_API registration flow.

Výstup:

- nový normativní katalog,
- nová onboarding pravidla pro druhou pipeline.

## Fáze 7: EXTERNAL_API manifest a pipeline

1. Přidat validátor `service-manifest-external-api-v1.0`.
2. Přidat intake flow pro `EXTERNAL_API_REGISTRATION`.
3. Validovat:
   - HTTPS identitu,
   - token endpoint / auth metadata,
   - health/readiness,
   - required scopes,
   - monitoring contract,
   - logging/state contract.
4. Aktivovat službu až po PASS všech gates.

Výstup:

- druhá pipeline pro interní i externí API servery.

## Fáze 8: První referenční integrace

1. Připojit první non-MCP službu, ideálně docházkový systém.
2. Namodelovat jeho scopes:
   - read state,
   - read logs,
   - read API,
   - write API,
   - disable/enable API interface.
3. Ověřit onboarding, monitoring, logs, token issuance a revokace.
4. Zapsat learned lessons do katalogu a runbooků.

Výstup:

- referenční ověřená `EXTERNAL_API` integrace.

## Fáze 9: Postupný přesun MCP runtime

1. Přesměrovat čtení katalogu z `mcp_server` na `managed_service` read model.
2. Přesměrovat permissions/token issuance na service layer.
3. Zachovat kompatibilní endpoints, dokud UI i runtime nepřejdou celé.
4. Teprve po plném cutover plánovat redukci MCP-only duplicit.

Výstup:

- jedna sjednocená platforma bez architektonického rozštěpení.

## Kritická pořadí, která se nesmí prohodit

1. Nejprve datový model a read model.
2. Potom scope model a token authority.
3. Potom monitoring/logging unification.
4. Až potom katalog v1.6, UI a EXTERNAL_API pipeline.
5. Referenční docházkový systém až po hotové operator scopes a API state.

## Otevřené otázky k potvrzení

1. Zda má KCML vystupovat jako speciální `kaja_credential`, nebo jako nový typ systémového principalu.
2. Zda mají být logy čitelné přímo jako runtime event stream, nebo přes redigovaný agregovaný view model.
3. Zda `api_state` zůstane binární, nebo časem přibude `READ_ONLY`.
