# Onboarding Catalog v1.6 Proposal

Tento návrh popisuje změny normativního katalogu po prostudování současné
verze `Connect in Catalog v1.5`. Cílem je rozšířit katalog z MCP-only
registrace na obecný model managed services a současně přesně vyjádřit práva
KCML nad API rozhraním registrovaných služeb.

## Proč je potřeba v1.6

Verze 1.5 je silná v oblasti MCP bezpečnosti, ale má tři omezení:

1. zaměňuje stav služby a stav API rozhraní,
2. neumí popsat non-MCP `EXTERNAL_API` pipeline,
3. nevyjadřuje explicitní operator scopes pro KCML nad stavem, logy a
   řízením API expozice.

## Nové principy v1.6

- `managed_service` je nadřazená entita pro MCP i jiné HTTPS služby.
- API rozhraní má samostatný stav `api_state`, oddělený od běhu celé služby.
- KCML nemá neomezený bypass; má explicitně přidělené řídicí scopes.
- Onboarding má dvě normativní pipeline:
  - `MCP_ONBOARDING`
  - `EXTERNAL_API_REGISTRATION`

## Normativní změny textu katalogu

### 1. Terminologie

V celém dokumentu nahradit úzké chápání „server“ tam, kde jde o obecnou
spravovanou službu:

- `MCP server` ponechat jen tam, kde se mluví výhradně o MCP kontraktu.
- Jinak použít `managed service` nebo `spravovaná služba`.

### 2. Oddělení služby a API rozhraní

Do kapitoly o lifecycle a fail-closed pravidlech doplnit:

- `lifecycle_state` a `operational_state` vyjadřují stav služby,
- `api_state` vyjadřuje dostupnost centrálně řízeného API rozhraní,
- vypnutí API rozhraní nesmí být interpretováno jako vypnutí samotného
  business serveru, workeru ani databázového backendu,
- API disable musí okamžitě zneplatnit vydané access tokeny pro dané
  rozhraní.

### 3. KCML operator scopes

Do sekce autorizace a permissions přidat závazný scope model pro KCML:

- `service.read_state`
- `service.read_logs`
- `service.monitor.read`
- `service.api.enable`
- `service.api.disable`
- pro MCP navíc `mcp.invoke`
- pro externí API navíc `api.read`, `api.write`, `api.admin` podle manifestu

Normativní text:

- KCML musí umět číst aktuální stav, recertifikaci, monitoring a audit-safe
  log evidence spravovaných služeb.
- KCML musí umět vypnout a znovu zapnout pouze centrálně řízené API
  rozhraní.
- KCML nesmí z katalogu odvozovat implicitní oprávnění k vypnutí celého
  serveru nebo provozní infrastruktury služby.

### 4. Katalog logů a stavu

Do provozního kontraktu doplnit, že každá služba musí zveřejnit nebo
poskytnout pro centrální sběr:

- aktuální lifecycle a API state,
- health/readiness stav,
- poslední revizi a monitoring freshness,
- runtime log evidence v redigovaném formátu,
- correlation ID pro řetězení volání, probe a auditu.

### 5. Druhá pipeline pro EXTERNAL_API

Do katalogu přidat samostatnou kapitolu:

- `EXTERNAL_API` registrace nepředává ZIP handleru,
- předává manifest, kontrakt endpointů, auth metadata, health endpointy,
  monitoring profil, governance a evidence,
- centrální systém ověří HTTPS identitu, token contract, scopes, health,
  monitoring a aktivaci API rozhraní.

### 6. Manifestové změny

Vedle `onboarding-manifest-v1.5.example.json` přidat nový normativní vzor:

- `service-manifest-external-api-v1.0.example.json`

Povinné větve:

- `serviceKind`
- `serviceIdentity`
- `auth`
- `endpoints`
- `requiredScopes`
- `loggingContract`
- `stateContract`
- `monitoringProfile`
- `governance`
- `approvals`
- `change`

### 7. UI a operace

Katalog musí nově vyžadovat, aby UI umělo:

- zobrazit lifecycle i API state odděleně,
- zobrazit poslední důvod API disable,
- zobrazit redigované logy a probe evidence,
- udělit a odebrat operator scopes,
- spustit akci `Disable API interface` a `Enable API interface`.

## Přesné změny do kapitol v1.5

### Kapitola 33

Rozšířit z `manifest 1.5` na:

- `MCP manifest 1.5`
- `EXTERNAL_API manifest 1.0`

Přidat tabulku, která říká, které větve jsou společné a které typově
specifické.

### Kapitola 34

Doplnit nový stavový blok:

- `api_state = ENABLED | DISABLED`
- `api_state` je orthogonální k `operational_state`
- `ACTIVE + api_state=DISABLED` znamená běžící službu s centrálně vypnutým API

### Kapitola 35

Rozšířit `Probe set` a `Invocation` na obecné `service usage`:

- MCP synthetic call,
- external API auth check,
- external API business probe,
- log ingestion freshness,
- state endpoint freshness.

### Kapitola 36

Akceptační důkazy rozšířit o:

- ověření API disable bez odstavení backendu,
- ověření operator scopes,
- ověření čtení logů a stavu přes KCML,
- ověření EXTERNAL_API pipeline.

## Co se v katalogu nemá změnit

- fail-closed princip,
- append-only audit a hash chain,
- recertifikace,
- oddělení tajných hodnot od UI,
- HMAC-backed token lookup digesty,
- požadavek na monitoring a alerting před aktivací.
