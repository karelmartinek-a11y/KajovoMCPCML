# Extracted SSOT: KCML_Spravce_MCP_serveru_SSOT_v1.4_automaticky_onboarding.docx

KCML

Správce MCP serverů

Jednotné závazné zadání systému (SSOT)

Tento dokument je jediným zdrojem pravdy. Verze 1.4 zachovává původní požadavky, odstraňuje nejednoznačnosti a doplňuje závazný protokolový, architektonický, bezpečnostní, integrační a provozní profil. Všechna klientská tajemství a opaque Bearer access tokeny musí mít nejméně 512 bitů kryptografické entropie. Verze 1.4 normativně doplňuje automatický onboarding integračním tokenem, PR/CI, podepsaný izolovaný OCI runtime a automatickou aktivaci po úplném PASS. Implementace nesmí zavést fallbacky, skryté výjimky, společný veřejný endpoint pro více MCP serverů ani jiné chování, které zde není výslovně povoleno.

## Obsah

1. Účel a výsledný produkt

2. Neměnné principy

3. Architektura a adresace

4. Standard MCP a chování jednotlivého serveru

5. Autorizační autorita, pověření a tokeny

6. Administrátorské UI

7. Testování a zapínání MCP serverů

8. Datový model a perzistence

9. Povinná registrace a řízená integrace každého MCP serveru

10. Bezpečnostní požadavky

11. Audit, statistiky a observabilita

12. Provoz na sdíleném Ubuntu serveru

13. Chybové a hraniční stavy

14. Nultá verze systému

15. Akceptační kritéria

16. Povinné implementační testy

17. Výslovně zakázaná řešení

18. Definice dokončení

19. Normativní základ a protokolový profil

20. Referenční architektura a hranice komponent

21. Technologický profil a struktura řešení

22. Databáze, transakce a konzistence

23. Handler SDK, životní cyklus a izolace

24. Autorizační profil a profil pověření

25. Administrátorský backend a uživatelské postupy

26. Síť, reverzní proxy, DNS a TLS

27. Nefunkční požadavky, kapacita a limity

28. Observabilita, audit a alerting

29. Bezpečnostní základna a model hrozeb

30. CI/CD, vydání, migrace a rollback

31. Zálohování, obnova, retence a incidenty

32. Rozšířená akceptační matice

33. Povinné endpointy a HTTP kontrakt

34. Konfigurace, tajemství a provozní parametry

35. Předávací balíček a dokumentace

36. Konečná definice dokončení verze 1.4

37. Automatický onboarding zdrojového handleru

## 1. Účel a výsledný produkt

Výsledkem bude jedna centrální aplikace nazvaná Správce MCP serverů. Aplikace bude provozovat, autorizovat, monitorovat a administrativně řídit libovolný počet veřejně oddělených MCP serverů. Každý registrovaný kód KCML představuje jeden samostatný MCP server s vlastní subdoménou a právě jedním zveřejněným nástrojem.

Správce je společný interní runtime, databáze, administrace, audit a autorizační autorita.

Jednotlivé KCML položky jsou z pohledu klienta samostatné MCP servery.

Každý MCP server má jednu vlastní kanonickou adresu a zveřejňuje právě jednu funkci.

Nultá verze po nasazení neobsahuje žádný registrovaný MCP server; administrace, tokeny, audit a systémový dohled však fungují plně.

## 2. Neměnné principy

## 3. Architektura a adresace

Všechny MCP servery mohou běžet v jednom procesu nebo v jedné sadě kontejnerů. Tato skutečnost je interním implementačním detailem a nesmí narušit veřejnou izolaci jednotlivých serverů.

Host header je bezpečnostní hranice. Požadavek přijatý na kcml0001.hcasc.cz nesmí žádným způsobem zobrazit ani spustit KCML0002.

### 3.1 DNS a reverzní proxy

DNS hcasc.cz musí směrovat požadované subdomény na produkční server. Lze použít explicitní záznamy nebo řízený wildcard záznam, pokud aplikace a proxy neznámé subdomény odmítnou.

Reverzní proxy poslouchá na portech 80/443 a směruje admin, auth a kcml subdomény na oddělené interní routy aplikace.

Aplikace nesmí převzít nebo měnit routy jiných aplikací na serveru.

Před každým reloadem proxy musí proběhnout kontrola syntaxe, duplicit hostname a dostupnosti stávajících služeb.

TLS certifikáty musí pokrýt používané subdomény; správa certifikátů nesmí narušit existující certifikáty jiných služeb.

## 4. Standard MCP a chování jednotlivého serveru

Každá KCML subdoména implementuje vzdálený MCP server přes HTTPS a podporovaný HTTP transport. Server musí korektně obsloužit inicializaci relace, zjištění nástrojů a volání nástroje v souladu s implementovanou verzí protokolu MCP.

### 4.1 Katalogizace MCP serverů

Každý registrovaný MCP server je evidován jako samostatná katalogová položka s těmito údaji:

neměnný kód KCML0001, KCML0002 a dále

název a administrátorský popis

jediný kanonický hostname a HTTPS adresa

název nástroje zveřejněný přes MCP

vstupní schéma a popis vstupů

výstupní schéma a popis výsledku

stav zapnuto/vypnuto

implementační handler a jeho verze

testovací vstup a pravidla vyhodnocení testu

datum vytvoření a datum poslední změny

provozní statistiky a poslední výsledky volání

aktuální registrační stav, registrační revize a datum příští recertifikace

vlastník služby, technický vlastník, provozní kontakt a kritičnost

manifest digest, build ID, aktivní artefakt digest a poslední schválená verze

monitorovací profil, vypočtený provozní stav, poslední syntetický test a aktivní alerty

## 5. Autorizační autorita, pověření a tokeny

Správce MCP serverů funguje současně jako autorizační autorita pro strojové klienty, agenty, programy a případně konkrétní uživatele. Každý klient používá vlastní pověření. Síťový původ požadavku neposkytuje žádné automatické oprávnění.

### 5.1 Identifikátor Kaja a klientské tajemství

Každému pověření se automaticky přidělí veřejný identifikátor Kaja0001, Kaja0002 a dále.

Po Kaja9999 následuje Kaja10000, poté Kaja10001 a další bez recyklace a bez návratu k uvolněným číslům.

Identifikátor Kaja není bezpečnostní tajemství a nesmí být použit jako samotný token.

Klientské tajemství je kryptograficky náhodná hodnota s nejméně 512 bity skutečné entropie, vytvořená kryptograficky bezpečným generátorem náhodných čísel (CSPRNG). Neposílá se na MCP endpoint; používá se pouze pro získání krátkodobého Bearer access tokenu na autorizační autoritě.

V databázi se ukládá pouze bezpečný hash klientského tajemství; u vydaných access tokenů pouze keyed hash a necitlivý fingerprint pro auditní dohledání.

Plná hodnota klientského tajemství se zobrazí přesně jednou po vytvoření. UI ani databáze ji nesmí umožnit znovu zobrazit.

### 5.2 Životní cyklus tokenu

### 5.3 Vyhodnocení každého volání

Ověřit přesný hostname a existenci odpovídajícího MCP serveru.

Načíst krátkodobý Bearer access token výhradně z hlavičky Authorization.

Ověřit keyed hash access tokenu, jeho expiraci, audience, vazbu na aktivní Kaja pověření a stav revokace.

Ověřit audience/resource proti přesné adrese volaného MCP serveru.

Ověřit explicitní oprávnění tokenu ke konkrétnímu kódu KCML.

Ověřit, že MCP server je zapnutý.

Ověřit název nástroje a vstupní schéma.

Spustit přesně přiřazený handler.

Ověřit výstupní schéma.

Zapsat výsledek, latenci, klasifikaci chyby a korelační ID do auditu a statistik.

## 6. Administrátorské UI

Administrace je dostupná pouze na https://admin.hcasc.cz. Přístup je výhradně administrátorský. V nulté verzi existuje jeden nebo více administrátorských účtů, ale nejsou zavedeny běžné uživatelské role.

### 6.1 Přihlášení a účet

přihlášení jménem a heslem

vícefaktorové ověření administrátora

bezpečná serverová session v HttpOnly, Secure a SameSite cookie

CSRF ochrana všech změnových operací

rate limiting a ochrana proti brute-force

odhlášení všech relací daného účtu

změna hesla a správa druhého faktoru

audit přihlášení, odhlášení a neúspěšných pokusů

### 6.2 Navigace

### 6.3 Úvodní obrazovka a monitoring

Po přihlášení se zobrazí tabulka MCP serverů. V nulté verzi je tabulka prázdná a UI zobrazí jednoznačný stav „Neexistuje žádný registrovaný MCP server“ bez testovacích dat.

Tabulka podporuje hledání, řazení, stránkování a ruční obnovu.

Dlouhá schémata se zobrazují v detailu; nesmí rozbít šířku tabulky ani přetékat mimo obrazovku.

Datum a čas se zobrazují v lokálním časovém pásmu administrace, ale v databázi se ukládají v UTC.

## 7. Testování a zapínání MCP serverů

### 7.1 Tlačítko Test

Test spustí skutečné MCP volání proti stejnému hostname, autorizační cestě, schématu a handleru jako produkční klient. Test nesmí volat zjednodušenou nebo zvláštní implementaci.

použije uložený testovací vstup a samostatné systémové testovací pověření

ověří HTTP, MCP lifecycle, tools/list, tools/call, vstupní i výstupní schéma

změří latenci a uloží výsledek do auditu

zobrazí jasné vyhodnocení: úspěch nebo přesná chyba

neprovede automatický retry ani fallback

u funkce s vedlejšími účinky musí být testovací kontrakt explicitně bezpečný a izolovaný; bez něj se funkce nesmí zaregistrovat

Test je povinným registračním gate. Bez platného registračního manifestu, schváleného testContract a aktivního monitorovacího profilu se tlačítko Test nespustí a server nelze zapnout.

Výsledek Testu se váže na přesný contract version, handler version, build ID, manifest digest a artefakt digest; výsledek jiné verze nelze použít k aktivaci.

### 7.2 Zapnout a vypnout

Vypnutí je okamžité a zabrání novým autorizovaným voláním.

Rozpracované volání se dokončí nebo ukončí podle závazné politiky konkrétního handleru; tato politika musí být registrována spolu s funkcí.

Vypnutý server zůstává viditelný v administraci a auditu.

Každá změna stavu vyžaduje potvrzení s přesným kódem a je auditována.

## 8. Datový model a perzistence

Databázové čítače Kaja a KCML jsou atomické a transakční.

Kumulativní statistiky se nesmí vynulovat při restartu, vypnutí nebo smazání tokenu.

Auditní záznamy a identifikátory musí zůstat zachované i po logickém smazání objektu.

Schémata a konfigurační změny jsou verzované databázovými migracemi.

## 9. Povinná registrace a řízená integrace každého MCP serveru

Každý jednotlivý MCP server musí před prvním produkčním nasazením projít samostatnou registrací a řízenou integrací. Registrace není administrativní poznámka, ale bezpečnostní a provozní gate, který propojuje neměnnou identitu KCML, schválený MCP kontrakt, konkrétní handler artefakt, vlastníka, limity, testovací důkazy a monitorovací profil.

Bez dokončené registrace nesmí vzniknout aktivní veřejný routing, nesmí být vydán access token pro daný resource, server nesmí být zapnut a centrální správa jej nesmí označit jako provozuschopný. Neúplná, expirovaná nebo bezpečnostně zamítnutá registrace se vždy vyhodnotí fail-closed.

### 9.1 Registrační jednotka a rozsah

Jedna registrace se vztahuje právě k jednomu kódu KCML, jednomu kanonickému hostname, jednomu tool name, jedné verzi MCP kontraktu, jedné verzi handleru a jednomu neměnnému digestu release artefaktu.

Kód KCML, hostname a tool name přiděluje Správce. Integrující tým je nesmí volit, předregistrovat ani odvozovat mimo centrální transakční sekvenci.

Registrace metadat nikdy neinstaluje ani nespouští kód. Spustitelný handler se dodává pouze schváleným CI/CD release artefaktem; registrační záznam na tento artefakt odkazuje jeho digestem a build ID.

Registrace se provádí odděleně pro staging a produkci. Produkční registrace smí převzít pouze důkazy vytvořené nad totožným zdrojovým commitem a artefaktem; prostředí, tajemství a endpointy se nepřenášejí.

Změna, která ovlivní kontrakt, vedlejší účinky, bezpečnost, síť, tajemství, data, limity, monitoring nebo handler artefakt, vytváří novou registrační verzi a nesmí přepsat aktivní historickou verzi.

### 9.2 Stavový model registrace

Registrační stav je oddělen od provozního stavu monitoringu a od přepínače zapnuto/vypnuto. Přechody provádí výhradně backend podle níže uvedených podmínek; UI nesmí nabídnout přeskočení povinného kroku.

Každý přechod ukládá předchozí a nový stav, identitu aktéra, čas UTC, důvod, digest manifestu, digest artefaktu a odkazy na testovací a schvalovací důkazy. Ruční změna databázového stavu mimo doménovou operaci je zakázána.

### 9.3 Povinný integrační a registrační balík

Integrující tým předá pro každý MCP server uzavřený balík. Neexistuje možnost nahradit některou oblast ústním vysvětlením, odkazem na neřízenou konverzaci nebo pozdějším doplněním po aktivaci.

### 9.4 Strojově čitelný registrační manifest

Součástí balíku je verzovaný soubor mcp-registration.yaml nebo ekvivalentní JSON se schématem spravovaným v repozitáři Správce. Manifest se validuje v CI i při registraci a jeho kanonický hash je uložen v katalogu.

Manifest s neznámým polem, neznámou enum hodnotou, rozporem mezi anotací a effectClass, nekanonickým schématem nebo odkazem na neexistující důkaz se odmítne. Automatické doplnění výchozí bezpečnostně významné hodnoty při registraci je zakázáno.

### 9.5 Podmínky bezpečnostního a architektonického schválení

Tool vstup, výstup, popis a anotace jsou stabilní, deterministicky verzované a negenerují se z nedůvěryhodných externích dat. Popis nesmí obsahovat tajemství, interní topologii ani pokyny k obcházení autorizace.

Všechny vstupy se validují před handlerem, všechny strukturované výstupy proti outputSchema a textový obsah se sanitizuje s ohledem na downstream klienty. Nevalidní výstup se nikdy nevydá jako úspěch.

Handler používá nejnižší nutná oprávnění, samostatnou runtime identitu a pouze deklarované secret references. Přístup k admin session, Kaja client_secret, access tokenům jiných klientů a systémové databázové roli je zakázán.

Odchozí komunikace používá centrální bezpečný klient a explicitní allowlist. SSRF, DNS rebinding, redirect na neallowlistovaný host, přístup na loopback/link-local/metadata rozsahy a nekontrolované file URI jsou blokovány.

Release artefakt je reprodukovatelný, podepsaný nebo jednoznačně ověřený digestem, běží jako non-root a neobsahuje kritickou zranitelnost. High zranitelnost vyžaduje časově omezenou schválenou výjimku s vlastníkem, kompenzačním opatřením a datem expirace.

Každá operace se zápisem nebo destruktivním účinkem má explicitní idempotency a compensation pravidlo, případně je označena NON_IDEMPOTENT_WRITE. Automatický retry mimo schválenou politiku je zakázán.

Citlivá nebo destruktivní funkce má v dokumentaci jednoznačně uveden požadavek na informovaný souhlas a potvrzení na straně MCP klienta; server nesmí tvrdit, že souhlas sám nahradil.

Logy, traces, metriky, testovací důkazy a chybové odpovědi neobsahují tajemství ani plné payloady. Výjimka pro diagnostiku musí být časově omezená, schválená, redigovaná a auditovaná.

Architektura prokazuje fail-closed chování při nedostupné databázi, auditu, autorizační autoritě, závislosti, síti nebo monitorovací kontrole. Žádná lokální cache nesmí změnit oprávnění ani server znovu zapnout.

Kapacitní limity handleru se vejdou do sdíleného produkčního serveru a mají backpressure. Integrace nesmí ohrozit dostupnost jiných aplikací, proxy, databáze ani auditní vrstvy.

### 9.6 Povinné integrační, bezpečnostní a provozní testy

Před přechodem do REGISTERED_DISABLED musí být automatické testy zelené nad kandidátním artefaktem. Před přechodem do ACTIVE musí být produkční testy zelené nad skutečným hostname, TLS, autorizační autoritou, katalogem, handlerem, auditem a monitoringem.

Validace registračního manifestu, povinných důkazů, kanonických hashů, podpisu artefaktu a shody source commit → build ID → artefakt digest.

Unikátnost KCML, hostname, tool name a handlerKey; pokus o registraci stejného artefaktu pod jiným neřízeným serverem se odmítne.

DNS, SNI, TLS, Host, proxy routing, HTTP→HTTPS na stejném hostu, odmítnutí neznámé subdomény a nulová cross-host dostupnost.

OAuth protected resource metadata, token request, přesný resource/audience, chybějící token, chybný token, cizí token, revokace a zákaz interního bypassu.

MCP initialize, notifications/initialized, MCP-Protocol-Version, tools/list s právě jedním nástrojem, tools/call, neznámá metoda, neznámý tool a neplatný Origin.

Pozitivní, hraniční a negativní vstupy; odmítnutí unknown fields; limity velikosti; validace outputSchema; sanitizace textového výstupu a absence tajemství.

Bezpečný syntetický tools/call test proti produkčnímu handleru. U zápisové funkce musí být test izolovaný, opakovatelný a mít ověřený cleanup nebo deterministickou kompenzaci.

Timeout, zrušení, concurrency, rate limit, přetížení, fronta, restart, graceful shutdown a deklarovaná shutdownPolicy.

Výpadek každé deklarované závislosti, DNS chyba, pomalá odpověď, neplatný certifikát, databázová chyba a selhání auditu bez retry nebo fallbacku.

Monitoring enrollment, doručení metrik, trace correlation, vyhodnocení HEALTHY/DEGRADED/UNHEALTHY, stale data, alert routing a automatická karanténa kritického bezpečnostního stavu.

Rollback na předchozí kompatibilní verzi a ověření, že rollback nemění KCML identitu, oprávnění, audit ani kumulativní statistiky.

Zátěžový test podle deklarovaného loadProfile včetně ověření, že limity jednoho handleru nevyčerpají společný worker pool, databázový pool ani ostatní MCP servery.

Každý testovací běh uloží build ID, artefakt digest, manifest digest, prostředí, čas, výsledky jednotlivých kroků a korelační ID. Screenshot nebo ruční tvrzení bez strojově ověřitelného výsledku není dostačující důkaz.

### 9.7 Povinný monitorovací profil při registraci

Registrace obsahuje monitorovací profil a centrální správa jej aktivuje současně s vytvořením katalogového záznamu. Server bez aktivního profilu nebo se zastaralou telemetrií nesmí mít stav HEALTHY.

Uvedené intervaly jsou maximální. Kritičtější server může mít interval kratší. Prodloužení intervalu, vynechání syntetického tools/call nebo změna prahu vyžaduje novou schválenou registrační revizi.

### 9.8 Výpočet provozního stavu v centrální správě

Provozní stav vypočítává centrální monitor. Handler ani vlastník integrace jej nesmí jednostranně nastavit. Stav je výsledkem nejhorší relevantní kontroly, platnosti registrace, zapnutí serveru a bezpečnostních invariantů.

Přechod do QUARANTINED okamžitě zablokuje nové tokeny a nová MCP volání, vytvoří Critical alert a auditní událost. Návrat do ACTIVE je možný pouze přes novou registrační revizi, opakované bezpečnostní testy a ruční schválení; automatické zotavení je zakázáno.

### 9.9 Povinné údaje a akce v centrální správě

### 9.10 Alerting, eskalace a reakce

Alert obsahuje KCML, prostředí, build ID, stav, první a poslední výskyt, relevantní korelační ID, vlastníka a odkaz na runbook; nikdy neobsahuje token, secret ani plný payload.

Acknowledgement, přiřazení, potlačení a uzavření alertu se auditují. Potlačení má povinný důvod, vlastníka a expiraci a nesmí změnit vypočtený provozní stav.

Alert routing je součástí registračního gate. Testovací alert musí před aktivací prokazatelně dorazit alespoň na primární i záložní provozní kanál.

Centrální správa nesmí automaticky opakovat tools/call po timeoutu nebo nejednoznačném výsledku. Další syntetický pokus proběhne až v následujícím intervalu a je samostatnou auditní událostí.

### 9.11 Změnové řízení a opakovaná certifikace

Aktivní registrační revize je neměnná. Změna níže uvedené vlastnosti vytváří novou kandidátní revizi, která projde odpovídající částí integrace a před aktivací se atomicky přepne.

inputSchema, outputSchema, tool title/description, error catalog, anotace nebo supported MCP capability;

effectClass, idempotence, retry, transakce, kompenzace, vedlejší účinky nebo bezpečný testContract;

handler version, source commit, build ID, artefakt digest, runtime nebo významná závislost;

síťový allowlist, databázová role, filesystem policy, secret reference, scope nebo jiná oprávnění;

data classification, osobní údaje, retence, redakce, export nebo lokalita dat;

timeout, velikost, concurrency, rate limit, SLO, monitoring interval, alert threshold nebo auto-quarantine pravidlo;

vlastník služby bez platného nástupce, provozní kontakt, runbook, kritičnost nebo plán obnovy.

Server třídy NON_IDEMPOTENT_WRITE, server pracující s citlivými/osobními daty nebo kritická služba se recertifikuje nejméně každých 180 dnů. Ostatní servery nejméně každých 365 dnů. Třicet dnů před termínem vzniká Warning; po překročení termínu nelze aktivovat novou verzi a po 30 dnech prodlení se server přesune do SUSPENDED.

### 9.12 Pozastavení, karanténa a vyřazení

SUSPENDED a QUARANTINED blokují vydání nových access tokenů a nová MCP volání. Již vydané tokeny pro daný resource se zneplatní revocation epochou nebo ekvivalentně konzistentním mechanismem.

Vyřazení vyžaduje kontrolu aktivních oprávnění, klientů, závislostí, retence, záloh, DNS/proxy konfigurace, alertů a dokumentace. Nevyřešená závislost blokuje RETIRED.

RETIRED je nevratný. KCML kód, hostname, tool name, registrace, audit a statistiky zůstávají historicky dohledatelné a nikdy se nepřiřadí jiné funkci.

Veřejný endpoint vyřazeného serveru nesmí přesměrovat na jiný server ani nabídnout jiný nástroj. Odpoví jednotnou neúspěšnou odpovědí podle stavového kontraktu Správce a událost audituje.

Odstranění artefaktu, tajemství a síťových oprávnění proběhne až po splnění retenční a rollback lhůty. Samotný katalogový a auditní záznam se fyzicky nemaže.

### 9.13 Registrační audit a důkazní stopa

Audit ukládá každé podání, validaci, zamítnutí, schválení, přidělení KCML, nasazení, test, aktivaci, změnu stavu, maintenance, karanténu, recertifikaci a vyřazení.

Důkazní stopa obsahuje kanonický manifest a jeho digest, artefakt digest, SBOM digest, výsledky skenů, identitu schvalovatelů, testovací protokoly, monitorovací profil a všechny výjimky včetně expirace.

Z UI lze exportovat kompletní registrační dossier bez tajemství. Export má vlastní hash a auditní záznam a je použitelný pro nezávislou kontrolu nebo incidentní šetření.

Auditní události registrace jsou append-only, časově seřazené a propojené s korelačním ID release a testů. Oprava chybného údaje vytvoří novou událost; původní údaj se nepřepisuje.

## 10. Bezpečnostní požadavky

TLS pro všechny veřejné adresy; nešifrovaný provoz se přesměruje pouze na odpovídající HTTPS hostname, nikoli na jiný MCP server.

Validace Host headeru proti přesnému aktivnímu katalogu; neznámé a neplatné hosty se odmítají.

Bearer token se přijímá pouze v hlavičce Authorization, nikdy v URL, query parametru ani logu.

Striktní limity velikosti požadavku, délky vstupů, timeoutu, souběhu a frekvence volání.

Vstup a výstup každého handleru se validují proti uzamčenému schématu.

Tajemství, hesla, tokeny a session hodnoty se redigují ze všech logů a chybových odpovědí.

Databázová role aplikace používá nejnižší nutná oprávnění.

Administrace není dostupná přes KCML subdomény a MCP endpointy nejsou dostupné přes admin subdoménu.

Chyby nesmí odhalovat existenci jiných KCML serverů ani oprávnění jiných tokenů.

Zálohy databáze jsou šifrované, testovaně obnovitelné a přístupné jen určenému provoznímu účtu.

Čas serveru je synchronizovaný; expirace a audit se vyhodnocují podle UTC.

## 11. Audit, statistiky a observabilita

Každá administrativní změna a každý pokus o MCP volání vytvoří auditní stopu. Audit je append-only z pohledu aplikace a nesmí být z UI mazatelný ani upravitelný.

Dashboard musí rozlišit poslední neúspěšné volání obecně a kumulativní počet neautorizovaných volání.

Logy používají korelační ID od vstupu přes autorizaci až po handler a odpověď.

Provozní logy se rotují a mají definovanou retenční dobu; auditní data mají samostatnou retenční politiku.

Systém poskytuje health a readiness kontrolu pouze pro interní monitoring nebo přes chráněný administrátorský endpoint.

## 12. Provoz na sdíleném Ubuntu serveru

Aplikace běží pod samostatným systémovým účtem nebo v izolovaných kontejnerech.

Používá vlastní interní porty a nesmí přímo zabrat port 80 nebo 443.

Konfigurace reverzní proxy je oddělený include nebo ekvivalentní izolovaný blok.

Databáze používá vlastní databázi nebo schéma a vlastní roli.

Konfigurace a tajemství se ukládají mimo zdrojový kód, s omezenými právy souborů nebo v secrets úložišti.

Nasazení musí před změnou zkontrolovat obsazené porty, existující hostname, stav ostatních služeb a platnost proxy konfigurace.

Aktualizace se provádí řízeně s databázovou zálohou, migrací, health kontrolou a možností návratu aplikační verze; návrat nesmí obcházet databázovou integritu.

Restart Správce nesmí změnit kódy, oprávnění, statistiky ani audit.

## 13. Chybové a hraniční stavy

## 14. Nultá verze systému

První produkční verze je plně funkční Správce MCP serverů bez registrovaných MCP funkcí. Nejde o demo ani maketu. Prázdný katalog je platný produkční stav.

## 15. Akceptační kritéria

## 16. Povinné implementační testy

Test, že tools/list nikdy nevrátí více než jeden nástroj.

Testy tokenů: platný, chybějící, náhodný, expirovaný, revokovaný, smazaný, bez oprávnění a s oprávněním.

Test, že interní volání bez tokenu není zvýhodněno.

Test neměnnosti expirace a nerecyklace identifikátorů při souběžném vytváření.

Test jednorázového zobrazení tajemství a absence plného tokenu v databázi, logu, auditu a chybě.

Test prokáže, že klientské tajemství i každý opaque Bearer access token vznikají z nejméně 64 náhodných bajtů (512 bitů) dodaných CSPRNG; kratší hodnota, deterministická hodnota nebo hodnota s nižší skutečnou entropií je kritická chyba a blokuje nasazení.

Test vypnutí během běžného provozu.

Test validačního odmítnutí před handlerem a odmítnutí neplatného výstupu.

Test persistence statistik a auditu po restartu.

Test bezpečného chování při nedostupné databázi a selhání auditu.

Test proxy konfigurace a nekonfliktnosti se stávajícími službami před produkčním reloadem.

Test stavového automatu registrace včetně zakázaných přechodů, optimistic locking, neměnnosti schválené revize a úplné auditní stopy.

Test JSON/YAML schématu mcp-registration manifestu, unknown fields, konfliktu anotací s effectClass, chybějících důkazů a kanonického digestu.

Test, že server bez monitorovacího profilu, bezpečného testContract nebo alert routingu nelze aktivovat.

Test všech probe intervalů, stale telemetrie, deterministického výpočtu provozního stavu a aktualizace UI nejpozději do 60 s.

Test automatické karantény při cross-host porušení, chybné audience, artefakt/contract driftu a neautorizované změně routingu.

Test, že karanténa zneplatní existující access tokeny pro resource a že bez nové revize a ručního schválení není možné znovuzapnutí.

Test recertifikačních termínů, expirace bezpečnostní výjimky, Warning/High alertu a automatického SUSPENDED po stanoveném prodlení.

Test registrace, změny, rollbacku a vyřazení bez recyklace KCML/hostname/tool name a bez ztráty auditu, statistik nebo důkazů.

## 17. Výslovně zakázaná řešení

jeden veřejný MCP server nabízející všechny KCML funkce

společný endpoint typu api.hcasc.cz/mcp s výběrem funkce parametrem

zpřístupnění stejné KCML funkce na více subdoménách

obcházení tokenu pro localhost, interní IP nebo proces na stejném serveru

použití identifikátoru Kaja jako tajného tokenu

ukládání nebo logování plné hodnoty tokenu

wildcard oprávnění ke všem současným i budoucím MCP serverům

automatické přesměrování z neznámého KCML serveru na existující server

fallback na jiný handler nebo úprava neplatného vstupu

testovací handler odlišný od produkčního handleru

mazání auditu nebo nulování historických čítačů

možnost vložit nebo spustit libovolný kód z administrátorského UI

demo data, mock odpovědi, placeholder servery nebo předstírané úspěchy

## 18. Definice dokončení

Systém je dokončen pouze tehdy, když splňuje všechny požadavky tohoto dokumentu, všechny akceptační a bezpečnostní testy procházejí a produkční nasazení na sdíleném Ubuntu serveru je doloženo bez konfliktu s ostatními službami. Neexistuje částečné přijetí, skrytý fallback ani náhradní zjednodušený režim.

Každá odchylka, která umožní volat KCML funkci přes jinou adresu, obejít autorizaci nebo provést jinou funkci než tu přiřazenou přesnému hostname, je kritická chyba a blokuje nasazení.

## 19. Normativní základ a protokolový profil

Tato kapitola uzavírá nejednoznačnosti kolem verze protokolu, transportu a podporovaných schopností. Při rozporu s obecnou formulací v kapitolách 1–18 má tato kapitola přednost.

### 19.1 Povinné chování transportu

POST /mcp přijímá pouze Content-Type application/json; chybějící nebo jiný typ se odmítne HTTP 415.

Klient musí v Accept uvést application/json a text/event-stream. Server v nulté verzi odpovídá application/json; nevyužívá SSE.

Po initialize klient na všech dalších požadavcích posílá MCP-Protocol-Version: 2025-11-25. Neplatná nebo nepodporovaná hodnota vrací HTTP 400.

Origin se validuje proti explicitnímu allowlistu. Chybějící Origin u neprohlížečových klientů je přípustný; přítomný neznámý Origin vrací HTTP 403.

Host a Forwarded/X-Forwarded-Host se vyhodnocují pouze z důvěryhodné proxy cesty. Přímý nedůvěryhodný forwarding header se ignoruje.

InitializeResult uvádí přesnou identitu daného KCML serveru, verzi serverového software, protocolVersion a capabilities pouze pro tools.

tools/list vrací právě jeden Tool. Tool obsahuje name, description, inputSchema a outputSchema; název je lowercase kód KCML.

tools/call s jiným názvem vrací MCP chybu neznámého nástroje. Handler se nesmí spustit ani částečně inicializovat.

Notifikace initialized se přijme jako platná MCP notifikace, ale ve stateless profilu se nepoužívá jako bezpečnostní, autorizační ani směrovací podmínka.

### 19.2 Protokolové chyby

Protokolová kompatibilita se prokazuje automatickými kontraktními testy proti verzi MCP 2025-11-25. Pouhá schopnost odpovědět na tools/list nestačí.

## 20. Referenční architektura a hranice komponent

Produkční řešení je modulární monolit s oddělenými procesními rolemi. Veřejně jde o tři typy hostů (admin, auth, kcmlNNNN), interně o jeden verzovaný produkt a jednu autoritativní databázi.

### 20.1 Povinný průchod MCP požadavku

1. Proxy přijme TLS požadavek, vynutí limit velikosti a předá interně ověřený původní hostname.

2. Host Router odmítne neznámý hostname a ověří přesnou cestu /mcp.

3. Authorization Service validuje access token, audience/resource a oprávnění ke konkrétnímu KCML.

4. Catalog Service vrátí jedinou aktivní definici serveru a jeho uzamčenou verzi kontraktu.

5. MCP Protocol Adapter validuje JSON-RPC a požadovanou MCP metodu.

6. Invocation Orchestrator založí auditní záznam pokusu a přidělí korelační ID.

7. Při tools/call validuje vstup podle přesné verze JSON Schema a předá ho jedinému handleru.

8. Worker spustí handler s deklarovanými limity, bez automatického retry.

9. Orchestrator validuje výstup, transakčně dokončí audit a statistiky a teprve poté vytvoří odpověď.

### 20.2 Závislostní pravidla

Handler nesmí přímo číst tabulky Credential, AccessToken, AdminAccount ani AdminSession.

Admin Backend nesmí volat handler jinou cestou než přes interní Invocation Orchestrator; tlačítko Test používá veřejnou produkční cestu přes HTTPS.

MCP vrstva nesmí přímo měnit katalog, oprávnění ani účty.

Kód nesmí vytvářet globální mapu tool name → handler použitelnou napříč hosty bez předchozího jednoznačného výběru hostu.

Všechny komponenty používají jeden formát korelačního ID a strukturovaných chybových tříd.

## 21. Technologický profil a struktura řešení

Následující profil je výchozí závazná implementační platforma. Odchylka vyžaduje písemné architektonické rozhodnutí, prokázání rovnocenné bezpečnosti a nové schválení akceptačních testů.

### 21.1 Struktura repozitáře

Kompilace selže při TypeScript chybě, neaktuálním generovaném schématu, neaplikované migraci nebo porušení lint/security pravidel.

Produkční image nesmí obsahovat zdrojové mapy s citlivými cestami, testovací data, vývojové klíče ani nepoužité CLI nástroje.

Každé vydání má jednoznačné build ID a git commit; stejná hodnota se uvádí v health odpovědi a auditních záznamech nasazení.

## 22. Databáze, transakce a konzistence

Databáze je autoritativní a všechny bezpečnostní podmínky musí být vynuceny kombinací doménové logiky a databázových constraints. Cache nesmí být zdrojem oprávnění ani stavu zapnuto/vypnuto.

### 22.1 Generování identifikátorů

KCML a Kaja čísla vznikají databázovou sequence. Sequence se nikdy nesnižuje, nerecykluje a není odvozena z počtu řádků.

Kód se formátuje minimálně na čtyři číslice, ale po 9999 pokračuje bez omezení: KCML10000, Kaja10000.

Přidělení čísla a vložení objektu probíhá v jedné transakci. Neúspěšná transakce může vytvořit mezeru v řadě; mezery jsou přípustné a nesmí se doplňovat.

### 22.2 Hashování a dohledání tajemství

Klientské tajemství se ověřuje pomocí paměťově náročného password hashing algoritmu (Argon2id) s individuální solí.

Krátkodobý opaque Bearer access token má nejméně 512 bitů skutečné kryptografické entropie a je generován CSPRNG. Pro rychlé dohledání se ukládá HMAC-SHA-256 digest s odděleným serverovým pepperem uloženým mimo databázi. Použití SHA-256 pro digest nesnižuje požadovanou 512bitovou entropii samotného tokenu; plná hodnota tokenu se nikdy neukládá.

Fingerprint je necitlivý zkrácený SHA-256 identifikátor určený pouze pro auditní zobrazení; nesmí umožnit ověření tokenu.

Porovnání tajných hodnot je konstantního času. Pepper má verzovaný key ID a řízený rotační postup bez vystavení tokenů.

### 22.3 Transakční hranice volání

1. Před spuštěním handleru se v krátké transakci zapíše invocation ve stavu accepted a audit intent. Pokud zápis selže, handler se nespustí.

2. Handler běží mimo otevřenou databázovou transakci Správce; nesmí blokovat systémové tabulky po dobu externí operace.

3. Po dokončení se v jedné transakci uloží výsledek, error class, latence, konečný audit event a aktualizují statistiky.

4. Pokud konečný auditní zápis selže po provedení handleru s vedlejším účinkem, systém vrátí chybu, vyvolá kritický alert a nesmí automaticky opakovat handler.

5. Idempotency key se podporuje pouze u handleru, který ho deklaruje v manifestu. Unikátnost se vynucuje databázově v rozsahu handleru a klienta.

## 23. Handler SDK, životní cyklus a izolace

Každá KCML funkce je implementační modul sestavený spolu s aplikací nebo jako předem schválený verzovaný balíček. Registrace metadat nikdy nezpřístupní kód, který nebyl součástí schváleného release artefaktu.

### 23.1 Rozhraní handleru

Handler přijímá validovaný immutable input a InvocationContext s correlationId, KCML kódem, Kaja identitou, deadline a abort signalem.

Handler nesmí dostat Bearer token, klientské tajemství, admin session ani databázový connection pool Správce.

Handler vrací strukturovaný výsledek odpovídající outputSchema nebo typovanou doménovou chybu. Libovolný throw se mapuje na internal_handler_error.

Logování probíhá přes poskytnutý logger s automatickou redakcí; console.log/console.error v produkčním handleru je zakázán lint pravidlem.

Odchozí HTTP používá centrální klient s DNS/IP kontrolou, timeoutem, limitem odpovědi a zákazem přístupu na loopback, link-local a metadata adresy, není-li explicitně schváleno.

### 23.2 Nasazení nové verze handleru

1. Nová verze se sestaví a otestuje v CI, včetně kontraktů a bezpečnostních skenů.

2. Release nasadí kód, ale katalog nadále ukazuje na původní aktivní verzi.

3. Migrace vloží nový mcp_contract a handler version jako neaktivní kandidát.

4. Administrátor spustí produkční Test proti kandidátní verzi v řízeném režimu.

5. Aktivace proběhne atomickou změnou contract_version/handler_version a vytvoří auditní událost.

6. Rollback přepne na předchozí kompatibilní verzi pouze tehdy, pokud datové a externí změny dovolují bezpečný návrat.

Automatický retry handleru je zakázán. Retry smí existovat pouze uvnitř konkrétního handleru, musí být deklarován v manifestu, omezen počtem pokusů a bezpečný podle effectClass.

## 24. Autorizační profil a profil pověření

Verze 1.1 zpřesňuje terminologii: Kaja je OAuth klientské pověření, jednorázově zobrazená hodnota je client_secret a MCP endpoint přijímá pouze krátkodobý Bearer access token vydaný autorizační autoritou.

### 24.1 Token request

Token endpoint přijme grant_type=client_credentials, resource=<přesná URL /mcp> a volitelný scope. Více hodnot resource v jednom requestu se odmítne.

Před vydáním ověří Kaja stav, secret, explicitní Permission, existenci cílového serveru a jeho stav. Vypnutý server nevydává nový access token.

Odpověď obsahuje access_token, token_type=Bearer, expires_in a scope. Neobsahuje refresh_token ani údaje o jiných KCML serverech.

Chybné client credentials vracejí obecné invalid_client bez rozlišení neexistujícího Kaja, chybného secretu, revokace nebo smazání.

Rate limit token endpointu je samostatný podle IP a client_id; překročení je auditováno a nesmí blokovat jiné klienty globálně.

### 24.2 Discovery a metadata

Každý KCML host poskytuje /.well-known/oauth-protected-resource/mcp a kořenový /.well-known/oauth-protected-resource.

Protected Resource Metadata uvádí přesný resource a authorization_servers=["https://auth.hcasc.cz"].

auth.hcasc.cz poskytuje /.well-known/oauth-authorization-server s issuer, token_endpoint, grant_types_supported=["client_credentials"], token_endpoint_auth_methods_supported=["client_secret_basic"] a scopes_supported.

HTTP 401 z /mcp obsahuje WWW-Authenticate: Bearer s resource_metadata a případně scope. Chybové texty neprozradí validitu Kaja ani existenci jiných serverů.

### 24.3 Rotace a kompromitace

Client secret se nemění. Rotace znamená vytvoření nového Kaja, paralelní přidělení oprávnění, ověření klienta a revokaci původního Kaja.

Nouzová revokace je okamžitá, vyžaduje důvod a zneplatní access tokeny v téže transakci nebo přes konzistentní revocation epoch kontrolovanou při každém volání.

Access tokeny se nesmí logovat, zobrazovat v administraci ani vracet v auditu. UI zobrazuje pouze fingerprint a expiraci.

## 25. Administrátorský backend a uživatelské postupy

Administrace používá server-side Backend-for-Frontend. Prohlížeč nikdy nevolá databázi, interní handler API ani token endpoint s klientskými tajemstvími. Všechny změny mají CSRF ochranu, audit a optimistic locking.

### 25.1 Přihlášení a MFA

Účet se zakládá pouze provozním CLI nebo již přihlášeným administrátorem s oprávněním správy účtů; veřejná registrace neexistuje.

Heslo má minimálně 14 znaků, kontrolu proti kompromitovaným heslům a Argon2id hash. Povinné MFA je TOTP; recovery codes se zobrazí jednou a ukládají hashovaně.

Po pěti neúspěšných pokusech následuje progresivní zpoždění a dočasný lock. Ochrana nesmí umožnit snadné DoS trvalým zamykáním účtů.

Session ID má nejméně 256 bitů, v databázi je pouze hash. Cookie: Secure, HttpOnly, SameSite=Strict, Path=/, bez Domain atributu.

Absolutní expirace session je 8 hodin, neaktivita 30 minut. Citlivé operace vyžadují reautentizaci heslem a MFA, pokud je poslední silné ověření starší než 10 minut.

### 25.2 Vytvoření Kaja pověření

1. Administrátor zadá popis, zvolí explicitní KCML oprávnění a potvrdí, že rozumí jednorázovému zobrazení secretu.

2. Backend vytvoří Kaja a client_secret v jedné transakci a zapíše audit bez secretu.

3. UI zobrazí client_id, client_secret a příklad token requestu pouze na jedné stránce. Opětovné načtení stránky secret nevrátí.

4. Tlačítko Kopírovat nesmí zapisovat secret do logu, analytiky ani telemetrie. Po opuštění stránky není možné hodnotu znovu získat.

5. Administrátor musí potvrdit uložení secretu; bez potvrzení lze pouze pověření okamžitě zneplatnit a vytvořit nové.

### 25.3 Změnové operace

### 25.4 Konzistence UI

Každý detail zobrazuje updated_at a verzi záznamu. Konflikt souběžné změny vrací HTTP 409 a UI načte aktuální stav bez přepsání cizí změny.

Prázdné, loading, error, forbidden a stale stavy jsou explicitní. UI nesmí zobrazit úspěch před potvrzením backendu.

Destruktivní tlačítka nejsou dostupná klávesovou zkratkou bez potvrzení. Formuláře jsou ovladatelné klávesnicí a mají popisky chyb.

Admin API je stejného originu, nemá CORS pro cizí originy a přijímá pouze session cookie, nikoli Kaja access token.

## 26. Síť, reverzní proxy, DNS a TLS

Síťová konfigurace je součástí akceptace. Wildcard DNS nebo wildcard certifikát nezakládá existenci MCP serveru; existenci vždy určuje aktivní katalog a přesný host router.

### 26.1 Routing invariants

admin.hcasc.cz obsluhuje pouze administraci a její statická/API rozhraní; /mcp zde vrací 404.

auth.hcasc.cz obsluhuje pouze token endpoint, metadata a chráněné provozní endpointy; /mcp zde vrací 404.

kcmlNNNN.hcasc.cz obsluhuje /mcp a protected resource metadata; administrátorské cesty zde vracejí 404.

Hostname se normalizuje na lowercase a bez koncové tečky; port je přípustný pouze interně a nesmí změnit resource identitu veřejné URL.

SNI, HTTP Host a efektivní veřejný hostname musí být konzistentní; rozpor se odmítne a audituje jako host_mismatch.

### 26.2 Předreloadová kontrola

1. Ověřit syntaxi celé proxy konfigurace, nikoli jen nového include.

2. Ověřit, že nový hostname nekoliduje s existujícím server_name ani certifikátem jiné aplikace.

3. Ověřit dostupnost stávajících kritických virtual hostů před změnou.

4. Na staging socketu ověřit routing admin/auth/známý KCML/neznámý KCML a HTTP→HTTPS chování.

5. Provést atomický reload. Při chybě zachovat původní konfiguraci a vytvořit auditní/operátorský záznam.

## 27. Nefunkční požadavky, kapacita a limity

### 27.1 Chování při přetížení

Při dosažení fronty nebo concurrency limitu se nový požadavek odmítne 429 nebo 503 před spuštěním handleru.

Systém nesmí kvůli přetížení vynechat autorizaci, audit intent ani validační kroky.

Priorita administrace nesmí umožnit obcházet limity MCP; admin Test má vlastní nízký limit a je identifikovatelný v auditu.

Backpressure je konečný a měřitelný. Nekonečné fronty v paměti jsou zakázány.

### 27.2 Kapacitní test

Před produkčním přijetím proběhne 30minutový stabilní test na očekávané zátěži a 10minutový test na 2× očekávané zátěži.

Test měří latenci, error rate, spotřebu CPU/RAM, počet DB spojení, audit throughput a chování při limitu.

Akceptace vyžaduje nulové cross-host chyby, nulové ztracené auditní události a žádný růst paměti bez návratu po skončení testu.

## 28. Observabilita, audit a alerting

Observabilita nesmí změnit bezpečnostní hranice. Payloady a tajemství se ve výchozím stavu nelogují; diagnostika používá metadata, klasifikace a korelační ID.

### 28.1 Minimální metriky

kcml_http_requests_total{host_class,route,status}

kcml_mcp_invocations_total{kcml,outcome,error_class}

kcml_mcp_invocation_duration_seconds{kcml}

kcml_auth_token_requests_total{outcome,error_class}

kcml_auth_failures_total{reason_class}

kcml_rate_limited_total{surface}

kcml_handler_active{kcml} a kcml_handler_queue_depth{kcml}

kcml_audit_write_failures_total, kcml_db_pool_in_use, kcml_readiness_status.

kcml_probe_results_total{kcml,probe,outcome} a kcml_probe_duration_seconds{kcml,probe}

kcml_operational_state{kcml,state}, kcml_state_transitions_total{kcml,from,to,reason_class}

kcml_monitoring_staleness_seconds{kcml,signal} a kcml_last_synthetic_success_timestamp{kcml}

kcml_registration_review_due_timestamp{kcml}, kcml_security_exception_expiry_timestamp{kcml}

kcml_contract_integrity_status{kcml} a kcml_artifact_integrity_status{kcml}

### 28.2 Povinné alerty

Alert obsahuje runbook link, build ID, prostředí a korelační příklady, ale ne tokeny ani payloady.

Health endpoint potvrzuje pouze proces; readiness ověřuje databázi, migrace, katalog, audit write probe a handler registry integrity.

## 29. Bezpečnostní základna a model hrozeb

Bezpečnostní návrh se posuzuje před prvním nasazením a při každé změně handleru s novým typem dat, síťovým přístupem nebo vedlejším účinkem.

Při registraci se provádí threat model konkrétního handleru včetně zneužití tool description, prompt injection přes externí data, exfiltrace, nečekaných vedlejších účinků a záměny prostředí.

Tool anotace a popis se považují za bezpečnostně významná metadata. Musejí projít lidskou kontrolou a nesmějí být dynamicky převzaty z nedůvěryhodné služby.

Integrita aktivního handleru, kontraktu, monitorovacího profilu a proxy routingu se průběžně porovnává s registrovanými digesty; neshoda je Critical a vede ke karanténě.

### 29.1 Povinné HTTP security headers

Admin: Content-Security-Policy bez unsafe-eval, frame-ancestors none, object-src none, Referrer-Policy no-referrer, X-Content-Type-Options nosniff, Permissions-Policy minimální.

MCP/auth JSON endpointy: Cache-Control no-store pro tokeny a citlivé odpovědi; žádné CORS wildcard. MCP může povolit pouze explicitně schválené klientské originy.

Server nesmí zveřejnit framework banner, interní stack trace, SQL chybu, absolutní cestu ani verzi závislosti mimo chráněný systémový detail.

### 29.2 Bezpečnostní gates

SAST, dependency vulnerability scan, secret scan, container scan a SBOM jsou povinné v CI.

Critical a High zranitelnosti v runtime závislostech blokují release, pokud není schválena časově omezená výjimka s kompenzačním opatřením.

Před produkcí proběhne penetrační test zaměřený na host isolation, OAuth client_credentials, admin session, CSRF, SSRF a audit fail-closed.

## 30. CI/CD, vydání, migrace a rollback

Release je reprodukovatelný a auditovatelný. Produkční server nesestavuje zdrojový kód a nestahuje nepřipnuté závislosti při nasazení.

### 30.1 Povinná CI pipeline

1. Instalace přes lockfile a ověření integrity závislostí.

2. Lint, TypeScript strict compile a architektonické dependency rules.

3. Jednotkové testy, databázové integrační testy a migrace na prázdnou i předchozí podporovanou verzi databáze.

4. MCP kontraktní, OAuth, cross-host, fail-closed a UI Playwright testy.

5. SAST, secret scan, dependency scan, SBOM a OCI image scan.

6. Sestavení image, podpis nebo důvěryhodný digest a publikace do řízeného registru.

7. Nasazení do staging, smoke test skutečných hostů, proxy config test a backup/restore rehearsal podle plánu.

8. Ruční schválení produkčního release se záznamem verze, migrací, rizik a rollback postupu.

### 30.2 Databázové migrace

Migrace jsou dopředné, verzované a idempotentně detekují již aplikovanou verzi. Ruční změny produkčního schématu jsou zakázány.

Změny používají expand/contract, pokud stará a nová verze musí krátce koexistovat. Destruktivní DROP probíhá až v samostatném pozdějším release.

Před migrací vznikne ověřená záloha. Migrace má timeout, lock strategy a odhad dopadu na sdílený server.

Při selhání migrace se nová aplikace nespustí ready. Automatické pokračování s částečně změněným schématem je zakázáno.

### 30.3 Produkční rollout a rollback

Rollout používá atomickou výměnu image/verze a readiness gate. Původní verze zůstává dostupná pro rychlý návrat, pokud je databázově kompatibilní.

Rollback aplikace nesmí automaticky vracet databázi. Databázový rollback je samostatný schválený postup s kontrolou ztráty dat.

Po release proběhne ověření admin loginu, token requestu, neznámého hostu, jednoho testovacího KCML (pokud existuje), auditu a metrik.

Release event se zapíše s build ID, operátorem, migracemi, časem a výsledkem smoke testů.

## 31. Zálohování, obnova, retence a incidenty

Záloha je platná pouze tehdy, pokud byla obnovena v izolovaném prostředí a prošla kontrolou integrity, migrací a minimálním aplikačním smoke testem.

### 31.1 Minimalizace dat

Vstupy a výstupy handleru se do auditu standardně neukládají. Ukládá se pouze schema-safe souhrn nebo hash, pokud to konkrétní kontrakt výslovně vyžaduje.

Zdrojová IP se ukládá pouze v bezpečnostním auditu a podle retenční politiky; UI ji zobrazí jen oprávněnému administrátorovi.

Smazání Kaja nebo admin účtu je logické; osobní popis lze anonymizovat po uplynutí retenční povinnosti, identifikátor a auditní vazba zůstávají.

### 31.2 Incident response

1. Detekovat a klasifikovat incident; přidělit incident ID a uchovat korelační data.

2. Omezit dopad vypnutím konkrétního KCML, revokací Kaja nebo izolací release, nikoli přesměrováním na jiný handler.

3. Uchovat důkazy, export relevantního auditu a build/proxy konfigurace; tokeny a klientská tajemství se neexportují.

4. Obnovit službu podle schváleného runbooku a ověřit všechny bezpečnostní invariants.

5. Vypracovat post-incident review s příčinou, dopadem, časovou osou a konkrétními nápravnými úkoly.

## 32. Rozšířená akceptační matice

Následující testy doplňují kapitoly 15 a 16. Každý test má automatizovatelný důkaz, očekávaný výsledek a odkaz na build. Kritické testy nelze nahradit ručním prohlášením.

### 32.1 Důkazní materiál

Machine-readable report testů s build ID a časem.

Export pokrytí, seznam migrací, SBOM a image digest.

Proxy config test log, TLS test a seznam aktivních hostů.

Protokol backup/restore testu a naměřené RPO/RTO.

Screenshoty pouze jako doplněk; nejsou náhradou automatických výsledků.

## 33. Povinné endpointy a HTTP kontrakt

### 33.1 Standardní response headers

X-Correlation-Id na každé odpovědi; klientskou hodnotu lze přijmout pouze po validaci formátu, jinak se vygeneruje nová.

Cache-Control: no-store na token endpointu, 401/403 a odpovědích s citlivými administrátorskými údaji.

Content-Type s explicitním charset tam, kde je relevantní; JSON je UTF-8.

Retry-After jen pro 429/503, pokud je interval založen na známém limitu nebo plánovaném stavu.

### 33.2 Chybový envelope mimo MCP

## 34. Konfigurace, tajemství a provozní parametry

Konfigurace je explicitní, validovaná při startu a rozdělená na necitlivé parametry a tajemství. Chybějící povinná hodnota způsobí ne-ready stav; aplikace nesmí použít tichý výchozí fallback.

### 34.1 Pravidla práce s tajemstvími

Tajemství se předávají přes root-readable secrets soubory, systemd credentials nebo schválený secret store; ne přes image, git ani shell history.

Proces běží pod samostatným UID a čte pouze své secrets. Admin UI ani handler worker nemá přístup ke všem klíčům, pokud je nepotřebuje.

Rotace klíčů má dual-key období s key ID, audit a test. Starý klíč se odstraní až po expiraci všech jím chráněných krátkodobých artefaktů.

Startup log smí uvést pouze názvy načtených konfiguračních položek a jejich bezpečné validace, nikdy hodnoty tajemství.

## 35. Předávací balíček a dokumentace

Dodavatel předá implementaci tak, aby ji jiný kvalifikovaný tým mohl sestavit, nasadit, auditovat, zálohovat a bezpečně provozovat bez skrytých znalostí původního autora.

### 35.1 Provozní runbooky

Vytvoření prvního administrátora a aktivace MFA.

Vytvoření, rotace, revokace a vyšetření kompromitace Kaja pověření.

Registrace nového KCML, test, aktivace, vypnutí a rollback handler verze.

Selhání databáze, audit writeru, certifikátu, proxy reloadu, diskové kapacity a externí závislosti handleru.

Obnova zálohy, ověření integrity a návrat DNS/proxy provozu.

Šablona a JSON/YAML Schema povinného mcp-registration manifestu včetně validačního CLI a příkladů pouze se syntetickými daty.

Registrační runbook od DRAFT po ACTIVE, změnovou revizi, recertifikaci, SUSPENDED, QUARANTINED a RETIRED.

Pro každý integrovaný MCP server exportovatelný registrační dossier: manifest, digesty, schválení, testy, SBOM, monitorovací profil, runbook, výjimky a auditní timeline.

Runbook centrálního monitoringu: probe, stavový algoritmus, stale data, alert routing, maintenance, automatická karanténa, návrat do provozu a ověření nerecyklace identity.

## 36. Konečná definice dokončení verze 1.2

Tato kapitola doplňuje kapitolu 18 a je konečným přejímacím pravidlem pro architektonicky doplněnou verzi.

Systém není dokončen, pokud splňuje pouze funkční obrazovky nebo ukázkové MCP volání. Dokončení vyžaduje prokázanou izolaci hostů, standardní MCP transport, bezpečné vydávání access tokenů, fail-closed audit, obnovitelnost dat a provozní předání.

Všechny požadavky kapitol 1–36 včetně registračních a monitorovacích gates jsou implementovány nebo je u nich výslovně uvedeno, že jsou mimo nultou verzi.

Všechny ACC testy a původní povinné implementační testy procházejí na přesném produkčním build artefaktu.

Produkční nasazení používá schválený OCI digest, aplikované migrace, validní proxy konfiguraci a TLS bez konfliktu s ostatními službami.

Je doložena jednorázovost client_secret, krátkodobost a audience binding access tokenů a okamžitá revokace.

Je doložen úspěšný backup/restore test, povinná registrace každého MCP serveru, centrální monitoring, stavový algoritmus, alerting, karanténa a incidentní runbooky.

Předávací balíček podle kapitoly 35 je úplný a bez tajemství.

Neexistuje veřejný společný MCP endpoint, cross-host fallback, skrytá autorizace pro interní síť, legacy transport ani demo režim.

Žádný MCP server není považován za dokončený ani integrovaný, pokud nemá schválenou neměnnou registrační revizi, úplný důkazní balík, bezpečný syntetický test, aktivní monitorovací profil, ověřený alert routing a prokazatelně fungující karanténu.

### Závěrečné pořadí přednosti požadavků:

1. Konkrétní bezpečnostní a protokolové pravidlo v kapitolách 19–36.

2. Konkrétní pravidlo v kapitolách 1–18.

3. Obecné technologické doporučení nebo výchozí nastavení frameworku.

Při skutečném rozporu, který nelze vyřešit tímto pořadím, se implementace zastaví a vznikne verzovaná změna SSOT. Dodavatel nesmí rozpor vyřešit vlastním fallbackem nebo tichým předpokladem.


## Table 1

| Položka | Hodnota |
| --- | --- |
| Dokument | Výrobní a akceptační specifikace nové aplikace |
| Cílové prostředí | Produkční Ubuntu server se sdíleným provozem více aplikací |
| Doména | hcasc.cz |
| Administrace | https://admin.hcasc.cz |
| Autorizační autorita | https://auth.hcasc.cz |
| Verze zadání | 1.3 |
| Stav | Závazné zadání pro implementaci – doplněno o povinnou registraci, integrační governance a centrální monitoring |
| Datum integrační revize | 12. 7. 2026 |
| Normativní MCP profil | MCP 2025-11-25, Streamable HTTP |
| Charakter revize | Zvýšení minimální kryptografické entropie klientských tajemství a opaque Bearer access tokenů z 256 na 512 bitů; doplnění povinných validačních a bezpečnostních testů. |


## Table 2

| Princip | Závazné pravidlo |
| --- | --- |
| Jedna adresa = jeden MCP server | KCML0001 je dostupný pouze na https://kcml0001.hcasc.cz/mcp. Na jiné subdoméně nesmí být nalezitelný ani volatelný. |
| Jeden MCP server = jeden nástroj | Odpověď tools/list obsahuje právě jednu funkci odpovídající kódu daného serveru. |
| Žádný společný veřejný endpoint | Nesmí existovat veřejná adresa, přes kterou lze volat více KCML funkcí nebo zvolit funkci parametrem cesty či těla požadavku. |
| Autorizace vždy | Každé volání, včetně volání ze stejného fyzického serveru, musí mít platný token a oprávnění ke konkrétnímu MCP serveru. |
| Fail-closed | Neznámý hostname, nástroj, token, oprávnění, vstup nebo výstup vždy skončí jednoznačnou chybou. |
| Bez fallbacků | Systém nesmí vybrat jiný server, jiný nástroj, upravit vstup, obejít autorizaci ani předstírat úspěch. |
| Bez recyklace identifikátorů | Kódy KCML ani identifikátory Kaja se nikdy znovu nepoužijí. |
| Tajemství jen jednou | Klientské tajemství se zobrazí pouze po vytvoření a nelze jej později získat z databáze ani UI. |


## Table 3

| Veřejná adresa | Úloha |
| --- | --- |
| https://admin.hcasc.cz | Administrátorské UI Správce MCP serverů. |
| https://auth.hcasc.cz | Autorizační autorita, metadata a případné standardní autorizační endpointy. |
| https://kcml0001.hcasc.cz/mcp | Samostatný MCP server KCML0001 s jediným nástrojem kcml0001. |
| https://kcml0002.hcasc.cz/mcp | Samostatný MCP server KCML0002 s jediným nástrojem kcml0002. |
| https://kcmlNNNN.hcasc.cz/mcp | Obecný tvar dalších samostatných MCP serverů. |


## Table 4

| Operace | Požadované chování |
| --- | --- |
| initialize | Vrátí identitu konkrétního MCP serveru, podporovanou verzi protokolu a jeho schopnosti. |
| tools/list | Vrátí právě jeden nástroj. Název nástroje je lowercase varianta kódu, například kcml0001. |
| tools/call | Přijme pouze název jediného nástroje náležejícího danému hostname a vstup odpovídající uloženému schématu. |
| Neznámý nástroj | Vrátí protokolovou chybu; nesmí hledat nástroj na jiné KCML subdoméně. |
| Vypnutý server | Odmítne inicializaci nebo volání provozní chybou 503 podle přesně definovaného kontraktu. |
| Neplatný výstup handleru | Volání skončí chybou, výsledek se neodešle jako úspěšný. |


## Table 5

| Operace | Pravidlo |
| --- | --- |
| Vytvořit | Administrátor zadá popis, dobu neurčitou nebo přesné datum a čas expirace a vybere povolené MCP servery. |
| Změnit popis | Povoleno a auditováno. |
| Změnit oprávnění | Povoleno po jednotlivých MCP serverech a auditováno. |
| Změnit expiraci | Zakázáno po vytvoření. |
| Zneplatnit | Nevratně ukončí použitelnost tokenu. |
| Smazat | Logické smazání; záznam a identifikátor zůstávají kvůli auditu. |
| Obnovit tajemství | Zakázáno. Náhradou je vytvoření nového tokenu a zneplatnění původního. |


## Table 6

| Stav | Výsledek |
| --- | --- |
| Chybějící nebo neplatný token | HTTP 401 a standardní autorizační metadata. |
| Platný token bez oprávnění | HTTP 403. |
| Vypnutý MCP server | HTTP 503. |
| Neznámý hostname | Odmítnutí bez přesměrování a bez odhalení katalogu. |
| Chybný vstup | Protokolová validační chyba; handler se nespustí. |
| Chyba handleru nebo výstupu | Jednoznačná chyba, žádný předstíraný úspěch. |


## Table 7

| Sekce | Obsah |
| --- | --- |
| MCP servery | Hlavní monitoring a katalog všech KCML serverů. |
| Pověření a tokeny | Vytváření a správa Kaja pověření, oprávnění a krátkodobých access tokenů. |
| Audit | Neměnný přehled administrativních a provozních událostí. |
| Systém | Stav aplikace, databáze, proxy integrace, front, časů a základních závislostí. |
| Účet | Bezpečnostní nastavení přihlášeného administrátora. |
| Registrace | Fronta nových a změnových registrací, validace, bezpečnostní schválení, důkazní balíky, recertifikace a vyřazení. |


## Table 8

| Sloupec | Význam |
| --- | --- |
| Kód | KCML0001 |
| Označení | Čitelný název serveru/funkce |
| Adresa | https://kcml0001.hcasc.cz/mcp |
| Kontrakt | Vstupní a výstupní schéma v rozbalitelném detailu |
| Stav | Zapnuto nebo vypnuto |
| Poslední úspěch | Datum a čas posledního úspěšného volání |
| Poslední neúspěch | Datum a čas posledního neúspěšného volání |
| Úspěšná volání | Kumulativní počet od vytvoření |
| Neautorizovaná volání | Kumulativní počet od vytvoření |
| Akce | Detail, Test, Zapnout/Vypnout |
| Registrační stav | DRAFT až RETIRED podle kapitoly 9; zobrazen odděleně od provozního stavu. |
| Provozní stav | HEALTHY, DEGRADED, UNHEALTHY, UNKNOWN, MAINTENANCE, QUARANTINED, DISABLED nebo RETIRED. |
| Verze a integrita | Contract version, handler version, build ID a zkrácené manifest/artifact digesty. |
| Vlastník a kritičnost | Odpovědný vlastník služby, provozní kontakt, kritičnost a termín recertifikace. |
| Poslední kontroly | Readiness, OAuth/MCP kontrakt, syntetický tools/call, integrita a certifikát. |
| SLO a alerty | p95, error rate, timeouty, fronta, aktivní alerty a odkaz na runbook. |


## Table 9

| Objekt | Povinná data |
| --- | --- |
| McpServer | Kód, název, popis, hostname, URL, tool name, stav zapnutí, registrační stav, aktivní contract/handler version, manifest/artifact digest, vlastníci, kritičnost, monitorovací profil a časové údaje. |
| Credential | Kaja identifikátor, Argon2id hash klientského tajemství, popis, stav, vytvoření, expirace nebo bez expirace. |
| Permission | Jednoznačná vazba Credential–McpServer. Wildcard oprávnění neexistuje. |
| Invocation | Každý pokus: čas, hostname, KCML kód, token ID nebo anonymní klasifikace, výsledek, chyba, latence, korelační ID. |
| FunctionStatistics | Počty úspěchů, neautorizovaných pokusů, poslední úspěch, poslední neúspěch. |
| AdminAccount | Přihlašovací identita, heslový hash, MFA konfigurace, stav. |
| AdminSession | Bezpečná serverová relace, expirace, revokace a auditní metadata. |
| AuditEvent | Neměnná administrativní nebo provozní událost včetně aktéra, objektu, předchozího a nového stavu bez tajemství. |
| AccessToken | Keyed hash, fingerprint, vazba na Credential a jediný resource/audience, čas vydání, krátká expirace, stav revokace a poslední použití. Plná hodnota se neukládá. |
| IntegrationRegistration | Neměnná revize registrace: manifest, digest, stav, předchozí revize, prostředí, vlastníci, schválení, výjimky, reviewDueAt a odkazy na důkazy. |
| IntegrationEvidence | Typ důkazu, hash, build/manifest/artifact vazba, výsledek, vznik, expirace, schvalovatel a bezpečný odkaz na uložený artefakt. |
| MonitoringProfile | Intervaly, timeouty, SLO, syntetický test, alert rules, auto-quarantine triggery, runbook a verzovaný digest profilu. |
| MonitorSample | Čas, KCML, probe type, outcome, latency, error class, build ID, correlation ID a stáří; bez payloadu a tajemství. |
| OperationalStateHistory | Vypočtený stav, předchozí stav, důvod, zdrojové kontroly, alert ID, začátek, konec a případná manuální akce. |


## Table 10

| Stav registrace | Závazný význam a povolený přechod |
| --- | --- |
| DRAFT | Rozpracovaný záznam. Nemá KCML kód ani veřejný routing; může být upravován vlastníkem integrace. |
| SUBMITTED | Balík byl odeslán ke kontrole a je uzamčen proti tiché změně. Každá oprava vytváří novou revizi manifestu. |
| VALIDATION_FAILED | Automatická validace zjistila chybějící, neplatné nebo vzájemně rozporné údaje. Nelze pokračovat bez opravy a nového podání. |
| SECURITY_REVIEW | Probíhá bezpečnostní, datová a provozní kontrola včetně důkazů sestavení, SBOM, síťové politiky a threat modelu. |
| APPROVED_FOR_DEPLOYMENT | Kontrakt a artefakt jsou schváleny pro řízené nasazení. Server ještě není veřejně aktivní. |
| REGISTERED_DISABLED | Byl atomicky přidělen KCML kód, hostname, katalogový záznam a monitorovací profil. Server je povinně vypnutý. |
| PROBATION | Produkční testy procházejí skutečnou HTTPS, OAuth a MCP cestou. Běžná klientská oprávnění se ještě nevydávají. |
| ACTIVE | Všechny gates jsou splněny, registrace je platná, server je explicitně zapnut a podléhá centrálnímu monitoringu. |
| SUSPENDED | Provoz byl administrativně pozastaven kvůli změně, incidentu, expirované revizi nebo nesplněnému SLO. Návrat vyžaduje doloženou nápravu. |
| QUARANTINED | Automatické nebo ruční bezpečnostní odpojení po porušení kritického invariantu. Nová volání jsou blokována a automatické znovuzapnutí je zakázáno. |
| REJECTED | Registrace byla zamítnuta. Důvod a rozhodnutí zůstávají v auditu; pokračování vyžaduje nový registrační balík. |
| RETIRED | Trvale vyřazený server. Kód, hostname a historie se nerecyklují a stav již nelze změnit zpět na ACTIVE. |


## Table 11

| Oblast | Povinný obsah |
| --- | --- |
| Identita a vlastnictví | Název, účel, odpovědný vlastník služby, technický vlastník, datový vlastník, provozní kontakt, eskalační kontakt a zastupitelnost. |
| Obchodní a provozní účel | Konkrétní scénáře použití, zakázaná použití, očekávaní klienti, kritičnost služby, provozní okna a dopad výpadku. |
| MCP kontrakt | Tool title/description, přesný inputSchema a outputSchema, příklady, chybové třídy, anotace vedlejších účinků a potvrzení kompatibility s profilem MCP 2025-11-25. |
| Vedlejší účinky | effectClass, destruktivnost, idempotence, transakční hranice, případné kompenzace, zákaz automatického retry a požadavek na potvrzení citlivé operace na straně klienta. |
| Data a soukromí | Klasifikace všech vstupů a výstupů, osobní a citlivé údaje, právní titul, minimalizace, retenční doby, redakce, lokalita dat a pravidla exportu. |
| Závislosti | Databáze, API, soubory, fronty a další služby, jejich vlastník, autentizace, timeout, očekávané SLO a chování při nedostupnosti. |
| Síťová politika | Explicitní odchozí allowlist FQDN/port/protokol, zákaz privátních a metadata adres, DNS re-resolution pravidla a potvrzení, že volný internet není potřebný. |
| Tajemství a oprávnění | Pouze názvy secret references, způsob rotace, minimální scope/role, databázová oprávnění, systémová identita a důkaz oddělení od admin a autorizačních tajemství. |
| Runtime a limity | CPU/RAM, timeout, maximální velikost vstupu a výstupu, souběh, fronta, rate limit, očekávaná propustnost a bezpečné ukončení. |
| Artefakt a supply chain | handlerKey, semantická verze, source commit, build ID, OCI/package digest, podpis, SBOM, licence, výsledky SAST, dependency, secret a image scanů. |
| Testovací kontrakt | Bezpečný syntetický vstup, očekávaný výstup/invarianty, izolace vedlejších účinků, testovací data, cleanup a důkaz, že test používá produkční handler. |
| Monitoring a SLO | Monitorovací profil, intervaly, timeouty, metriky, prahy, SLO, alert routing, runbook, maintenance režim a pravidla automatické karantény. |
| Nasazení a obnova | Pořadí nasazení, migrace, smoke test, rollback, kill switch, obnova závislostí, kompatibilita verzí a plán vyřazení. |
| Dokumentace | Uživatelský popis nástroje, integrační příklady, katalog chyb, provozní runbook, incidentní postup, troubleshooting a kontakty. |
| Schválení | Jmenovité schválení vlastníka služby, architekta, bezpečnosti, datového vlastníka a provozu podle rizikové třídy. |


## Table 12

| Skupina polí | Minimální povinná pole a pravidla |
| --- | --- |
| Verze a identita | schemaVersion, registrationRevision, environment, handlerKey, handlerVersion, displayName, businessPurpose; KCML/hostname/toolName jsou výstup centrální registrace, nikoli vstup. |
| Vlastnictví | serviceOwner, technicalOwner, dataOwner, operationsContact, escalationContact, criticality, reviewIntervalDays. |
| Protokol | protocolVersion=2025-11-25, transport=streamable-http, capabilities=[tools], inputSchema, outputSchema, schemaDigest, errorCatalog. |
| Tool metadata | title, description, readOnlyHint, destructiveHint, idempotentHint, openWorldHint a taskSupport=forbidden; hodnoty musí odpovídat effectClass a skutečnému chování. |
| Provozní chování | effectClass, timeoutMs, maxConcurrency, requestMaxBytes, responseMaxBytes, rateLimit, shutdownPolicy, idempotencyPolicy, retryPolicy. |
| Závislosti a síť | dependencies[], networkPolicy, dnsPolicy, outboundAllowlist, databaseRole, filesystemPolicy a zakázané cílové sítě. |
| Tajemství | secretRefs[], rotationOwner, rotationProcedureRef; manifest nesmí obsahovat žádnou tajnou hodnotu ani ukázkové produkční pověření. |
| Data | inputDataClassification, outputDataClassification, containsPersonalData, retentionPolicy, loggingPolicy, redactionFields a exportRestrictions. |
| Testování | testContract, expectedInvariants, cleanupPolicy, negativeCases, loadProfile, testDataOwner a testCredentialScope. |
| Monitoring | monitoringProfile, sloTargets, probeIntervals, alertRules, runbookRef, maintenancePolicy a autoQuarantineTriggers. |
| Artefakt | sourceCommit, buildId, artifactDigest, signatureRef, sbomDigest, dependencyScanRef, sastRef a licenseReportRef. |
| Změna a obnova | changeClass, migrationRef, rollbackRef, compatibilityWindow, decommissionRef, previousApprovedRevision a reviewDueAt. |


## Table 13

| Kontrola | Výchozí závazné provedení |
| --- | --- |
| Process liveness | Interní kontrola každých 30 s, timeout 3 s. Potvrzuje pouze běh procesu; sama nikdy neznamená HEALTHY. |
| Readiness | Každých 60 s, timeout 5 s. Ověří databázi, migrace, katalog, audit write probe, registry handleru a nutné lokální závislosti. |
| Veřejný routing a TLS | Každých 5 min přes veřejnou produkční HTTPS adresu. Ověří DNS, certifikát, SNI, Host a zákaz přesměrování na jiný server. |
| OAuth a MCP kontrakt | Každých 5 min systémovým testovacím Kaja pověřením s oprávněním pouze ke konkrétnímu KCML: token, initialize, initialized a tools/list. |
| Syntetické tools/call | Každých 15 min nebo častěji podle kritičnosti. Použije registrovaný testContract, produkční handler a izolovaná testovací data; automatický retry je zakázán. |
| Metriky provozu | Agregace nejvýše po 60 s: počet volání, outcome, p50/p95/p99, timeouty, auth odmítnutí, schema chyby, aktivní volání, fronta, rate limit a resource saturation. |
| Závislosti | Stav se odvozuje z reálných handler spanů a bezpečných aktivních kontrol. Self-report bez důkazu není dostačující. |
| Integrita konfigurace | Při startu, nasazení a nejméně každých 5 min se ověří aktivní contract digest, handler version, artefakt digest, monitorovací profil a očekávaný routing. |
| Certifikát a čas | Nejméně denně se kontroluje expirace TLS, chain, hostname coverage a synchronizace času; varování 30 dnů a high alert 7 dnů před expirací. |
| Recertifikace | Denně se vyhodnotí reviewDueAt, expirace bezpečnostní výjimky, stáří skenů, vlastník a dostupnost runbooku. |


## Table 14

| Provozní stav | Deterministické pravidlo |
| --- | --- |
| DISABLED | Server je administrativně vypnutý nebo v registračním stavu, který nepovoluje provoz. Syntetické funkční volání se nespouští, ale integrita a certifikát se dále sledují. |
| UNKNOWN | Po registraci dosud není dostatek výsledků nebo je poslední povinná telemetrie starší než dvojnásobek svého intervalu. UNKNOWN se nesmí zobrazit jako zelený stav. |
| HEALTHY | Readiness, veřejný routing, OAuth/MCP kontrakt a poslední syntetický tools/call jsou úspěšné; telemetrie není stale; SLO a bezpečnostní kontroly jsou v limitu. |
| DEGRADED | Jedna nekritická kontrola selhala, p95 nebo error rate překračuje varovný práh, závislost je degradovaná nebo se blíží expirace revize/certifikátu. Server může zůstat dostupný, ale vzniká alert. |
| UNHEALTHY | Tři po sobě jdoucí povinné probe neuspěly, readiness neprochází, není úspěšný syntetický test déle než 30 min, nebo 5xx/timeout překročí schválený high práh po 5 min. |
| MAINTENANCE | Časově omezený ruční režim s důvodem, vlastníkem a koncem. Nezakrývá bezpečnostní chybu, nezastaví audit a po expiraci se automaticky zruší. |
| QUARANTINED | Okamžitě při cross-host porušení, přijetí chybné audience, autorizačním bypassu, neshodě artefakt/contract digestu, neautorizované změně routingu nebo jiném kritickém bezpečnostním invariantu. |
| RETIRED | Server byl trvale vyřazen. Monitoring zachovává kontrolu, že hostname není přesměrován na jinou KCML funkci a identifikátor nebyl znovu použit. |


## Table 15

| Položka UI | Požadované chování |
| --- | --- |
| Identita | KCML kód, název, přesný hostname, tool name, registrační revize, contract version, handler version, build ID a zkrácený artefakt digest. |
| Vlastnictví | Vlastník služby, technický vlastník, provozní kontakt, kritičnost, odkaz na runbook a datum příští recertifikace. |
| Stavy | Registrační stav, zapnuto/vypnuto a provozní stav se zobrazují odděleně, s časem poslední změny a vysvětlením důvodu. |
| Kontroly | Čas a výsledek liveness, readiness, routing/TLS, OAuth/MCP kontraktu, syntetického tools/call, integrity a závislostí. |
| Provoz | Počty, error rate, auth odmítnutí, p50/p95/p99, timeouty, aktivní volání, fronta, rate limit, poslední úspěch a neúspěch. |
| Bezpečnost | Stav posledních skenů, aktivní výjimky a expirace, data classification, síťová politika a poslední security review bez zobrazení tajemství. |
| Důkazy | Čitelný detail manifestu, hash, schválení, testovací protokoly, změnová historie a auditní timeline. Původní verze se nesmějí přepsat. |
| Akce | Test, zapnout, vypnout, maintenance, suspendovat, karanténa, podat novou revizi a vyřadit. Každá destruktivní akce vyžaduje přesný kód, důvod, reautentizaci a audit. |
| Filtry | Podle registračního/provozního stavu, vlastníka, kritičnosti, blížící se recertifikace, aktivního alertu, verze a posledního úspěšného testu. |
| Aktualizace | Stav po výsledku probe nebo změně se v UI projeví nejpozději do 60 s; UI vždy uvádí stáří dat a nesmí zobrazit stale stav jako aktuální. |


## Table 16

| Závažnost | Povinné integrační alerty a reakce |
| --- | --- |
| Critical | Cross-host porušení, chybná audience přijatá jako platná, autorizační bypass, neshoda artefaktu nebo kontraktu, neautorizovaný routing, selhání auditu při citlivé operaci. Okamžitá karanténa a eskalace bezpečnosti/provozu. |
| High | UNHEALTHY déle než 5 min, 5xx nebo timeouty nad schválený práh 5 min, syntetický test bez úspěchu 30 min, neplatný certifikát, kritická závislost nedostupná nebo expirovaná bezpečnostní výjimka. |
| Warning | DEGRADED déle než 15 min, p95 mimo SLO 15 min, fronta nebo resource saturation nad 80 %, certifikát do 30 dnů, recertifikace do 30 dnů nebo neaktuální scan. |
| Info | Nasazení, aktivace, maintenance, změna monitorovacího profilu, úspěšný návrat z incidentu a plánované vyřazení. |


## Table 17

| Událost | Povinné auditní údaje |
| --- | --- |
| Volání MCP | Čas, hostname, KCML kód, výsledek, status, klasifikace chyby, latence, korelační ID, identifikátor Kaja pokud jej lze bezpečně určit. |
| Neautorizovaný pokus | Důvod odmítnutí bez uložení tokenu, hostname, čas, zdrojové síťové metadata dle retenční politiky. |
| Vytvoření tokenu | Kaja ID, administrátor, expirace, počáteční seznam oprávnění; bez tajné hodnoty. |
| Změna oprávnění | Předchozí a nový seznam KCML kódů. |
| Revokace/smazání | Kaja ID, administrátor, čas, důvod pokud byl zadán. |
| Zapnutí/vypnutí | KCML kód, předchozí a nový stav, administrátor. |
| Test | KCML kód, výsledek všech kontrol, latence a korelační ID. |
| Přihlášení administrátora | Úspěch/neúspěch, účet, čas a bezpečně omezená síťová metadata. |
| Registrace/revize | KCML nebo kandidát, stavový přechod, manifest/artifact digest, aktér, důvod, schválení a odkazy na důkazy. |
| Monitoring stav | Předchozí a nový provozní stav, rozhodující probe/metrika, čas, build ID, alert a korelační ID. |
| Karanténa/maintenance | Spouštěč, vlastník, důvod, začátek, expirace, zneplatnění tokenů a podmínky návratu. |
| Recertifikace/vyřazení | Rozsah kontroly, schvalovatelé, výjimky, datum další revize a potvrzení nerecyklace identity. |


## Table 18

| Situace | Závazné chování |
| --- | --- |
| Subdoména nemá registrovaný KCML server | Odmítnout. Bez přesměrování na administraci nebo jinou funkci. |
| Kód existuje, ale server je vypnutý | Vrátit 503 a auditovat pokus. |
| Klient zavolá jiný tool name | Vrátit chybu neznámého nástroje; nesmí se provést žádný handler. |
| Token je platný pro KCML0002, volá KCML0001 | Vrátit 403. |
| Token je expirovaný nebo zneplatněný | Vrátit 401. |
| Vstup neodpovídá schématu | Vrátit validační chybu před spuštěním handleru. |
| Handler překročí timeout | Ukončit volání podle bezpečné politiky, vrátit chybu a auditovat timeout. |
| Handler vrátí neplatný výstup | Nevydat úspěšnou odpověď. |
| Databáze není dostupná | MCP volání se neprovede; žádná cache nesmí obejít autorizaci. |
| Audit nelze bezpečně zapsat | Změnové administrativní operace a citlivá volání se odmítnou fail-closed. |
| Duplicitní nebo opakovaný request | Systém používá korelační a případně idempotency pravidla konkrétní funkce; nesmí svévolně opakovat handler. |


## Table 19

| Oblast | Požadovaný stav v nulté verzi |
| --- | --- |
| Přihlášení administrátora | Plně funkční včetně MFA, session, ochrany a auditu. |
| Přehled MCP serverů | Prázdný stav bez smyšlených položek. |
| Pověření a tokeny | Plně funkční vytváření Kaja pověření, jednorázové zobrazení client_secret, expirace, revokace, smazání, oprávnění a token endpoint; seznam funkcí je zatím prázdný. |
| Audit | Plně funkční. |
| Systémový stav | Plně funkční. |
| Datový model a migrace | Připravené pro registraci prvního KCML serveru. |
| MCP routing | Neznámé kcml subdomény jsou bezpečně odmítány. |
| Monitoring funkcí | Zobrazuje prázdný stav, nikoli nulové testovací záznamy. |


## Table 20

| Oblast | Podmínka přijetí |
| --- | --- |
| Izolace adres | KCML0001 lze zjistit a zavolat pouze na kcml0001.hcasc.cz. Pokusy přes kcml0002, admin, auth nebo společnou adresu selžou. |
| Jeden nástroj | tools/list na každé KCML adrese vrací právě jeden odpovídající nástroj. |
| Autorizace | Stejný platný token funguje interně i externě; neplatný nebo neoprávněný token je vždy odmítnut. |
| Oprávnění | Token s přístupem ke KCML0001 nemá přístup ke KCML0002, dokud mu není explicitně přidělen. |
| Jednorázové tajemství | Client_secret nelze po zavření obrazovky znovu zobrazit ani získat z databázového výpisu. |
| Neměnná expirace | Po vytvoření neexistuje API ani UI operace pro změnu expirace. |
| Bez recyklace | Smazané Kaja a KCML identifikátory se nikdy znovu nevydají. |
| Vypnutí | Vypnutý MCP server není dostupný ani platně autorizovanému klientovi. |
| Test | Tlačítko Test ověří skutečnou produkční cestu a uloží auditní výsledek. |
| Monitoring | Počty a poslední časy odpovídají skutečným transakčně zaznamenaným voláním a přežijí restart. |
| Sdílený server | Nasazení nepoškodí routy, porty, certifikáty ani dostupnost ostatních aplikací. |
| Fail-closed | Při chybě databáze, autorizace, schématu nebo handleru není provedena alternativní akce. |
| Nultá verze | Po čistém nasazení je katalog prázdný, ale tokeny, administrace, audit a systémový dohled jsou plně funkční. |
| Povinná registrace | Bez dokončené registrační revize nelze přidělit aktivní routing, vydat token, spustit produkční Test ani server zapnout. |
| Integrační balík | Manifest, dokumentace, bezpečnostní důkazy, SBOM, artefakt digest, testContract, monitoring profile a schválení jsou úplné a vzájemně konzistentní. |
| Centrální monitoring | Každý aktivní KCML má liveness, readiness, veřejný routing/TLS, OAuth/MCP a syntetický tools/call probe; stav se zobrazí do 60 s. |
| Stavový algoritmus | HEALTHY/DEGRADED/UNHEALTHY/UNKNOWN/QUARANTINED se vypočítají deterministicky a stale nebo chybějící data nejsou zobrazena jako HEALTHY. |
| Bezpečnostní karanténa | Cross-host, audience bypass nebo digest drift okamžitě blokuje nové tokeny a volání; návrat není automatický. |
| Změnové řízení | Materiální změna vytváří novou neměnnou registrační revizi a aktivace vyžaduje testy a schválení přesné verze. |
| Recertifikace | Systém upozorňuje na reviewDueAt, blokuje aktivaci expirované revize a po stanoveném prodlení přechází do SUSPENDED. |


## Table 21

| Položka | Závazné rozhodnutí |
| --- | --- |
| Normativní verze MCP | MCP 2025-11-25. Automatický přechod na novější verzi je zakázán; vyžaduje změnu SSOT, regresní testy a řízené vydání. |
| Transport | Pouze vzdálený Streamable HTTP přes HTTPS na přesné cestě /mcp. Veřejný stdio transport neexistuje. |
| Legacy HTTP+SSE | Není podporován. Neexistuje samostatný /sse ani legacy message endpoint. |
| JSON-RPC | JSON-RPC 2.0, UTF-8, jedno JSON-RPC sdělení v těle jednoho HTTP POST požadavku. |
| Schémata nástrojů | JSON Schema 2020-12. Každé schéma má explicitní additionalProperties; implicitní přijímání neznámých polí je zakázáno. |
| Podporované serverové schopnosti | Pouze tools. Resources, prompts, sampling, elicitation, roots a server-initiated requests nejsou v nulté verzi nabízeny. |
| Relace | Nultá verze je stateless a nevydává MCP-Session-Id. GET /mcp a DELETE /mcp vracejí 405. |
| Streaming | Odpovědi jsou application/json. SSE streamování není v nulté verzi zapnuto. |


## Table 22

| Vrstva | Závazný výsledek |
| --- | --- |
| Neplatný HTTP request | Příslušný 4xx/5xx stav, obecné tělo bez interních detailů, korelační ID v hlavičce. |
| Neplatný JSON | HTTP 400 a JSON-RPC Parse error, pokud lze bezpečně vrátit protokolové tělo. |
| Neplatný JSON-RPC envelope | HTTP 400 a JSON-RPC Invalid Request. |
| Neznámá MCP metoda | HTTP 200 s JSON-RPC Method not found; žádný fallback. |
| Neplatné params nebo vstupní schéma | HTTP 200 s JSON-RPC validační chybou; handler se nespustí. |
| Chyba nástroje po jeho spuštění | HTTP 200 s výsledkem tools/call označeným isError=true nebo s protokolovou chybou podle klasifikace; nikdy falešný úspěch. |
| Chyba autorizace před MCP zpracováním | HTTP 401 nebo 403 bez odhalení katalogu či cizích oprávnění. |
| Vypnutý server nebo nedostupná kritická závislost | HTTP 503, Retry-After pouze pokud je znám bezpečný interval. |


## Table 23

| Komponenta | Odpovědnost a zakázané přesahy |
| --- | --- |
| Edge / reverse proxy | TLS terminace, přesný hostname routing, limity těla a spojení. Neprovádí autorizaci podle KCML oprávnění a nevybírá handler. |
| Host Router | Validuje efektivní hostname a cestu, načte jediný McpServer z katalogu. Nesmí vyhledávat podle tool name ani parametru požadavku. |
| MCP Protocol Adapter | Parse JSON-RPC/MCP, lifecycle, tools/list a tools/call. Neobsahuje obchodní logiku handlerů. |
| Authorization Service | Vydání a validace access tokenu, audience/resource, oprávnění, revokace a audit. |
| Catalog Service | Čtení verzovaných definic McpServer, schémat, limitů a aktivní verze handleru. |
| Invocation Orchestrator | Předzápis auditu, validace vstupu, spuštění handleru, timeout, validace výstupu a finalizace statistik. |
| Handler Worker Pool | Spouští pouze build-time registrované handlery. Nemá přístup k administrátorským session ani k plným klientským tajemstvím. |
| Admin Backend | Server-side UI API, účty, MFA, katalog, pověření, testy a systémový stav. Není dostupný z KCML hostů. |
| Audit/Statistics Writer | Transakčně zapisuje neměnné události a agregované čítače; neposkytuje možnost UPDATE/DELETE auditních řádků aplikaci. |
| PostgreSQL | Jediný autoritativní stav katalogu, pověření, access tokenů, oprávnění, auditu a statistik. |


## Table 24

| Oblast | Závazný profil |
| --- | --- |
| Backend runtime | Node.js 24 LTS, TypeScript v režimu strict, ESM. Verze jsou přesně připnuté v lockfile a OCI image digestu. |
| HTTP framework | Fastify 5 nebo rovnocenný framework schválený změnovým řízením; centrální schema validation a jednotný error handler. |
| MCP | Oficiální TypeScript MCP SDK kompatibilní s 2025-11-25; wrapper zakáže nepoužívané capabilities. |
| Databáze | PostgreSQL 16 nebo novější podporovaná major verze; SQL migrace, explicitní constraints, transakce a row-level locking tam, kde je nutný. |
| Admin UI | React 19 + TypeScript, server-side session; žádné ukládání tajemství, tokenů nebo session v localStorage/sessionStorage. |
| Testy | Vitest/Jest pro jednotkové a integrační testy, Playwright pro UI, samostatné kontraktní MCP a bezpečnostní testy. |
| Observabilita | OpenTelemetry kompatibilní traces/metrics/log correlation; export nesmí obsahovat tajemství ani plné payloady ve výchozím stavu. |
| Artefakt | Reprodukovatelný OCI image bez vývojových závislostí, běh jako non-root, read-only root filesystem kde to provoz dovolí. |


## Table 25

| Adresář/balíček | Obsah |
| --- | --- |
| apps/server | Admin, auth a MCP HTTP entrypointy, host router, dependency injection a startup checks. |
| apps/admin-ui | Administrátorské rozhraní a statická distribuce. |
| packages/domain | Doménové modely, invariants, error classes a use cases bez závislosti na HTTP. |
| packages/mcp-adapter | MCP lifecycle, transport profile a mapování chyb. |
| packages/auth | Kaja credentials, OAuth client_credentials, access tokeny, audience a permissions. |
| packages/handlers | Handler SDK, registry manifesty a jednotlivé implementační moduly. |
| packages/persistence | SQL, repositories, transakce a migrace. |
| packages/observability | Audit, metrics, traces, redaction a correlation. |
| tests/contract | Cross-host, MCP, OAuth, proxy a fail-closed testy. |
| deploy | OCI build, systemd/compose manifest, proxy include, migrace, backup a rollback skripty. |


## Table 26

| Entita | Minimální klíče a constraints |
| --- | --- |
| mcp_server | id UUID, kcml_number BIGINT UNIQUE, code CITEXT UNIQUE, hostname CITEXT UNIQUE, tool_name CITEXT UNIQUE, status, contract_version, handler_key, lock_version. |
| mcp_contract | server_id, version, input_schema JSONB, output_schema JSONB, test_vector JSONB, effect_class, limits; UNIQUE(server_id, version). Staré verze se nemažou. |
| credential | id UUID, kaja_number BIGINT UNIQUE, public_id CITEXT UNIQUE, secret_hash, status, description, created_at, revoked_at, deleted_at, lock_version. |
| permission | credential_id + server_id jako složený UNIQUE/PRIMARY KEY; žádný NULL ani wildcard server. |
| access_token | lookup_digest BYTEA UNIQUE, fingerprint, credential_id, server_id/resource, issued_at, expires_at, revoked_at, last_used_at. |
| invocation | id UUID, correlation_id UUID UNIQUE, server_id nullable pouze pro neznámý host, credential_id nullable, outcome, error_class, latency_ms, timestamps. |
| audit_event | id BIGINT monotonic, event_type, actor_type/id, object_type/id, before_json, after_json, correlation_id, created_at; append-only. |
| function_statistics | server_id PRIMARY KEY, success_count, unauthorized_count, failure_count, last_success_at, last_failure_at; žádné záporné hodnoty. |
| admin_account/session | Normalizované účty, MFA stav, password hash, session hash, expirace, revokace a bezpečnostní metadata. |


## Table 27

| Povinné pole manifestu | Význam |
| --- | --- |
| handlerKey a version | Neměnný technický identifikátor a semantická verze implementace. |
| displayName a description | Text pro administraci a MCP tool description bez citlivých interních detailů. |
| inputSchema/outputSchema | Uzamčené JSON Schema 2020-12 včetně examples a limitů. |
| effectClass | PURE, READ_ONLY, IDEMPOTENT_WRITE nebo NON_IDEMPOTENT_WRITE. |
| timeoutMs | Výchozí a maximální timeout; maximum 120 000 ms bez změny SSOT. |
| maxConcurrency | Limit souběhu konkrétního handleru. |
| networkPolicy | Explicitní allowlist hostů/portů nebo NONE. Volný internet je zakázán. |
| testContract | Bezpečný testovací vstup, očekávané invariants a pravidlo izolace vedlejších účinků. |
| shutdownPolicy | Chování při vypnutí serveru a ukončení procesu: dokončit, kooperativně zrušit nebo bezpečně odmítnout. |
| dataClassification | Klasifikace vstupu/výstupu a pravidla logování/redakce. |
| ownership a criticality | Vlastník služby, technický vlastník, provozní kontakt, datový vlastník, kritičnost a maximální interval recertifikace. |
| artifactIdentity | sourceCommit, buildId, artifactDigest, signatureRef, sbomDigest a vazba na schválenou registrační revizi. |
| dependencies a secretRefs | Deklarované závislosti, minimální oprávnění a pouze odkazy na tajemství; žádná tajná hodnota v manifestu. |
| monitoringProfile | Probe, SLO, prahy, synthetic test, alert routing, auto-quarantine a runbook podle kapitoly 9. |
| toolAnnotations | readOnlyHint, destructiveHint, idempotentHint, openWorldHint a taskSupport; musí odpovídat effectClass. |
| reviewDueAt a changeClass | Termín nové certifikace a klasifikace změny určující rozsah opakovaných testů a schválení. |


## Table 28

| Prvek | Závazné chování |
| --- | --- |
| client_id | Veřejný identifikátor KajaNNNN; stabilní, nerecyklovatelný. |
| client_secret | Nejméně 512 bitů skutečné kryptografické entropie, generováno CSPRNG, zobrazeno jednou, uloženo pouze jako Argon2id hash. Nesmí být přijato na /mcp. |
| Grant | OAuth 2.0 client_credentials pro strojové klienty. Authorization code, password grant, implicit grant a refresh tokeny nejsou v nulté verzi podporovány. |
| Token endpoint | POST https://auth.hcasc.cz/oauth/token, pouze application/x-www-form-urlencoded, klientská autentizace client_secret_basic. |
| resource | Povinný přesný kanonický URI cílového MCP serveru včetně /mcp. Jeden request vydá token pro jeden resource. |
| Access token | Opaque Bearer, nejméně 512 bitů skutečné kryptografické entropie, generováno CSPRNG, výchozí TTL 15 minut, maximum 60 minut. Bez refresh tokenu. |
| Audience | Přesně resource z token requestu. Token pro KCML0001 nelze přijmout na KCML0002 ani na admin/auth hostu. |
| Scope | Minimálně mcp:invoke; efektivní oprávnění je průnik scope, permission Credential–McpServer a aktivního stavu serveru. |
| Revokace | Revokace nebo logické smazání Kaja okamžitě zneplatní i dosud neexpirované access tokeny. |


## Table 29

| Operace | UI a backend pravidlo |
| --- | --- |
| Přidání/odebrání oprávnění | Zobrazí přesný rozdíl, vyžaduje potvrzení a lock_version. Odebrání zneplatní existující access tokeny pro daný resource. |
| Revokace Kaja | Nevratná, vyžaduje reautentizaci a povinný důvod. Aktivní tokeny jsou okamžitě neplatné. |
| Logické smazání | Dostupné pouze po revokaci; záznam zůstává v auditu a seznamech s filtrem. |
| Zapnutí/vypnutí MCP | Potvrzení opsáním KCML kódu. Vypnutí je okamžité pro nové tokeny i volání. |
| Aktivace handler verze | Zobrazí předchozí/novou verzi, výsledek posledního testu a rizikovou třídu; bez úspěšného testu nelze aktivovat. |
| Správa MFA | Změna nebo reset vyžaduje reautentizaci a audit; recovery postup nesmí obejít druhý faktor bez řízeného provozního zásahu. |


## Table 30

| Vrstva | Závazné nastavení |
| --- | --- |
| DNS | admin, auth a řízený kcml wildcard nebo explicitní záznamy. Neznámé subdomény se na aplikační vrstvě odmítnou. |
| TLS | TLS 1.2 a 1.3, moderní cipher suite, automatická obnova certifikátů s přednasazovacím testem. HSTS pouze po ověření všech subdomén. |
| HTTP → HTTPS | 301/308 pouze na stejný hostname a stejnou cestu. Nikdy na admin, auth ani jiný KCML host. |
| Proxy route | Samostatné bloky pro admin.hcasc.cz, auth.hcasc.cz a kcml host pattern. Default server vrací 444/404 bez aplikace. |
| Forwarded headers | Proxy přepisuje Host/X-Forwarded-Host/X-Forwarded-Proto a odstraňuje hodnoty klienta. Aplikace důvěřuje pouze IP proxy. |
| Interní port | Aplikace poslouchá na loopback nebo privátní container network; není přímo dostupná z internetu. |
| Request limits | Limit těla, headerů, času čtení a počtu spojení se vynucuje v proxy i aplikaci. |


## Table 31

| Metrika/limit | Požadavek |
| --- | --- |
| Dostupnost řídicí vrstvy | Měsíční SLO 99,5 % pro admin, auth a MCP gateway; plánovaná údržba je evidována odděleně. |
| Režie gateway | p95 do 100 ms a p99 do 250 ms bez času handleru při běžné zátěži a dostupné databázi. |
| Token endpoint | p95 do 300 ms včetně Argon2id ověření; musí být dimenzován tak, aby ochrana hesla nezpůsobila vyčerpání workerů. |
| Velikost requestu | Výchozí maximum 1 MiB; handler může mít nižší limit. Vyšší limit vyžaduje explicitní manifest a bezpečnostní revizi. |
| Velikost response | Výchozí maximum 4 MiB; po překročení se výsledek odmítne a nezapisuje se celý do logu. |
| Timeout | Gateway 130 s, handler nejvýše 120 s, externí dependency timeouty kratší než handler deadline. |
| Souběh | Výchozí 100 aktivních MCP požadavků na instanci a 20 na handler; konkrétní manifest může limit snížit. |
| Rate limit MCP | Výchozí 60 požadavků/min na Kaja a server, burst 20; oddělený limit pro neautorizované IP. |
| Rate limit auth | Výchozí 10 neúspěšných token requestů/min na IP a 10/min na client_id; úspěšné requesty mají samostatný limit. |
| Start | Readiness do 60 s; pokud migrace nebo katalogový self-check selže, instance nesmí být ready. |


## Table 32

| Signál | Povinné položky |
| --- | --- |
| Structured log | timestamp UTC, level, service, build_id, correlation_id, host, route, KCML, Kaja public ID/fingerprint, outcome, error_class, latency_ms. |
| Trace | Proxy/gateway, auth, catalog, validation, handler, external dependency a persistence spans; bez tokenu a plného payloadu. |
| Metrics | HTTP/MCP request count, latency histogram, auth failures, handler outcomes, timeouty, rate limits, DB pool, audit failures, readiness. |
| Audit | Neměnné doménové události s aktérem, objektem, before/after a důvodem; citlivé hodnoty redigované. |


## Table 33

| Závažnost | Podmínka |
| --- | --- |
| Critical | Audit nelze zapsat; databáze nedostupná; cross-host invariant porušen; token přijat pro chybnou audience; opakovaně selhává obnova zálohy. |
| High | 5xx > 5 % po 5 minut, prudký nárůst 401/403, handler timeouty nad limit, disk > 85 %, certifikát expirovává do 7 dnů. |
| Warning | p95 překračuje SLO 15 minut, DB pool > 80 %, fronta handleru roste, certifikát expirovává do 30 dnů. |
| Critical – integrace | Cross-host, audience bypass, contract/artifact digest drift, neautorizovaný routing nebo monitorovací důkaz bezpečnostního invariantu; povinná automatická karanténa. |
| High – integrace | Bez úspěšného syntetického testu 30 min, stale povinná telemetrie, expirovaná bezpečnostní výjimka nebo registrační revize po grace period. |


## Table 34

| Hrozba | Povinné zmírnění |
| --- | --- |
| Host confusion / cross-host | Exact host mapping, audience binding, unikátní hostname constraint, cross-host testy a žádný výběr podle tool name. |
| DNS rebinding / malicious Origin | Origin allowlist, efektivní host pouze z důvěryhodné proxy, interní bind a odmítnutí privátních cílových IP v outbound klientu. |
| Token theft | Krátké access token TTL, žádné logování, HTTPS, keyed digest, okamžitá revokace, redakce a omezené telemetry. |
| Credential stuffing / brute force | Argon2id, rate limit, progresivní zpoždění, obecné chyby a alerting. |
| SSRF v handleru | Centrální outbound klient, allowlist, DNS re-resolution kontrola, blokace loopback/link-local/metadata sítí a limity odpovědi. |
| Injection | Schema validation, parametrizované SQL, zákaz shell=true a zákaz skládání příkazů z uživatelských dat. |
| Supply chain | Lockfile, SBOM, dependency review, image scanning, podpis/digest a zákaz postinstall skriptů bez schválení. |
| Admin session hijacking | Secure HttpOnly SameSite cookie, rotace session po login/MFA, CSRF, CSP, frame-ancestors none a reautentizace. |
| Audit tampering | Append-only role, oddělená DB oprávnění, pravidelné exporty/otisky a alert na selhání. |
| Resource exhaustion | Dvojité limity proxy/aplikace, bounded queues, timeouty, concurrency a response size limit. |


## Table 35

| Oblast | Závazný požadavek |
| --- | --- |
| Databázová záloha | Denní plná záloha a průběžné WAL/PITR, pokud to provozní platforma umožňuje. Šifrování při přenosu i uložení. |
| RPO | Maximálně 24 hodin bez PITR; cílově 15 minut s PITR. |
| RTO | Obnova základní služby do 4 hodin od rozhodnutí o disaster recovery. |
| Retence záloh | Denní 14 dní, týdenní 8 týdnů, měsíční 12 měsíců; přístup pouze provozní roli. |
| Test obnovy | Nejméně čtvrtletně, s protokolem výsledku, doby obnovy a nalezených odchylek. |
| Auditní data | Administrativní a bezpečnostní audit minimálně 3 roky; invocation detail 12 měsíců; agregované statistiky po dobu existence serveru. |
| Provozní logy | Standardně 30 dní online a 90 dní archivně, pokud bezpečnostní politika nevyžaduje déle. |


## Table 36

| ID | Akceptační scénář |
| --- | --- |
| ACC-PROTO-01 | initialize, initialized, tools/list a tools/call odpovídají MCP 2025-11-25; server nenabízí nepovolené capabilities. |
| ACC-PROTO-02 | GET/DELETE /mcp vrací 405, legacy /sse neexistuje, POST s chybným Accept/Content-Type je odmítnut. |
| ACC-HOST-02 | Neznámý kcml hostname, admin /mcp a auth /mcp neodhalí katalog a nepřesměrují. |
| ACC-AUTH-01 | Kaja client_secret funguje pouze na token endpointu a je odmítnut jako Bearer na /mcp. |
| ACC-AUTH-03 | Revokace Kaja a odebrání Permission okamžitě zneplatní existující access tokeny. |
| ACC-SECRET-01 | Client_secret nelze získat z DB dumpu, logu, auditu, telemetry, browser storage ani po refresh UI. |
| ACC-DATA-01 | Současné vytváření 100 Kaja a 100 KCML nevytvoří duplicitu ani recyklaci; mezery v sequence jsou akceptovány. |
| ACC-AUDIT-01 | Selhání pre-invocation auditu zabrání spuštění handleru. Selhání finalizace vyvolá fail-closed odpověď a critical alert. |
| ACC-UI-01 | CSRF, session fixation, timeout session, MFA, reauth a optimistic locking jsou otestovány. |
| ACC-OPS-01 | Proxy config test prokáže nekonfliktnost, stejný-host redirect a odmítnutí default hostu. |
| ACC-DR-01 | Záloha je obnovena na čisté infrastruktuře a aplikace projde smoke testem v RTO. |
| ACC-LOAD-01 | Kapacitní test splní SLO a limity bez ztraceného auditu, cross-host chyby nebo nekontrolovaného růstu fronty. |
| ACC-SEC-01 | SAST/SCA/container scan bez nevyřešené Critical/High zranitelnosti; penetrační nálezy Critical/High jsou uzavřeny. |
| ACC-REG-01 | Neúplný nebo neplatný registrační manifest je odmítnut a nevytvoří aktivní KCML routing ani token resource. |
| ACC-REG-02 | Schválená revize je neměnná; změna kontraktu nebo artefaktu vytvoří novou kandidátní revizi s novými důkazy. |
| ACC-MON-01 | Aktivní server dosáhne HEALTHY pouze po úspěšné readiness, public routing/TLS, OAuth/MCP a synthetic tools/call kontrole. |
| ACC-MON-02 | Stale nebo chybějící monitorovací signál vede nejméně k UNKNOWN/DEGRADED, nikdy k HEALTHY. |
| ACC-SEC-REG-01 | Cross-host, audience bypass nebo digest drift způsobí automatickou QUARANTINED, revokaci resource tokenů a Critical alert. |
| ACC-RECERT-01 | Termín recertifikace, výjimky a eskalace se vyhodnocují automaticky a prodlení vede podle kapitoly 9 k SUSPENDED. |


## Table 37

| Host a cesta | Metody a přístup |
| --- | --- |
| admin.hcasc.cz/ | GET; přesměruje na /login nebo /mcp-servers podle session. Žádný cross-host redirect. |
| admin.hcasc.cz/api/* | Same-origin admin API; session cookie + CSRF pro změny; Kaja tokeny se odmítají. |
| admin.hcasc.cz/health | Pouze interní nebo administrátorsky chráněný detail; veřejně minimální/404. |
| auth.hcasc.cz/oauth/token | POST form-urlencoded; client_secret_basic; grant_type=client_credentials; resource povinný. |
| auth.hcasc.cz/.well-known/oauth-authorization-server | GET veřejné metadata, bez citlivých údajů. |
| kcmlNNNN.hcasc.cz/mcp | POST s Bearer access tokenem. GET/DELETE 405. OPTIONS jen pokud je explicitně povolený CORS origin. |
| kcmlNNNN.hcasc.cz/.well-known/oauth-protected-resource/mcp | GET veřejná resource metadata. |
| kcmlNNNN.hcasc.cz/.well-known/oauth-protected-resource | GET veřejná kořenová resource metadata se stejným resource. |
| libovolný jiný host/cesta | 404/421 nebo proxy-level odmítnutí; bez přesměrování a bez katalogových informací. |


## Table 38

| Pole | Pravidlo |
| --- | --- |
| error | Stabilní strojový kód, např. invalid_client, invalid_resource, rate_limited, service_unavailable. |
| message | Bezpečný obecný text v češtině nebo angličtině podle povrchu; nesmí obsahovat interní detail. |
| correlationId | UUID odpovídající auditu a logům. |
| details | Pouze schema validační chyby bez hodnot tajných polí; v produkci žádný stack trace. |


## Table 39

| Skupina | Povinné parametry |
| --- | --- |
| Public URLs | ADMIN_PUBLIC_URL, AUTH_ISSUER_URL, BASE_DOMAIN, MCP_PROTOCOL_VERSION. |
| Database | DATABASE_URL nebo oddělené host/db/user/secret; TLS režim; pool min/max; statement timeout. |
| Secrets | ACCESS_TOKEN_HMAC_KEY + key ID, session signing/encryption key, CSRF key, MFA encryption key. Každý účel má vlastní klíč. |
| Limits | Request/response size, global a handler concurrency, timeouty, rate limits, token TTL. |
| Proxy trust | Explicitní seznam CIDR důvěryhodné proxy; prázdný seznam znamená žádnou důvěru ve Forwarded headers. |
| Observability | Log level, OTEL endpoint, metric endpoint, sampling; produkční sampling nesmí zahrnout secrets/payloady. |
| Retention | Audit, invocation, logs a token cleanup intervaly podle kapitoly 31. |


## Table 40

| Artefakt | Minimální obsah |
| --- | --- |
| Zdrojový kód | Kompletní repozitář, lockfile, licence, build skripty, bez tajemství a generovaných binárních blobů bez původu. |
| Architektura | C4 kontext/kontejnery/komponenty, request sequence, trust boundaries a ADR pro zásadní rozhodnutí. |
| Databáze | ERD, migrations, constraints, indexy, data dictionary a postup obnovy. |
| API/protokol | OpenAPI pro admin/auth HTTP API, MCP kontraktní příklady, JSON Schemas a seznam chybových kódů. |
| Handler SDK | Rozhraní, manifest schema, vzorový neprodukční handler v test fixtures a pravidla bezpečnosti. |
| Provoz | Install/upgrade/rollback, proxy include, DNS/TLS, config reference, monitoring a alert runbooks. |
| Bezpečnost | Threat model, SBOM, výsledky skenů a penetračního testu, seznam výjimek a rotace secrets. |
| Testy | Automatické testy, test data bez osobních údajů, reporty a postup lokálního/staging spuštění. |
| DR | Backup/restore runbook, poslední protokol obnovy, RPO/RTO a kontaktní/escalation role. |


## 37. Automatický onboarding zdrojového handleru

Tato kapitola je normativní pro automatickou integraci jednoho nového MCP serveru integračním tokenem. Upřesňuje starší ruční registrační postup. Při rozporu má přednost bezpečnější požadavek této kapitoly; token autorizuje workflow, nikoli přímé zapnutí serveru.

### 37.1 Token, TTL a stavový automat

Jeden 512bitový `kci_` token smí nevratně založit nebo obnovit právě jeden onboarding job a právě jednu centrálně přidělenou KCML identitu. Bez platného tokenu vrací všechny `/v1/onboardings` operace jednotné `401 invalid_integration_token`.

| Pravidlo | Normativní požadavek |
| --- | --- |
| Uložení | Jednorázové zobrazení; v DB pouze HMAC digest s odděleným klíčem, key ID, fingerprint a audit. Žádný plaintext sloupec. |
| TTL | Počáteční 2h; pouze aktivní pronajatý serverový job prodlužuje v oknech na `now+2h`, nejvýše `issuedAt+24h`. Klientská aktivita neprodlužuje. |
| Vazba | Token–job–server je transakční a idempotentní. Druhý server je konflikt. Po `ACTIVE` je povolen jen GET stavu do expirace. |
| Resume | Po expiraci job zůstane blokovaný a server disabled. Nový token lze navázat na stejný job/identitu; starší tokeny se revokují. |
| Stavy | `CREATED`, `SOURCE_UPLOADED`, `PR_CREATED`, `CI_RUNNING`, `AWAITING_REVISION`, `MERGED`, `ARTIFACT_BUILDING`, `DEPLOYING`, `REGISTERED_DISABLED`, `TRIAL_TESTING`, `ACTIVE`, `FAILED`, `QUARANTINED`, `CANCELLED`. |

### 37.2 Programátorské a administrační API

- Admin session+CSRF: `POST/GET /api/integration-tokens`, `GET /api/onboarding-jobs[/id]`, POST revoke, cancel a soft delete.
- Programátor: `POST /v1/onboardings` s Bearer tokenem, multipart `manifest` + `source` a `Idempotency-Key`; `GET /v1/onboardings/:id`; `PUT /source` s novým klíčem a `If-Match`; `POST /cancel`.
- API běží pouze na `register.hcasc.cz`; admin, auth, KCML a neznámý host nesmí registrační API obsloužit.
- POST vrací 202 a rezervuje `KCMLNNNN`, `kcmlNNNN.hcasc.cz`, přesný `/mcp` resource a jednoznačný `toolName`. Identita je výstup systému, ne vstup manifestu.

### 37.3 Intake, supply chain a runtime

- Manifest 1.4 je strict a popisuje Node.js 22/TypeScript ESM handler, schémata, limity, safe test, monitoring, změnové vazby a egress allowlist.
- ZIP má nejvýše 10 MiB/50 MiB/1000 položek a obsahuje jen schválené kořenové soubory a `.ts` pod `src/`. Traversal, symlink, binární addon, Dockerfile, `.env`, lifecycle script, tajemství, nepřesná/nepovolená závislost nebo rozšířený tsconfig jsou odmítnuty před spuštěním.
- GitHub App zapisuje jen `handlers/KCMLNNNN/`, vytváří PR a sleduje required checks. PR runner nemá produkční tajemství ani uložené checkout credentials. Auto-merge nastane pouze po úplném PASS. Actions-read oprávnění slouží výhradně ke svázání úspěšného trusted main run ID s provenance.
- Důvěryhodný main workflow s pevným Dockerfile sestaví OCI image, SBOM a provenance, image podepíše a publikuje do GHCR. Worker ověří commit, build ID, digest, podpis a attestace.
- Handler běží samostatně v rootless Podman: non-root, read-only, cap-drop ALL, no-new-privileges, CPU/RAM/PID/timeout/concurrency limity, log-driver none, network none a privátní Unix socket. Pevný supervisor spouští každý call v odděleném podprocesu a po timeoutu jej násilně ukončí.
- Strukturované logy se vracejí gateway a redigují. Povolený upstream je dostupný jen přes `context.egress.fetch` a centrální Unix-socket proxy s per-job capability, přesným HTTPS allowlistem a SSRF/DNS-rebinding ochranou.

### 37.4 Registrace, veřejný trial a automatická aktivace

1. Po ověření OCI workeru vytvořit `mcp_server` jako `REGISTERED_DISABLED/DISABLED/enabled=false`, registration revision, monitoring profile, statistiky, audit a všechny digestové vazby.
2. Ověřit DNS, DNS-01 wildcard certifikát `*.hcasc.cz`, SAN konkrétního hostu, SNI/Host routing, protected-resource metadata, podpis image a readiness Unix socketu.
3. Přejít do `TRIAL_TESTING` a vytvořit krátkodobé systémové Kaja pověření s `EXECUTE` pouze pro testovaný server.
4. Přes veřejné HTTPS ověřit negativní tokeny, initialize, initialized, tools/list, safe tools/call, schémata, timeout/size/rate limit, correlation, audit, logy, statistiky a probes.
5. Revokovat systémové pověření a access tokeny. Pouze úplný PASS přepne `ACTIVE/enabled=true`; `HEALTHY` vyžaduje readiness, DNS/TLS metadata, syntetický call a artifact integrity.

Cross-host chyba, audience bypass, digest drift, neplatný podpis/provenance nebo únik integračního, Kaja, access či egress tokenu vždy nastaví `QUARANTINED`, revokuje tokeny/capabilities, vypne server a zastaví worker. Automatický návrat je zakázán.

### 37.5 Produkční release gate

| Závislost | Release podmínka |
| --- | --- |
| HTTPS | Wildcard DNS a platný DNS-01 certifikát `*.hcasc.cz`; nginx exact register host, regex KCML hosty, zachovaný Host a default deny. |
| GitHub | Nainstalovaná GitHub App s minimálními contents/PR/check a Actions-read permissions; branch protection a required checks odpovídají workeru. |
| Supply chain | GHCR namespace, důvěryhodný signing key, cosign verify, SBOM/provenance attestace a immutable digest. |
| Runtime | Rootless Podman pro uživatele `kcml`, worker a egress-proxy systemd služby, karanténní/runtime adresáře a privátní socket permissions. |
| Testy | Root CI včetně PostgreSQL migrací a integračních testů, onboarding PR gates, runtime/supply-chain staging E2E a desktop/mobile browser QA. |
