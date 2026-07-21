import { isExpiredAdminSession, REAUTH_REQUIRED_EVENT, SESSION_EXPIRED_EVENT } from "./session-auth.js";
import type { AccessTokenCredential } from "./types.js";

let uiTimeZone = "Europe/Prague";

export function setUiTimeZone(value: string): void {
  new Intl.DateTimeFormat("en", { timeZone: value }).format(0);
  uiTimeZone = value;
}

type ApiErrorPayload = {
  error?: string;
  correlationId?: string;
  message?: string;
};

export class ApiRequestError extends Error {
  constructor(readonly code: string, readonly correlationId: string | null) {
    super(describeApiError(code, correlationId));
    this.name = "ApiRequestError";
  }
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { ...init, credentials: "include", headers: { "content-type": "application/json", ...(init?.headers ?? {}) } });
  if (!res.ok) {
    const body = await res.json().catch((): ApiErrorPayload => ({ error: res.statusText })) as ApiErrorPayload;
    if (isExpiredAdminSession(res.status, body.error)) window.dispatchEvent(new Event(SESSION_EXPIRED_EVENT));
    if (res.status === 428 && body.error === "reauthentication_required") window.dispatchEvent(new Event(REAUTH_REQUIRED_EVENT));
    throw new ApiRequestError(body.error ?? res.statusText, body.correlationId ?? null);
  }
  return res.json() as Promise<T>;
}

export function describeApiError(code: string, correlationId: string | null = null): string {
  const map: Record<string, string> = {
    unauthorized: "Relace vypršela. Přihlaste se prosím znovu.",
    invalid_login: "Přihlášení se nepodařilo. Zkontrolujte uživatelské jméno a heslo.",
    invalid_mfa_code: "Ověřovací MFA kód nebo recovery kód není správný.",
    mfa_challenge_required: "MFA ověření už není platné. Zadejte znovu uživatelské jméno a heslo.",
    login_rate_limited: "Bylo zaznamenáno příliš mnoho pokusů o přihlášení. Chvíli počkejte a zkuste to znovu.",
    csrf_failed: "Bezpečnostní kontrola formuláře selhala. Obnovte stránku a akci zopakujte.",
    invalid_permissions: "Oprávnění nejsou v platném formátu.",
    invalid_label: "Zadané označení není platné.",
    invalid_expiration: "Datum expirace musí být v budoucnosti.",
    suppression_must_be_future: "Konec potlačení musí být v budoucnosti.",
    config_version_conflict: "Konfigurace se mezitím změnila v jiné relaci. Nejprve obnovte stránku nebo seznam konfigurace.",
    handler_unavailable: "Server v této verzi aplikace nemá dostupný handler.",
    manifest_test_contract_missing: "Server nemá zaregistrovaný testovací kontrakt pro bezpečný test.",
    rate_limit_exceeded: "Byl překročen povolený limit volání. Zkuste to znovu později.",
    weak_password: "Nové heslo musí mít alespoň 12 znaků.",
    invalid_mfa_secret: "MFA tajemství musí mít alespoň 16 znaků.",
    invalid_mfa_enrollment: "Registrace MFA už není platná. Začněte prosím znovu.",
    admin_mfa_deployment_managed: "MFA tohoto účtu spravuje produkční deployment a nelze ji měnit v UI.",
    reauthentication_required: "Pro tuto změnu je nutné znovu potvrdit heslo a MFA.",
    reauthentication_failed: "Opětovné ověření se nezdařilo.",
    owner_role_required: "Tuto operaci může provést pouze vlastník systému.",
    admin_role_forbidden: "Role auditora nepovoluje změny systému.",
    last_owner_required: "Posledního aktivního vlastníka nelze deaktivovat ani převést na jinou roli.",
    bootstrap_access_denied: "První nastavení je povoleno pouze z důvěryhodného rozhraní nebo s bootstrap secretem.",
    bootstrap_input_invalid: "Vyplňte uživatelské jméno a heslo alespoň o 12 znacích.",
    bootstrap_completed: "První nastavení už bylo dokončeno.",
    bootstrap_username_unavailable: "Zvolené uživatelské jméno už nelze použít.",
    confirmation_code_mismatch: "Potvrzovací KCML kód nesouhlasí.",
    server_disabled: "Server je vypnutý nebo není v provozním stavu.",
    active_revision_required: "Operace vyžaduje aktivní registrační revizi.",
    active_monitoring_profile_required: "Operace vyžaduje aktivní monitorovací profil.",
    monitoring_profile_not_found: "Monitorovací profil nebyl nalezen.",
    monitoring_profile_invalid: "Monitorovací profil není platný.",
    monitoring_profile_version_conflict: "Monitorovací profil se mezitím změnil. Nejprve jej obnovte.",
    monitoring_revision_required: "Změna monitoringu vyžaduje novou revizi serveru.",
    manifest_not_found: "Aktivní registrační manifest nebyl nalezen.",
    manifest_safe_input_schema_failed: "Bezpečný testovací vstup neodpovídá registrovanému schématu.",
    unsafe_write_test_contract: "Zápisový nástroj nemá bezpečně izolovaný testovací kontrakt.",
    test_compensation_policy_mismatch: "Kompenzační test neodpovídá politice ukončení handleru.",
    output_schema_failed: "Výstup handleru neodpovídá registrovanému schématu.",
    handler_timeout: "Handler překročil registrovaný časový limit.",
    concurrency_limit_exceeded: "Server právě využívá celý povolený souběh.",
    config_key_not_found: "Konfigurační klíč nebyl nalezen.",
    config_value_required: "Konfigurační hodnota je povinná.",
    config_invalid_hostname: "Hostname není platný.",
    config_invalid_time_zone: "Časové pásmo není platné.",
    config_invalid_interval: "Zadaný interval není platný.",
    config_invalid_secret: "Tajná hodnota nemá požadovaný formát nebo délku.",
    secret_principal_public_id_must_not_be_token: "Do Public ID nepatří plná hodnota integračního tokenu. Použijte pouze jeho fingerprint nebo veřejný identifikátor.",
    audit_cursor_invalid: "Stránkovací kurzor auditu není platný.",
    audit_time_range_invalid: "Časový rozsah auditu není platný.",
    audit_event_id_invalid: "Identifikátor auditní události není platný.",
    alert_not_open: "Alert už není otevřený.",
    alert_not_suppressible: "Alert v tomto stavu nelze potlačit.",
    delivery_not_retryable: "Toto doručení už nelze opakovat.",
    invalid_delete_request: "Požadavek na smazání není platný.",
    invalid_disable_request: "Požadavek na vypnutí není platný.",
    invalid_enable_request: "Požadavek na zapnutí není platný.",
    invalid_integration_descriptor: "Popis integračního záměru není úplný.",
    invalid_integration_token: "Integrační token není platný.",
    invalid_token: "Přístupový token komponenty není platný.",
    expired_token: "Přístupový token komponenty vypršel.",
    revoked_token: "Přístupový token nebo přístupový token byl revokován.",
    insufficient_scope: "Komponenta nemá požadovaný scope.",
    invalid_audience: "Audience tokenu neodpovídá výhradnímu endpointu komponenty.",
    component_disabled: "Komponenta je deaktivovaná a provoz je zablokován.",
    component_quarantined: "Komponenta je v karanténě.",
    route_denied: "Směrované oprávnění pro tuto route není povoleno.",
    catalog_incompatible: "Komponenta nebo její revize není kompatibilní s aktuálním katalogem.",
    monitoring_failed: "Aktivace vyžaduje zdravý monitoring.",
    audit_gap: "Aktivace je blokována nevyřešenou mezerou v auditním streamu.",
    invalid_state: "Operaci nelze provést v aktuálním stavu komponenty.",
    component_must_be_retired: "Před odregistrací musí být komponenta vyřazena.",
    credential_already_revoked: "Přístupový token už byl revokován.",
    audit_stream_unavailable: "Auditní kanál komponenty není dostupný.",
    job_not_found: "Onboarding úloha nebyla nalezena.",
    job_not_resumable: "Onboarding úlohu v tomto stavu nelze obnovit.",
    job_not_quarantined: "Onboarding úloha není v karanténě.",
    lock_version_conflict: "Záznam se mezitím změnil. Obnovte stránku a akci zopakujte.",
    operation_failed: "Operaci se nepodařilo dokončit.",
    internal_error: "Operaci se nepodařilo dokončit kvůli interní chybě."
  };
  const base = map[code] ?? "Operaci se nepodařilo dokončit";
  return correlationId ? `${base} (Correlation ID: ${correlationId})` : base;
}

export function csrf(): string {
  return document.cookie.split("; ").find((row) => row.startsWith("__Host-kcml_csrf="))?.split("=")[1] ?? "";
}

export function formatDate(value: string | null): string {
  return value
    ? new Intl.DateTimeFormat("cs-CZ", {
      dateStyle: "medium",
      timeStyle: "short",
      timeZone: uiTimeZone
    }).format(new Date(value))
    : "-";
}

export function formatCzNumber(value: number): string {
  return new Intl.NumberFormat("cs-CZ").format(value);
}

export function formatDateWithUtc(value: string | null): string {
  if (!value) return "-";
  return `${formatDate(value)} · ${new Date(value).toISOString()}`;
}

export function formatLocalDateTimeInput(value: Date): string {
  return new Date(value.getTime() - value.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
}

export function prettyJson(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

export function statusClass(credential: AccessTokenCredential): string {
  if (credential.revokedAt || !credential.active) return "danger";
  if (credential.expiresAt && new Date(credential.expiresAt).getTime() - Date.now() < 7 * 24 * 3600 * 1000) return "warn";
  return "ok";
}

export function recertificationState(reviewDueAt: string | null): { tone: "neutral" | "warning" | "danger"; label: string } {
  if (!reviewDueAt) return { tone: "neutral", label: "Bez data revize" };
  const deltaMs = new Date(reviewDueAt).getTime() - Date.now();
  if (deltaMs <= 0) return { tone: "danger", label: "Revize po splatnosti" };
  if (deltaMs <= 14 * 24 * 3600 * 1000) return { tone: "warning", label: "Blíží se revize" };
  return { tone: "neutral", label: "Revize naplánována" };
}
