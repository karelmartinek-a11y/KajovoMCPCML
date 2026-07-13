import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  AlertTriangle,
  Ban,
  CalendarDays,
  CheckCircle2,
  ChevronDown,
  CircleHelp,
  ClipboardCopy,
  Clock3,
  KeyRound,
  LockKeyhole,
  LogOut,
  MoreHorizontal,
  Plus,
  RefreshCw,
  Rocket,
  Save,
  Search,
  Server as ServerIcon,
  ShieldCheck,
  SlidersHorizontal,
  Terminal,
  Workflow,
  X
} from "lucide-react";
import "./styles.css";

type Page = "monitoring" | "registration" | "integration" | "tokens" | "permissions" | "audit";
type ServerAction = "test" | "trial" | "mcp-test" | "bind-manifest" | "disable" | "resume" | "activate";
type Session = { authenticated: boolean; account: string | null };
type Server = {
  id: string;
  code: string;
  hostname: string;
  displayName: string;
  description: string;
  toolName: string;
  registrationState: string;
  operationalState: string;
  enabled: boolean;
  handlerKey: string;
  handlerVersion: string;
  contractVersion: string;
  inputSchema: unknown;
  outputSchema: unknown;
  artifactDigest: string;
  manifestDigest: string;
  successCount: number;
  unauthorizedCount: number;
  failureCount: number;
  lastLatencyMs: number | null;
  averageLatencyMs: number | null;
  p95LatencyMs: number | null;
  lastSuccessAt: string | null;
  lastFailureAt: string | null;
  lastUnauthorizedAt: string | null;
  handlerSmokePassed: boolean;
  manifestIdentityBound: boolean;
  uiMcpTest: {
    status: "PASS" | "FAIL";
    testedAt: string;
    latencyMs: number;
    schemaValidated?: boolean;
    toolCount?: number;
    deviceCount?: number;
    entityCount?: number;
    rowCount?: number;
    errorCode?: string;
  } | null;
  acceptancePassed: boolean;
  createdAt: string;
  updatedAt: string;
};
type KajaCredential = {
  id: string;
  publicId: string;
  label: string;
  fingerprint: string;
  active: boolean;
  revokedAt: string | null;
  deletedAt: string | null;
  createdAt: string;
  updatedAt: string;
  expiresAt: string | null;
  permissionCount: number;
  activeAccessTokenCount: number;
  lastTokenIssuedAt: string | null;
  lastTokenExpiresAt: string | null;
};
type AccessLevel = "READ" | "EXECUTE" | "MANAGE";
type KajaPermission = {
  serverId: string;
  code: string;
  hostname: string;
  displayName: string;
  granted: boolean;
  accessLevel: AccessLevel | null;
  grantedAt: string | null;
};
type AuditEvent = { id: number; event_type: string; actor_type: string; object_type: string; object_id: string; correlation_id: string; created_at: string };
type SecretResult = { publicId: string; label: string; clientSecret: string; fingerprint: string; expiresAt: string | null };
type IntegrationToken = {
  id: string;
  label: string;
  fingerprint: string;
  jobId: string | null;
  issuedAt: string;
  initialExpiresAt: string;
  expiresAt: string;
  maxExpiresAt: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
  active: boolean;
  jobState: string | null;
  code: string | null;
  hostname: string | null;
};
type IntegrationSecret = IntegrationToken & { token: string };
type OnboardingGate = { gate_name: string; stage: string; status: string; evidence: Record<string, unknown>; correlation_id: string; started_at: string | null; completed_at: string | null };
type OnboardingEvent = { id: number; from_state: string | null; to_state: string; event_type: string; detail: Record<string, unknown>; correlation_id: string; created_at: string };
type OnboardingJob = {
  id: string;
  state: string;
  correlationId: string;
  lockVersion: number;
  sourceRevision: number;
  code: string | null;
  hostname: string | null;
  resource: string | null;
  toolName: string | null;
  serverId: string | null;
  githubPrUrl: string | null;
  imageDigest: string | null;
  sbomDigest: string | null;
  blockingErrorCode: string | null;
  blockingErrorDetail: string | null;
  createdAt: string | null;
  updatedAt: string | null;
  completedAt: string | null;
  gates?: OnboardingGate[];
  events?: OnboardingEvent[];
};
type MonitoringProbe = { id: number; server_id: string; code: string; hostname: string; probe_type: string; status: string; latency_ms: number | null; correlation_id: string; checked_at: string };
type McpTestResult = {
  result: { status: "PASS"; testedAt: string; latencyMs: number; schemaValidated: boolean; toolCount: number; deviceCount: number; entityCount: number; rowCount: number };
  response: unknown;
};

const pageNames: Record<Page, string> = {
  monitoring: "Monitoring MCP",
  registration: "Registrace serveru",
  integration: "Implementační tokeny",
  tokens: "Tokeny",
  permissions: "Správa oprávnění",
  audit: "Audit"
};

const accessLabels: Record<AccessLevel, string> = {
  READ: "Čtení",
  EXECUTE: "Spouštění",
  MANAGE: "Správa"
};

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { ...init, credentials: "include", headers: { "content-type": "application/json", ...(init?.headers ?? {}) } });
  if (!res.ok) {
    const body = await res.json().catch((): { error?: string } => ({ error: res.statusText })) as { error?: string };
    throw new Error(body.error ?? res.statusText);
  }
  return res.json() as Promise<T>;
}

function csrf(): string {
  return document.cookie.split("; ").find((row) => row.startsWith("__Host-kcml_csrf="))?.split("=")[1] ?? "";
}

function formatDate(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "-";
}

function statusClass(credential: KajaCredential): string {
  if (credential.revokedAt || !credential.active) return "danger";
  if (credential.expiresAt && new Date(credential.expiresAt).getTime() - Date.now() < 7 * 24 * 3600 * 1000) return "warn";
  return "ok";
}

function Modal({ title, children, onClose }: { title: string; children: React.ReactNode; onClose: () => void }) {
  return (
    <div className="modal-backdrop" role="presentation">
      <section className="modal" role="dialog" aria-modal="true" aria-label={title}>
        <header className="modal-head">
          <h2>{title}</h2>
          <button className="icon-button" onClick={onClose} aria-label="Zavřít"><X size={18} /></button>
        </header>
        {children}
      </section>
    </div>
  );
}

function Login({ onLogin }: { onLogin: () => void }) {
  const [username, setUsername] = useState("karmar78");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [error, setError] = useState("");
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    try {
      await api("/api/login", { method: "POST", body: JSON.stringify({ username, password, totp }) });
      onLogin();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Přihlášení selhalo");
    }
  }
  return (
    <main className="login-shell">
      <section className="login-panel">
        <div className="brand-row"><ShieldCheck size={28} /><strong>KCML</strong></div>
        <h1>Správce MCP serverů</h1>
        <form onSubmit={(event) => { void submit(event); }}>
          <label>Uživatel<input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" /></label>
          <label>Heslo<input value={password} onChange={(e) => setPassword(e.target.value)} type="password" autoComplete="current-password" /></label>
          <label>MFA kód<input value={totp} onChange={(e) => setTotp(e.target.value)} inputMode="numeric" autoComplete="one-time-code" /></label>
          {error && <p className="error">{error}</p>}
          <button type="submit"><KeyRound size={18} /> Přihlásit</button>
        </form>
      </section>
    </main>
  );
}

function CreateTokenModal({ serverCount, onClose, onCreated }: { serverCount: number; onClose: () => void; onCreated: (secret: SecretResult) => void }) {
  const [label, setLabel] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [error, setError] = useState("");
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    const form = new FormData(event.currentTarget as HTMLFormElement);
    const labelValue = form.get("label");
    const expiresAtValue = form.get("expiresAt");
    const submittedLabel = typeof labelValue === "string" ? labelValue.trim() : "";
    const submittedExpiresAt = typeof expiresAtValue === "string" ? expiresAtValue : "";
    if (!submittedLabel) {
      setError("Zadej označení tokenu.");
      return;
    }
    try {
      const secret = await api<SecretResult>("/api/kaja", {
        method: "POST",
        headers: { "x-csrf-token": csrf() },
        body: JSON.stringify({ label: submittedLabel, expiresAt: submittedExpiresAt ? new Date(submittedExpiresAt).toISOString() : null })
      });
      onCreated(secret);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Token se nepodařilo vytvořit");
    }
  }
  return (
    <Modal title="Založit Kaja token" onClose={onClose}>
      <form className="modal-form" onSubmit={(event) => { void submit(event); }}>
        <div className="form-intro"><span className="modal-icon"><KeyRound size={20} /></span><p>Vytvoř nové pověření pro aplikaci nebo integrační službu. Přístup k serverům nastavíš hned poté ve správě oprávnění.</p></div>
        <label>Označení tokenu<span className="field-hint">Srozumitelný název podle účelu nebo aplikace</span><input name="label" autoFocus value={label} onChange={(event) => setLabel(event.target.value)} maxLength={120} placeholder="Např. CI/CD pipeline" /></label>
        <label>Expirace pověření<span className="field-hint">Nepovinné, bez data zůstane pověření bez časového omezení</span><div className="input-with-icon"><CalendarDays size={16} /><input name="expiresAt" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} type="datetime-local" /></div></label>
        <div className="permission-preview">
          <div className="preview-title"><LockKeyhole size={16} /><strong>Přehled oprávnění</strong></div>
          <span>Nový token vznikne bezpečně bez přístupu. Oprávnění mu přiřadíš na samostatné stránce.</span>
          <dl><dt>Dostupné MCP servery</dt><dd>{serverCount}</dd><dt>Výchozí přístup</dt><dd>Bez oprávnění</dd></dl>
        </div>
        {error && <p className="error">{error}</p>}
        <footer className="modal-actions">
          <button type="button" className="secondary" onClick={onClose}>Zrušit</button>
          <button type="submit"><KeyRound size={16} /> Vygenerovat token</button>
        </footer>
      </form>
    </Modal>
  );
}

function SecretModal({ secret, onClose }: { secret: SecretResult; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    await navigator.clipboard.writeText(secret.clientSecret);
    setCopied(true);
  }
  return (
    <Modal title="Token byl vytvořen" onClose={onClose}>
      <div className="secret-dialog">
        <p>Hodnota secretu se zobrazuje pouze jednou. Po zavření už ji nepůjde znovu zobrazit.</p>
        <div className="secret-once"><strong>{secret.label} · {secret.publicId}</strong><code>{secret.clientSecret}</code><span>Fingerprint {secret.fingerprint}. Expirace {secret.expiresAt ? formatDate(secret.expiresAt) : "bez omezení"}.</span></div>
        <footer className="modal-actions">
          <button className="secondary" onClick={onClose}>Zavřít</button>
          <button onClick={() => { void copy(); }}><ClipboardCopy size={16} /> {copied ? "Zkopírováno" : "Zkopírovat token"}</button>
        </footer>
      </div>
    </Modal>
  );
}

function CreateIntegrationTokenModal({ resumeJobId, onClose, onCreated }: { resumeJobId?: string; onClose: () => void; onCreated: (secret: IntegrationSecret) => void }) {
  const [label, setLabel] = useState(resumeJobId ? `Pokračování jobu ${resumeJobId.slice(0, 8)}` : "");
  const [error, setError] = useState("");
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!label.trim()) { setError("Zadej označení implementačního tokenu."); return; }
    try {
      const result = await api<IntegrationSecret>("/api/integration-tokens", {
        method: "POST",
        headers: { "x-csrf-token": csrf() },
        body: JSON.stringify({ label: label.trim(), resumeJobId })
      });
      onCreated(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Token se nepodařilo vytvořit");
    }
  }
  return (
    <Modal title={resumeJobId ? "Navazující implementační token" : "Automaticky integrovat MCP server"} onClose={onClose}>
      <form className="modal-form" onSubmit={(event) => { void submit(event); }}>
        <div className="form-intro"><span className="modal-icon"><Workflow size={20} /></span><p>Token má 512 bitů entropie, platí nejprve 2 hodiny a smí založit právě jeden onboardingový job a jeden MCP server. Serverový job jej může prodlužovat nejvýše 24 hodin.</p></div>
        <label>Označení tokenu<span className="field-hint">Jméno programátora, týmu nebo integrace</span><input autoFocus value={label} onChange={(event) => setLabel(event.target.value)} maxLength={120} placeholder="Např. Fakturační MCP – dodavatel" /></label>
        {resumeJobId ? <div className="permission-preview"><strong>Pokračování existujícího jobu</strong><code>{resumeJobId}</code><span>Předchozí token bude revokován. KCML identita zůstane zachována.</span></div> : null}
        {error && <p className="error">{error}</p>}
        <footer className="modal-actions"><button type="button" className="secondary" onClick={onClose}>Zrušit</button><button type="submit"><Rocket size={16} /> Vygenerovat token</button></footer>
      </form>
    </Modal>
  );
}

function IntegrationSecretModal({ secret, onClose }: { secret: IntegrationSecret; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    await navigator.clipboard.writeText(secret.token);
    setCopied(true);
  }
  return (
    <Modal title="Implementační token byl vytvořen" onClose={onClose}>
      <div className="secret-dialog">
        <p>Token se zobrazuje pouze nyní. KajovoMCPCML ukládá jen HMAC digest a fingerprint.</p>
        <div className="secret-once"><strong>{secret.label}</strong><code>{secret.token}</code><span>Fingerprint {secret.fingerprint}</span><span>Počáteční expirace {formatDate(secret.initialExpiresAt)} · nejzazší expirace {formatDate(secret.maxExpiresAt)}</span></div>
        <div className="permission-preview"><strong>Programátorské API</strong><code>POST https://register.hcasc.cz/v1/onboardings</code><span>Bearer token + multipart pole <code>manifest</code> a <code>source</code> + hlavička <code>Idempotency-Key</code>.</span></div>
        <footer className="modal-actions"><button className="secondary" onClick={onClose}>Zavřít</button><button onClick={() => { void copy(); }}><ClipboardCopy size={16} /> {copied ? "Zkopírováno" : "Zkopírovat token"}</button></footer>
      </div>
    </Modal>
  );
}

function IntegrationConfirmModal({ token, action, onClose, onConfirm }: { token: IntegrationToken; action: "revoke" | "delete"; onClose: () => void; onConfirm: () => Promise<void> }) {
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  async function confirmAction() {
    setBusy(true);
    try { await onConfirm(); } finally { setBusy(false); }
  }
  return (
    <Modal title={action === "revoke" ? "Revokovat implementační token?" : "Smazat záznam tokenu?"} onClose={onClose}>
      <div className="modal-form">
        <p className="destructive-copy">{action === "revoke" ? "Programátorské API token okamžitě odmítne. Běžící krok jobu skončí fail-closed a nebude znovu pronajat." : "Token bude revokován a skryt z přehledu; auditní a onboardingová stopa zůstane zachována."}</p>
        <label>Pro potvrzení opiš označení<input value={typed} onChange={(event) => setTyped(event.target.value)} placeholder={token.label} /></label>
        <footer className="modal-actions"><button className="secondary" onClick={onClose}>Zrušit</button><button className="danger-button" disabled={typed !== token.label || busy} onClick={() => { void confirmAction(); }}>{action === "revoke" ? "Revokovat" : "Smazat"}</button></footer>
      </div>
    </Modal>
  );
}

function McpTestResultModal({ value, onClose }: { value: McpTestResult; onClose: () => void }) {
  return (
    <Modal title="Výsledek skutečného MCP testu" onClose={onClose}>
      <div className="test-result-dialog">
        <div className="notice"><ShieldCheck size={18} /> OAuth, autorizace, initialize, tools/list, tools/call a výstupní schéma prošly.</div>
        <dl className="registration-contract">
          <dt>Výsledek</dt><dd>{value.result.status}</dd>
          <dt>Latence celého toku</dt><dd>{value.result.latencyMs} ms</dd>
          <dt>Nástroje</dt><dd>{value.result.toolCount}</dd>
          <dt>Zařízení / entity</dt><dd>{value.result.deviceCount} / {value.result.entityCount}</dd>
          <dt>Řádky tabulky</dt><dd>{value.result.rowCount}</dd>
          <dt>Validace schématu</dt><dd>{value.result.schemaValidated ? "PASS" : "FAIL"}</dd>
        </dl>
        <h3>Přesná MCP odpověď</h3>
        <pre className="test-output">{JSON.stringify(value.response, null, 2)}</pre>
        <footer className="modal-actions"><button type="button" onClick={onClose}>Zavřít výsledek</button></footer>
      </div>
    </Modal>
  );
}

function ConfirmModal({ credential, action, onClose, onConfirm }: { credential: KajaCredential; action: "revoke" | "delete"; onClose: () => void; onConfirm: () => Promise<void> }) {
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const isRevoke = action === "revoke";
  async function confirm() {
    setBusy(true);
    try {
      await onConfirm();
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal title={isRevoke ? "Revokovat token?" : "Smazat záznam tokenu?"} onClose={onClose}>
      <div className="modal-form">
        <p className="destructive-copy">{isRevoke ? "Aplikace používající tento token okamžitě ztratí přístup." : "Záznam zmizí z běžného přehledu. Auditní stopa zůstane zachovaná."}</p>
        <label>Pro potvrzení opiš označení tokenu<input value={typed} onChange={(event) => setTyped(event.target.value)} placeholder={credential.label} /></label>
        <footer className="modal-actions">
          <button className="secondary" onClick={onClose}>Zrušit</button>
          <button className="danger-button" disabled={typed !== credential.label || busy} onClick={() => { void confirm(); }}>{isRevoke ? "Revokovat token" : "Smazat záznam"}</button>
        </footer>
      </div>
    </Modal>
  );
}

function PageHeader({ title, description, children }: { title: string; description: string; children?: React.ReactNode }) {
  return (
    <header className="page-header">
      <div><h1>{title}</h1><p>{description}</p></div>
      <div className="actions">{children}</div>
    </header>
  );
}

function IconButton({ label, children, onClick }: { label: string; children: React.ReactNode; onClick?: () => void }) {
  return <button className="icon-button" type="button" title={label} aria-label={label} onClick={onClick}>{children}</button>;
}

function MetricCard({ tone, icon, value, label }: { tone: "neutral" | "success" | "warning" | "danger"; icon: React.ReactNode; value: number; label: string }) {
  return <article className={`metric-card ${tone}`}><span className="metric-icon">{icon}</span><strong>{value}</strong><span>{label}</span></article>;
}

function ServerDetailModal({ server, busy, onClose, onAction }: { server: Server; busy: boolean; onClose: () => void; onAction: (action: ServerAction) => void }) {
  return (
    <Modal title={server.displayName} onClose={onClose}>
      <div className="server-detail">
        <div className="server-detail-status"><span className={`status-dot ${server.enabled ? "ok" : "danger"}`} /><strong>{server.operationalState}</strong><span>{server.registrationState}</span></div>
        <dl>
          <dt>Kód serveru</dt><dd>{server.code}</dd>
          <dt>Hostname</dt><dd>{server.hostname}</dd>
          <dt>Nástroj</dt><dd>{server.toolName}</dd>
          <dt>Handler</dt><dd>{server.handlerKey} · {server.handlerVersion}</dd>
          <dt>Contract</dt><dd>{server.contractVersion}</dd>
          <dt>Artifact digest</dt><dd><code>{server.artifactDigest}</code></dd>
          <dt>Manifest digest</dt><dd><code>{server.manifestDigest}</code></dd>
          <dt>Úspěšná volání</dt><dd>{server.successCount}</dd>
          <dt>Chyby autorizace</dt><dd>{server.unauthorizedCount}</dd>
          <dt>Provozní chyby</dt><dd>{server.failureCount}</dd>
          <dt>Latence poslední / průměr / p95</dt><dd>{server.lastLatencyMs ?? "-"} / {server.averageLatencyMs ?? "-"} / {server.p95LatencyMs ?? "-"} ms</dd>
          <dt>Poslední úspěch</dt><dd>{formatDate(server.lastSuccessAt)}</dd>
          <dt>Poslední chyba</dt><dd>{formatDate(server.lastFailureAt)}</dd>
          <dt>Smoke test</dt><dd>{server.handlerSmokePassed ? "PASS" : "NOT TESTED"}</dd>
          <dt>Identita v manifestu</dt><dd>{server.manifestIdentityBound ? "PASS" : "VYŽADUJE SYNCHRONIZACI"}</dd>
          <dt>Skutečný MCP test</dt><dd>{server.uiMcpTest?.status ?? "NOT TESTED"}{server.uiMcpTest ? ` · ${server.uiMcpTest.latencyMs} ms` : ""}</dd>
          <dt>Akceptační matice</dt><dd>{server.acceptancePassed ? "PASS" : "NOT TESTED"}</dd>
        </dl>
        {server.description ? <p>{server.description}</p> : null}
        <details><summary>Vstupní JSON Schema</summary><pre className="test-output">{JSON.stringify(server.inputSchema, null, 2)}</pre></details>
        <details><summary>Výstupní JSON Schema</summary><pre className="test-output">{JSON.stringify(server.outputSchema, null, 2)}</pre></details>
        <footer className="modal-actions">
          <button type="button" className="secondary" onClick={onClose}>Zavřít detail</button>
          {server.registrationState === "REGISTERED_DISABLED" ? <button type="button" disabled={busy} onClick={() => onAction("test")}>Otestovat handler</button> : null}
          {!server.manifestIdentityBound ? <button type="button" disabled={busy} onClick={() => onAction("bind-manifest")}>Synchronizovat manifest</button> : null}
          {server.registrationState === "REGISTERED_DISABLED" && server.handlerSmokePassed ? <button type="button" disabled={busy} onClick={() => onAction("trial")}>Povolit TRIAL</button> : null}
          {["TRIAL", "ACTIVE"].includes(server.registrationState) ? <button type="button" disabled={busy} onClick={() => onAction("mcp-test")}>Otestovat přes MCP</button> : null}
          {server.registrationState === "TRIAL" && server.acceptancePassed ? <button type="button" disabled={busy} onClick={() => onAction("activate")}>Aktivovat</button> : null}
          {["TRIAL", "ACTIVE"].includes(server.registrationState) ? <button type="button" className="danger-button" disabled={busy} onClick={() => { if (window.confirm("Opravdu okamžitě vypnout server a zneplatnit jeho access tokeny?")) onAction("disable"); }}>Vypnout server</button> : null}
          {server.registrationState === "SUSPENDED" ? <button type="button" disabled={busy} onClick={() => onAction("resume")}>Obnovit provoz</button> : null}
        </footer>
      </div>
    </Modal>
  );
}

function MonitoringPage({
  servers,
  probes,
  actionBusy,
  onRefresh,
  onAutomatedOnboarding,
  onServerAction
}: {
  servers: Server[];
  probes: MonitoringProbe[];
  actionBusy: boolean;
  onRefresh: () => void;
  onAutomatedOnboarding: () => void;
  onServerAction: (server: Server, action: ServerAction) => Promise<void>;
}) {
  const [query, setQuery] = useState("");
  const [timeRange, setTimeRange] = useState("24h");
  const [detailServer, setDetailServer] = useState<Server | null>(null);
  const online = servers.filter((server) => server.enabled && ["ACTIVE", "TRIAL"].includes(server.registrationState)).length;
  const degraded = servers.filter((server) => server.operationalState === "DEGRADED").length;
  const offline = servers.filter((server) => !server.enabled || ["SUSPENDED", "QUARANTINED", "RETIRED"].includes(server.registrationState)).length;
  const filtered = servers.filter((server) => `${server.displayName} ${server.hostname} ${server.code}`.toLowerCase().includes(query.toLowerCase()));
  const rangeMs = timeRange === "30d" ? 30 * 86400000 : timeRange === "7d" ? 7 * 86400000 : 86400000;
  const visibleProbes = probes.filter((probe) => new Date(probe.checked_at).getTime() > Date.now() - rangeMs).slice(0, 80).reverse();
  return (
    <>
      <PageHeader title="Monitoring MCP" description="Přehled stavu a dostupnosti MCP serverů">
        <button onClick={onAutomatedOnboarding}><Rocket size={17} /> Automaticky integrovat MCP server</button>
        <IconButton label="Obnovit monitoring" onClick={onRefresh}><RefreshCw size={17} /></IconButton>
        <label className="range-select"><Clock3 size={16} /><select value={timeRange} onChange={(event) => setTimeRange(event.target.value)} aria-label="Časový rozsah monitoringu"><option value="24h">Posledních 24 hodin</option><option value="7d">Posledních 7 dní</option><option value="30d">Posledních 30 dní</option></select><ChevronDown size={15} /></label>
      </PageHeader>
      <section className="metric-row">
        <MetricCard tone="neutral" icon={<ServerIcon size={22} />} value={servers.length} label="Celkem serverů" />
        <MetricCard tone="success" icon={<CheckCircle2 size={22} />} value={online} label="Online" />
        <MetricCard tone="warning" icon={<AlertTriangle size={22} />} value={degraded} label="Degradováno" />
        <MetricCard tone="danger" icon={<Ban size={22} />} value={offline} label="Offline" />
      </section>
      <section className="panel monitor-panel">
        <div className="panel-head"><div className="heading-with-help"><h2>Stav v čase</h2><CircleHelp size={15} /></div></div>
        <div className="timeline-chart" aria-label="Dostupnost MCP serverů za posledních 24 hodin">
          <div className="chart-y-axis"><span>100%</span><span>75%</span><span>50%</span><span>25%</span><span>0%</span></div>
          <div className="chart-grid">
            {visibleProbes.length === 0 ? <div className="timeline-empty"><ServerIcon size={34} /><strong>Žádná data k zobrazení</strong><span>Probe scheduler zatím neuložil žádnou kontrolu.</span></div> : <div className="probe-timeline">{visibleProbes.map((probe) => <span key={probe.id} className={`probe-point ${probe.status.toLowerCase()}`} title={`${probe.code} · ${probe.probe_type} · ${probe.status} · ${formatDate(probe.checked_at)}`} />)}</div>}
            <div className="chart-x-axis"><span>18:00</span><span>22:00</span><span>02:00</span><span>06:00</span><span>10:00</span><span>14:00</span></div>
          </div>
        </div>
      </section>
      <section className="panel">
        <div className="panel-head server-panel-head"><h2>Přehled serverů</h2><label className="search-box compact-search"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Hledat podle názvu serveru" aria-label="Hledat podle názvu serveru" /></label></div>
        {servers.length === 0 ? (
          <div className="empty-state server-empty">
            <ServerIcon size={34} /><strong>Katalog MCP serverů je prázdný</strong>
            <p>Spusť automatickou integraci. Server se objeví až po ověření zdrojů, CI, podepsaném OCI deployi a veřejných aktivačních testech.</p>
          </div>
        ) : (
          <table><thead><tr><th>Server</th><th>Hostname</th><th>Registrace</th><th>Provoz</th><th>Volání</th><th>Auth chyby</th><th>Poslední kontrola</th><th>Akce</th></tr></thead>
            <tbody>{filtered.map((server) => <tr key={server.id}><td><strong>{server.displayName}</strong><span className="cell-subtitle">{server.code}</span></td><td>{server.hostname}</td><td><span className="badge neutral">{server.registrationState}</span></td><td><span className="badge ok">{server.operationalState}</span></td><td>{server.successCount}/{server.failureCount}</td><td>{server.unauthorizedCount}</td><td>{formatDate(server.updatedAt)}</td><td><IconButton label={`Detail serveru ${server.displayName}`} onClick={() => setDetailServer(server)}><MoreHorizontal size={17} /></IconButton></td></tr>)}</tbody></table>
        )}
      </section>
      {detailServer ? <ServerDetailModal server={servers.find((server) => server.id === detailServer.id) ?? detailServer} busy={actionBusy} onClose={() => setDetailServer(null)} onAction={(action) => { void onServerAction(detailServer, action); }} /> : null}
    </>
  );
}

function RegistrationPage({ servers, busy, onRegister }: { servers: Server[]; busy: boolean; onRegister: () => Promise<void> }) {
  const existing = servers.find((server) => server.handlerKey === "home_assistant_device_inventory");
  return (
    <>
      <PageHeader title="Registrace MCP serveru" description="Systémem řízené přidělení identity a registrace jednoúčelového KCML handleru" />
      <section className="panel registration-panel">
        <div className="panel-head"><div><h2>Seznam zařízení Home Assistant</h2><p>Read-only nástroj vracející tabulku zařízení, umístění, typů, ovladatelných hodnot, čitelných informací a aktuálních stavů.</p></div><span className={`badge ${existing ? "ok" : "neutral"}`}>{existing ? existing.registrationState : "PŘIPRAVENO"}</span></div>
        <dl className="registration-contract">
          <dt>Tool name</dt><dd><code>get_home_assistant_device_inventory</code></dd>
          <dt>Handler</dt><dd><code>home_assistant_device_inventory@1.0.0</code></dd>
          <dt>Vstup</dt><dd>Prázdný striktní objekt bez parametrů</dd>
          <dt>Výstup</dt><dd>Strukturované řádky a Markdown tabulka, maximálně 2 MiB</dd>
          <dt>Vedlejší účinky</dt><dd>Žádné; pouze čtení přes lokální Home Assistant agent</dd>
          <dt>Identita</dt><dd>{existing ? `${existing.code} · https://${existing.hostname}/mcp` : "Přidělí katalog automaticky"}</dd>
        </dl>
        <div className="notice"><ShieldCheck size={18} /> Token Home Assistantu se do KCML katalogu ani handleru nepřenáší.</div>
        <footer className="modal-actions">
          <button disabled={Boolean(existing) || busy} onClick={() => { void onRegister(); }}><Plus size={17} /> {existing ? "Server je registrován" : "Registrovat server"}</button>
        </footer>
      </section>
    </>
  );
}

function OnboardingJobModal({ jobId, onClose, onResume, onCancel }: { jobId: string; onClose: () => void; onResume: (jobId: string) => void; onCancel: (jobId: string) => Promise<void> }) {
  const [job, setJob] = useState<OnboardingJob | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    void api<{ job: OnboardingJob }>(`/api/onboarding-jobs/${jobId}`).then((result) => setJob(result.job)).catch((err) => setError(err instanceof Error ? err.message : "Detail se nepodařilo načíst"));
  }, [jobId]);
  return (
    <Modal title="Detail onboarding jobu" onClose={onClose}>
      {!job ? <div className="server-detail">{error ? <p className="error">{error}</p> : <p>Načítám detail…</p>}</div> : <div className="job-detail">
        <div className="server-detail-status"><span className={`status-dot ${job.state === "ACTIVE" ? "ok" : ["FAILED", "QUARANTINED", "CANCELLED"].includes(job.state) ? "danger" : "warn"}`} /><strong>{job.state}</strong><span>{job.code ?? "Bez identity"}</span></div>
        <dl className="job-metadata"><dt>Job ID</dt><dd><code>{job.id}</code></dd><dt>Correlation ID</dt><dd><code>{job.correlationId}</code></dd><dt>HTTPS resource</dt><dd>{job.resource ? <a href={job.resource} target="_blank" rel="noreferrer">{job.resource}</a> : "-"}</dd><dt>PR / CI</dt><dd>{job.githubPrUrl ? <a href={job.githubPrUrl} target="_blank" rel="noreferrer">Otevřít pull request</a> : "-"}</dd><dt>Image digest</dt><dd><code>{job.imageDigest ?? "-"}</code></dd><dt>SBOM digest</dt><dd><code>{job.sbomDigest ?? "-"}</code></dd><dt>Revize zdrojů</dt><dd>{job.sourceRevision}</dd></dl>
        {job.blockingErrorCode ? <div className="notice error"><AlertTriangle size={18} /><span><strong>{job.blockingErrorCode}</strong><br />{job.blockingErrorDetail}</span></div> : null}
        <section><h3>Bezpečnostní a aktivační brány</h3><div className="gate-grid">{job.gates?.map((gate) => <article key={gate.gate_name}><span className={`status-dot ${gate.status === "PASS" ? "ok" : ["FAIL", "QUARANTINED"].includes(gate.status) ? "danger" : "warn"}`} /><div><strong>{gate.gate_name}</strong><small>{gate.stage} · {gate.status}</small></div></article>)}</div></section>
        <section><h3>Časová osa</h3><ol className="job-timeline">{job.events?.map((event) => <li key={event.id}><span className="status-dot ok" /><div><strong>{event.event_type}</strong><small>{event.from_state ?? "START"} → {event.to_state} · {formatDate(event.created_at)}</small><code>{event.correlation_id}</code></div></li>)}</ol></section>
        <footer className="modal-actions"><button className="secondary" onClick={onClose}>Zavřít</button>{job.state !== "ACTIVE" && job.state !== "QUARANTINED" && job.state !== "CANCELLED" ? <button className="secondary" onClick={() => onResume(job.id)}>Vystavit navazující token</button> : null}{!["ACTIVE", "FAILED", "QUARANTINED", "CANCELLED"].includes(job.state) ? <button className="danger-button" onClick={() => { void onCancel(job.id); }}>Zrušit job</button> : null}</footer>
      </div>}
    </Modal>
  );
}

function IntegrationTokensPage({ tokens, jobs, onCreate, onOpenJob, onResume, onRevoke, onDelete, onRefresh }: { tokens: IntegrationToken[]; jobs: OnboardingJob[]; onCreate: () => void; onOpenJob: (id: string) => void; onResume: (id: string) => void; onRevoke: (token: IntegrationToken) => void; onDelete: (token: IntegrationToken) => void; onRefresh: () => void }) {
  const [query, setQuery] = useState("");
  const filtered = tokens.filter((token) => `${token.label} ${token.fingerprint} ${token.code ?? ""}`.toLowerCase().includes(query.toLowerCase()));
  return (
    <>
      <PageHeader title="Implementační tokeny" description="Jednorázové 512bitové tokeny pro plně automatický onboarding jednoho MCP serveru.">
        <label className="search-box"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Hledat token, job nebo KCML…" aria-label="Hledat implementační token" /></label>
        <button onClick={onCreate}><Plus size={17} /> Vygenerovat token</button><IconButton label="Obnovit" onClick={onRefresh}><RefreshCw size={17} /></IconButton>
      </PageHeader>
      <section className="panel table-panel"><div className="panel-head"><div><h2>Vydané tokeny</h2><p>Hodnotu tokenu nelze měnit ani znovu zobrazit.</p></div><span className="panel-count">{filtered.length} záznamů</span></div>
        {filtered.length === 0 ? <div className="empty-state"><Workflow size={34} /><strong>Žádné implementační tokeny</strong><p>Vygeneruj první token a předej jej programátorovi bezpečným kanálem.</p></div> : <div className="table-scroll"><table><thead><tr><th>Označení</th><th>Fingerprint</th><th>KCML / job</th><th>Stav</th><th>Aktuální expirace</th><th>Maximum</th><th>Akce</th></tr></thead><tbody>{filtered.map((token) => <tr key={token.id}><td><strong>{token.label}</strong><span className="cell-subtitle">Vydán {formatDate(token.issuedAt)}</span></td><td><code>{token.fingerprint}</code></td><td>{token.code ?? "Čeká na upload"}<span className="cell-subtitle">{token.jobId ? token.jobId.slice(0, 8) : "Nevázaný"}</span></td><td><span className={`badge ${token.active ? "ok" : "danger"}`}>{token.jobState ?? (token.active ? "PŘIPRAVEN" : "NEPLATNÝ")}</span></td><td>{formatDate(token.expiresAt)}</td><td>{formatDate(token.maxExpiresAt)}</td><td><div className="row-actions">{token.jobId ? <button className="small-button" onClick={() => onOpenJob(token.jobId!)}>Detail</button> : null}{token.jobId && !["ACTIVE", "QUARANTINED", "CANCELLED"].includes(token.jobState ?? "") && !token.active ? <button className="small-button" onClick={() => onResume(token.jobId!)}>Navázat</button> : null}<button className="small-button" disabled={!token.active} onClick={() => onRevoke(token)}>Revokovat</button><button className="small-button danger-link" onClick={() => onDelete(token)}>Smazat</button></div></td></tr>)}</tbody></table></div>}
      </section>
      <section className="panel"><div className="panel-head"><h2>Onboardingové joby</h2><span className="panel-count">{jobs.length} jobů</span></div>{jobs.length === 0 ? <div className="empty-state server-empty"><Rocket size={32} /><strong>Zatím nebyl zahájen žádný upload</strong></div> : <div className="job-cards">{jobs.map((job) => <button key={job.id} onClick={() => onOpenJob(job.id)}><span className={`status-dot ${job.state === "ACTIVE" ? "ok" : ["FAILED", "QUARANTINED", "CANCELLED"].includes(job.state) ? "danger" : "warn"}`} /><span><strong>{job.code ?? "Čeká na identitu"}</strong><small>{job.state} · {formatDate(job.updatedAt)}</small></span><ChevronDown className="item-chevron" size={15} /></button>)}</div>}</section>
    </>
  );
}

function TokensPage({ credentials, onOpenCreate, onEditPermissions, onConfirm, onRefresh }: { credentials: KajaCredential[]; onOpenCreate: () => void; onEditPermissions: (id: string) => void; onConfirm: (credential: KajaCredential, action: "revoke" | "delete") => void; onRefresh: () => void }) {
  const [query, setQuery] = useState("");
  const filtered = credentials.filter((credential) => `${credential.label} ${credential.publicId}`.toLowerCase().includes(query.toLowerCase()));
  return (
    <>
      <PageHeader title="Tokeny" description="Správa Kaja tokenů pro přístup k MCP serverům.">
        <label className="search-box"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Hledat tokeny..." aria-label="Hledat tokeny" /></label>
        <button onClick={onOpenCreate}><Plus size={17} /> Založit token</button>
        <IconButton label="Obnovit tokeny" onClick={onRefresh}><RefreshCw size={17} /></IconButton>
      </PageHeader>
      <section className="panel table-panel">
        <div className="panel-head"><div className="heading-with-help"><h2>Přehled tokenů</h2><CircleHelp size={15} /></div><span className="panel-count">{filtered.length} záznamů</span></div>
        {filtered.length === 0 ? <div className="empty-state"><KeyRound size={34} /><strong>Žádné tokeny k zobrazení</strong><p>Vytvoř první token přes primární akci nahoře.</p></div> : (
          <table><thead><tr><th>Označení</th><th>Kaja ID</th><th>Fingerprint</th><th>Stav</th><th>Oprávnění</th><th>Expirace</th><th>Poslední použití</th><th>Akce</th></tr></thead>
            <tbody>{filtered.map((credential) => <tr key={credential.id}><td><strong>{credential.label}</strong></td><td>{credential.publicId}</td><td><code>{credential.fingerprint}</code></td><td><span className={`badge ${statusClass(credential)}`}>{credential.active && !credential.revokedAt ? "Aktivní" : "Revokováno"}</span></td><td>{credential.permissionCount}</td><td>{credential.expiresAt ? formatDate(credential.expiresAt) : "Bez omezení"}</td><td>{formatDate(credential.lastTokenIssuedAt)}</td><td><div className="row-actions"><button className="small-button" onClick={() => onEditPermissions(credential.id)}>Oprávnění</button><button className="small-button" disabled={!credential.active || Boolean(credential.revokedAt)} onClick={() => onConfirm(credential, "revoke")}>Revokovat</button><button className="small-button danger-link" onClick={() => onConfirm(credential, "delete")}>Smazat</button></div></td></tr>)}</tbody></table>
        )}
      </section>
    </>
  );
}

function PermissionsPage({ credentials, servers, selectedId, permissions, saving, onSelect, onChange, onSave }: { credentials: KajaCredential[]; servers: Server[]; selectedId: string | null; permissions: KajaPermission[]; saving: boolean; onSelect: (id: string) => void; onChange: (items: KajaPermission[]) => void; onSave: () => void }) {
  const [query, setQuery] = useState("");
  const selected = credentials.find((credential) => credential.id === selectedId) ?? null;
  const grantedCount = permissions.filter((permission) => permission.granted).length;
  const filteredCredentials = credentials.filter((credential) => `${credential.label} ${credential.publicId}`.toLowerCase().includes(query.toLowerCase()));
  return (
    <>
      <PageHeader title="Správa oprávnění" description="Nastavení přístupu tokenů k MCP serverům">
        <button disabled={!selectedId || saving || servers.length === 0} onClick={onSave}><Save size={16} /> Uložit změny</button>
      </PageHeader>
      <section className="permissions-layout">
        <aside className="token-list-panel">
          <div className="token-list-heading"><strong>Vyberte token</strong><span>{credentials.length}</span></div>
          <label className="search-box full"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Hledat tokeny..." aria-label="Hledat tokeny" /></label>
          <div className="token-list-scroll">
            {filteredCredentials.length === 0 ? <p className="list-empty">Žádný token neodpovídá hledání.</p> : filteredCredentials.map((credential) => <button key={credential.id} className={`token-list-item ${credential.id === selectedId ? "active" : ""}`} onClick={() => onSelect(credential.id)}><span className={`status-dot ${statusClass(credential)}`} /><span className="token-list-copy"><strong>{credential.label}</strong><small>{credential.publicId} · {credential.active && !credential.revokedAt ? "Aktivní" : "Revokováno"}</small></span><ChevronDown className="item-chevron" size={15} /></button>)}
          </div>
        </aside>
        <section className="panel permissions-panel">
          <div className="panel-head"><div><div className="heading-with-help"><h2>Oprávnění k MCP serverům</h2><CircleHelp size={15} /></div><p>{selected ? `${selected.label} má přístup k ${grantedCount} z ${servers.length} serverů.` : "Vyber token v levém panelu."}</p></div>{selected ? <span className="credential-reference">{selected.publicId}</span> : null}</div>
          {!selected ? <div className="empty-state"><LockKeyhole size={34} /><strong>Vyber token pro úpravu práv</strong></div> : servers.length === 0 ? <div className="empty-state"><ServerIcon size={34} /><strong>Nejsou dostupné MCP servery pro přiřazení oprávnění</strong><p>Matice oprávnění je připravená a začne fungovat po registraci prvního serveru.</p></div> : (
            <table><thead><tr><th>Přístup</th><th>MCP server</th><th>Hostname</th><th>Úroveň oprávnění</th><th>Uděleno</th></tr></thead>
              <tbody>{permissions.map((permission) => <tr key={permission.serverId}><td><input type="checkbox" checked={permission.granted} onChange={(event) => onChange(permissions.map((item) => item.serverId === permission.serverId ? { ...item, granted: event.target.checked, accessLevel: event.target.checked ? item.accessLevel ?? "EXECUTE" : null } : item))} /></td><td>{permission.displayName}</td><td>{permission.hostname}</td><td><select disabled={!permission.granted} value={permission.accessLevel ?? "EXECUTE"} onChange={(event) => onChange(permissions.map((item) => item.serverId === permission.serverId ? { ...item, accessLevel: event.target.value as AccessLevel } : item))}>{Object.entries(accessLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></td><td>{formatDate(permission.grantedAt)}</td></tr>)}</tbody></table>
          )}
          <footer className="permissions-foot"><CircleHelp size={15} /><span>Změny oprávnění se projeví okamžitě po uložení.</span></footer>
        </section>
      </section>
    </>
  );
}

function AuditPage({ events }: { events: AuditEvent[] }) {
  const [query, setQuery] = useState("");
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [eventType, setEventType] = useState("all");
  const eventTypes = [...new Set(events.map((event) => event.event_type))];
  const filtered = events.filter((event) => (eventType === "all" || event.event_type === eventType) && `${event.event_type} ${event.actor_type} ${event.object_type} ${event.correlation_id}`.toLowerCase().includes(query.toLowerCase()));
  return (
    <>
      <PageHeader title="Audit" description="Záznam systémových, tokenových a bezpečnostních událostí.">
        <label className="search-box"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Hledat v auditu..." aria-label="Hledat v auditu" /></label>
        <button className="secondary" aria-expanded={filtersOpen} onClick={() => setFiltersOpen((current) => !current)}><SlidersHorizontal size={16} /> Filtry</button>
      </PageHeader>
      {filtersOpen ? <section className="filter-bar"><label>Typ události<select value={eventType} onChange={(event) => setEventType(event.target.value)}><option value="all">Všechny události</option>{eventTypes.map((type) => <option key={type} value={type}>{type}</option>)}</select></label><button className="secondary" onClick={() => { setQuery(""); setEventType("all"); }}>Vymazat filtry</button></section> : null}
      <section className="panel table-panel">
        <table><thead><tr><th>Čas</th><th>Uživatel</th><th>Akce</th><th>Objekt</th><th>Correlation ID</th></tr></thead>
          <tbody>{filtered.map((event) => <tr key={event.id}><td>{formatDate(event.created_at)}</td><td>{event.actor_type}</td><td><span className="badge neutral">{event.event_type}</span></td><td>{event.object_type ?? ""}</td><td><code>{event.correlation_id}</code></td></tr>)}</tbody></table>
        {filtered.length === 0 ? <div className="empty-state"><Terminal size={34} /><strong>Žádné auditní události k zobrazení</strong></div> : null}
      </section>
    </>
  );
}

function Dashboard({ onLogout }: { onLogout: () => void }) {
  const [page, setPage] = useState<Page>("monitoring");
  const [servers, setServers] = useState<Server[]>([]);
  const [credentials, setCredentials] = useState<KajaCredential[]>([]);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [integrationTokens, setIntegrationTokens] = useState<IntegrationToken[]>([]);
  const [onboardingJobs, setOnboardingJobs] = useState<OnboardingJob[]>([]);
  const [probes, setProbes] = useState<MonitoringProbe[]>([]);
  const [selectedCredentialId, setSelectedCredentialId] = useState<string | null>(null);
  const [permissions, setPermissions] = useState<KajaPermission[]>([]);
  const [savingPermissions, setSavingPermissions] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [secret, setSecret] = useState<SecretResult | null>(null);
  const [integrationCreate, setIntegrationCreate] = useState<{ resumeJobId?: string } | null>(null);
  const [integrationSecret, setIntegrationSecret] = useState<IntegrationSecret | null>(null);
  const [integrationConfirm, setIntegrationConfirm] = useState<{ token: IntegrationToken; action: "revoke" | "delete" } | null>(null);
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<{ credential: KajaCredential; action: "revoke" | "delete" } | null>(null);
  const [serverActionBusy, setServerActionBusy] = useState(false);
  const [mcpTestResult, setMcpTestResult] = useState<McpTestResult | null>(null);
  const [error, setError] = useState("");
  async function load() {
    setError("");
    try {
      const [serverRes, credentialRes, auditRes, integrationRes, jobsRes, probesRes] = await Promise.all([
        api<{ servers: Server[] }>("/api/mcp-servers"),
        api<{ credentials: KajaCredential[] }>("/api/kaja"),
        api<{ events: AuditEvent[] }>("/api/audit"),
        api<{ tokens: IntegrationToken[] }>("/api/integration-tokens"),
        api<{ jobs: OnboardingJob[] }>("/api/onboarding-jobs"),
        api<{ probes: MonitoringProbe[] }>("/api/monitoring-probes")
      ]);
      setServers(serverRes.servers);
      setCredentials(credentialRes.credentials);
      setEvents(auditRes.events);
      setIntegrationTokens(integrationRes.tokens);
      setOnboardingJobs(jobsRes.jobs);
      setProbes(probesRes.probes);
      setSelectedCredentialId((current) => current ?? credentialRes.credentials[0]?.id ?? null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Načtení selhalo");
    }
  }

  useEffect(() => { void load(); }, []);
  useEffect(() => {
    if (!selectedCredentialId) {
      setPermissions([]);
      return;
    }
    void api<{ permissions: KajaPermission[] }>(`/api/kaja/${selectedCredentialId}/permissions`)
      .then((result) => setPermissions(result.permissions))
      .catch((err) => setError(err instanceof Error ? err.message : "Načtení oprávnění selhalo"));
  }, [selectedCredentialId]);

  async function savePermissions() {
    if (!selectedCredentialId) return;
    setSavingPermissions(true);
    try {
      await api(`/api/kaja/${selectedCredentialId}/permissions`, {
        method: "PUT",
        headers: { "x-csrf-token": csrf() },
        body: JSON.stringify({ permissions: permissions.filter((permission) => permission.granted).map((permission) => ({ serverId: permission.serverId, accessLevel: permission.accessLevel ?? "EXECUTE" })) })
      });
      await load();
    } finally {
      setSavingPermissions(false);
    }
  }

  async function runConfirm() {
    if (!confirm) return;
    await api(`/api/kaja/${confirm.credential.id}/${confirm.action === "revoke" ? "revoke" : "delete"}`, { method: "POST", headers: { "x-csrf-token": csrf() }, body: "{}" });
    setConfirm(null);
    await load();
  }

  async function runIntegrationConfirm() {
    if (!integrationConfirm) return;
    await api(`/api/integration-tokens/${integrationConfirm.token.id}/${integrationConfirm.action}`, { method: "POST", headers: { "x-csrf-token": csrf() }, body: "{}" });
    setIntegrationConfirm(null);
    await load();
  }

  async function cancelOnboardingJob(jobId: string) {
    await api(`/api/onboarding-jobs/${jobId}/cancel`, { method: "POST", headers: { "x-csrf-token": csrf() }, body: "{}" });
    setSelectedJobId(null);
    await load();
  }

  async function logout() {
    await api("/api/logout", { method: "POST", body: "{}" });
    onLogout();
  }

  function openPermissions(id: string) {
    setSelectedCredentialId(id);
    setPage("permissions");
  }

  async function registerInventoryServer() {
    setServerActionBusy(true);
    setError("");
    try {
      await api("/api/mcp-servers/home-assistant-inventory", { method: "POST", headers: { "x-csrf-token": csrf() }, body: "{}" });
      await load();
      setPage("monitoring");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Registrace selhala");
    } finally {
      setServerActionBusy(false);
    }
  }

  async function runServerAction(server: Server, action: ServerAction) {
    setServerActionBusy(true);
    setError("");
    try {
      const result = await api<unknown>(`/api/mcp-servers/${server.id}/${action}`, { method: "POST", headers: { "x-csrf-token": csrf() }, body: "{}" });
      if (action === "mcp-test") setMcpTestResult(result as McpTestResult);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Operace serveru selhala");
    } finally {
      setServerActionBusy(false);
    }
  }

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand-row"><span className="brand-mark"><ShieldCheck size={22} /></span><div><strong>KCML</strong><span>Správce MCP serverů</span></div></div>
        <nav>
          <button aria-pressed={page === "monitoring"} className={page === "monitoring" ? "active" : ""} onClick={() => setPage("monitoring")}><Activity size={18} /> Monitoring MCP</button>
          <button aria-pressed={page === "registration"} className={page === "registration" ? "active" : ""} onClick={() => setPage("registration")}><Plus size={18} /> Registrace serveru</button>
          <button aria-pressed={page === "integration"} className={page === "integration" ? "active" : ""} onClick={() => setPage("integration")}><Workflow size={18} /> Implementační tokeny</button>
          <button aria-pressed={page === "tokens"} className={page === "tokens" ? "active" : ""} onClick={() => setPage("tokens")}><KeyRound size={18} /> Tokeny</button>
          <button aria-pressed={page === "permissions"} className={page === "permissions" ? "active" : ""} onClick={() => setPage("permissions")}><LockKeyhole size={18} /> Správa oprávnění</button>
          <button aria-pressed={page === "audit"} className={page === "audit" ? "active" : ""} onClick={() => setPage("audit")}><Terminal size={18} /> Audit</button>
        </nav>
        <div className="sidebar-footer"><div className="environment"><span className="status-dot ok" /><span>Production</span></div><div className="account"><span className="avatar">AD</span><span><strong>admin</strong><small>Administrátor</small></span></div><button onClick={() => { void logout(); }}><LogOut size={16} /> Odhlásit se</button></div>
      </aside>
      <section className="workspace">
        <div className="mobile-topbar"><div className="brand-row"><span className="brand-mark"><ShieldCheck size={20} /></span><strong>KCML</strong></div><span>{pageNames[page]}</span></div>
        {error && <div className="notice error"><AlertTriangle size={18} /> {error}</div>}
        {page === "monitoring" && <MonitoringPage servers={servers} probes={probes} actionBusy={serverActionBusy} onRefresh={() => { void load(); }} onAutomatedOnboarding={() => setIntegrationCreate({})} onServerAction={runServerAction} />}
        {page === "registration" && <RegistrationPage servers={servers} busy={serverActionBusy} onRegister={registerInventoryServer} />}
        {page === "integration" && <IntegrationTokensPage tokens={integrationTokens} jobs={onboardingJobs} onCreate={() => setIntegrationCreate({})} onOpenJob={setSelectedJobId} onResume={(jobId) => setIntegrationCreate({ resumeJobId: jobId })} onRevoke={(token) => setIntegrationConfirm({ token, action: "revoke" })} onDelete={(token) => setIntegrationConfirm({ token, action: "delete" })} onRefresh={() => { void load(); }} />}
        {page === "tokens" && <TokensPage credentials={credentials} onOpenCreate={() => setCreateOpen(true)} onEditPermissions={openPermissions} onConfirm={(credential, action) => setConfirm({ credential, action })} onRefresh={() => { void load(); }} />}
        {page === "permissions" && <PermissionsPage credentials={credentials} servers={servers} selectedId={selectedCredentialId} permissions={permissions} saving={savingPermissions} onSelect={setSelectedCredentialId} onChange={setPermissions} onSave={() => { void savePermissions(); }} />}
        {page === "audit" && <AuditPage events={events} />}
      </section>
      {createOpen && <CreateTokenModal serverCount={servers.length} onClose={() => setCreateOpen(false)} onCreated={(created) => { setCreateOpen(false); setSecret(created); void load(); }} />}
      {secret && <SecretModal secret={secret} onClose={() => setSecret(null)} />}
      {mcpTestResult && <McpTestResultModal value={mcpTestResult} onClose={() => setMcpTestResult(null)} />}
      {confirm && <ConfirmModal credential={confirm.credential} action={confirm.action} onClose={() => setConfirm(null)} onConfirm={runConfirm} />}
      {integrationCreate && <CreateIntegrationTokenModal resumeJobId={integrationCreate.resumeJobId} onClose={() => setIntegrationCreate(null)} onCreated={(created) => { setIntegrationCreate(null); setIntegrationSecret(created); setPage("integration"); void load(); }} />}
      {integrationSecret && <IntegrationSecretModal secret={integrationSecret} onClose={() => setIntegrationSecret(null)} />}
      {integrationConfirm && <IntegrationConfirmModal token={integrationConfirm.token} action={integrationConfirm.action} onClose={() => setIntegrationConfirm(null)} onConfirm={runIntegrationConfirm} />}
      {selectedJobId && <OnboardingJobModal jobId={selectedJobId} onClose={() => setSelectedJobId(null)} onResume={(jobId) => { setSelectedJobId(null); setIntegrationCreate({ resumeJobId: jobId }); }} onCancel={cancelOnboardingJob} />}
    </main>
  );
}

function App() {
  const [session, setSession] = useState<Session | null>(null);
  useEffect(() => { void api<Session>("/api/session").then(setSession).catch(() => setSession({ authenticated: false, account: null })); }, []);
  if (!session) return <main className="loading">Načítám</main>;
  return session.authenticated ? <Dashboard onLogout={() => setSession({ authenticated: false, account: null })} /> : <Login onLogin={() => setSession({ authenticated: true, account: "karmar78" })} />;
}

createRoot(document.getElementById("root")!).render(<App />);
