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
  Save,
  Search,
  Server as ServerIcon,
  ShieldCheck,
  SlidersHorizontal,
  Terminal,
  X
} from "lucide-react";
import "./styles.css";

type Page = "monitoring" | "tokens" | "permissions" | "audit";
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
  artifactDigest: string;
  manifestDigest: string;
  successCount: number;
  unauthorizedCount: number;
  failureCount: number;
  lastSuccessAt: string | null;
  lastFailureAt: string | null;
  lastUnauthorizedAt: string | null;
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

const pageNames: Record<Page, string> = {
  monitoring: "Monitoring MCP",
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

function ServerDetailModal({ server, onClose }: { server: Server; onClose: () => void }) {
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
          <dt>Úspěšná volání</dt><dd>{server.successCount}</dd>
          <dt>Chyby autorizace</dt><dd>{server.unauthorizedCount}</dd>
          <dt>Provozní chyby</dt><dd>{server.failureCount}</dd>
          <dt>Poslední úspěch</dt><dd>{formatDate(server.lastSuccessAt)}</dd>
          <dt>Poslední chyba</dt><dd>{formatDate(server.lastFailureAt)}</dd>
        </dl>
        {server.description ? <p>{server.description}</p> : null}
        <footer className="modal-actions"><button type="button" onClick={onClose}>Zavřít detail</button></footer>
      </div>
    </Modal>
  );
}

function MonitoringPage({ servers, onRefresh }: { servers: Server[]; onRefresh: () => void }) {
  const [query, setQuery] = useState("");
  const [timeRange, setTimeRange] = useState("24h");
  const [detailServer, setDetailServer] = useState<Server | null>(null);
  const online = servers.filter((server) => server.enabled && ["ACTIVE", "TRIAL"].includes(server.registrationState)).length;
  const degraded = servers.filter((server) => server.operationalState === "DEGRADED").length;
  const offline = servers.filter((server) => !server.enabled || ["SUSPENDED", "QUARANTINED", "RETIRED"].includes(server.registrationState)).length;
  const filtered = servers.filter((server) => `${server.displayName} ${server.hostname} ${server.code}`.toLowerCase().includes(query.toLowerCase()));
  return (
    <>
      <PageHeader title="Monitoring MCP" description="Přehled stavu a dostupnosti MCP serverů">
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
            <div className="timeline-empty"><ServerIcon size={34} /><strong>Žádná data k zobrazení</strong><span>Nejsou evidované žádné MCP servery.</span></div>
            <div className="chart-x-axis"><span>18:00</span><span>22:00</span><span>02:00</span><span>06:00</span><span>10:00</span><span>14:00</span></div>
          </div>
        </div>
      </section>
      <section className="panel">
        <div className="panel-head server-panel-head"><h2>Přehled serverů</h2><label className="search-box compact-search"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Hledat podle názvu serveru" aria-label="Hledat podle názvu serveru" /></label></div>
        {servers.length === 0 ? (
          <div className="empty-state server-empty">
            <ServerIcon size={34} /><strong>Katalog MCP serverů je prázdný</strong>
            <p>Tokeny lze připravit, ale oprávnění půjde přiřadit až po registraci serveru.</p>
          </div>
        ) : (
          <table><thead><tr><th>Server</th><th>Hostname</th><th>Registrace</th><th>Provoz</th><th>Volání</th><th>Auth chyby</th><th>Poslední kontrola</th><th>Akce</th></tr></thead>
            <tbody>{filtered.map((server) => <tr key={server.id}><td><strong>{server.displayName}</strong><span className="cell-subtitle">{server.code}</span></td><td>{server.hostname}</td><td><span className="badge neutral">{server.registrationState}</span></td><td><span className="badge ok">{server.operationalState}</span></td><td>{server.successCount}/{server.failureCount}</td><td>{server.unauthorizedCount}</td><td>{formatDate(server.updatedAt)}</td><td><IconButton label={`Detail serveru ${server.displayName}`} onClick={() => setDetailServer(server)}><MoreHorizontal size={17} /></IconButton></td></tr>)}</tbody></table>
        )}
      </section>
      {detailServer ? <ServerDetailModal server={detailServer} onClose={() => setDetailServer(null)} /> : null}
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
  const [selectedCredentialId, setSelectedCredentialId] = useState<string | null>(null);
  const [permissions, setPermissions] = useState<KajaPermission[]>([]);
  const [savingPermissions, setSavingPermissions] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [secret, setSecret] = useState<SecretResult | null>(null);
  const [confirm, setConfirm] = useState<{ credential: KajaCredential; action: "revoke" | "delete" } | null>(null);
  const [error, setError] = useState("");
  async function load() {
    setError("");
    try {
      const [serverRes, credentialRes, auditRes] = await Promise.all([
        api<{ servers: Server[] }>("/api/mcp-servers"),
        api<{ credentials: KajaCredential[] }>("/api/kaja"),
        api<{ events: AuditEvent[] }>("/api/audit")
      ]);
      setServers(serverRes.servers);
      setCredentials(credentialRes.credentials);
      setEvents(auditRes.events);
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

  async function logout() {
    await api("/api/logout", { method: "POST", body: "{}" });
    onLogout();
  }

  function openPermissions(id: string) {
    setSelectedCredentialId(id);
    setPage("permissions");
  }

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand-row"><span className="brand-mark"><ShieldCheck size={22} /></span><div><strong>KCML</strong><span>Správce MCP serverů</span></div></div>
        <nav>
          <button aria-pressed={page === "monitoring"} className={page === "monitoring" ? "active" : ""} onClick={() => setPage("monitoring")}><Activity size={18} /> Monitoring MCP</button>
          <button aria-pressed={page === "tokens"} className={page === "tokens" ? "active" : ""} onClick={() => setPage("tokens")}><KeyRound size={18} /> Tokeny</button>
          <button aria-pressed={page === "permissions"} className={page === "permissions" ? "active" : ""} onClick={() => setPage("permissions")}><LockKeyhole size={18} /> Správa oprávnění</button>
          <button aria-pressed={page === "audit"} className={page === "audit" ? "active" : ""} onClick={() => setPage("audit")}><Terminal size={18} /> Audit</button>
        </nav>
        <div className="sidebar-footer"><div className="environment"><span className="status-dot ok" /><span>Production</span></div><div className="account"><span className="avatar">AD</span><span><strong>admin</strong><small>Administrátor</small></span></div><button onClick={() => { void logout(); }}><LogOut size={16} /> Odhlásit se</button></div>
      </aside>
      <section className="workspace">
        <div className="mobile-topbar"><div className="brand-row"><span className="brand-mark"><ShieldCheck size={20} /></span><strong>KCML</strong></div><span>{pageNames[page]}</span></div>
        {error && <div className="notice error"><AlertTriangle size={18} /> {error}</div>}
        {page === "monitoring" && <MonitoringPage servers={servers} onRefresh={() => { void load(); }} />}
        {page === "tokens" && <TokensPage credentials={credentials} onOpenCreate={() => setCreateOpen(true)} onEditPermissions={openPermissions} onConfirm={(credential, action) => setConfirm({ credential, action })} onRefresh={() => { void load(); }} />}
        {page === "permissions" && <PermissionsPage credentials={credentials} servers={servers} selectedId={selectedCredentialId} permissions={permissions} saving={savingPermissions} onSelect={setSelectedCredentialId} onChange={setPermissions} onSave={() => { void savePermissions(); }} />}
        {page === "audit" && <AuditPage events={events} />}
      </section>
      {createOpen && <CreateTokenModal serverCount={servers.length} onClose={() => setCreateOpen(false)} onCreated={(created) => { setCreateOpen(false); setSecret(created); void load(); }} />}
      {secret && <SecretModal secret={secret} onClose={() => setSecret(null)} />}
      {confirm && <ConfirmModal credential={confirm.credential} action={confirm.action} onClose={() => setConfirm(null)} onConfirm={runConfirm} />}
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
