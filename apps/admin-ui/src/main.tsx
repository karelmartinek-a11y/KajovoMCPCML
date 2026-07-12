import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { Activity, Ban, Database, KeyRound, LogOut, RefreshCw, Save, Server as ServerIcon, ShieldCheck, Terminal, Trash2, TriangleAlert } from "lucide-react";
import "./styles.css";

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
type KajaPermission = {
  serverId: string;
  code: string;
  hostname: string;
  displayName: string;
  granted: boolean;
  grantedAt: string | null;
};
type AuditEvent = { id: number; event_type: string; actor_type: string; object_type: string; object_id: string; correlation_id: string; created_at: string };

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { credentials: "include", headers: { "content-type": "application/json", ...(init?.headers ?? {}) }, ...init });
  if (!res.ok) {
    const body = await res.json().catch((): { error?: string } => ({ error: res.statusText })) as { error?: string };
    throw new Error(body.error ?? res.statusText);
  }
  return res.json() as Promise<T>;
}

function csrf(): string {
  return document.cookie.split("; ").find((row) => row.startsWith("__Host-kcml_csrf="))?.split("=")[1] ?? "";
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

function Dashboard({ onLogout }: { onLogout: () => void }) {
  const [servers, setServers] = useState<Server[]>([]);
  const [credentials, setCredentials] = useState<KajaCredential[]>([]);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [secret, setSecret] = useState<{ publicId: string; label: string; clientSecret: string; fingerprint: string; expiresAt: string | null } | null>(null);
  const [newCredentialLabel, setNewCredentialLabel] = useState("");
  const [newCredentialExpiresAt, setNewCredentialExpiresAt] = useState("");
  const [selectedCredentialId, setSelectedCredentialId] = useState<string | null>(null);
  const [permissions, setPermissions] = useState<KajaPermission[]>([]);
  const [savingPermissions, setSavingPermissions] = useState(false);
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
  async function createKaja(event: React.FormEvent) {
    event.preventDefault();
    const label = newCredentialLabel.trim();
    if (!label) {
      setError("Zadej označení tokenu.");
      return;
    }
    setSecret(await api("/api/kaja", {
      method: "POST",
      headers: { "x-csrf-token": csrf() },
      body: JSON.stringify({ label, expiresAt: newCredentialExpiresAt ? new Date(newCredentialExpiresAt).toISOString() : null })
    }));
    setNewCredentialLabel("");
    setNewCredentialExpiresAt("");
    await load();
  }
  useEffect(() => {
    if (!selectedCredentialId) {
      setPermissions([]);
      return;
    }
    void api<{ permissions: KajaPermission[] }>(`/api/kaja/${selectedCredentialId}/permissions`)
      .then((result) => setPermissions(result.permissions))
      .catch((err) => setError(err instanceof Error ? err.message : "Načtení oprávnění selhalo"));
  }, [selectedCredentialId]);
  async function revokeCredential(id: string) {
    await api(`/api/kaja/${id}/revoke`, { method: "POST", headers: { "x-csrf-token": csrf() }, body: "{}" });
    await load();
  }
  async function deleteCredential(id: string) {
    await api(`/api/kaja/${id}/delete`, { method: "POST", headers: { "x-csrf-token": csrf() }, body: "{}" });
    if (selectedCredentialId === id) setSelectedCredentialId(null);
    await load();
  }
  async function savePermissions() {
    if (!selectedCredentialId) return;
    setSavingPermissions(true);
    try {
      await api(`/api/kaja/${selectedCredentialId}/permissions`, {
        method: "PUT",
        headers: { "x-csrf-token": csrf() },
        body: JSON.stringify({ serverIds: permissions.filter((permission) => permission.granted).map((permission) => permission.serverId) })
      });
      await load();
    } finally {
      setSavingPermissions(false);
    }
  }
  async function logout() {
    await api("/api/logout", { method: "POST", body: "{}" });
    onLogout();
  }
  return (
    <main className="app-shell">
      <aside>
        <div className="brand-row"><ShieldCheck size={24} /><strong>KCML</strong></div>
        <nav>
          <a className="active"><Activity size={18} /> Monitoring</a>
          <a><ServerIcon size={18} /> MCP servery</a>
          <a><KeyRound size={18} /> Tokeny</a>
          <a><Terminal size={18} /> Audit</a>
        </nav>
      </aside>
      <section className="workspace">
        <header>
          <div><h1>Produkční správa</h1><p>Nultá verze bez registrovaných MCP serverů je platný bezpečný stav.</p></div>
          <div className="actions">
            <button onClick={() => { void load(); }}><RefreshCw size={17} /> Obnovit</button>
            <button onClick={() => { void logout(); }}><LogOut size={17} /> Odhlásit</button>
          </div>
        </header>
        {error && <div className="notice error"><TriangleAlert size={18} /> {error}</div>}
        <section className="metrics">
          <article><span>Katalog</span><strong>{servers.length}</strong><small>registrovaných KCML serverů</small></article>
          <article><span>Tokeny</span><strong>{credentials.length}</strong><small>Kaja pověření v evidenci</small></article>
          <article><span>Audit</span><strong>{events.length}</strong><small>posledních událostí</small></article>
          <article><span>Aktivní access tokeny</span><strong>{credentials.reduce((sum, item) => sum + item.activeAccessTokenCount, 0)}</strong><small>krátkodobých Bearer tokenů</small></article>
          <article><span>Fail-closed</span><strong>ON</strong><small>neznámé hosty se odmítají</small></article>
        </section>
        <section className="panel">
          <div className="panel-head"><h2>MCP servery</h2><span className="panel-count">{servers.length} záznamů</span></div>
          {servers.length === 0 ? <div className="empty">Katalog je prázdný. Žádná demo data nebyla vytvořena.</div> : (
            <table><thead><tr><th>Kód</th><th>Název</th><th>Hostname</th><th>Tool</th><th>Registrace</th><th>Provoz</th><th>Zapnuto</th><th>Volání</th><th>Auth chyby</th><th>Handler</th><th>Kontrakt</th><th>Aktualizace</th></tr></thead>
              <tbody>{servers.map((server) => <tr key={server.id}><td>{server.code}</td><td>{server.displayName}</td><td>{server.hostname}</td><td>{server.toolName}</td><td>{server.registrationState}</td><td>{server.operationalState}</td><td>{server.enabled ? "Ano" : "Ne"}</td><td>{server.successCount}/{server.failureCount}</td><td>{server.unauthorizedCount}</td><td>{server.handlerKey}@{server.handlerVersion}</td><td>{server.contractVersion}</td><td>{new Date(server.updatedAt).toLocaleString()}</td></tr>)}</tbody></table>
          )}
        </section>
        <section className="panel">
          <div className="panel-head"><h2>Tokeny a Kaja pověření</h2><span className="panel-count">{credentials.length} záznamů</span></div>
          <form className="inline-form" onSubmit={(event) => { void createKaja(event); }}>
            <label>Označení tokenu<input value={newCredentialLabel} onChange={(event) => setNewCredentialLabel(event.target.value)} maxLength={120} placeholder="např. Produkční klient Fakturace" /></label>
            <label>Expirace pověření<input value={newCredentialExpiresAt} onChange={(event) => setNewCredentialExpiresAt(event.target.value)} type="datetime-local" /></label>
            <button type="submit"><KeyRound size={16} /> Vygenerovat token</button>
          </form>
          {secret && <div className="secret-once"><strong>{secret.label} · {secret.publicId}</strong><code>{secret.clientSecret}</code><span>Fingerprint {secret.fingerprint}. Expirace {secret.expiresAt ? new Date(secret.expiresAt).toLocaleString() : "bez omezení"}. Plná hodnota se zobrazuje přesně jednou.</span></div>}
          {credentials.length === 0 ? <div className="empty">Zatím není vytvořené žádné Kaja pověření. Nový token musí mít označení.</div> : (
            <table><thead><tr><th>Označení</th><th>Kaja ID</th><th>Fingerprint</th><th>Stav</th><th>Expirace</th><th>Oprávnění</th><th>Aktivní access tokeny</th><th>Vytvořeno</th><th>Aktualizováno</th><th>Poslední token</th><th>Akce</th></tr></thead>
              <tbody>{credentials.map((credential) => <tr key={credential.id} className={selectedCredentialId === credential.id ? "selected-row" : undefined}><td><button className="link-button" onClick={() => setSelectedCredentialId(credential.id)}>{credential.label}</button></td><td>{credential.publicId}</td><td><code>{credential.fingerprint}</code></td><td>{credential.active && !credential.revokedAt ? "Aktivní" : "Revokováno"}</td><td>{credential.expiresAt ? new Date(credential.expiresAt).toLocaleString() : "Bez omezení"}</td><td>{credential.permissionCount}</td><td>{credential.activeAccessTokenCount}</td><td>{new Date(credential.createdAt).toLocaleString()}</td><td>{new Date(credential.updatedAt).toLocaleString()}</td><td>{credential.lastTokenIssuedAt ? new Date(credential.lastTokenIssuedAt).toLocaleString() : "-"}</td><td><div className="row-actions"><button disabled={!credential.active || Boolean(credential.revokedAt)} onClick={() => { void revokeCredential(credential.id); }}><Ban size={15} /> Revokovat</button><button onClick={() => { void deleteCredential(credential.id); }}><Trash2 size={15} /> Smazat</button></div></td></tr>)}</tbody></table>
          )}
        </section>
        <section className="panel">
          <div className="panel-head"><h2>Oprávnění k MCP serverům</h2><button disabled={!selectedCredentialId || savingPermissions || servers.length === 0} onClick={() => { void savePermissions(); }}><Save size={16} /> Uložit oprávnění</button></div>
          {!selectedCredentialId ? <div className="empty">Vyber token v přehledu pověření.</div> : servers.length === 0 ? <div className="empty">Nejsou registrované žádné MCP servery. Přehled oprávnění je proto prázdný, ale backend endpoint je dostupný a vrací prázdnou matici.</div> : (
            <table><thead><tr><th>Povoleno</th><th>Kód</th><th>Název</th><th>Hostname</th><th>Uděleno</th></tr></thead>
              <tbody>{permissions.map((permission) => <tr key={permission.serverId}><td><input aria-label={`Oprávnění ${permission.code}`} type="checkbox" checked={permission.granted} onChange={(event) => setPermissions((items) => items.map((item) => item.serverId === permission.serverId ? { ...item, granted: event.target.checked } : item))} /></td><td>{permission.code}</td><td>{permission.displayName}</td><td>{permission.hostname}</td><td>{permission.grantedAt ? new Date(permission.grantedAt).toLocaleString() : "-"}</td></tr>)}</tbody></table>
          )}
        </section>
        <section className="panel">
          <div className="panel-head"><h2>Provozní přehled</h2><Database size={18} /></div>
          <div className="overview-grid">
            <article><span>Registrované aktivní servery</span><strong>{servers.filter((server) => server.registrationState === "ACTIVE").length}</strong></article>
            <article><span>Vypnuté / prázdné zdroje</span><strong>{servers.filter((server) => !server.enabled).length}</strong></article>
            <article><span>Neautorizované pokusy</span><strong>{servers.reduce((sum, server) => sum + server.unauthorizedCount, 0)}</strong></article>
          </div>
        </section>
        <section className="panel">
          <h2>Audit</h2>
          <table><thead><tr><th>ID</th><th>Událost</th><th>Objekt</th><th>Čas UTC</th><th>Correlation ID</th></tr></thead>
            <tbody>{events.map((event) => <tr key={event.id}><td>{event.id}</td><td>{event.event_type}</td><td>{event.object_type ?? ""}</td><td>{new Date(event.created_at).toISOString()}</td><td><code>{event.correlation_id}</code></td></tr>)}</tbody></table>
        </section>
      </section>
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
