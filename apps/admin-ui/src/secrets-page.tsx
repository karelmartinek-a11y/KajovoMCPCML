import React, { useEffect, useMemo, useState } from "react";
import { Ban, Eye, History, KeyRound, LockKeyhole, Plus, Power, RefreshCw, RotateCw, Search, ShieldAlert, Trash2, Undo2 } from "lucide-react";
import { IconButton, MetricCard, Modal, PageHeader } from "./common.js";
import {
  createManagedSecret,
  createSecretRevealGrant,
  deleteManagedSecret,
  grantManagedSecret,
  auditSecretRevealUiEvent,
  listSecretGrants,
  listSecretVersions,
  revealManagedSecret,
  restoreManagedSecret,
  revokeManagedSecretGrant,
  rotateManagedSecret,
  setManagedSecretStatus
} from "./server-api.js";
import type { ManagedSecret, SecretGrant, SecretVersion } from "./types.js";
import { formatDate } from "./ui-helpers.js";

function SecretFormModal({ onClose, onSaved }: {
  onClose: () => void;
  onSaved: (secret: ManagedSecret) => void;
}) {
  const [stableName, setStableName] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [description, setDescription] = useState("");
  const [value, setValue] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const result = await createManagedSecret({ stableName, displayName, description, value });
      setValue("");
      onSaved(result.secret);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Secret se nepodařilo uložit");
    } finally {
      setBusy(false);
    }
  }
  return <Modal title="Nový secret" onClose={onClose}>
    <form className="modal-form" onSubmit={(event) => { void submit(event); }}>
      <label>Stabilní název<input autoFocus value={stableName} onChange={(event) => setStableName(event.target.value.toUpperCase())} placeholder="NAPR_API_KEY" pattern="[A-Z][A-Z0-9_]{2,127}" /></label>
      <label>Zobrazovaný název<input value={displayName} onChange={(event) => setDisplayName(event.target.value)} maxLength={160} /></label>
      <label>Popis<textarea value={description} onChange={(event) => setDescription(event.target.value)} maxLength={2000} rows={3} /></label>
      <label>Hodnota<input value={value} onChange={(event) => setValue(event.target.value)} type="password" autoComplete="off" /></label>
      {error ? <p className="error">{error}</p> : null}
      <footer className="modal-actions"><button type="button" className="secondary" onClick={onClose} disabled={busy}>Zrušit</button><button type="submit" disabled={busy || !stableName || !displayName || !value}><Plus size={16} /> {busy ? "Ukládám…" : "Uložit secret"}</button></footer>
    </form>
  </Modal>;
}

function RotateSecretModal({ secret, onClose, onSaved }: {
  secret: ManagedSecret;
  onClose: () => void;
  onSaved: (secret: ManagedSecret) => void;
}) {
  const [value, setValue] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const result = await rotateManagedSecret(secret, value);
      setValue("");
      onSaved(result.secret);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Rotace selhala");
    } finally {
      setBusy(false);
    }
  }
  return <Modal title={`Rotovat ${secret.stableName}`} onClose={onClose}>
    <form className="modal-form" onSubmit={(event) => { void submit(event); }}>
      <div className="notice"><ShieldAlert size={18} /><span>Aktivní verze se přepne atomicky. Předchozí verze zůstane v historii bez veřejného resolve přístupu.</span></div>
      <label>Nová hodnota<input autoFocus value={value} onChange={(event) => setValue(event.target.value)} type="password" autoComplete="off" /></label>
      {error ? <p className="error">{error}</p> : null}
      <footer className="modal-actions"><button type="button" className="secondary" onClick={onClose} disabled={busy}>Zrušit</button><button type="submit" disabled={busy || !value}><RotateCw size={16} /> {busy ? "Rotuji…" : "Rotovat"}</button></footer>
    </form>
  </Modal>;
}

function RevealSecretModal({ secret, accountName, onClose }: {
  secret: ManagedSecret;
  accountName: string | null;
  onClose: () => void;
}) {
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [purpose, setPurpose] = useState(`Prohlédnutí ${secret.stableName}`);
  const [value, setValue] = useState("");
  const [expiresAt, setExpiresAt] = useState<string | null>(null);
  const [revealGrantId, setRevealGrantId] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!value || !expiresAt) return undefined;
    const clear = (eventType: "blur" | "visibility_hidden" | "expired" | "cleared") => {
      void auditSecretRevealUiEvent(secret, eventType, revealGrantId);
      setValue("");
      setExpiresAt(null);
      setRevealGrantId(null);
    };
    const timeout = window.setTimeout(() => clear("expired"), Math.max(0, new Date(expiresAt).getTime() - Date.now()));
    const visibility = () => { if (document.hidden) clear("visibility_hidden"); };
    const blur = () => clear("blur");
    window.addEventListener("blur", blur);
    document.addEventListener("visibilitychange", visibility);
    return () => {
      window.clearTimeout(timeout);
      window.removeEventListener("blur", blur);
      document.removeEventListener("visibilitychange", visibility);
    };
  }, [secret, value, expiresAt, revealGrantId]);
  async function reveal(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setValue("");
    setRevealGrantId(null);
    try {
      const grant = await createSecretRevealGrant(secret, { password, totp, purpose });
      const revealed = await revealManagedSecret(secret, grant.revealGrantId);
      setValue(revealed.value);
      setExpiresAt(revealed.expiresAt);
      setRevealGrantId(grant.revealGrantId);
      setPassword("");
      setTotp("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Reveal selhal");
    } finally {
      setBusy(false);
    }
  }
  const forbid = (event: React.SyntheticEvent, eventType: "copy" | "cut" | "contextmenu") => {
    event.preventDefault();
    void auditSecretRevealUiEvent(secret, eventType, revealGrantId);
  };
  return <Modal title={`Reveal ${secret.stableName}`} onClose={() => { if (value) void auditSecretRevealUiEvent(secret, "cleared", revealGrantId); setValue(""); onClose(); }}>
    <form className="modal-form secret-reveal-form" onSubmit={(event) => { void reveal(event); }}>
      <div className="notice error"><ShieldAlert size={18} /><span>Reveal je jednorázový, vyžaduje aktuální heslo i TOTP a po 15 sekundách se vymaže z obrazovky.</span></div>
      <input type="text" autoComplete="username" value={accountName ?? ""} readOnly hidden />
      <label>Účel reveal<input value={purpose} onChange={(event) => setPurpose(event.target.value)} maxLength={240} /></label>
      <label>Heslo administrátora<input value={password} onChange={(event) => setPassword(event.target.value)} type="password" autoComplete="current-password" /></label>
      <label>Aktuální TOTP<input value={totp} onChange={(event) => setTotp(event.target.value)} inputMode="numeric" autoComplete="one-time-code" /></label>
      {value ? <div className="secret-reveal-value" onCopy={(event) => forbid(event, "copy")} onCut={(event) => forbid(event, "cut")} onContextMenu={(event) => forbid(event, "contextmenu")}>
        <small>Viditelné do {expiresAt ? formatDate(expiresAt) : "-"}</small>
        <code>{value}</code>
        <span>{accountName ?? "admin"} · {secret.stableName} · audit {revealGrantId?.slice(0, 8) ?? "-"}</span>
      </div> : null}
      {error ? <p className="error">{error}</p> : null}
      <footer className="modal-actions"><button type="button" className="secondary" onClick={() => { if (value) void auditSecretRevealUiEvent(secret, "cleared", revealGrantId); setValue(""); onClose(); }} disabled={busy}>Zavřít</button><button type="submit" disabled={busy || !password || !totp || !purpose.trim()}><Eye size={16} /> {busy ? "Ověřuji…" : "Reveal"}</button></footer>
    </form>
  </Modal>;
}

function SecretDetailModal({ secret, accountName, onClose, onChanged }: {
  secret: ManagedSecret;
  accountName: string | null;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [grants, setGrants] = useState<SecretGrant[]>([]);
  const [versions, setVersions] = useState<SecretVersion[]>([]);
  const [principalKind, setPrincipalKind] = useState<SecretGrant["principalKind"]>("COMPONENT");
  const [principalId, setPrincipalId] = useState("");
  const [principalPublicId, setPrincipalPublicId] = useState("");
  const [allSecrets, setAllSecrets] = useState(false);
  const [revealOpen, setRevealOpen] = useState(false);
  const [rotateOpen, setRotateOpen] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    void listSecretGrants(secret).then((result) => setGrants(result.grants)).catch((err) => setError(err instanceof Error ? err.message : "Granty se nepodařilo načíst"));
    void listSecretVersions(secret).then((result) => setVersions(result.versions)).catch((err) => setError(err instanceof Error ? err.message : "Verze se nepodařilo načíst"));
  }, [secret]);
  async function addGrant() {
    setError("");
    try {
      const result = await grantManagedSecret(secret, {
        principalKind,
        principalId: principalId.trim() || null,
        principalPublicId: principalPublicId.trim() || null,
        allSecrets
      });
      setGrants(result.grants);
      setPrincipalId("");
      setPrincipalPublicId("");
      setAllSecrets(false);
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Grant se nepodařilo uložit");
    }
  }
  async function revoke(grant: SecretGrant) {
    await revokeManagedSecretGrant(grant);
    setGrants((current) => current.map((item) => item.id === grant.id ? { ...item, revokedAt: new Date().toISOString() } : item));
    onChanged();
  }
  async function removeSecret() {
    await deleteManagedSecret(secret);
    onChanged();
    onClose();
  }
  async function updateStatus(status: "ACTIVE" | "DISABLED") {
    setError("");
    try {
      await setManagedSecretStatus(secret, status);
      onChanged();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Změna stavu selhala");
    }
  }
  async function restore() {
    setError("");
    try {
      await restoreManagedSecret(secret);
      onChanged();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Restore selhal");
    }
  }
  const active = secret.status === "ACTIVE";
  const deleted = secret.status === "DELETED";
  return <>
    <Modal title={`${secret.stableName} · ${secret.displayName}`} onClose={onClose} className="secret-detail-modal">
      <div className="secret-detail">
        <section className="secret-summary-panel">
          <div><small>Verze</small><strong>{secret.activeVersionNumber ?? "-"}</strong></div>
          <div><small>Fingerprint</small><code>{secret.activeFingerprint ?? "-"}</code></div>
          <div><small>Granty</small><strong>{secret.grantCount}</strong></div>
          <div><small>Stav</small><strong>{secret.status}</strong></div>
        </section>
        {deleted ? <div className="notice error"><ShieldAlert size={18} /><span>Secret je soft-deleted. Runtime resolve je vypnutý; restore ho vrátí do DISABLED a granty se z bezpečnostních důvodů automaticky neobnoví.</span></div> : null}
        <section className="secret-grant-editor">
          <h3>Granty</h3>
          <div className="secret-grant-form">
            <label>Typ<select value={principalKind} onChange={(event) => setPrincipalKind(event.target.value as SecretGrant["principalKind"])}><option value="COMPONENT">Prvek</option><option value="KAJA">Přístupový token/KCML přístup</option><option value="INTEGRATION_TOKEN">Integrační token</option></select></label>
            <label>Principal UUID<input value={principalId} onChange={(event) => setPrincipalId(event.target.value)} placeholder="volitelné UUID komponenty / tokenu" /></label>
            <label>Public ID<span className="field-hint">Nikdy nevkládejte plný token kci_…; pro integrační token použijte fingerprint nebo veřejný identifikátor.</span><input value={principalPublicId} onChange={(event) => setPrincipalPublicId(event.target.value)} placeholder="např. přístupový veřejný identifikátor, KCML0001-C01 nebo sha256:…" /></label>
            <label className="checkbox-line"><input type="checkbox" checked={allSecrets} onChange={(event) => setAllSecrets(event.target.checked)} /> Povolit všechny proměnné KCML Secrets pro tuto identitu</label>
            <button type="button" onClick={() => { void addGrant(); }} disabled={deleted || (!principalId.trim() && !principalPublicId.trim())}><LockKeyhole size={16} /> Přidat grant</button>
          </div>
          {grants.length ? <div className="table-scroll"><table><thead><tr><th>Principal</th><th>Identita</th><th>Rozsah</th><th>Vydáno</th><th>Stav</th><th>Akce</th></tr></thead><tbody>{grants.map((grant) => <tr key={grant.id}><td>{grant.principalKind === "COMPONENT" ? "Prvek" : grant.principalKind === "INTEGRATION_TOKEN" ? "Integrační token" : "Přístupový token/KCML přístup"}</td><td><code>{grant.principalPublicId ?? grant.principalId}</code></td><td>{grant.allSecrets ? "Všechny proměnné" : "Tento secret"}</td><td>{formatDate(grant.grantedAt)}</td><td><span className={`badge ${grant.revokedAt ? "danger" : "ok"}`}>{grant.revokedAt ? "REVOKED" : "ACTIVE"}</span></td><td>{grant.revokedAt ? null : <button className="small-button danger-link" onClick={() => { void revoke(grant); }}>Revokovat</button>}</td></tr>)}</tbody></table></div> : <p>Secret zatím nemá žádný grant.</p>}
        </section>
        <section className="secret-grant-editor">
          <h3><History size={16} /> Historie verzí</h3>
          {versions.length ? <div className="table-scroll"><table><thead><tr><th>Verze</th><th>Fingerprint</th><th>Algoritmus</th><th>Vytvořeno</th><th>Retired</th><th>Stav</th></tr></thead><tbody>{versions.map((version) => <tr key={version.id}><td>{version.versionNumber}</td><td><code>{version.fingerprint}</code></td><td>{version.algorithm}</td><td>{formatDate(version.createdAt)}</td><td>{version.retiredAt ? formatDate(version.retiredAt) : "-"}</td><td><span className={`badge ${version.active ? "ok" : "neutral"}`}>{version.active ? "ACTIVE" : "HISTORY"}</span></td></tr>)}</tbody></table></div> : <p>Historie verzí zatím není dostupná.</p>}
        </section>
        {error ? <p className="error">{error}</p> : null}
        <footer className="modal-actions">
          <button type="button" className="secondary" onClick={onClose}>Zavřít</button>
          {deleted ? <button type="button" className="secondary" onClick={() => { void restore(); }}><Undo2 size={16} /> Restore do DISABLED</button> : null}
          {!deleted && active ? <button type="button" className="secondary" onClick={() => { void updateStatus("DISABLED"); }}><Ban size={16} /> Deaktivovat</button> : null}
          {!deleted && !active ? <button type="button" className="secondary" onClick={() => { void updateStatus("ACTIVE"); }}><Power size={16} /> Aktivovat</button> : null}
          <button type="button" className="secondary" onClick={() => setRevealOpen(true)} disabled={!active}><Eye size={16} /> Reveal</button>
          <button type="button" className="secondary" onClick={() => setRotateOpen(true)} disabled={deleted}><RotateCw size={16} /> Rotovat</button>
          <button type="button" className="danger-button" onClick={() => { void removeSecret(); }} disabled={deleted}><Trash2 size={16} /> Smazat</button>
        </footer>
      </div>
    </Modal>
    {revealOpen ? <RevealSecretModal secret={secret} accountName={accountName} onClose={() => setRevealOpen(false)} /> : null}
    {rotateOpen ? <RotateSecretModal secret={secret} onClose={() => setRotateOpen(false)} onSaved={() => { setRotateOpen(false); onChanged(); }} /> : null}
  </>;
}

export function SecretsPage({ secrets, accountName, onRefresh }: {
  secrets: ManagedSecret[];
  accountName: string | null;
  onRefresh: () => void;
}) {
  const [query, setQuery] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [selected, setSelected] = useState<ManagedSecret | null>(null);
  const filtered = useMemo(() => secrets.filter((secret) => `${secret.stableName} ${secret.displayName} ${secret.description}`.toLowerCase().includes(query.toLowerCase())), [secrets, query]);
  return <>
    <PageHeader title="Secrets" description="Centrální správa stabilních secret názvů, verzí a grantů pro komponenty a přístupové tokeny.">
      <label className="search-box"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Hledat secret…" aria-label="Hledat secret" /></label>
      <button onClick={() => setCreateOpen(true)}><Plus size={17} /> Nový secret</button>
      <IconButton label="Obnovit secrets" onClick={onRefresh}><RefreshCw size={17} /></IconButton>
    </PageHeader>
    <section className="metric-row">
      <MetricCard tone="neutral" icon={<KeyRound size={22} />} value={secrets.length} label="Secrets celkem" />
      <MetricCard tone="success" icon={<LockKeyhole size={22} />} value={secrets.filter((secret) => secret.status === "ACTIVE").length} label="Aktivní" />
      <MetricCard tone="warning" icon={<RotateCw size={22} />} value={secrets.reduce((sum, secret) => sum + (secret.activeVersionNumber ?? 0), 0)} label="Součet verzí" />
      <MetricCard tone="danger" icon={<ShieldAlert size={22} />} value={secrets.filter((secret) => secret.grantCount === 0).length} label="Bez grantů" />
    </section>
    <section className="panel table-panel">
      <div className="panel-head"><div><h2>Spravované secrets</h2><p>Public API resolvuje pouze stabilní název a jen pro explicitně grantované identity.</p></div><span className="panel-count">{filtered.length} záznamů</span></div>
      {filtered.length ? <div className="table-scroll"><table><thead><tr><th>Název</th><th>Popis</th><th>Stav</th><th>Verze</th><th>Fingerprint</th><th>Granty</th><th>Aktualizace</th><th>Akce</th></tr></thead><tbody>{filtered.map((secret) => <tr key={secret.id}><td><strong>{secret.displayName}</strong><span className="cell-subtitle"><code>{secret.stableName}</code></span></td><td>{secret.description || "-"}<span className="cell-subtitle">{secret.ownerKind}</span></td><td><span className={`badge ${secret.status === "ACTIVE" ? "ok" : secret.status === "DELETED" ? "danger" : "warn"}`}>{secret.status}</span></td><td>{secret.activeVersionNumber ?? "-"}</td><td><code>{secret.activeFingerprint ?? "-"}</code></td><td>{secret.grantCount}</td><td>{formatDate(secret.updatedAt)}</td><td><button className="small-button" onClick={() => setSelected(secret)}>Detail</button></td></tr>)}</tbody></table></div> : <div className="empty-state"><KeyRound size={34} /><strong>Žádný secret neodpovídá filtrům</strong></div>}
    </section>
    {createOpen ? <SecretFormModal onClose={() => setCreateOpen(false)} onSaved={() => { setCreateOpen(false); onRefresh(); }} /> : null}
    {selected ? <SecretDetailModal secret={selected} accountName={accountName} onClose={() => setSelected(null)} onChanged={onRefresh} /> : null}
  </>;
}
