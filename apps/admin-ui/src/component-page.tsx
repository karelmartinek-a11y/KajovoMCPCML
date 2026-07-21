import React, { useMemo, useState } from "react";
import { Activity, Boxes, CheckCircle2, KeyRound, MoreHorizontal, RefreshCw, Search, ShieldAlert } from "lucide-react";
import { IconButton, MetricCard, Modal, PageHeader } from "./common.js";
import type { AdminRole, Component } from "./types.js";
import { formatDate, prettyJson } from "./ui-helpers.js";

function tone(value: string): "ok" | "warn" | "danger" | "neutral" {
  if (["ACTIVE", "HEALTHY", "PASSED", "CONTIGUOUS", "READY"].includes(value)) return "ok";
  if (["PENDING", "DEGRADED", "DUE", "IN_REVIEW", "UNKNOWN", "ENABLE_REQUESTED", "DISABLE_REQUESTED", "ACK_PENDING", "ACKED", "STATE_CONFIRMED", "HEARTBEAT_CONFIRMED", "READY_FOR_ACTIVATION"].includes(value)) return "warn";
  if (["FAILED", "QUARANTINED", "OVERDUE", "BLOCKED", "UNAVAILABLE", "GAP_DETECTED", "DISABLED", "DISABLE_UNCONFIRMED", "REJECTED", "CONFLICT", "BROKEN"].includes(value)) return "danger";
  return "neutral";
}

function ComponentDetail({ component, role, busy, onClose, onToggle, onLifecycle, onPermission, onCredentialRevoke, onCredentialRotate }: {
  component: Component;
  role: AdminRole;
  busy: boolean;
  onClose: () => void;
  onToggle: (component: Component, enabled: boolean) => Promise<void>;
  onLifecycle: (component: Component, action: "QUARANTINE" | "RESTORE" | "RETIRE" | "DEREGISTER") => Promise<void>;
  onPermission: (component: Component, permissionId: string, enabled: boolean) => Promise<void>;
  onCredentialRevoke: (component: Component, credentialId: string) => Promise<void>;
  onCredentialRotate: (component: Component, credentialId: string) => Promise<{ clientId: string; clientSecret: string; fingerprint: string }>;
}) {
  const [credentialSecret, setCredentialSecret] = useState<{ clientId: string; clientSecret: string; fingerprint: string } | null>(null);
  function confirmed(message: string, action: () => void) {
    if (window.confirm(message)) action();
  }
  return <Modal title={`${component.code} · ${component.displayName}`} onClose={onClose} className="component-detail-modal">
    <div className="component-detail-hero">
      <div><span className={`badge ${tone(component.activationState)}`}>{component.activationState}</span><span className={`badge ${tone(component.operationalState)}`}>{component.operationalState}</span></div>
      <code>{component.hostname}</code>
    </div>
    <div className="component-detail-grid">
      <section><h3>Identita a katalog</h3><dl><dt>Kategorie</dt><dd>{component.category}</dd><dt>Registrační typ</dt><dd>{component.registrationType}</dd><dt>Role</dt><dd>{component.role}</dd><dt>Release</dt><dd>{component.releaseVersion}</dd><dt>Revize</dt><dd>{component.revision ?? "-"}</dd><dt>Policy epoch</dt><dd>{component.policyEpoch}</dd></dl></section>
      <section><h3>Oddělené stavy</h3><dl><dt>Lifecycle</dt><dd><span className={`badge ${tone(component.lifecycleState)}`}>{component.lifecycleState}</span></dd><dt>Aktivace</dt><dd>{component.activationState}</dd><dt>Provoz</dt><dd>{component.operationalState}</dd><dt>Monitoring</dt><dd>{component.monitoringState}</dd><dt>Recertifikace</dt><dd>{component.recertificationState}</dd></dl></section>
      <section><h3>Směry provozu</h3><dl><dt>Ingress</dt><dd>{component.ingressEnabled ? "Povolen" : "Blokován"}</dd><dt>Pulse</dt><dd>{component.pulseEnabled ? "Povolen" : "Blokován"}</dd><dt>Egress</dt><dd>{component.egressEnabled ? "Povolen" : "Blokován"}</dd></dl></section>
      <section><h3>Auditní kontinuita</h3><dl><dt>Mezera</dt><dd><span className={`badge ${tone(component.audit.gapState)}`}>{component.audit.gapState}</span></dd><dt>Integrita</dt><dd><span className={`badge ${tone(component.audit.integrityState)}`}>{component.audit.integrityState}</span></dd><dt>Přijato</dt><dd>{component.audit.highestReceivedSequence}</dd><dt>Potvrzeno</dt><dd>{component.audit.highestAcknowledgedSequence}</dd></dl></section>
    </div>
    <section className="component-detail-section"><h3>Audit hash-chain</h3><dl><dt>Aktuální hash</dt><dd><code>{component.audit.currentEventHash ?? "-"}</code></dd><dt>Důvod integrity</dt><dd>{component.audit.integrityReason ?? "bez konfliktu"}</dd></dl></section>
    <section className="component-detail-section"><h3>Capabilities, protokoly a transporty</h3><div className="chip-list">{component.capabilities.map((value) => <span key={value}>{value}</span>)}{component.capabilities.length === 0 ? <em>Žádné deklarované capabilities</em> : null}</div><p>Protokoly: {component.protocols.join(", ") || "-"} · Transporty: {component.transports.join(", ") || "-"}</p></section>
    <section className="component-detail-section"><h3>Příchozí a odchozí oprávnění</h3>{component.permissions?.length ? <div className="table-scroll"><table><thead><tr><th>Směr</th><th>Scope</th><th>Route</th><th>Stav</th>{role !== "AUDITOR" ? <th>Akce</th> : null}</tr></thead><tbody>{component.permissions.map((permission) => <tr key={permission.id}><td>{permission.target_component_id === component.id ? "Příchozí" : "Odchozí"}</td><td>{permission.scope_name}</td><td><code>{permission.route_pattern}</code></td><td>{permission.revoked_at ? "Revokováno" : "Platné"}</td>{role !== "AUDITOR" ? <td><button className="secondary compact-button" disabled={busy} onClick={() => confirmed(permission.revoked_at ? "Obnovit toto směrované oprávnění?" : "Odebrat toto směrované oprávnění? Aktivní volání budou okamžitě odmítnuta.", () => { void onPermission(component, permission.id, Boolean(permission.revoked_at)); })}>{permission.revoked_at ? "Obnovit" : "Odebrat"}</button></td> : null}</tr>)}</tbody></table></div> : <p>Komponenta nemá směrovaná oprávnění.</p>}</section>
    <section className="component-detail-section"><h3>Dlouhodobé client credentials</h3>{component.credentials?.length ? <div className="table-scroll"><table><thead><tr><th>Client ID</th><th>Fingerprint</th><th>Stav</th><th>Naposledy použito</th>{role !== "AUDITOR" ? <th>Akce</th> : null}</tr></thead><tbody>{component.credentials.map((credential) => <tr key={credential.id}><td>{credential.public_id}</td><td><code>{credential.secret_fingerprint}</code></td><td>{credential.status}</td><td>{formatDate(credential.last_used_at)}</td>{role !== "AUDITOR" ? <td><div className="inline-actions"><button className="secondary compact-button" disabled={busy || credential.status !== "ACTIVE"} onClick={() => confirmed("Rotovat dlouhodobý client credential? Současný credential i z něj vydané krátkodobé bearer tokeny budou explicitně revokovány.", () => { void onCredentialRotate(component, credential.id).then(setCredentialSecret); })}>Rotovat</button><button className="danger-button compact-button" disabled={busy || credential.status !== "ACTIVE"} onClick={() => confirmed("Nevratně revokovat tento dlouhodobý client credential?", () => { void onCredentialRevoke(component, credential.id); })}>Revokovat</button></div></td> : null}</tr>)}</tbody></table></div> : <p>Žádný dlouhodobý client credential. Uložené secret values se standardně nezobrazují; nový client secret lze zobrazit pouze jednorázově při vytvoření nebo rotaci.</p>}</section>
    {credentialSecret ? <section className="component-secret-reveal" role="status"><h3>Nový client secret - zobrazí se pouze nyní</h3><dl><dt>Client ID</dt><dd><code>{credentialSecret.clientId}</code></dd><dt>Client secret</dt><dd><code>{credentialSecret.clientSecret}</code></dd><dt>Fingerprint</dt><dd><code>{credentialSecret.fingerprint}</code></dd></dl><p>Po skrytí už tuto hodnotu nelze načíst znovu a její zobrazení je auditováno.</p><button className="secondary" onClick={() => setCredentialSecret(null)}>Rozumím, skrýt secret</button></section> : null}
    <section className="component-detail-section"><h3>Readiness gates</h3>{component.readinessGates?.length ? <div className="table-scroll"><table><thead><tr><th>Gate</th><th>Stav</th><th>Reason</th><th>Evaluator</th><th>Čas</th></tr></thead><tbody>{component.readinessGates.map((gate) => <tr key={`${gate.gate_key}-${gate.correlation_id}`}><td>{gate.gate_key}</td><td><span className={`badge ${tone(gate.status)}`}>{gate.status}</span></td><td>{gate.reason_code}</td><td>{gate.evaluator_version}</td><td>{formatDate(gate.executed_at)}</td></tr>)}</tbody></table></div> : <p>Zatím nejsou dostupné žádné důkazní readiness gates.</p>}</section>
    <section className="component-detail-section"><h3>Control command timeline</h3>{component.controlDispatches?.length ? <div className="table-scroll"><table><thead><tr><th>Příkaz</th><th>Stav</th><th>Policy epoch</th><th>Deadline</th><th>ACK digest</th></tr></thead><tbody>{component.controlDispatches.map((dispatch) => <tr key={dispatch.id}><td>{dispatch.command_type}<span className="cell-subtitle"><code>{dispatch.target_hostname}{dispatch.endpoint_path}</code></span></td><td><span className={`badge ${tone(dispatch.state)}`}>{dispatch.state}</span><span className="cell-subtitle">{dispatch.final_error_code ?? "bez chyby"}</span></td><td>{dispatch.requested_policy_epoch}</td><td>{formatDate(dispatch.deadline_at)}</td><td><code>{dispatch.ack_digest ?? "-"}</code></td></tr>)}</tbody></table></div> : <p>Zatím nebyl zaevidován žádný control command.</p>}</section>
    <section className="component-detail-section"><h3>State observations</h3>{component.stateObservations?.length ? <div className="table-scroll"><table><thead><tr><th>State</th><th>Validace</th><th>Client ID</th><th>Policy epoch</th><th>Čas</th></tr></thead><tbody>{component.stateObservations.map((state) => <tr key={state.id}><td>{state.state_key}</td><td><span className={`badge ${tone(state.validation_state)}`}>{state.validation_state}</span><span className="cell-subtitle">{state.rejection_reason ?? "schema OK"}</span></td><td><code>{state.declared_client_id ?? "-"}</code></td><td>{state.policy_epoch ?? "-"}</td><td>{formatDate(state.observed_at)}</td></tr>)}</tbody></table></div> : <p>Zatím nejsou dostupná žádná state observations.</p>}</section>
    <section className="component-detail-section"><h3>Heartbeat historie</h3>{component.heartbeatHistory?.length ? <div className="table-scroll"><table><thead><tr><th>Heartbeat</th><th>Validace</th><th>Stav</th><th>Challenge</th></tr></thead><tbody>{component.heartbeatHistory.map((heartbeat) => <tr key={heartbeat.id}><td>{formatDate(heartbeat.heartbeat_at)}<span className="cell-subtitle"><code>{heartbeat.declared_client_id ?? "-"}</code></span></td><td><span className={`badge ${tone(heartbeat.validation_state)}`}>{heartbeat.validation_state}</span><span className="cell-subtitle">{heartbeat.rejection_reason ?? "kontrola prošla"}</span></td><td>{heartbeat.operational_state}</td><td><code>{heartbeat.challenge_id ?? "-"}</code></td></tr>)}</tbody></table></div> : <p>Zatím nejsou dostupné žádné heartbeat záznamy.</p>}</section>
    <details className="component-json"><summary>Vlastníci a kontakty</summary><pre>{prettyJson({ owners: component.owners, contacts: component.contacts })}</pre></details>
    <footer className="modal-actions"><button className="secondary" onClick={onClose}>Zavřít</button>{role !== "AUDITOR" ? <><button disabled={busy || component.lifecycleState === "RETIRED" || component.lifecycleState === "DEREGISTERED"} className={component.enabled ? "danger-button" : ""} onClick={() => confirmed(component.enabled ? "Vyžádat deaktivaci komponenty? Ingress, Pulse i egress budou uzavřeny okamžitě, krátkodobé bearer tokeny revokovány a finální deaktivace zůstane fail-closed do potvrzení ACK a stavu." : "Vyžádat aktivaci komponenty? Provoz se otevře až po ACK, state query a heartbeat challenge.", () => { void onToggle(component, !component.enabled); })}>{component.enabled ? "Vyžádat deaktivaci" : "Vyžádat aktivaci"}</button>{component.lifecycleState === "QUARANTINED" ? <button disabled={busy} onClick={() => confirmed("Uvolnit komponentu z karantény do stavu připraveno?", () => { void onLifecycle(component, "RESTORE"); })}>Uvolnit z karantény</button> : <button className="danger-button" disabled={busy || component.lifecycleState === "RETIRED" || component.lifecycleState === "DEREGISTERED"} onClick={() => confirmed("Umístit komponentu do karantény? Veškerý provoz bude zablokován.", () => { void onLifecycle(component, "QUARANTINE"); })}>Karanténa</button>}<button className="danger-button" disabled={busy || component.lifecycleState === "RETIRED" || component.lifecycleState === "DEREGISTERED"} onClick={() => confirmed("Vyřadit komponentu z provozu?", () => { void onLifecycle(component, "RETIRE"); })}>Vyřadit</button>{component.lifecycleState === "RETIRED" ? <button className="danger-button" disabled={busy} onClick={() => confirmed("Odregistrovat vyřazenou komponentu? Tuto operaci nelze vrátit přes GUI.", () => { void onLifecycle(component, "DEREGISTER"); })}>Odregistrovat</button> : null}</> : null}</footer>
  </Modal>;
}

export function ComponentCatalogPage({ components, role, onRefresh, onLoadDetail, onToggle, onLifecycle, onPermission, onCredentialRevoke, onCredentialRotate }: {
  components: Component[];
  role: AdminRole;
  onRefresh: () => void;
  onLoadDetail: (id: string) => Promise<Component>;
  onToggle: (component: Component, enabled: boolean) => Promise<Component>;
  onLifecycle: (component: Component, action: "QUARANTINE" | "RESTORE" | "RETIRE" | "DEREGISTER") => Promise<Component>;
  onPermission: (component: Component, permissionId: string, enabled: boolean) => Promise<Component>;
  onCredentialRevoke: (component: Component, credentialId: string) => Promise<Component>;
  onCredentialRotate: (component: Component, credentialId: string) => Promise<{ component: Component; credential: { clientId: string; clientSecret: string; fingerprint: string } }>;
}) {
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("ALL");
  const [lifecycle, setLifecycle] = useState("ALL");
  const [selected, setSelected] = useState<Component | null>(null);
  const [busy, setBusy] = useState(false);
  const categories = useMemo(() => [...new Set(components.map((component) => component.category))].sort(), [components]);
  const filtered = components.filter((component) => {
    const search = `${component.code} ${component.displayName} ${component.hostname} ${component.capabilities.join(" ")}`.toLowerCase();
    return search.includes(query.toLowerCase()) && (category === "ALL" || component.category === category) && (lifecycle === "ALL" || component.lifecycleState === lifecycle);
  });
  async function open(component: Component) {
    setBusy(true);
    try { setSelected(await onLoadDetail(component.id)); } finally { setBusy(false); }
  }
  async function toggle(component: Component, enabled: boolean) {
    setBusy(true);
    try { setSelected(await onToggle(component, enabled)); } finally { setBusy(false); }
  }
  async function runLifecycle(component: Component, action: "QUARANTINE" | "RESTORE" | "RETIRE" | "DEREGISTER") {
    setBusy(true);
    try { setSelected(await onLifecycle(component, action)); } finally { setBusy(false); }
  }
  async function permission(component: Component, permissionId: string, enabled: boolean) {
    setBusy(true);
    try { setSelected(await onPermission(component, permissionId, enabled)); } finally { setBusy(false); }
  }
  async function revokeCredential(component: Component, credentialId: string) {
    setBusy(true);
    try { setSelected(await onCredentialRevoke(component, credentialId)); } finally { setBusy(false); }
  }
  async function rotateCredential(component: Component, credentialId: string) {
    setBusy(true);
    try {
      const result = await onCredentialRotate(component, credentialId);
      setSelected(result.component);
      return result.credential;
    } finally { setBusy(false); }
  }
  return <>
    <PageHeader title="Katalog komponent" description="Kanonické identity, capability profily, stav, pověření, oprávnění, audit a recertifikace.">
      <IconButton label="Obnovit katalog komponent" onClick={onRefresh}><RefreshCw size={17} /></IconButton>
    </PageHeader>
    <section className="metric-row">
      <MetricCard tone="neutral" icon={<Boxes size={22} />} value={components.length} label="Komponent celkem" />
      <MetricCard tone="success" icon={<CheckCircle2 size={22} />} value={components.filter((component) => component.enabled).length} label="Aktivní" />
      <MetricCard tone="warning" icon={<Activity size={22} />} value={components.filter((component) => component.monitoringState !== "HEALTHY").length} label="Monitoring vyžaduje pozornost" />
      <MetricCard tone="danger" icon={<ShieldAlert size={22} />} value={components.filter((component) => component.audit.gapState !== "CONTIGUOUS").length} label="Auditní mezery" />
    </section>
    <section className="panel component-catalog-panel">
      <div className="panel-head component-filter-bar"><h2>Komponenty</h2><label className="search-box compact-search"><Search size={16} /><input aria-label="Hledat komponentu" placeholder="Kód, název, hostname nebo capability" value={query} onChange={(event) => setQuery(event.target.value)} /></label><label>Kategorie<select value={category} onChange={(event) => setCategory(event.target.value)}><option value="ALL">Všechny</option>{categories.map((value) => <option key={value}>{value}</option>)}</select></label><label>Lifecycle<select value={lifecycle} onChange={(event) => setLifecycle(event.target.value)}><option value="ALL">Všechny</option>{[...new Set(components.map((component) => component.lifecycleState))].sort().map((value) => <option key={value}>{value}</option>)}</select></label></div>
      {filtered.length ? <div className="table-scroll"><table><thead><tr><th>Komponenta</th><th>Kategorie / role</th><th>Lifecycle</th><th>Technický stav</th><th>Verze / capabilities</th><th>Oprávnění / tokeny</th><th>Audit</th><th>Akce</th></tr></thead><tbody>{filtered.map((component) => <tr key={component.id}><td><strong>{component.displayName}</strong><span className="cell-subtitle">{component.code} · {component.hostname}</span></td><td>{component.category}<span className="cell-subtitle">{component.role}</span></td><td><span className={`badge ${tone(component.lifecycleState)}`}>{component.lifecycleState}</span><span className="cell-subtitle">{component.activationState}</span></td><td><span className={`badge ${tone(component.operationalState)}`}>{component.operationalState}</span><span className="cell-subtitle">Monitoring: {component.monitoringState}</span></td><td>{component.revision ?? "-"}<span className="cell-subtitle">{component.capabilities.length} capabilities</span></td><td>{component.permissionCount} / {component.credentialCount}<span className="cell-subtitle"><KeyRound size={12} /> bezpečné fingerprinty</span></td><td><span className={`badge ${tone(component.audit.gapState)}`}>{component.audit.gapState}</span><span className={`badge ${tone(component.audit.integrityState)}`}>{component.audit.integrityState}</span><span className="cell-subtitle">ACK {component.audit.highestAcknowledgedSequence}</span></td><td><IconButton label={`Detail komponenty ${component.displayName}`} onClick={() => { void open(component); }}><MoreHorizontal size={17} /></IconButton></td></tr>)}</tbody></table></div> : <div className="empty-state"><Boxes size={34} /><strong>Žádná komponenta neodpovídá filtrům</strong></div>}
    </section>
    {selected ? <ComponentDetail component={selected} role={role} busy={busy} onClose={() => setSelected(null)} onToggle={toggle} onLifecycle={runLifecycle} onPermission={permission} onCredentialRevoke={revokeCredential} onCredentialRotate={rotateCredential} /> : null}
  </>;
}
