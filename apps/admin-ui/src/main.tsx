import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  AlertTriangle,
  Ban,
  BellOff,
  CheckCircle2,
  ChevronDown,
  CircleHelp,
  ClipboardCopy,
  Clock3,
  Download,
  GitBranchPlus,
  LoaderCircle,
  MoreHorizontal,
  OctagonAlert,
  PauseCircle,
  PlayCircle,
  Plus,
  RefreshCw,
  Rocket,
  Radar,
  Save,
  Search,
  Server as ServerIcon,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Trash2,
  Workflow
} from "lucide-react";
import "./styles.css";
import { AppLayout, PageRouter } from "./app-layout.js";
import { AdminAccountsPage, SecurityPage } from "./admin-pages.js";
import { AuditPage, auditQueryParams, type AuditFilters } from "./audit-page.js";
import { BootstrapPage, Login, ReauthModal } from "./auth-pages.js";
import { IconButton, MetricCard, Modal, PageHeader } from "./common.js";
import { ComponentCatalogPage } from "./component-page.js";
import {
  CreateCredentialModal,
  CredentialConfirmModal,
  CredentialSecretModal,
  CredentialsPage,
  PermissionsPage,
  RenameCredentialModal
} from "./credential-pages.js";
import { onboardingHandoffText } from "./onboarding-handoff.js";
import { OperationalConfigPage } from "./operational-config-page.js";
import { formatMinuteSecondCountdown, getIntegrationTokenLifecycle } from "./integration-token-lifecycle.js";
import { REAUTH_REQUIRED_EVENT, SESSION_EXPIRED_EVENT } from "./session-auth.js";
import {
  acknowledgeOperationalAlert,
  createServerRevision,
  getMonitoringProfile,
  persistMonitoringProfile,
  retryAlertDelivery as retryAlertDeliveryRequest,
  runRegisteredServerTest,
  setComponentEnabled,
  setComponentLifecycle as setComponentLifecycleRequest,
  setComponentPermission as setComponentPermissionRequest,
  revokeComponentCredential as revokeComponentCredentialRequest,
  rotateComponentCredential as rotateComponentCredentialRequest,
  setServerEnabled,
  suppressOperationalAlert,
  testAlertChannels,
  type ServerTestCheckpoint,
  type ServerTestCheckpointKey,
  type ServerTestResult
} from "./server-api.js";
import {
  type AdminRole,
  type AdminAccount,
  type AdminSecurity,
  type AlertDelivery,
  type AuditEvent,
  type AuditIntegrity,
  type AuditResponse,
  type Component,
  type IntegrationSecret,
  type IntegrationToken,
  type KajaCredential,
  type KajaPermission,
  type MonitoringProbe,
  type MonitoringOverview,
  type MonitoringProfile,
  type OnboardingDescriptor,
  type OnboardingJob,
  type OperationalConfigSetting,
  type OperationalAlert,
  type Page,
  type SecretResult,
  type Server,
  type ServerStateHistory,
  type Session
} from "./types.js";
import { ApiRequestError, api, csrf, describeApiError, formatDate, formatLocalDateTimeInput, prettyJson, setUiTimeZone } from "./ui-helpers.js";

const integrationTokenActionLabel = "Vygenerovat Integrační token";

function recertificationTone(phase: Server["recertification"]["phase"]): "ok" | "warn" | "danger" | "neutral" {
  if (phase === "VALID") return "ok";
  if (phase === "WARNING") return "warn";
  if (phase === "GRACE") return "danger";
  return phase === "SUSPENDED" || phase === "INVALID" ? "danger" : "neutral";
}

function formatBoundary(seconds: number | null): string {
  if (seconds === null) return "Bez dalšího termínu";
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  if (days > 0) return `${days} d ${hours} h`;
  return formatMinuteSecondCountdown(seconds * 1_000);
}

function operationalTone(state: Server["operationalState"]): "ok" | "warn" | "danger" | "neutral" {
  if (state === "HEALTHY") return "ok";
  if (state === "DEGRADED" || state === "UNKNOWN") return "warn";
  if (["UNHEALTHY", "QUARANTINED", "DISABLED", "RETIRED"].includes(state)) return "danger";
  return "neutral";
}

function registrationLabel(server: Server): string {
  if (!server.enabled) return "Server je vypnutý administrátorem";
  if (server.registrationState === "TRIAL") return "Server je v ověřovacím režimu";
  if (server.registrationState === "ACTIVE") return "Server je v aktivním provozu";
  return `Registrační stav ${server.registrationState}`;
}

function recommendedAction(server: Server): { title: string; detail: string } {
  if (!server.enabled) return { title: "Nejdřív obnovit provoz", detail: "Server je vypnutý. Další test nebo aktivace dává smysl až po znovuzapnutí." };
  if (server.registrationState === "TRIAL") return { title: "Dokončit safe test", detail: "Úspěšný test může server povýšit z TRIAL do ACTIVE a uzavřít onboarding." };
  if (server.operationalState === "UNHEALTHY") return { title: "Prověřit monitoring a znovu otestovat", detail: "Server je aktivní, ale monitor hlásí kritický problém. Otestování pomůže rychle ověřit funkční kontrakt." };
  return { title: "Server je připraven pro provozní údržbu", detail: "Můžete provést bezpečný test, založit revizi nebo upravit monitoring podle potřeby." };
}

function createTestCheckpointBlueprint(server: Server): ServerTestCheckpoint[] {
  return [
    { key: "contract", label: "Připravuji testovací kontrakt", description: "Načítám aktivní revizi a bezpečnostní režim testu.", status: "PENDING" },
    { key: "input_validation", label: "Validuji bezpečný vstup", description: "Ověřuji safe input proti registrovanému vstupnímu schématu.", status: "PENDING" },
    { key: "runtime_lease", label: "Rezervuji runtime", description: "Získávám execution lease, aby test běžel bez kolize.", status: "PENDING" },
    { key: "handler_run", label: "Spouštím handler", description: "Volám registrovaný handler a sleduji timeout i runtime logy.", status: "PENDING" },
    { key: "output_validation", label: "Validuji výstup", description: "Kontroluji velikost odpovědi a výstupní schema.", status: "PENDING" },
    { key: "result_match", label: "Porovnávám expected result", description: "Vyhodnocuji, zda je výstup v souladu s kontraktem.", status: "PENDING" },
    {
      key: "activation",
      label: "Uzavírám výsledek",
      description: server.registrationState === "TRIAL"
        ? "Při úspěchu může dojít k povýšení serveru do ACTIVE."
        : "Zapisuji audit a uzavírám výsledek testu.",
      status: "PENDING"
    }
  ];
}

function checkpointForError(code: string): ServerTestCheckpointKey {
  if (["manifest_not_found", "manifest_test_contract_missing", "unsafe_write_test_contract", "test_compensation_policy_mismatch", "server_disabled", "active_monitoring_profile_required"].includes(code)) return "contract";
  if (code === "manifest_safe_input_schema_failed") return "input_validation";
  if (["handler_unavailable", "concurrency_limit_exceeded"].includes(code)) return "runtime_lease";
  if (["handler_timeout", "recertification_blocks_test"].includes(code)) return "handler_run";
  if (["output_schema_failed", "worker_response_too_large"].includes(code)) return "output_validation";
  return "result_match";
}

function synthesizeFailedTestResult(server: Server, error: ApiRequestError | Error): ServerTestResult {
  const code = error instanceof ApiRequestError ? error.code : "operation_failed";
  const failedCheckpointKey = checkpointForError(code);
  const checkpoints = createTestCheckpointBlueprint(server).map((checkpoint) => {
    if (checkpoint.key === failedCheckpointKey) {
      return { ...checkpoint, status: "FAILED" as const, detail: describeApiError(code, error instanceof ApiRequestError ? error.correlationId : null) };
    }
    return {
      ...checkpoint,
      status: checkpoint.key === "contract" && failedCheckpointKey !== "contract" ? "PASSED" as const : "SKIPPED" as const
    };
  });
  return {
    ok: false,
    status: "FAILED",
    correlationId: error instanceof ApiRequestError ? error.correlationId ?? "nezadáno" : "nezadáno",
    latencyMs: 0,
    activeRevisionId: server.activeRevisionId ?? "-",
    manifestDigest: server.manifestDigest,
    checkpoints,
    errorCode: code,
    errorMessage: error.message,
    failedCheckpointKey
  };
}

function summarizeProbe(probe: MonitoringProbe): string {
  const status = probe.status === "PASS" ? "v pořádku" : probe.status === "STALE" ? "zastaralé" : "selhalo";
  return `${probe.probe_type} · ${status}`;
}

function CreateIntegrationTokenModal({ resumeJobId, onClose, onCreated }: { resumeJobId?: string; onClose: () => void; onCreated: (secret: IntegrationSecret) => void }) {
  const [label, setLabel] = useState(resumeJobId ? `Pokračování integrace ${resumeJobId.slice(0, 8)}` : "");
  const [summary, setSummary] = useState("");
  const [businessPurpose, setBusinessPurpose] = useState("");
  const [serviceOwner, setServiceOwner] = useState("");
  const [technicalOwner, setTechnicalOwner] = useState("");
  const [criticality, setCriticality] = useState<OnboardingDescriptor["criticality"]>("MEDIUM");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!label.trim()) { setError("Zadej označení tokenu."); return; }
    if (!summary.trim() || !businessPurpose.trim() || !serviceOwner.trim() || !technicalOwner.trim()) {
      setError("Vyplň shrnutí, účel i oba vlastníky serveru.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const result = await api<IntegrationSecret>("/api/integration-tokens", {
        method: "POST",
        headers: { "x-csrf-token": csrf() },
        body: JSON.stringify({
          label: label.trim(),
          descriptor: {
            summary: summary.trim(),
            businessPurpose: businessPurpose.trim(),
            serviceOwner: serviceOwner.trim(),
            technicalOwner: technicalOwner.trim(),
            criticality
          },
          resumeJobId
        })
      });
      onCreated(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Token se nepodařilo vytvořit");
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal title={resumeJobId ? "Navazující implementační token" : integrationTokenActionLabel} onClose={onClose}>
      <form className="modal-form" onSubmit={(event) => { void submit(event); }}>
        <div className="form-intro"><span className="modal-icon"><Workflow size={20} /></span><p>KajovoCML 2026.07.21, strukturovaný descriptor a integrační token.</p></div>
        <label>Označení tokenu<span className="field-hint">Krátký interní název pro pozdější dohledání tokenu.</span><input autoFocus value={label} onChange={(event) => setLabel(event.target.value)} maxLength={120} placeholder="Např. Fakturační onboarding" /></label>
        <div className="descriptor-grid">
          <label>Shrnutí serveru<span className="field-hint">Jednovětý popis integračního záměru.</span><textarea value={summary} onChange={(event) => setSummary(event.target.value)} maxLength={120} rows={3} placeholder="Např. Zpracování fakturačních podkladů" /></label>
          <label>Účel serveru<span className="field-hint">Formální business purpose, který se předá dál.</span><textarea value={businessPurpose} onChange={(event) => setBusinessPurpose(event.target.value)} maxLength={400} rows={3} placeholder="Např. Automatizace fakturačního workflow" /></label>
          <label>Vlastník služby<input value={serviceOwner} onChange={(event) => setServiceOwner(event.target.value)} maxLength={160} placeholder="Např. Finance Ops" /></label>
          <label>Technický vlastník<input value={technicalOwner} onChange={(event) => setTechnicalOwner(event.target.value)} maxLength={160} placeholder="Např. Platform Engineering" /></label>
          <label>Kritičnost<select value={criticality} onChange={(event) => setCriticality(event.target.value as OnboardingDescriptor["criticality"])}><option value="LOW">Low</option><option value="MEDIUM">Medium</option><option value="HIGH">High</option><option value="CRITICAL">Critical</option></select></label>
        </div>
        {resumeJobId ? <div className="permission-preview"><strong>Pokračování existujícího jobu</strong><code>{resumeJobId}</code><span>Předchozí token bude revokován. KCML identita zůstane zachována.</span></div> : null}
        {error && <p className="error">{error}</p>}
        <footer className="modal-actions"><button type="button" className="secondary" onClick={onClose} disabled={busy}>Zrušit</button><button type="submit" disabled={busy}><Rocket size={16} /> {busy ? "Generuji…" : integrationTokenActionLabel}</button></footer>
      </form>
    </Modal>
  );
}

function IntegrationSecretModal({ secret, onClose }: { secret: IntegrationSecret; onClose: () => void }) {
  const [copied, setCopied] = useState<"token" | "instructions" | null>(null);
  async function copyToken() {
    await navigator.clipboard.writeText(secret.token);
    setCopied("token");
  }
  async function copyInstructions() {
    await navigator.clipboard.writeText(onboardingHandoffText({
      label: secret.label,
      descriptor: secret.descriptor,
      token: secret.token,
      initialExpiresAt: secret.initialExpiresAt,
      programmerApiUrl: secret.programmerApiUrl
    }));
    setCopied("instructions");
  }
  return (
    <Modal title="Podklady pro programátora jsou připravené" onClose={onClose}>
      <div className="secret-dialog">
        <div className="notice success"><CheckCircle2 size={18} /><span><strong>Vaše práce tímto končí.</strong><br />Programátorovi předejte onboarding katalog a token. Stav, opravitelné chyby i nahrání nové revize obslouží sám přes programátorské API až do zeleného výsledku.</span></div>
        <div className="handoff-step"><span>1</span><div><strong>Onboarding katalog</strong><p>Závazný registrační kontrakt 2026.07.21.</p><a className="button-link secondary" href={secret.onboardingCatalogUrl} download={secret.onboardingCatalogFileName}><Download size={16} /> Stáhnout onboarding katalog</a></div></div>
        <div className="handoff-step"><span>2</span><div><strong>Server descriptor</strong><p>{secret.descriptor.summary}</p><dl className="descriptor-dl"><dt>Účel</dt><dd>{secret.descriptor.businessPurpose}</dd><dt>Vlastník služby</dt><dd>{secret.descriptor.serviceOwner}</dd><dt>Technický vlastník</dt><dd>{secret.descriptor.technicalOwner}</dd><dt>Kritičnost</dt><dd>{secret.descriptor.criticality}</dd></dl></div></div>
        <div className="handoff-step"><span>3</span><div><strong>Integrační token</strong><p>Plnou hodnotu lze zobrazit i předat v tomto handoffu. První upload musí programátor provést do {formatDate(secret.initialExpiresAt)}.</p><div className="secret-once"><code>{secret.token}</code><small>Fingerprint {secret.fingerprint}</small></div><button type="button" className="secondary" onClick={() => { void copyToken(); }}><ClipboardCopy size={16} /> {copied === "token" ? "Token zkopírován" : "Zkopírovat token"}</button></div></div>
        <div className="permission-preview"><strong>Co proběhne po uploadu</strong><span>Systém přidělí KCML identitu a vlastní HTTPS adresu a provede PR/CI, podepsaný OCI build, izolované nasazení, katalog, autorizaci, logging, audit, monitoring, veřejné testy a aktivaci. Opravitelnou chybu API vrátí programátorovi jako <code>UPLOAD_REVISION</code>; po nové revizi pipeline sama pokračuje.</span></div>
        <footer className="modal-actions"><button className="secondary" onClick={onClose}>Zavřít</button><button onClick={() => { void copyInstructions(); }}><ClipboardCopy size={16} /> {copied === "instructions" ? "Pokyny zkopírovány" : "Zkopírovat pokyny i token"}</button></footer>
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

function ServerTestFlowModal({
  server,
  result,
  running,
  elapsedMs,
  optimisticIndex,
  onRetry,
  onClose
}: {
  server: Server;
  result: ServerTestResult | null;
  running: boolean;
  elapsedMs: number;
  optimisticIndex: number;
  onRetry: () => Promise<void>;
  onClose: () => void;
}) {
  const baseCheckpoints = result?.checkpoints ?? createTestCheckpointBlueprint(server);
  const visualState = (checkpoint: ServerTestCheckpoint, index: number): "PENDING" | "RUNNING" | "PASSED" | "FAILED" | "SKIPPED" => {
    if (result) {
      if (checkpoint.status === "PENDING" && !running) return "PENDING";
      return checkpoint.status;
    }
    if (index < optimisticIndex) return "PASSED";
    if (index === optimisticIndex) return "RUNNING";
    return "PENDING";
  };
  const completionTone = result?.ok ? "success" : result ? "error" : "neutral";
  const headline = result
    ? result.ok
      ? "Safe test byl dokončen úspěšně"
      : result.status === "EXPECTED_RESULT_MISMATCH"
        ? "Safe test doběhl, ale expected result nesouhlasí"
        : "Safe test skončil chybou"
    : "Probíhá bezpečný test serveru";
  const summary = result
    ? result.ok
      ? `Latence ${result.latencyMs} ms · revize ${result.activeRevisionId}`
      : `${result.errorMessage ?? result.status} · correlation ${result.correlationId}`
    : `Server ${server.code} právě prochází kontrolovaným kontraktním testem.`;
  const progress = result
    ? Math.max(0, Math.round(baseCheckpoints.filter((item) => ["PASSED", "FAILED", "SKIPPED"].includes(item.status)).length / baseCheckpoints.length * 100))
    : Math.max(8, Math.round((optimisticIndex + 1) / baseCheckpoints.length * 100));

  return (
    <Modal title="Bezpečný test serveru" onClose={onClose} className="modal-server-test-flow">
      <div className="server-test-flow">
        <div className={`server-test-hero ${completionTone}`}>
          <div className="server-test-hero-copy">
            <span className={`status-pill ${result?.ok ? "ok" : result ? "danger" : "warn"}`}>{result ? (result.ok ? "DOKONČENO" : "VYŽADUJE ZÁSAH") : "TEST PROBÍHÁ"}</span>
            <strong>{headline}</strong>
            <p>{summary}</p>
          </div>
          <div className="server-test-hero-meta">
            <div><small>Elapsed</small><strong>{formatMinuteSecondCountdown(elapsedMs)}</strong></div>
            <div><small>Correlation ID</small><code>{result?.correlationId ?? "připravuji…"}</code></div>
          </div>
        </div>
        <div className="server-test-progress">
          <div className={`server-test-progress-bar ${result && !result.ok ? "error" : ""}`}><span style={{ width: `${progress}%` }} /></div>
          <small>{result ? `Hotovo · ${progress}% checkpointů uzavřeno` : `Probíhá checkpoint ${Math.min(optimisticIndex + 1, baseCheckpoints.length)} z ${baseCheckpoints.length}`}</small>
        </div>
        <div className="server-test-checkpoints">
          {baseCheckpoints.map((checkpoint, index) => {
            const state = visualState(checkpoint, index);
            return (
              <article key={checkpoint.key} className={`server-test-checkpoint ${state.toLowerCase()}`}>
                <span className="server-test-checkpoint-icon">
                  {state === "PASSED" || state === "SKIPPED" ? <CheckCircle2 size={16} /> : state === "FAILED" ? <OctagonAlert size={16} /> : state === "RUNNING" ? <LoaderCircle size={16} /> : <span>{index + 1}</span>}
                </span>
                <div>
                  <strong>{checkpoint.label}</strong>
                  <p>{checkpoint.detail ?? checkpoint.description}</p>
                </div>
                <small>{checkpoint.durationMs ? `${checkpoint.durationMs} ms` : state === "RUNNING" ? "běží…" : state === "PENDING" ? "čeká" : state === "SKIPPED" ? "přeskočeno" : ""}</small>
              </article>
            );
          })}
        </div>
        {result ? <div className={`server-test-result-panel ${result.ok ? "success" : "error"}`}>
          <div>
            <strong>{result.ok ? "Výsledek testu je použitelný jako provozní důkaz." : "Test skončil se signálem k zásahu nebo s neshodou kontraktu."}</strong>
            <p>Manifest {result.manifestDigest} · revize {result.activeRevisionId}</p>
          </div>
          {result.output === undefined ? null : <details>
            <summary>Zobrazit výstup handleru</summary>
            <pre className="test-output">{prettyJson(result.output)}</pre>
          </details>}
        </div> : null}
        <footer className="modal-actions">
          <button type="button" className="secondary" onClick={onClose} disabled={running}>Zavřít</button>
          <button type="button" onClick={() => { void onRetry(); }} disabled={running}>{running ? "Test probíhá…" : result ? "Spustit znovu" : "Obnovit průběh"}</button>
        </footer>
      </div>
    </Modal>
  );
}

function ServerDetailModal({
  server,
  probes,
  history,
  accountName,
  onClose,
  onToggleEnabled,
  onRunTest,
  onLoadMonitoringProfile,
  onSaveMonitoringProfile,
  onStartRevision,
  onDeleteServer
}: {
  server: Server;
  probes: MonitoringProbe[];
  history: ServerStateHistory[];
  accountName: string | null;
  onClose: () => void;
  onToggleEnabled: (server: Server, enabled: boolean) => Promise<void>;
  onRunTest: (server: Server) => Promise<ServerTestResult>;
  onLoadMonitoringProfile: (server: Server) => Promise<MonitoringProfile>;
  onSaveMonitoringProfile: (server: Server, profile: MonitoringProfile) => Promise<void>;
  onStartRevision: (server: Server) => Promise<void>;
  onDeleteServer: (server: Server, input: { confirmedCode: string; reason: string; password: string; totp: string }) => Promise<void>;
}) {
  const [busyAction, setBusyAction] = useState<"toggle" | "saveMonitoring" | "revision" | "test" | null>(null);
  const [lastTest, setLastTest] = useState<ServerTestResult | null>(null);
  const [error, setError] = useState("");
  const [monitoring, setMonitoring] = useState<MonitoringProfile | null>(null);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [testModalOpen, setTestModalOpen] = useState(false);
  const [testRunning, setTestRunning] = useState(false);
  const [testElapsedMs, setTestElapsedMs] = useState(0);
  const [testResult, setTestResult] = useState<ServerTestResult | null>(null);
  const [optimisticIndex, setOptimisticIndex] = useState(0);
  const activeRevision = ["ACTIVE", "TRIAL"].includes(server.registrationState);
  const recommendation = recommendedAction(server);
  const latestProbes = [...probes].sort((left, right) => new Date(right.checked_at).getTime() - new Date(left.checked_at).getTime()).slice(0, 5);
  const stateHistory = history.slice(0, 5);
  useEffect(() => {
    void onLoadMonitoringProfile(server)
      .then(setMonitoring)
      .catch((err) => setError(err instanceof Error ? err.message : "Profil monitoringu se nepodařilo načíst"));
  }, [onLoadMonitoringProfile, server]);
  async function toggleEnabled() {
    setBusyAction("toggle");
    setError("");
    try {
      await onToggleEnabled(server, !server.enabled);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Změna stavu selhala");
    } finally {
      setBusyAction(null);
    }
  }
  async function runTest() {
    setBusyAction("test");
    setError("");
    setTestModalOpen(true);
    setTestRunning(true);
    setTestResult(null);
    setTestElapsedMs(0);
    setOptimisticIndex(0);
    const startedAt = Date.now();
    const elapsedTimer = window.setInterval(() => setTestElapsedMs(Date.now() - startedAt), 200);
    const checkpointTimer = window.setInterval(() => {
      setOptimisticIndex((current) => Math.min(current + 1, createTestCheckpointBlueprint(server).length - 1));
    }, 650);
    try {
      const result = await onRunTest(server);
      setTestResult(result);
      setLastTest(result);
    } catch (err) {
      const failure = synthesizeFailedTestResult(server, err instanceof ApiRequestError ? err : new Error("operation_failed"));
      setTestResult(failure);
      setLastTest(failure);
      setError(err instanceof Error ? err.message : "Test serveru selhal");
    } finally {
      window.clearInterval(elapsedTimer);
      window.clearInterval(checkpointTimer);
      setTestElapsedMs(Date.now() - startedAt);
      setTestRunning(false);
      setBusyAction(null);
    }
  }
  async function saveMonitoring() {
    if (!monitoring) return;
    setBusyAction("saveMonitoring");
    setError("");
    try {
      await onSaveMonitoringProfile(server, monitoring);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Profil monitoringu se nepodařilo uložit");
    } finally {
      setBusyAction(null);
    }
  }
  return (
    <Modal title="Detail serveru" onClose={onClose} className="modal-server-detail">
      <div className="server-detail-v2">
        <section className="server-detail-hero">
          <div className="server-detail-identity">
            <span className={`server-badge ${operationalTone(server.operationalState)}`}><ServerIcon size={18} /></span>
            <div>
              <strong>{server.displayName}</strong>
              <div className="server-detail-identity-meta">
                <span>{server.code}</span>
                <span>{server.hostname}</span>
                <span>{server.toolName}</span>
              </div>
            </div>
          </div>
          <div className="server-detail-hero-status">
            <span className={`status-pill ${operationalTone(server.operationalState)}`}>{server.operationalState}</span>
            <span className="status-pill neutral">{server.registrationState}</span>
            <span className={`status-pill ${recertificationTone(server.recertification.phase)}`}>{server.recertification.phase}</span>
          </div>
          <div className="server-detail-hero-guidance">
            <strong>{recommendation.title}</strong>
            <p>{recommendation.detail}</p>
          </div>
        </section>

        <div className="server-detail-layout">
          <div className="server-detail-main">
            <section className="server-detail-section">
              <div className="server-section-head"><h3>Přehled provozu</h3><span>{registrationLabel(server)}</span></div>
              <div className="server-summary-grid">
                <article><small>Dostupnost</small><strong>{server.enabled ? "V provozu" : "Vypnuto"}</strong><span>{server.monitoringEnabled ? "Monitoring aktivní" : "Monitoring blokuje provoz"}</span></article>
                <article><small>Latence p95</small><strong>{server.p95LatencyMs ?? "-"} ms</strong><span>poslední {server.lastLatencyMs ?? "-"} ms</span></article>
                <article><small>Volání</small><strong>{server.successCount}</strong><span>{server.failureCount} provozních chyb / {server.unauthorizedCount} auth chyb</span></article>
                <article><small>Recertifikace</small><strong>{server.recertification.phase}</strong><span>{formatBoundary(server.recertification.secondsToBoundary)}</span></article>
                <article><small>Aktivní revize</small><strong>{server.registrationRevision ?? "-"}</strong><span>{server.contractVersion} · {server.handlerVersion}</span></article>
                <article><small>Poslední výsledek testu</small><strong>{lastTest ? (lastTest.ok ? "Prošel" : "Vyžaduje zásah") : "Zatím neproveden"}</strong><span>{lastTest ? `${lastTest.status} · ${lastTest.latencyMs} ms` : "Spusťte safe test pro auditní důkaz."}</span></article>
              </div>
            </section>

            {lastTest ? <section className="server-detail-section">
              <div className="server-section-head"><h3>Poslední safe test</h3><span>{formatDate(server.updatedAt)}</span></div>
              <div className={`server-last-test ${lastTest.ok ? "success" : "error"}`}>
                <div>
                  <strong>{lastTest.ok ? "Poslední test skončil úspěšně." : "Poslední test skončil s varováním nebo chybou."}</strong>
                  <p>{lastTest.status} · latence {lastTest.latencyMs} ms · correlation ID <code>{lastTest.correlationId}</code></p>
                </div>
                <button type="button" className="secondary" onClick={() => { setTestModalOpen(true); setTestResult(lastTest); }}>Zobrazit checkpointy</button>
              </div>
            </section> : null}

            <section className="server-detail-section">
              <div className="server-section-head"><h3>Monitoring a health</h3><span>{server.monitoringProfileDigest ?? "Digest chybí"}</span></div>
              <div className="server-monitoring-grid">
                <article className="server-inline-card">
                  <div className="server-inline-card-head"><ShieldCheck size={16} /><strong>Monitoring profil</strong></div>
                  <p>{server.monitoringEnabled ? "Povinný monitoring profil je aktivní a může držet server v provozním režimu." : "Profil aktuálně blokuje provoz serveru."}</p>
                  {monitoring ? <dl className="server-meta-grid">
                    <div><dt>Runbook</dt><dd>{monitoring.profile.runbookRef || "-"}</dd></div>
                    <div><dt>Primární alert</dt><dd>{monitoring.profile.primaryAlertChannel || "-"}</dd></div>
                    <div><dt>Záložní alert</dt><dd>{monitoring.profile.backupAlertChannel || "-"}</dd></div>
                    <div><dt>Stale after</dt><dd>{monitoring.profile.staleAfterSeconds} s</dd></div>
                  </dl> : <p>Profil načítám…</p>}
                </article>
                <article className="server-inline-card">
                  <div className="server-inline-card-head"><Radar size={16} /><strong>Aktuální guardraily</strong></div>
                  <ul className="server-compact-list">
                    <li>{server.recertification.reason ?? "Recertifikace je v platném pásmu."}</li>
                    <li>{server.reviewDueAt ? `Termín revize ${formatDate(server.reviewDueAt)}` : "Termín revize není zapsán."}</li>
                    <li>{server.description || "Bez doplňujícího provozního popisu."}</li>
                  </ul>
                </article>
              </div>
              {monitoring && activeRevision ? <div className="server-inline-message">
                <ShieldAlert size={16} />
                <span>Monitoring aktivní revize je uzamčený. Změna profilu založí novou registrační revizi 2026.07.21 a znovu spustí povinné brány.</span>
              </div> : null}
              {monitoring && !activeRevision ? <details className="server-advanced-block">
                <summary>Upravit monitoring profil</summary>
                <div className="monitoring-editor monitoring-editor-v2">
                  <label>Runbook reference<input value={monitoring.profile.runbookRef} onChange={(event) => setMonitoring({ ...monitoring, profile: { ...monitoring.profile, runbookRef: event.target.value } })} /></label>
                  <label>Primární alert kanál<input value={monitoring.profile.primaryAlertChannel} onChange={(event) => setMonitoring({ ...monitoring, profile: { ...monitoring.profile, primaryAlertChannel: event.target.value } })} /></label>
                  <label>Záložní alert kanál<input value={monitoring.profile.backupAlertChannel} onChange={(event) => setMonitoring({ ...monitoring, profile: { ...monitoring.profile, backupAlertChannel: event.target.value } })} /></label>
                  <label>Vzorek je zastaralý po (s)<input type="number" min={30} max={7200} value={monitoring.profile.staleAfterSeconds} onChange={(event) => setMonitoring({ ...monitoring, profile: { ...monitoring.profile, staleAfterSeconds: Number(event.target.value) } })} /></label>
                  <label>Retence výsledků (dny)<input type="number" min={1} max={3650} value={monitoring.profile.retentionDays} onChange={(event) => setMonitoring({ ...monitoring, profile: { ...monitoring.profile, retentionDays: Number(event.target.value) } })} /></label>
                  <label>SLO targety (JSON)<textarea rows={5} value={prettyJson(monitoring.profile.sloTargets)} onChange={(event) => {
                    try {
                      setMonitoring({ ...monitoring, profile: { ...monitoring.profile, sloTargets: JSON.parse(event.target.value) as Record<string, unknown> } });
                      setError("");
                    } catch {
                      setError("SLO targety musí být platný JSON.");
                    }
                  }} /></label>
                  <label>Intervaly probe (JSON)<textarea rows={5} value={prettyJson(monitoring.profile.probeIntervals)} onChange={(event) => {
                    try {
                      setMonitoring({ ...monitoring, profile: { ...monitoring.profile, probeIntervals: JSON.parse(event.target.value) as Record<string, unknown> } });
                      setError("");
                    } catch {
                      setError("Intervaly probe musí být platný JSON.");
                    }
                  }} /></label>
                  <label>Alert pravidla (JSON pole)<textarea rows={6} value={prettyJson(monitoring.profile.alertRules)} onChange={(event) => {
                    try {
                      setMonitoring({ ...monitoring, profile: { ...monitoring.profile, alertRules: JSON.parse(event.target.value) as Array<Record<string, unknown>> } });
                      setError("");
                    } catch {
                      setError("Alert pravidla musí být platné JSON pole.");
                    }
                  }} /></label>
                  <div className="server-inline-actions">
                    <button type="button" className="secondary" disabled={busyAction !== null || !monitoring} onClick={() => { void saveMonitoring(); }}><Save size={16} /> {busyAction === "saveMonitoring" ? "Ukládám…" : "Uložit monitoring"}</button>
                  </div>
                </div>
              </details> : null}
            </section>

            <section className="server-detail-section">
              <div className="server-section-head"><h3>Technické detaily</h3><span>pro audit a troubleshooting</span></div>
              <details className="server-advanced-block">
                <summary>Zobrazit technický kontrakt a artefakty</summary>
                <div className="server-tech-grid">
                  <dl className="server-meta-grid">
                    <div><dt>Handler</dt><dd>{server.handlerKey} · {server.handlerVersion}</dd></div>
                    <div><dt>Contract</dt><dd>{server.contractVersion}</dd></div>
                    <div><dt>Artifact digest</dt><dd><code>{server.artifactDigest}</code></dd></div>
                    <div><dt>Manifest digest</dt><dd><code>{server.manifestDigest}</code></dd></div>
                    <div><dt>Poslední úspěch</dt><dd>{formatDate(server.lastSuccessAt)}</dd></div>
                    <div><dt>Poslední chyba</dt><dd>{formatDate(server.lastFailureAt)}</dd></div>
                  </dl>
                  <details>
                    <summary>Vstupní JSON schema</summary>
                    <pre className="test-output">{JSON.stringify(server.inputSchema, null, 2)}</pre>
                  </details>
                  <details>
                    <summary>Výstupní JSON schema</summary>
                    <pre className="test-output">{JSON.stringify(server.outputSchema, null, 2)}</pre>
                  </details>
                </div>
              </details>
            </section>

            {error ? <p className="error">{error}</p> : null}
          </div>

          <aside className="server-detail-side">
            <section className="server-action-card">
              <div className="server-section-head"><h3>Akce</h3><span>provozní zásahy</span></div>
              <button type="button" className="server-primary-action" disabled={busyAction !== null} onClick={() => { void runTest(); }}>
                <Terminal size={16} /> {busyAction === "test" ? "Test probíhá…" : "Spustit bezpečný test"}
              </button>
              <div className="server-action-list">
                <button type="button" className="secondary" disabled={busyAction !== null} onClick={() => { setBusyAction("revision"); void onStartRevision(server).catch((err) => setError(err instanceof Error ? err.message : "Založení revize selhalo")).finally(() => setBusyAction(null)); }}>
                  <GitBranchPlus size={16} /> {busyAction === "revision" ? "Zakládám revizi…" : "Založit změnovou revizi"}
                </button>
                <button type="button" className="secondary" disabled={busyAction !== null} onClick={() => { void toggleEnabled(); }}>
                  {server.enabled ? <PauseCircle size={16} /> : <PlayCircle size={16} />} {busyAction === "toggle" ? "Ukládám stav…" : server.enabled ? "Vypnout server" : "Zapnout server"}
                </button>
              </div>
            </section>

            <section className="server-side-card">
              <div className="server-section-head"><h3>Poslední probes</h3><span>{latestProbes.length} záznamů</span></div>
              {latestProbes.length === 0 ? <p className="server-muted-copy">Zatím nejsou k dispozici žádné probe vzorky.</p> : <div className="server-side-list">
                {latestProbes.map((probe) => <article key={probe.id}>
                  <div><span className={`status-dot ${probe.status === "PASS" ? "ok" : probe.status === "STALE" ? "warn" : "danger"}`} /><strong>{probe.probe_type}</strong></div>
                  <small>{summarizeProbe(probe)} · {formatDate(probe.checked_at)}</small>
                </article>)}
              </div>}
            </section>

            <section className="server-side-card">
              <div className="server-section-head"><h3>Evidence změn stavu</h3><span>poslední přechody</span></div>
              {stateHistory.length === 0 ? <p className="server-muted-copy">Pro tento server zatím není uložená historie změn stavu.</p> : <div className="server-side-list">
                {stateHistory.map((entry) => <article key={entry.id}>
                  <div><strong>{entry.operational_state}</strong><span className="status-pill neutral">{entry.registration_state}</span></div>
                  <small>{entry.reason} · {formatDate(entry.recorded_at)}</small>
                </article>)}
              </div>}
            </section>

            <section className="server-danger-zone">
              <div className="server-section-head"><h3>Destruktivní zóna</h3><span>nevratné akce</span></div>
              <p>Smazání registrace odstraní server z aktivní správy a z provozního pohledu jde o nevratný zásah.</p>
              <button type="button" className="danger-button" disabled={busyAction !== null} onClick={() => setDeleteOpen(true)}><Trash2 size={16} /> Smazat registraci</button>
            </section>
          </aside>
        </div>
      </div>
      {deleteOpen ? <DeleteServerModal
        server={server}
        accountName={accountName}
        onClose={() => setDeleteOpen(false)}
        onDeleted={async (input) => {
          await onDeleteServer(server, input);
          setDeleteOpen(false);
          onClose();
        }}
      /> : null}
      {testModalOpen ? <ServerTestFlowModal
        server={server}
        result={testResult}
        running={testRunning}
        elapsedMs={testElapsedMs}
        optimisticIndex={optimisticIndex}
        onRetry={runTest}
        onClose={() => { if (!testRunning) setTestModalOpen(false); }}
      /> : null}
    </Modal>
  );
}

function MonitoringPage({
  servers,
  accountName,
  probes,
  overview,
  onRefresh,
  onAutomatedOnboarding,
  onToggleEnabled,
  onRunTest,
  onLoadMonitoringProfile,
  onSaveMonitoringProfile,
  onStartRevision,
  onDeleteServer,
  onTestWebhook,
  onAcknowledgeAlert,
  onSuppressAlert,
  onRetryDelivery
}: {
  servers: Server[];
  accountName: string | null;
  probes: MonitoringProbe[];
  overview: MonitoringOverview;
  onRefresh: () => void;
  onAutomatedOnboarding: () => void;
  onToggleEnabled: (server: Server, enabled: boolean) => Promise<void>;
  onRunTest: (server: Server) => Promise<ServerTestResult>;
  onLoadMonitoringProfile: (server: Server) => Promise<MonitoringProfile>;
  onSaveMonitoringProfile: (server: Server, profile: MonitoringProfile) => Promise<void>;
  onStartRevision: (server: Server) => Promise<void>;
  onDeleteServer: (server: Server, input: { confirmedCode: string; reason: string; password: string; totp: string }) => Promise<void>;
  onTestWebhook: () => Promise<void>;
  onAcknowledgeAlert: (alert: OperationalAlert) => Promise<void>;
  onSuppressAlert: (alert: OperationalAlert, reason: string, until: string) => Promise<void>;
  onRetryDelivery: (delivery: AlertDelivery) => Promise<void>;
}) {
  const [actionBusy, setActionBusy] = useState(false);
  const [actionNotice, setActionNotice] = useState<{ tone: "success" | "error"; text: string } | null>(null);
  const [query, setQuery] = useState("");
  const [timeRange, setTimeRange] = useState("24h");
  const [view, setView] = useState<"status" | "alerts" | "deliveries" | "history">("status");
  const [detailServer, setDetailServer] = useState<Server | null>(null);
  const [suppressingAlert, setSuppressingAlert] = useState<OperationalAlert | null>(null);
  const online = servers.filter((server) => server.enabled && server.recertification.canServeExisting && server.monitoringEnabled).length;
  const degraded = servers.filter((server) => server.operationalState === "DEGRADED").length;
  const activeAlerts = overview.alerts.filter((alert) => alert.status !== "CLOSED");
  const filtered = servers.filter((server) => `${server.displayName} ${server.hostname} ${server.code}`.toLowerCase().includes(query.toLowerCase()));
  const rangeMs = timeRange === "30d" ? 30 * 86400000 : timeRange === "7d" ? 7 * 86400000 : 86400000;
  const visibleProbes = probes.filter((probe) => new Date(probe.checked_at).getTime() > Date.now() - rangeMs).slice(0, 80).reverse();
  const latestProbe = new Map<string, MonitoringProbe>();
  for (const probe of probes) if (!latestProbe.has(probe.server_id)) latestProbe.set(probe.server_id, probe);

  async function runAction(action: () => Promise<void>, successText: string, failureText: string) {
    setActionBusy(true);
    setActionNotice(null);
    try {
      await action();
      setActionNotice({ tone: "success", text: successText });
    } catch (err) {
      setActionNotice({ tone: "error", text: err instanceof Error ? err.message : failureText });
    } finally {
      setActionBusy(false);
    }
  }

  return (
    <>
      <PageHeader title="Monitoring komponent" description="Provozní stav kompatibilních MCP profilů, recertifikace a alerting">
        <button onClick={onAutomatedOnboarding}><Rocket size={17} /> {integrationTokenActionLabel}</button>
        <IconButton label="Obnovit monitoring" onClick={onRefresh}><RefreshCw size={17} /></IconButton>
        <label className="range-select"><Clock3 size={16} /><select value={timeRange} onChange={(event) => setTimeRange(event.target.value)} aria-label="Časový rozsah monitoringu"><option value="24h">Posledních 24 hodin</option><option value="7d">Posledních 7 dní</option><option value="30d">Posledních 30 dní</option></select><ChevronDown size={15} /></label>
      </PageHeader>
      <section className="metric-row">
        <MetricCard tone="neutral" icon={<ServerIcon size={22} />} value={servers.length} label="Celkem serverů" />
        <MetricCard tone="success" icon={<CheckCircle2 size={22} />} value={online} label="Online" />
        <MetricCard tone="warning" icon={<AlertTriangle size={22} />} value={degraded} label="Degradováno" />
        <MetricCard tone="danger" icon={<Ban size={22} />} value={activeAlerts.length} label="Aktivní alerty" />
      </section>
      <section className="monitor-toolbar">
        <div className="segmented-control" aria-label="Pohled monitoringu">
          <button aria-pressed={view === "status"} onClick={() => setView("status")}>Stav</button>
          <button aria-pressed={view === "alerts"} onClick={() => setView("alerts")}>Alerty <span>{activeAlerts.length}</span></button>
          <button aria-pressed={view === "deliveries"} onClick={() => setView("deliveries")}>Webhooky</button>
          <button aria-pressed={view === "history"} onClick={() => setView("history")}>Historie</button>
        </div>
        <div className={`scheduler-state ${overview.scheduler?.last_error ? "danger" : "ok"}`}><span className="status-dot" /><span><strong>{overview.scheduler?.last_error ? "Monitor selhal" : "Monitor aktivní"}</strong><small>{formatDate(overview.scheduler?.last_completed_at ?? null)}</small></span></div>
      </section>
      {view === "status" ? <>
        <section className="panel monitor-panel">
          <div className="panel-head"><div className="heading-with-help"><h2>Stav v čase</h2><CircleHelp size={15} /></div></div>
          <div className="timeline-chart" aria-label="Dostupnost MCP serverů ve zvoleném období">
            <div className="chart-y-axis"><span>100%</span><span>75%</span><span>50%</span><span>25%</span><span>0%</span></div>
            <div className="chart-grid">
              {visibleProbes.length === 0 ? <div className="timeline-empty"><ServerIcon size={34} /><strong>Žádná data k zobrazení</strong></div> : <div className="probe-timeline">{visibleProbes.map((probe) => <span key={probe.id} className={`probe-point ${probe.status.toLowerCase()}`} title={`${probe.code} · ${probe.probe_type} · ${probe.status} · ${formatDate(probe.checked_at)}`} />)}</div>}
              <div className="chart-x-axis"><span>-24 h</span><span>-18 h</span><span>-12 h</span><span>-6 h</span><span>nyní</span></div>
            </div>
          </div>
        </section>
        <section className="panel">
        <div className="panel-head server-panel-head"><h2>Přehled serverů</h2><label className="search-box compact-search"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Hledat podle názvu serveru" aria-label="Hledat podle názvu serveru" /></label></div>
        {servers.length === 0 ? (
          <div className="empty-state server-empty">
            <ServerIcon size={34} /><strong>Katalog MCP serverů je prázdný</strong>
          </div>
        ) : (
          <div className="table-scroll"><table><thead><tr><th>Server</th><th>Registrace</th><th>Recertifikace</th><th>Provoz</th><th>Volání</th><th>Vzorek</th><th>Akce</th></tr></thead>
            <tbody>{filtered.map((server) => {
              const probe = latestProbe.get(server.id);
              return <tr key={server.id}><td><strong>{server.displayName}</strong><span className="cell-subtitle">{server.code} · {server.hostname}</span></td><td><span className="badge neutral">{server.registrationState}</span><span className="cell-subtitle">rev. {server.registrationRevision ?? "-"}</span></td><td><span className={`badge ${recertificationTone(server.recertification.phase)}`}>{server.recertification.phase}</span><span className="cell-subtitle">{formatBoundary(server.recertification.secondsToBoundary)}</span></td><td><span className={`badge ${server.operationalState === "HEALTHY" ? "ok" : server.operationalState === "DEGRADED" ? "warn" : "danger"}`}>{server.operationalState}</span>{server.recertification.reason ? <span className="cell-subtitle">{server.recertification.reason}</span> : null}</td><td>{server.successCount}/{server.failureCount}<span className="cell-subtitle">p95 {server.p95LatencyMs ?? "-"} ms</span></td><td>{probe ? <><span className={`badge ${probe.status === "PASS" ? "ok" : "danger"}`}>{probe.probe_type}</span><span className="cell-subtitle">{formatDate(probe.checked_at)}</span></> : <span className="badge danger">Bez vzorku</span>}</td><td><IconButton label={`Detail serveru ${server.displayName}`} onClick={() => setDetailServer(server)}><MoreHorizontal size={17} /></IconButton></td></tr>;
            })}</tbody></table></div>
        )}
        </section>
      </> : null}
      {view === "alerts" ? <section className="panel table-panel">
        <div className="panel-head"><h2>Aktivní alerty</h2><button className="secondary" disabled={actionBusy} onClick={() => { void runAction(onTestWebhook, "Test webhooků byl úspěšně odeslán.", "Test webhooků selhal."); }}><Terminal size={16} /> Test webhooků</button></div>
        {actionNotice ? <div className={`notice ${actionNotice.tone === "success" ? "success" : "error"}`}><span>{actionNotice.text}</span></div> : null}
        <div className="table-scroll"><table><thead><tr><th>Závažnost</th><th>Server</th><th>Alert</th><th>Stav</th><th>Naposledy</th><th>Akce</th></tr></thead><tbody>{activeAlerts.map((alert) => <tr key={alert.id}><td><span className={`badge ${alert.severity === "CRITICAL" ? "danger" : "warn"}`}>{alert.severity}</span></td><td>{alert.code ?? "KCML"}</td><td><strong>{alert.title}</strong><span className="cell-subtitle">{alert.alert_type}</span></td><td><span className="badge neutral">{alert.status}</span>{alert.suppressed_until ? <span className="cell-subtitle">do {formatDate(alert.suppressed_until)}</span> : null}</td><td>{formatDate(alert.last_seen_at)}</td><td><div className="row-actions">{alert.status === "OPEN" ? <button className="secondary" disabled={actionBusy} onClick={() => { void runAction(() => onAcknowledgeAlert(alert), `Alert ${alert.title} byl potvrzen.`, "Potvrzení alertu selhalo."); }}>Potvrdit</button> : null}{["OPEN", "ACKNOWLEDGED"].includes(alert.status) ? <button className="secondary" disabled={actionBusy} onClick={() => setSuppressingAlert(alert)}><BellOff size={15} /> Potlačit</button> : null}</div></td></tr>)}</tbody></table></div>
        {activeAlerts.length === 0 ? <div className="empty-state"><CheckCircle2 size={34} /><strong>Žádné aktivní alerty</strong></div> : null}
      </section> : null}
      {view === "deliveries" ? <section className="panel table-panel">
        <div className="panel-head"><h2>Webhook delivery</h2></div>
        {actionNotice ? <div className={`notice ${actionNotice.tone === "success" ? "success" : "error"}`}><span>{actionNotice.text}</span></div> : null}
        <div className="table-scroll"><table><thead><tr><th>Kanál</th><th>Alert</th><th>Stav</th><th>Pokusy</th><th>HTTP</th><th>Další pokus</th><th>Akce</th></tr></thead><tbody>{overview.deliveries.map((delivery) => <tr key={delivery.id}><td><span className="badge neutral">{delivery.channel}</span></td><td>{delivery.code ?? "KCML"}<span className="cell-subtitle">{delivery.alert_type}</span></td><td><span className={`badge ${delivery.state === "DELIVERED" ? "ok" : delivery.state === "DEAD_LETTER" ? "danger" : "warn"}`}>{delivery.state}</span>{delivery.last_error ? <span className="cell-subtitle">{delivery.last_error}</span> : null}</td><td>{delivery.attempt_count}</td><td>{delivery.last_http_status ?? "-"}</td><td>{formatDate(delivery.next_attempt_at)}</td><td>{["RETRY", "DEAD_LETTER"].includes(delivery.state) ? <button className="secondary" disabled={actionBusy} onClick={() => { void runAction(() => onRetryDelivery(delivery), `Delivery ${delivery.id} byla zařazena k opakování.`, "Opakování delivery selhalo."); }}>Opakovat</button> : "-"}</td></tr>)}</tbody></table></div>
        {overview.deliveries.length === 0 ? <div className="empty-state"><Terminal size={34} /><strong>Žádné webhook delivery</strong></div> : null}
      </section> : null}
      {view === "history" ? <section className="panel table-panel">
        <div className="panel-head"><h2>Historie stavů</h2></div>
        <div className="table-scroll"><table><thead><tr><th>Čas</th><th>Server</th><th>Registrace</th><th>Provoz</th><th>Recertifikace</th><th>Důvod</th><th>Correlation ID</th></tr></thead><tbody>{overview.stateHistory.map((entry) => <tr key={entry.id}><td>{formatDate(entry.recorded_at)}</td><td>{entry.code}</td><td><span className="badge neutral">{entry.registration_state}</span></td><td>{entry.operational_state}</td><td>{entry.recertification_phase}</td><td>{entry.reason}</td><td><code>{entry.correlation_id}</code></td></tr>)}</tbody></table></div>
        {overview.stateHistory.length === 0 ? <div className="empty-state"><Clock3 size={34} /><strong>Historie je prázdná</strong></div> : null}
      </section> : null}
      {detailServer ? <ServerDetailModal
        server={servers.find((server) => server.id === detailServer.id) ?? detailServer}
        probes={probes.filter((probe) => probe.server_id === detailServer.id)}
        history={overview.stateHistory.filter((entry) => entry.server_id === detailServer.id)}
        accountName={accountName}
        onClose={() => setDetailServer(null)}
        onToggleEnabled={onToggleEnabled}
        onRunTest={onRunTest}
        onLoadMonitoringProfile={onLoadMonitoringProfile}
        onSaveMonitoringProfile={onSaveMonitoringProfile}
        onStartRevision={onStartRevision}
        onDeleteServer={onDeleteServer}
      /> : null}
      {suppressingAlert ? <AlertSuppressionModal alert={suppressingAlert} onClose={() => setSuppressingAlert(null)} onSubmit={async (reason, until) => { await onSuppressAlert(suppressingAlert, reason, until); setSuppressingAlert(null); }} /> : null}
    </>
  );
}

function DeleteServerModal({
  server,
  accountName,
  onClose,
  onDeleted
}: {
  server: Server;
  accountName: string | null;
  onClose: () => void;
  onDeleted: (input: { confirmedCode: string; reason: string; password: string; totp: string }) => Promise<void>;
}) {
  const [confirmedCode, setConfirmedCode] = useState("");
  const [reason, setReason] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await onDeleted({ confirmedCode: confirmedCode.trim(), reason: reason.trim(), password, totp: totp.trim() });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Smazání registrace selhalo");
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal title="Smazat registraci serveru" onClose={onClose}>
      <form className="modal-form" onSubmit={(event) => { void submit(event); }}>
        <div className="notice error"><AlertTriangle size={18} /><span>Server bude kompletně odstraněn z registru KCML. Pokud se bude registrovat znovu, musí být vystaven nový onboarding token a proběhne celý onboarding od začátku.</span></div>
        <label>Důvod smazání<textarea autoFocus value={reason} onChange={(event) => setReason(event.target.value)} minLength={10} maxLength={1000} rows={4} /></label>
        <label>Pro potvrzení opište přesný KCML kód<input value={confirmedCode} onChange={(event) => setConfirmedCode(event.target.value)} placeholder={server.code} /></label>
        <input type="text" autoComplete="username" value={accountName ?? ""} readOnly hidden />
        <label>Heslo administrátora<input name="password" value={password} onChange={(event) => setPassword(event.target.value)} type="password" autoComplete="current-password" /></label>
        <label>Jednorázový MFA kód (je-li zapnutý)<input value={totp} onChange={(event) => setTotp(event.target.value)} inputMode="numeric" autoComplete="one-time-code" /></label>
        {error ? <p className="error">{error}</p> : null}
        <footer className="modal-actions"><button type="button" className="secondary" onClick={onClose}>Zrušit</button><button type="submit" className="danger-button" disabled={busy || confirmedCode !== server.code || reason.trim().length < 10 || !password}>{busy ? "Mažu…" : "Smazat registraci"}</button></footer>
      </form>
    </Modal>
  );
}

function AlertSuppressionModal({ alert, onClose, onSubmit }: { alert: OperationalAlert; onClose: () => void; onSubmit: (reason: string, until: string) => Promise<void> }) {
  const [reason, setReason] = useState("");
  const [until, setUntil] = useState(() => formatLocalDateTimeInput(new Date(Date.now() + 60 * 60 * 1_000)));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await onSubmit(reason.trim(), new Date(until).toISOString());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Potlačení alertu selhalo");
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal title={`Potlačit alert ${alert.code ?? "KCML"}`} onClose={onClose}>
      <form className="modal-form" onSubmit={(event) => { void submit(event); }}>
        <div className="notice warning"><BellOff size={18} /><span>{alert.title}</span></div>
        <label>Důvod potlačení<textarea autoFocus rows={4} minLength={5} maxLength={500} value={reason} onChange={(event) => setReason(event.target.value)} /></label>
        <label>Potlačit do<input type="datetime-local" value={until} min={formatLocalDateTimeInput(new Date())} onChange={(event) => setUntil(event.target.value)} /></label>
        {error ? <p className="error">{error}</p> : null}
        <footer className="modal-actions"><button type="button" className="secondary" onClick={onClose}>Zrušit</button><button type="submit" disabled={busy || reason.trim().length < 5 || !until}><BellOff size={16} /> {busy ? "Ukládám…" : "Potlačit do termínu"}</button></footer>
      </form>
    </Modal>
  );
}

function OnboardingJobModal({ jobId, onClose, onResume, onCancel, onReleaseQuarantine }: { jobId: string; onClose: () => void; onResume: (jobId: string) => void; onCancel: (jobId: string) => Promise<void>; onReleaseQuarantine: (job: OnboardingJob) => void }) {
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
        <footer className="modal-actions"><button className="secondary" onClick={onClose}>Zavřít</button>{job.state === "QUARANTINED" ? <button className="danger-button" onClick={() => onReleaseQuarantine(job)}>Schválit novou revizi</button> : null}{job.state !== "ACTIVE" && job.state !== "QUARANTINED" && job.state !== "CANCELLED" ? <button className="secondary" onClick={() => onResume(job.id)}>Vystavit navazující token</button> : null}{!["ACTIVE", "FAILED", "QUARANTINED", "CANCELLED"].includes(job.state) ? <button className="danger-button" onClick={() => { void onCancel(job.id); }}>Zrušit job</button> : null}</footer>
      </div>}
    </Modal>
  );
}

function QuarantineReleaseModal({
  job,
  accountName,
  onClose,
  onReleased
}: {
  job: OnboardingJob;
  accountName: string | null;
  onClose: () => void;
  onReleased: () => Promise<void>;
}) {
  const [confirmedCode, setConfirmedCode] = useState("");
  const [reason, setReason] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api(`/api/onboarding-jobs/${job.id}/release-quarantine`, {
        method: "POST",
        headers: { "x-csrf-token": csrf() },
        body: JSON.stringify({ confirmedCode: confirmedCode.trim(), reason: reason.trim(), password, totp: totp.trim() })
      });
      await onReleased();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Uvolnění karantény selhalo");
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal title="Schválit novou registrační revizi" onClose={onClose}>
      <form className="modal-form" onSubmit={(event) => { void submit(event); }}>
        <div className="notice error"><AlertTriangle size={18} /><span>Server zůstane vypnutý. Tato ruční akce pouze povolí nahrání nové revize a její kompletní bezpečnostní přetestování.</span></div>
        <label>Důvod a doložená náprava<textarea autoFocus value={reason} onChange={(event) => setReason(event.target.value)} minLength={10} maxLength={1000} rows={4} /></label>
        <label>Pro potvrzení opište přesný KCML kód<input value={confirmedCode} onChange={(event) => setConfirmedCode(event.target.value)} placeholder={job.code ?? "KCML…"} /></label>
        <input type="text" autoComplete="username" value={accountName ?? ""} readOnly hidden />
        <label>Heslo administrátora<input name="password" value={password} onChange={(event) => setPassword(event.target.value)} type="password" autoComplete="current-password" /></label>
        <label>Jednorázový MFA kód (je-li zapnutý)<input value={totp} onChange={(event) => setTotp(event.target.value)} inputMode="numeric" autoComplete="one-time-code" /></label>
        {error ? <p className="error">{error}</p> : null}
        <footer className="modal-actions"><button type="button" className="secondary" onClick={onClose}>Zrušit</button><button type="submit" className="danger-button" disabled={busy || confirmedCode !== job.code || reason.trim().length < 10 || !password}>{busy ? "Ověřuji…" : "Schválit novou revizi"}</button></footer>
      </form>
    </Modal>
  );
}

function IntegrationTokenRunIndicator({ token, nowMs }: { token: IntegrationToken; nowMs: number }) {
  const lifecycle = getIntegrationTokenLifecycle(token, nowMs);
  return (
    <div className={`integration-run-state ${lifecycle.runState}`} title={lifecycle.protectionLabel}>
      <span className="integration-run-heading"><span className="integration-run-dot" /><strong>{lifecycle.runLabel}</strong></span>
      <span className={`integration-protection ${lifecycle.protectionActive ? "protected" : "unprotected"}`}>
        {lifecycle.protectionActive ? <ShieldCheck size={13} /> : <Clock3 size={13} />}{lifecycle.protectionLabel}
      </span>
      {token.tokenExtendedAt ? <small>Naposledy prodlouženo {formatDate(token.tokenExtendedAt)}</small> : null}
    </div>
  );
}

function IntegrationTokenExpiry({ token, nowMs }: { token: IntegrationToken; nowMs: number }) {
  const lifecycle = getIntegrationTokenLifecycle(token, nowMs);
  return (
    <div className={`token-countdown ${lifecycle.tokenValid ? "valid" : "expired"}`} aria-label={lifecycle.tokenValid ? `Platnost končí za ${formatMinuteSecondCountdown(lifecycle.currentRemainingMs)}` : "Platnost tokenu skončila"}>
      <strong>{formatMinuteSecondCountdown(lifecycle.currentRemainingMs)}</strong>
      <small>{lifecycle.tokenValid ? `Končí ${formatDate(token.expiresAt)}` : "Token již nelze použít"}</small>
    </div>
  );
}

function IntegrationTokenMaximum({ token, nowMs }: { token: IntegrationToken; nowMs: number }) {
  const lifecycle = getIntegrationTokenLifecycle(token, nowMs);
  const maximumExhausted = lifecycle.maximumRemainingMs === 0;
  const progressLabel = Math.round(lifecycle.maximumProgressPercent);
  return (
    <div className={`token-maximum ${lifecycle.nearMaximum || maximumExhausted ? "near" : "safe"}`}>
      <strong>{formatMinuteSecondCountdown(lifecycle.maximumRemainingMs)}</strong>
      <small>{maximumExhausted ? "Pevný limit 24 h vyčerpán" : lifecycle.nearMaximum ? "Blíží se pevný limit 24 h" : "Zbývá do pevného limitu 24 h"}</small>
      <progress max="100" value={lifecycle.maximumProgressPercent} aria-label={`Využito ${progressLabel} procent z maximální doby 24 hodin`} />
      <small>Využito {progressLabel} % · maximum {formatDate(token.maxExpiresAt)}</small>
    </div>
  );
}

function IntegrationTokensPage({ tokens, jobs, onCreate, onOpenJob, onResume, onRevoke, onDelete, onRefresh }: { tokens: IntegrationToken[]; jobs: OnboardingJob[]; onCreate: () => void; onOpenJob: (id: string) => void; onResume: (id: string) => void; onRevoke: (token: IntegrationToken) => void; onDelete: (token: IntegrationToken) => void; onRefresh: () => void }) {
  const [query, setQuery] = useState("");
  const [nowMs, setNowMs] = useState(() => Date.now());
  useEffect(() => {
    const countdownTimer = window.setInterval(() => setNowMs(Date.now()), 1_000);
    const refreshTimer = window.setInterval(onRefresh, 15_000);
    return () => {
      window.clearInterval(countdownTimer);
      window.clearInterval(refreshTimer);
    };
  }, [onRefresh]);
  const filtered = tokens.filter((token) => `${token.label} ${token.descriptor.summary} ${token.fingerprint} ${token.code ?? ""}`.toLowerCase().includes(query.toLowerCase()));
  return (
    <>
      <PageHeader title="Implementační tokeny" description="Označení integračního toku, strukturovaný descriptor a token pro automatickou integraci jednoho MCP serveru.">
        <label className="search-box"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Hledat token, job nebo KCML…" aria-label="Hledat implementační token" /></label>
        <button onClick={onCreate}><Plus size={17} /> {integrationTokenActionLabel}</button><IconButton label="Obnovit" onClick={onRefresh}><RefreshCw size={17} /></IconButton>
      </PageHeader>
      <section className="panel table-panel"><div className="panel-head"><div><h2>Vydané tokeny</h2><p>Plná hodnota je v create response a handoffu; tento přehled trvale uchovává fingerprint.</p></div><span className="panel-count">{filtered.length} záznamů</span></div>
        {filtered.length === 0 ? <div className="empty-state"><Workflow size={34} /><strong>Žádné implementační tokeny</strong><p>Vygeneruj první token a předej jej programátorovi bezpečným kanálem.</p></div> : <div className="table-scroll"><table className="integration-token-table"><thead><tr><th>Token</th><th>KCML / job</th><th>Stav integrace / ochrana</th><th>Platnost a limit 24 hodin</th><th>Akce</th></tr></thead><tbody>{filtered.map((token) => <tr key={token.id}><td><strong>{token.label}</strong><span className="cell-subtitle">{token.descriptor.summary}</span><span className="cell-subtitle">Vydán {formatDate(token.issuedAt)}</span><code className="cell-fingerprint">{token.fingerprint}</code></td><td>{token.code ?? "Čeká na upload"}<span className="cell-subtitle">{token.jobId ? token.jobId.slice(0, 8) : "Nevázaný"}</span></td><td><div className="integration-state-cell"><span className={`badge ${token.active ? "ok" : "danger"}`}>{token.jobState ?? (token.active ? "PŘIPRAVEN" : "NEPLATNÝ")}</span><IntegrationTokenRunIndicator token={token} nowMs={nowMs} /></div></td><td><div className="token-timing-cell"><IntegrationTokenExpiry token={token} nowMs={nowMs} /><IntegrationTokenMaximum token={token} nowMs={nowMs} /></div></td><td><div className="row-actions integration-row-actions">{token.jobId ? <button className="small-button" onClick={() => onOpenJob(token.jobId!)}>Detail</button> : null}{token.jobId && !["ACTIVE", "QUARANTINED", "CANCELLED"].includes(token.jobState ?? "") && !token.active ? <button className="small-button" onClick={() => onResume(token.jobId!)}>Navázat</button> : null}<button className="small-button" disabled={!token.active} onClick={() => onRevoke(token)}>Revokovat</button><button className="small-button danger-link" onClick={() => onDelete(token)}>Smazat</button></div></td></tr>)}</tbody></table></div>}
      </section>
      <section className="panel"><div className="panel-head"><h2>Onboardingové joby</h2><span className="panel-count">{jobs.length} jobů</span></div>{jobs.length === 0 ? <div className="empty-state server-empty"><Rocket size={32} /><strong>Zatím nebyl zahájen žádný upload</strong></div> : <div className="job-cards">{jobs.map((job) => <button key={job.id} onClick={() => onOpenJob(job.id)}><span className={`status-dot ${job.state === "ACTIVE" ? "ok" : ["FAILED", "QUARANTINED", "CANCELLED"].includes(job.state) ? "danger" : "warn"}`} /><span><strong>{job.code ?? "Čeká na identitu"}</strong><small>{job.state} · {formatDate(job.updatedAt)}</small></span><ChevronDown className="item-chevron" size={15} /></button>)}</div>}</section>
    </>
  );
}

function Dashboard({ accountName, role, onLogout }: { accountName: string | null; role: AdminRole; onLogout: () => void }) {
  const [page, setPage] = useState<Page>("components");
  const [components, setComponents] = useState<Component[]>([]);
  const [servers, setServers] = useState<Server[]>([]);
  const [credentials, setCredentials] = useState<KajaCredential[]>([]);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [auditNextCursor, setAuditNextCursor] = useState<string | null>(null);
  const [auditIntegrity, setAuditIntegrity] = useState<AuditIntegrity | null>(null);
  const [security, setSecurity] = useState<AdminSecurity | null>(null);
  const [adminAccounts, setAdminAccounts] = useState<AdminAccount[]>([]);
  const [operationalConfig, setOperationalConfig] = useState<OperationalConfigSetting[]>([]);
  const [integrationTokens, setIntegrationTokens] = useState<IntegrationToken[]>([]);
  const [onboardingJobs, setOnboardingJobs] = useState<OnboardingJob[]>([]);
  const [probes, setProbes] = useState<MonitoringProbe[]>([]);
  const [monitoringOverview, setMonitoringOverview] = useState<MonitoringOverview>({ alerts: [], deliveries: [], stateHistory: [], scheduler: null });
  const [selectedCredentialId, setSelectedCredentialId] = useState<string | null>(null);
  const [permissions, setPermissions] = useState<KajaPermission[]>([]);
  const [savingPermissions, setSavingPermissions] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [secret, setSecret] = useState<SecretResult | null>(null);
  const [integrationCreate, setIntegrationCreate] = useState<{ resumeJobId?: string } | null>(null);
  const [integrationSecret, setIntegrationSecret] = useState<IntegrationSecret | null>(null);
  const [integrationConfirm, setIntegrationConfirm] = useState<{ token: IntegrationToken; action: "revoke" | "delete" } | null>(null);
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null);
  const [quarantineRelease, setQuarantineRelease] = useState<OnboardingJob | null>(null);
  const [confirm, setConfirm] = useState<{ credential: KajaCredential; action: "revoke" | "delete" } | null>(null);
  const [renameCredential, setRenameCredential] = useState<KajaCredential | null>(null);
  const [error, setError] = useState("");
  async function load() {
    setError("");
    try {
      const [componentRes, serverRes, credentialRes, auditRes, integrationRes, jobsRes, probesRes, monitoringRes, securityRes, integrityRes, adminAccountsRes, configRes] = await Promise.all([
        api<{ components: Component[] }>("/api/components"),
        api<{ servers: Server[] }>("/api/mcp-servers"),
        api<{ credentials: KajaCredential[] }>("/api/kaja"),
        api<AuditResponse>("/api/audit"),
        api<{ tokens: IntegrationToken[] }>("/api/integration-tokens"),
        api<{ jobs: OnboardingJob[] }>("/api/onboarding-jobs"),
        api<{ probes: MonitoringProbe[] }>("/api/monitoring-probes"),
        api<MonitoringOverview>("/api/monitoring-overview"),
        api<AdminSecurity>("/api/admin-security"),
        api<AuditIntegrity>("/api/audit/integrity"),
        role === "OWNER" ? api<{ accounts: AdminAccount[] }>("/api/admin-accounts") : Promise.resolve({ accounts: [] }),
        api<{ settings: OperationalConfigSetting[] }>("/api/operational-config")
      ]);
      setComponents(componentRes.components);
      setServers(serverRes.servers);
      setCredentials(credentialRes.credentials);
      setEvents(auditRes.events);
      setAuditNextCursor(auditRes.nextCursor);
      setAuditIntegrity(integrityRes);
      const configuredTimeZone = configRes.settings.find((setting) => setting.key === "uiTimeZone")?.value;
      if (typeof configuredTimeZone === "string") setUiTimeZone(configuredTimeZone);
      setIntegrationTokens(integrationRes.tokens);
      setOnboardingJobs(jobsRes.jobs);
      setProbes(probesRes.probes);
      setMonitoringOverview(monitoringRes);
      setSecurity(securityRes);
      setAdminAccounts(adminAccountsRes.accounts);
      setOperationalConfig(configRes.settings);
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

  async function renameCredentialLabel(label: string) {
    if (!renameCredential) return;
    await api(`/api/kaja/${renameCredential.id}/label`, {
      method: "PATCH",
      headers: { "x-csrf-token": csrf() },
      body: JSON.stringify({ label })
    });
    setRenameCredential(null);
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
    await api("/api/logout", { method: "POST", headers: { "x-csrf-token": csrf() }, body: "{}" });
    onLogout();
  }

  async function toggleServerEnabled(server: Server, enabled: boolean) {
    await setServerEnabled(server, enabled);
    await load();
  }

  async function runServerTest(server: Server) {
    const result = await runRegisteredServerTest(server);
    await load();
    return result;
  }

  async function loadMonitoringProfile(server: Server) {
    return getMonitoringProfile(server);
  }

  async function saveMonitoringProfile(server: Server, profile: MonitoringProfile) {
    await persistMonitoringProfile(server, profile);
    await load();
  }

  async function startServerRevision(server: Server) {
    setIntegrationCreate({ resumeJobId: await createServerRevision(server) });
    await load();
  }

  async function deleteServerRegistration(server: Server, input: { confirmedCode: string; reason: string; password: string; totp: string }) {
    await api(`/api/mcp-servers/${server.id}/delete`, {
      method: "POST",
      headers: { "x-csrf-token": csrf() },
      body: JSON.stringify(input)
    });
    await load();
  }

  async function testAlertWebhooks() {
    await testAlertChannels();
    await load();
  }

  async function acknowledgeAlert(alert: OperationalAlert) {
    await acknowledgeOperationalAlert(alert);
    await load();
  }

  async function suppressAlert(alert: OperationalAlert, reason: string, until: string) {
    await suppressOperationalAlert(alert, reason, until);
    await load();
  }

  async function retryAlertDelivery(delivery: AlertDelivery) {
    await retryAlertDeliveryRequest(delivery);
    await load();
  }

  async function refreshAudit(params: AuditFilters) {
    const search = auditQueryParams(params);
    const result = await api<AuditResponse>(`/api/audit${search.size ? `?${search.toString()}` : ""}`);
    setEvents(result.events);
    setAuditNextCursor(result.nextCursor);
  }

  async function loadMoreAudit(params: AuditFilters) {
    if (!auditNextCursor) return;
    const search = auditQueryParams(params);
    search.set("cursor", auditNextCursor);
    const result = await api<AuditResponse>(`/api/audit?${search.toString()}`);
    setEvents((current) => [...current, ...result.events]);
    setAuditNextCursor(result.nextCursor);
  }

  async function refreshAuditIntegrity() {
    setAuditIntegrity(await api<AuditIntegrity>("/api/audit/integrity"));
  }

  async function loadAuditDetail(id: number) {
    const result = await api<{ event: AuditEvent }>(`/api/audit/events/${id}`);
    return result.event;
  }

  async function refreshSecurity() {
    const result = await api<AdminSecurity>("/api/admin-security");
    setSecurity(result);
  }

  async function changeAdminPassword(currentPassword: string, nextPassword: string) {
    await api("/api/admin-password", {
      method: "POST",
      headers: { "x-csrf-token": csrf() },
      body: JSON.stringify({ currentPassword, nextPassword })
    });
    await refreshSecurity();
  }

  async function revokeOtherSessions() {
    await api("/api/admin-sessions/revoke-others", {
      method: "POST",
      headers: { "x-csrf-token": csrf() },
      body: "{}"
    });
    await refreshSecurity();
  }

  async function revokeSession(sessionId: string) {
    await api(`/api/admin-sessions/${sessionId}/revoke`, {
      method: "POST",
      headers: { "x-csrf-token": csrf() },
      body: "{}"
    });
    await refreshSecurity();
  }

  async function revokeAllSessions() {
    await api("/api/admin-sessions/revoke-all", {
      method: "POST",
      headers: { "x-csrf-token": csrf() },
      body: "{}"
    });
    onLogout();
  }

  async function startMfaEnrollment() {
    return api<{
      ok: true;
      mfaEnabled: boolean;
      enrollmentToken: string;
      otpauthUri: string;
      manualSecret: string;
      expiresAt: string;
    }>("/api/admin-mfa/enrollment/start", {
      method: "POST",
      headers: { "x-csrf-token": csrf() },
      body: "{}"
    });
  }

  async function verifyMfaEnrollment(input: { enrollmentToken: string; code: string }) {
    const result = await api<{ ok: true; recoveryCodes: string[] }>("/api/admin-mfa/enrollment/verify", {
      method: "POST",
      headers: { "x-csrf-token": csrf() },
      body: JSON.stringify(input)
    });
    await refreshSecurity();
    return result.recoveryCodes;
  }

  async function refreshAdminAccounts() {
    const result = await api<{ accounts: AdminAccount[] }>("/api/admin-accounts");
    setAdminAccounts(result.accounts);
  }

  async function refreshOperationalConfig() {
    const result = await api<{ settings: OperationalConfigSetting[] }>("/api/operational-config");
    const configuredTimeZone = result.settings.find((setting) => setting.key === "uiTimeZone")?.value;
    if (typeof configuredTimeZone === "string") setUiTimeZone(configuredTimeZone);
    setOperationalConfig(result.settings);
  }

  async function saveOperationalConfig(setting: OperationalConfigSetting, value: string | number | boolean | string[]) {
    const domainVersions = Object.fromEntries(
      operationalConfig
        .filter((item) => ["publicBaseDomain", "adminHost", "authHost", "registerHost"].includes(item.key))
        .map((item) => [item.key, item.version])
    );
    const path = setting.key === "publicBaseDomain" ? "/api/operational-config/domain" : `/api/operational-config/${setting.key}`;
    const body = setting.key === "publicBaseDomain"
      ? { baseDomain: value, expectedVersions: domainVersions }
      : { value, expectedVersion: setting.version };
    await api(path, {
      method: "PUT",
      headers: { "x-csrf-token": csrf() },
      body: JSON.stringify(body)
    });
    await refreshOperationalConfig();
  }

  async function createAdminAccount(input: { username: string; password: string; role: AdminRole }) {
    await api("/api/admin-accounts", {
      method: "POST",
      headers: { "x-csrf-token": csrf() },
      body: JSON.stringify(input)
    });
    await refreshAdminAccounts();
  }

  async function updateAdminAccount(accountId: string, input: { role?: AdminRole; active?: boolean }) {
    await api(`/api/admin-accounts/${accountId}`, {
      method: "PATCH",
      headers: { "x-csrf-token": csrf() },
      body: JSON.stringify(input)
    });
    await refreshAdminAccounts();
  }

  async function setAdminAccountPassword(accountId: string, nextPassword: string) {
    await api(`/api/admin-accounts/${accountId}/password`, {
      method: "POST",
      headers: { "x-csrf-token": csrf() },
      body: JSON.stringify({ nextPassword })
    });
    await refreshAdminAccounts();
  }

  async function revokeAdminAccountSessions(accountId: string) {
    await api(`/api/admin-accounts/${accountId}/sessions/revoke`, {
      method: "POST",
      headers: { "x-csrf-token": csrf() },
      body: "{}"
    });
    await Promise.all([refreshAdminAccounts(), refreshSecurity()]);
  }

  async function rotateAdminRecoveryCodes(accountId: string) {
    const result = await api<{ recoveryCodes: string[] }>(`/api/admin-accounts/${accountId}/recovery/rotate`, {
      method: "POST",
      headers: { "x-csrf-token": csrf() },
      body: "{}"
    });
    await refreshAdminAccounts();
    return result.recoveryCodes;
  }

  function openPermissions(id: string) {
    setSelectedCredentialId(id);
    setPage("permissions");
  }

  async function loadComponentDetail(id: string): Promise<Component> {
    const result = await api<{ component: Component }>(`/api/components/${id}`);
    return result.component;
  }

  async function toggleComponent(component: Component, enabled: boolean): Promise<Component> {
    try {
      const updated = await setComponentEnabled(component, enabled);
      setComponents((current) => current.map((entry) => entry.id === updated.id ? updated : entry));
      return updated;
    } catch (err) {
      setError(err instanceof Error ? err.message : "Změna stavu komponenty selhala");
      throw err;
    }
  }

  async function updateComponent(component: Component, operation: () => Promise<Component>, failure: string): Promise<Component> {
    try {
      const updated = await operation();
      setComponents((current) => current.map((entry) => entry.id === updated.id ? updated : entry));
      return updated;
    } catch (err) {
      setError(err instanceof Error ? err.message : failure);
      throw err;
    }
  }

  return (
    <AppLayout
      page={page}
      role={role}
      accountName={accountName}
      error={error}
      onPageChange={setPage}
      onLogout={() => { void logout(); }}
      overlays={<>
        {createOpen && <CreateCredentialModal serverCount={servers.length} onClose={() => setCreateOpen(false)} onCreated={(created) => { setCreateOpen(false); setSecret(created); void load(); }} />}
        {secret && <CredentialSecretModal secret={secret} onClose={() => setSecret(null)} />}
        {confirm && <CredentialConfirmModal credential={confirm.credential} action={confirm.action} onClose={() => setConfirm(null)} onConfirm={runConfirm} />}
        {renameCredential && <RenameCredentialModal credential={renameCredential} onClose={() => setRenameCredential(null)} onRename={renameCredentialLabel} />}
        {integrationCreate && <CreateIntegrationTokenModal resumeJobId={integrationCreate.resumeJobId} onClose={() => setIntegrationCreate(null)} onCreated={(created) => { setIntegrationCreate(null); setIntegrationSecret(created); setPage("integration"); void load(); }} />}
        {integrationSecret && <IntegrationSecretModal secret={integrationSecret} onClose={() => setIntegrationSecret(null)} />}
        {integrationConfirm && <IntegrationConfirmModal token={integrationConfirm.token} action={integrationConfirm.action} onClose={() => setIntegrationConfirm(null)} onConfirm={runIntegrationConfirm} />}
        {selectedJobId && <OnboardingJobModal jobId={selectedJobId} onClose={() => setSelectedJobId(null)} onResume={(jobId) => { setSelectedJobId(null); setIntegrationCreate({ resumeJobId: jobId }); }} onCancel={cancelOnboardingJob} onReleaseQuarantine={(job) => { setSelectedJobId(null); setQuarantineRelease(job); }} />}
        {quarantineRelease && <QuarantineReleaseModal job={quarantineRelease} accountName={accountName} onClose={() => setQuarantineRelease(null)} onReleased={async () => { setQuarantineRelease(null); await load(); }} />}
      </>}
    >
      <PageRouter page={page} routes={{
        components: <ComponentCatalogPage components={components} role={role} onRefresh={() => { void load(); }} onLoadDetail={loadComponentDetail} onToggle={toggleComponent}
          onLifecycle={(component, action) => updateComponent(component, () => setComponentLifecycleRequest(component, action), "Změna lifecycle komponenty selhala")}
          onPermission={(component, permissionId, enabled) => updateComponent(component, () => setComponentPermissionRequest(component, permissionId, enabled), "Změna oprávnění selhala")}
          onCredentialRevoke={(component, credentialId) => updateComponent(component, () => revokeComponentCredentialRequest(component, credentialId), "Revokace credentialu selhala")}
          onCredentialRotate={async (component, credentialId) => {
            const result = await rotateComponentCredentialRequest(component, credentialId);
            setComponents((current) => current.map((entry) => entry.id === result.component.id ? result.component : entry));
            return result;
          }} />,
        monitoring: <MonitoringPage servers={servers} accountName={accountName} probes={probes} overview={monitoringOverview} onRefresh={() => { void load(); }} onAutomatedOnboarding={() => setIntegrationCreate({})} onToggleEnabled={toggleServerEnabled} onRunTest={runServerTest} onLoadMonitoringProfile={loadMonitoringProfile} onSaveMonitoringProfile={saveMonitoringProfile} onStartRevision={startServerRevision} onDeleteServer={deleteServerRegistration} onTestWebhook={testAlertWebhooks} onAcknowledgeAlert={acknowledgeAlert} onSuppressAlert={suppressAlert} onRetryDelivery={retryAlertDelivery} />,
        integration: <IntegrationTokensPage tokens={integrationTokens} jobs={onboardingJobs} onCreate={() => setIntegrationCreate({})} onOpenJob={setSelectedJobId} onResume={(jobId) => setIntegrationCreate({ resumeJobId: jobId })} onRevoke={(token) => setIntegrationConfirm({ token, action: "revoke" })} onDelete={(token) => setIntegrationConfirm({ token, action: "delete" })} onRefresh={() => { void load(); }} />,
        tokens: <CredentialsPage credentials={credentials} onOpenCreate={() => setCreateOpen(true)} onEditPermissions={openPermissions} onRename={setRenameCredential} onConfirm={(credential, action) => setConfirm({ credential, action })} onRefresh={() => { void load(); }} />,
        permissions: <PermissionsPage credentials={credentials} servers={servers} selectedId={selectedCredentialId} permissions={permissions} saving={savingPermissions} onSelect={setSelectedCredentialId} onChange={setPermissions} onSave={() => { void savePermissions(); }} />,
        audit: <AuditPage events={events} nextCursor={auditNextCursor} integrity={auditIntegrity} onLoadMore={loadMoreAudit} onLoadDetail={loadAuditDetail} onRefresh={refreshAudit} onRefreshIntegrity={refreshAuditIntegrity} />,
        config: <OperationalConfigPage settings={operationalConfig} onRefresh={refreshOperationalConfig} onSave={saveOperationalConfig} />,
        security: <SecurityPage security={security} onRefresh={refreshSecurity} onChangePassword={changeAdminPassword} onRevokeOtherSessions={revokeOtherSessions} onRevokeSession={revokeSession} onRevokeAllSessions={revokeAllSessions} onStartMfaEnrollment={startMfaEnrollment} onVerifyMfaEnrollment={verifyMfaEnrollment} />,
        admins: role === "OWNER" ? <AdminAccountsPage accounts={adminAccounts} onRefresh={refreshAdminAccounts} onCreate={createAdminAccount} onSetPassword={setAdminAccountPassword} onRevokeSessions={revokeAdminAccountSessions} onRotateRecovery={rotateAdminRecoveryCodes} onUpdate={updateAdminAccount} /> : null
      }} />
    </AppLayout>
  );
}

function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [sessionNotice, setSessionNotice] = useState("");
  const [reauthRequired, setReauthRequired] = useState(false);
  useEffect(() => { void api<Session>("/api/session").then(setSession).catch(() => setSession({ authenticated: false, account: null, role: null, bootstrapRequired: false })); }, []);
  useEffect(() => {
    const handleExpiredSession = () => {
      setSessionNotice("Vaše přihlašovací relace skončila nebo byla odhlášena. Po přihlášení můžete bezpečně pokračovat ve stejné operaci.");
      setSession({ authenticated: false, account: null, role: null, bootstrapRequired: false });
    };
    const handleReauthRequired = () => setReauthRequired(true);
    window.addEventListener(SESSION_EXPIRED_EVENT, handleExpiredSession);
    window.addEventListener(REAUTH_REQUIRED_EVENT, handleReauthRequired);
    return () => {
      window.removeEventListener(SESSION_EXPIRED_EVENT, handleExpiredSession);
      window.removeEventListener(REAUTH_REQUIRED_EVENT, handleReauthRequired);
    };
  }, []);
  if (!session) return <main className="loading">Načítám</main>;
  if (session.bootstrapRequired) return <BootstrapPage onComplete={() => setSession({ authenticated: false, account: null, role: null, bootstrapRequired: false })} />;
  if (!session.authenticated || !session.role) return <Login notice={sessionNotice} onLogin={() => { void api<Session>("/api/session").then((next) => { setSessionNotice(""); setSession(next); }); }} />;
  return <><Dashboard accountName={session.account} role={session.role} onLogout={() => { setSessionNotice(""); setSession({ authenticated: false, account: null, role: null, bootstrapRequired: false }); }} />{reauthRequired ? <ReauthModal onClose={() => setReauthRequired(false)} /> : null}</>;
}

createRoot(document.getElementById("root")!).render(<App />);
