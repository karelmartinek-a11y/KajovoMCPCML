import { createHash, randomUUID } from "node:crypto";
import dns from "node:dns/promises";
import http from "node:http";
import tls from "node:tls";
import type { MonitoringConfig } from "../config.js";
import type { Db } from "../db.js";
import { tx } from "../db.js";
import { closeAlert, deliverNextAlert, expireAlertSuppressions, raiseAlert } from "../domain/alerts.js";
import { appendAudit } from "../domain/audit.js";
import {
  listExternalApiMonitoringTargets,
  recordExternalApiMonitoringInternalError,
  runExternalApiMonitoringTarget
} from "../domain/external-api.js";
import { evaluateRecertification, type RecertificationDecision } from "../domain/recertification.js";
import { digestCanonicalJson, isStructuredOnboardingManifest, validateStoredOnboardingManifest, type OnboardingManifest } from "../domain/registration.js";
import { setComputedOperationalState, transitionServerState } from "../domain/server-state.js";
import { archivePendingAuditEvents } from "../domain/audit-archive.js";
import { verifyAuditChain } from "../domain/audit.js";
import { evaluateOperationalState } from "../domain/monitoring-policy.js";
import { markStaleComponentHeartbeats, queueComponentHeartbeatChallenge, recordComponentMonitoringWatchdog } from "../domain/component.js";
import { runSyntheticMonitoringProbe } from "./activation.js";
import { OciRuntime } from "./oci.js";
import { fetchThroughEgress } from "../domain/egress-client.js";

type ProbeStatus = "PASS" | "FAIL" | "STALE";
type Probe = { name: string; status: ProbeStatus; latencyMs: number; evidence: Record<string, unknown> };
type ProbeName = "liveness" | "readiness" | "tls" | "routing" | "oauth_mcp" | "synthetic_call" | "artifact_integrity" | "contract_profile_drift" | "dependencies";
type AlertRule = { probeType: string; severity: "WARNING" | "HIGH" | "CRITICAL"; consecutiveFailures: number };
type MonitorPolicy = {
  intervals: Record<ProbeName, number>;
  staleAfterSeconds: number;
  alertRules: AlertRule[];
  slo: { availabilityPercent: number; p95LatencyMs: number; maxErrorRatePercent: number } | null;
  legacyProfile: boolean;
};

export const LEGACY_MONITORING_INTERVALS: Record<ProbeName, number> = {
  liveness: 60,
  readiness: 60,
  tls: 3_600,
  routing: 60,
  oauth_mcp: 120,
  synthetic_call: 300,
  artifact_integrity: 300,
  contract_profile_drift: 300,
  dependencies: 300
};
export const LEGACY_MONITORING_STALE_AFTER_SECONDS = Math.max(...Object.values(LEGACY_MONITORING_INTERVALS));

export function routingProbePasses(status: number, allowHeader: string | null): boolean {
  if (status === 401) return true;
  if (status !== 405) return false;
  return (allowHeader ?? "")
    .split(",")
    .map((value) => value.trim().toUpperCase())
    .includes("POST");
}

export function completedProbeCheckTimes(rows: Array<Record<string, unknown>>): Map<string, number> {
  const completed = new Map<string, number>();
  for (const row of rows) {
    if (row.status === "STALE") continue;
    const probeType = String(row.probe_type);
    const checkedAt = new Date(row.checked_at as string | number | Date).getTime();
    if (!Number.isFinite(checkedAt) || checkedAt <= Number(completed.get(probeType) ?? 0)) continue;
    completed.set(probeType, checkedAt);
  }
  return completed;
}

export function expectedMonitoringProfileDigest(schemaVersion: string, profile: unknown, storedProfileText: unknown): string {
  if (schemaVersion === "1.4") {
    if (typeof storedProfileText !== "string") throw new Error("legacy_monitoring_profile_text_missing");
    return `sha256:${createHash("sha256").update(storedProfileText).digest("hex")}`;
  }
  return digestCanonicalJson(profile);
}

function monitorPolicy(manifest: OnboardingManifest): MonitorPolicy {
  if (isStructuredOnboardingManifest(manifest)) {
    const intervals = manifest.monitoringProfile.probeIntervals;
    return {
      intervals: {
        liveness: intervals.readinessSeconds,
        readiness: intervals.readinessSeconds,
        tls: intervals.tlsSeconds,
        routing: intervals.routingSeconds,
        oauth_mcp: intervals.oauthMcpSeconds,
        synthetic_call: intervals.syntheticCallSeconds,
        artifact_integrity: intervals.integritySeconds,
        contract_profile_drift: intervals.integritySeconds,
        dependencies: intervals.dependenciesSeconds
      },
      staleAfterSeconds: manifest.monitoringProfile.staleAfterSeconds,
      alertRules: manifest.monitoringProfile.alertRules,
      slo: manifest.monitoringProfile.sloTargets,
      legacyProfile: false
    };
  }
  return {
    intervals: LEGACY_MONITORING_INTERVALS,
    staleAfterSeconds: LEGACY_MONITORING_STALE_AFTER_SECONDS,
    alertRules: manifest.monitoringProfile.alertRules.flatMap((rule) => {
      const candidate = rule as { probeType?: unknown; name?: unknown; severity?: unknown; consecutiveFailures?: unknown };
      const probeType = typeof candidate.probeType === "string" ? candidate.probeType
        : typeof candidate.name === "string" ? candidate.name : null;
      const severity = typeof candidate.severity === "string" ? candidate.severity.toUpperCase() : "";
      if (!probeType || !["WARNING", "HIGH", "CRITICAL"].includes(severity)) return [];
      return [{
        probeType,
        severity: severity as AlertRule["severity"],
        consecutiveFailures: Math.max(1, Number(candidate.consecutiveFailures ?? 1))
      }];
    }),
    slo: null,
    legacyProfile: true
  };
}

async function measured(name: ProbeName, fn: () => Promise<Record<string, unknown>>): Promise<Probe> {
  const started = Date.now();
  try {
    const evidence = await fn();
    return { name, status: "PASS", latencyMs: Date.now() - started, evidence };
  } catch (error) {
    return {
      name,
      status: "FAIL",
      latencyMs: Date.now() - started,
      evidence: { error: error instanceof Error ? error.message.slice(0, 500) : "probe_failed" }
    };
  }
}

function socketHealth(socketPath: string): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const request = http.request({ socketPath, path: "/health", method: "GET", timeout: 3_000 }, (response) => {
      response.resume();
      if (response.statusCode === 200) resolve({ status: response.statusCode });
      else reject(new Error(`handler_health_status:${response.statusCode}`));
    });
    request.on("timeout", () => request.destroy(new Error("handler_health_timeout")));
    request.on("error", reject);
    request.end();
  });
}

function tlsCertificate(hostname: string): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host: hostname, port: 443, servername: hostname, rejectUnauthorized: true });
    socket.setTimeout(8_000);
    socket.once("secureConnect", () => {
      const certificate = socket.getPeerCertificate();
      const validTo = new Date(certificate.valid_to);
      socket.end();
      if (!certificate.valid_to || !Number.isFinite(validTo.getTime())) return reject(new Error("tls_expiry_missing"));
      const daysRemaining = Math.floor((validTo.getTime() - Date.now()) / 86_400_000);
      if (daysRemaining < 14) return reject(new Error(`tls_expiry_critical:${daysRemaining}`));
      resolve({ validTo: validTo.toISOString(), daysRemaining, subjectAltNamePresent: Boolean(certificate.subjectaltname) });
    });
    socket.once("timeout", () => socket.destroy(new Error("tls_timeout")));
    socket.once("error", reject);
  });
}

function recertificationFromRow(row: Record<string, unknown>): RecertificationDecision {
  return evaluateRecertification({
    activeRevisionId: typeof row.active_revision_id === "string" ? row.active_revision_id : null,
    validationState: typeof row.validation_state === "string" ? row.validation_state : null,
    approvedAt: row.approved_at ? new Date(row.approved_at as string | number | Date).toISOString() : null,
    reviewDueAt: row.review_due_at ? new Date(row.review_due_at as string | number | Date).toISOString() : null,
    reviewIntervalDays: row.review_interval_days === null || row.review_interval_days === undefined ? null : Number(row.review_interval_days)
  });
}

function externalDependencyUrls(manifest: OnboardingManifest): string[] {
  if (isStructuredOnboardingManifest(manifest)) return manifest.dependencies.externalServices.map((dependency) => dependency.endpoint);
  return manifest.dependencies?.externalServices.filter((dependency): dependency is string => typeof dependency === "string" && dependency.startsWith("https://")) ?? [];
}

async function dependencyHealth(manifest: OnboardingManifest): Promise<Record<string, unknown>> {
  const dependencies = externalDependencyUrls(manifest);
  const statuses: Array<{ host: string; status: number }> = [];
  for (const endpoint of dependencies) {
    const url = new URL(endpoint);
    await dns.lookup(url.hostname);
    const response = await fetch(url, { method: "HEAD", redirect: "manual", signal: AbortSignal.timeout(8_000) });
    if (response.status >= 500) throw new Error(`dependency_unavailable:${url.hostname}:${response.status}`);
    statuses.push({ host: url.hostname, status: response.status });
  }
  return { dependencyCount: dependencies.length, statuses };
}

export class MonitoringScheduler {
  private readonly oci: OciRuntime;
  private readonly workerId = `monitor-${randomUUID()}`;

  constructor(private readonly db: Db, private readonly config: MonitoringConfig) {
    this.oci = new OciRuntime(config);
  }

  async runOnce(): Promise<void> {
    await this.db.query(
      `insert into monitoring_scheduler_heartbeat(singleton,worker_id,last_started_at,last_completed_at,last_error,updated_at)
       values (true,$1,now(),null,null,now())
       on conflict (singleton) do update
         set worker_id=excluded.worker_id,last_started_at=now(),last_error=null,updated_at=now()`,
      [this.workerId]
    );
    try {
      await expireAlertSuppressions(this.db);
      await this.db.query("delete from http_rate_bucket where updated_at < clock_timestamp()-interval '1 day'");
      const auditIntegrity = await verifyAuditChain(this.db);
      const auditCorrelationId = randomUUID();
      await tx(this.db, async (client) => {
        if (auditIntegrity.valid) {
          await closeAlert(client, { alertType: "audit.integrity", reason: "audit_chain_valid", correlationId: auditCorrelationId });
        } else {
          await raiseAlert(client, {
            severity: "CRITICAL",
            alertType: "audit.integrity",
            title: "Integrita auditního řetězce je porušená",
            detail: auditIntegrity,
            correlationId: auditCorrelationId
          });
        }
      });
      await archivePendingAuditEvents(this.db, this.config.AUDIT_ARCHIVE_PATH);
      const result = await this.db.query(`
        select ms.*,rr.id as active_revision_id,rr.manifest,rr.manifest_digest as revision_manifest_digest,
               rr.artifact_digest as revision_artifact_digest,rr.validation_state,rr.approved_at,rr.review_due_at,
               rr.review_interval_days,rr.warning_emitted_at,mp.enabled as monitoring_enabled,mp.profile_digest,
               mp.profile::text as monitoring_profile_text,
               mp.next_probe_at,mp.consecutive_failures,job.image_digest as onboarding_image_digest
          from mcp_server ms
          left join registration_revision rr on rr.id=ms.active_revision_id and rr.server_id=ms.id and rr.active=true
          left join monitoring_profile mp on mp.server_id=ms.id and mp.registration_revision_id=rr.id
          left join lateral (
            select image_digest from onboarding_job where server_id=ms.id order by created_at desc limit 1
          ) job on true
         where ms.registration_state in ('ACTIVE','TRIAL')
           and (mp.next_probe_at is null or mp.next_probe_at<=now())
         order by ms.kcml_number
      `);
      for (const row of result.rows as Array<Record<string, unknown>>) {
        try {
          await this.probeServer(row);
        } catch (error) {
          await this.recordInternalError(row, error);
        }
      }
      const componentCorrelationId = randomUUID();
      const staleComponents = await markStaleComponentHeartbeats(this.db, 180, 600, componentCorrelationId);
      await tx(this.db, async (client) => {
        if (staleComponents > 0) {
          await raiseAlert(client, { severity: "CRITICAL", alertType: "component.heartbeat.stale",
            title: "Komponentové heartbeat překročily fail-closed limit", detail: { staleComponents }, correlationId: componentCorrelationId });
        } else {
          await closeAlert(client, { alertType: "component.heartbeat.stale", reason: "all_component_heartbeats_fresh", correlationId: componentCorrelationId });
        }
      });
      const activeComponents = await this.db.query("select id from component where lifecycle_state='ACTIVE' and enabled=true order by kcml_number");
      for (const component of activeComponents.rows) {
        try {
          await queueComponentHeartbeatChallenge(this.db, { componentId: String(component.id), correlationId: randomUUID() });
        } catch (error) {
          await tx(this.db, async (client) => raiseAlert(client, { severity: "HIGH", alertType: "component.heartbeat.challenge_failed",
            title: "Heartbeat challenge komponenty se nepodařilo zařadit", detail: { componentId: component.id, error: error instanceof Error ? error.message : "unknown" }, correlationId: randomUUID() }));
        }
      }
      const componentRuntimeTargets = await this.db.query(
        `select component.id,component.hostname,target.transport,target.upstream,target.expected_tls_identity,target.socket_path
           from component join component_runtime_target target on target.component_id=component.id and target.revision_id=component.active_revision_id
          where component.lifecycle_state in ('REVIEW','APPROVED','ACTIVE') and component.deregistered_at is null
          order by component.kcml_number`
      );
      for (const component of componentRuntimeTargets.rows) {
        const correlationId = randomUUID();
        const probe = await measured("readiness", async () => {
          if (component.transport === "UDS") return socketHealth(String(component.socket_path));
          if (component.transport !== "HTTPS" || !component.upstream || !component.expected_tls_identity) throw new Error("component_runtime_target_invalid");
          const upstream = new URL(String(component.upstream));
          if (upstream.protocol !== "https:" || upstream.hostname !== String(component.expected_tls_identity)) throw new Error("component_tls_identity_invalid");
          const response = await fetchThroughEgress(this.config, {
            url: new URL("/health", upstream).toString(), method: "GET",
            allowlist: [String(component.expected_tls_identity)],
            purpose: "component.monitoring.health", correlationId, ttlSeconds: 30
          });
          if (response.status !== 200) throw new Error(`component_health_status:${response.status}`);
          return { status: response.status, tlsIdentity: component.expected_tls_identity, transportPolicy: "KCML_EGRESS" };
        });
        await recordComponentMonitoringWatchdog(this.db, {
          componentId: String(component.id), pass: probe.status === "PASS",
          evidence: { transport: component.transport, latencyMs: probe.latencyMs, ...probe.evidence }, correlationId
        });
      }
      const externalTargets = await listExternalApiMonitoringTargets(this.db);
      for (const target of externalTargets) {
        try {
          await runExternalApiMonitoringTarget(this.db, this.config, target);
        } catch (error) {
          await recordExternalApiMonitoringInternalError(this.db, target, error);
        }
      }
      for (let delivered = 0; delivered < 20 && await deliverNextAlert(this.db, this.config); delivered += 1) {
        // Bound each scheduler cycle so fresh probes cannot be starved by a webhook outage.
      }
      await this.db.query(
        "update monitoring_scheduler_heartbeat set last_completed_at=now(),last_error=null,updated_at=now() where singleton=true and worker_id=$1",
        [this.workerId]
      );
    } catch (error) {
      await this.db.query(
        "update monitoring_scheduler_heartbeat set last_error=$2,updated_at=now() where singleton=true and worker_id=$1",
        [this.workerId, error instanceof Error ? error.message.slice(0, 500) : "monitor_cycle_failed"]
      ).catch(() => undefined);
      throw error;
    }
  }

  private async enforceRecertification(row: Record<string, unknown>, decision: RecertificationDecision, correlationId: string): Promise<boolean> {
    const serverId = String(row.id);
    const serverCode = String(row.code);
    if (decision.phase === "WARNING") {
      await tx(this.db, async (client) => {
        const warning = await client.query(
          "update registration_revision set warning_emitted_at=now() where id=$1 and warning_emitted_at is null returning id",
          [row.active_revision_id]
        );
        if (warning.rowCount) {
          await appendAudit(client, {
            eventType: "mcp_server.recertification.warning",
            actorType: "system",
            objectType: "mcp_server",
            objectId: serverId,
            after: { code: serverCode, reviewDueAt: decision.reviewDueAt, phase: decision.phase },
            correlationId
          });
        }
        await raiseAlert(client, {
          serverId,
          severity: "WARNING",
          alertType: "recertification.warning",
          title: `${serverCode}: recertifikace se blíží`,
          detail: { reviewDueAt: decision.reviewDueAt, secondsToBoundary: decision.secondsToBoundary },
          correlationId
        });
        await closeAlert(client, { serverId, alertType: "recertification.grace", reason: "phase_changed", correlationId });
      });
      return true;
    }
    if (decision.phase === "GRACE") {
      await tx(this.db, async (client) => {
        await raiseAlert(client, {
          serverId,
          severity: "HIGH",
          alertType: "recertification.grace",
          title: `${serverCode}: recertifikace je po termínu`,
          detail: { reviewDueAt: decision.reviewDueAt, secondsToSuspension: decision.secondsToBoundary },
          correlationId
        });
        await closeAlert(client, { serverId, alertType: "recertification.warning", reason: "grace_started", correlationId });
      });
      return true;
    }
    if (decision.phase === "SUSPENDED" || decision.phase === "INVALID") {
      await tx(this.db, async (client) => {
        await transitionServerState(client, {
          serverId,
          to: "SUSPENDED",
          actorType: "system",
          reason: decision.reason ?? "recertification_invalid",
          correlationId
        });
        await raiseAlert(client, {
          serverId,
          severity: "CRITICAL",
          alertType: "recertification.blocked",
          title: `${serverCode}: provoz zablokován recertifikací`,
          detail: { phase: decision.phase, reason: decision.reason, reviewDueAt: decision.reviewDueAt },
          correlationId
        });
      });
      await this.oci.stop(serverCode).catch(async (error) => {
        await this.recordInternalError(row, error);
      });
      return false;
    }
    await tx(this.db, async (client) => {
      await closeAlert(client, { serverId, alertType: "recertification.warning", reason: "recertification_valid", correlationId });
      await closeAlert(client, { serverId, alertType: "recertification.grace", reason: "recertification_valid", correlationId });
      await closeAlert(client, { serverId, alertType: "recertification.blocked", reason: "recertification_valid", correlationId });
    });
    return true;
  }

  private async probeServer(row: Record<string, unknown>): Promise<void> {
    const correlationId = randomUUID();
    const serverId = String(row.id);
    const hostname = String(row.hostname);
    const code = String(row.code);
    const recertification = recertificationFromRow(row);
    if (!await this.enforceRecertification(row, recertification, correlationId)) return;
    if (!row.monitoring_enabled || !row.profile_digest || !row.manifest) {
      await tx(this.db, async (client) => {
        await transitionServerState(client, {
          serverId,
          to: "SUSPENDED",
          actorType: "system",
          reason: "active_monitoring_profile_missing",
          correlationId
        });
        await raiseAlert(client, {
          serverId,
          severity: "CRITICAL",
          alertType: "monitoring.profile_missing",
          title: `${code}: povinný monitoring chybí`,
          detail: { reason: "active_monitoring_profile_missing" },
          correlationId
        });
      });
      await this.oci.stop(code).catch(async (error) => this.recordInternalError(row, error));
      return;
    }

    const validated = validateStoredOnboardingManifest(row.manifest);
    const manifest = validated.manifest;
    const policy = monitorPolicy(manifest);
    const latestResult = await this.db.query(
      `select distinct on (probe_type,status) probe_type,status,checked_at
         from monitoring_probe_result
        where server_id=$1
        order by probe_type,status,checked_at desc,id desc`,
      [serverId]
    );
    const latest = completedProbeCheckTimes(latestResult.rows as Array<Record<string, unknown>>);
    const due = (name: ProbeName): boolean => !latest.has(name) || Date.now() - Number(latest.get(name)) >= policy.intervals[name] * 1_000;
    const probes: Probe[] = [];
    const run = async (name: ProbeName, fn: () => Promise<Record<string, unknown>>): Promise<void> => {
      const lastChecked = latest.get(name);
      if (!due(name)) {
        if (lastChecked && Date.now() - lastChecked > policy.staleAfterSeconds * 1_000) {
          probes.push({ name, status: "STALE", latencyMs: 0, evidence: { lastCheckedAt: new Date(lastChecked).toISOString() } });
        }
        return;
      }
      probes.push(await measured(name, fn));
    };

    await run("liveness", () => socketHealth(String(row.runtime_socket)));
    await run("readiness", () => socketHealth(String(row.runtime_socket)));
    await run("tls", () => tlsCertificate(hostname));
    await run("routing", async () => {
      const addresses = (await dns.lookup(hostname, { all: true })).map((item) => item.address);
      const response = await fetch(`https://${hostname}/mcp`, { method: "GET", signal: AbortSignal.timeout(8_000), redirect: "manual" });
      const allowHeader = response.headers.get("allow");
      if (!routingProbePasses(response.status, allowHeader)) throw new Error(`routing_status:${response.status}`);
      return { addresses, status: response.status, allow: allowHeader };
    });
    await run("oauth_mcp", async () => {
      const response = await fetch(`https://${hostname}/.well-known/oauth-protected-resource/mcp`, { signal: AbortSignal.timeout(8_000), redirect: "manual" });
      if (response.status !== 200) throw new Error(`metadata_status:${response.status}`);
      const metadata = await response.json() as { resource?: string; authorization_servers?: string[] };
      if (metadata.resource !== `https://${hostname}/mcp` || !metadata.authorization_servers?.includes(`https://${this.config.AUTH_HOST}`)) throw new Error("metadata_mismatch");
      return { resource: metadata.resource };
    });
    await run("artifact_integrity", async () => {
      const imageDigest = typeof row.image_digest === "string" ? row.image_digest : "";
      if (!imageDigest || imageDigest !== String(row.revision_artifact_digest) || imageDigest !== String(row.onboarding_image_digest)) throw new Error("artifact_digest_drift");
      const imageReference = typeof row.image_reference === "string" ? row.image_reference : "";
      if (!imageReference) throw new Error("artifact_reference_missing");
      return this.oci.verifyRunningArtifact(code, imageReference, imageDigest);
    });
    await run("contract_profile_drift", async () => {
      if (String(row.manifest_digest) !== validated.digest || String(row.revision_manifest_digest) !== validated.digest) throw new Error("manifest_digest_drift");
      const expectedProfileDigest = expectedMonitoringProfileDigest(manifest.schemaVersion, manifest.monitoringProfile, row.monitoring_profile_text);
      if (String(row.profile_digest) !== expectedProfileDigest) throw new Error("monitoring_profile_digest_drift");
      if (digestCanonicalJson(row.input_schema) !== digestCanonicalJson(manifest.tool.inputSchema)) throw new Error("input_contract_drift");
      if (digestCanonicalJson(row.output_schema) !== digestCanonicalJson(manifest.tool.outputSchema)) throw new Error("output_contract_drift");
      return { manifestDigest: validated.digest, profileDigest: row.profile_digest };
    });
    await run("dependencies", () => dependencyHealth(manifest));
    await run("synthetic_call", async () => runSyntheticMonitoringProbe(this.db, this.config, {
      id: serverId,
      hostname,
      toolName: String(row.tool_name)
    }, manifest));

    const securityDrift = probes.find((probe) => probe.status === "FAIL" && ["artifact_integrity", "contract_profile_drift"].includes(probe.name));
    const stateEvaluation = evaluateOperationalState({
      currentState: String(row.operational_state) as import("../domain/types.js").OperationalState,
      samples: probes.map((probe) => ({
        status: probe.status,
        critical: ["liveness", "readiness", "tls", "routing", "oauth_mcp"].includes(probe.name)
      })),
      previousFailureStreak: Number(row.consecutive_failures ?? 0),
      evaluatedAt: new Date().toISOString()
    });
    await tx(this.db, async (client) => {
      for (const probe of probes) {
        await client.query(
          `insert into monitoring_probe_result(server_id,probe_type,status,latency_ms,evidence,correlation_id)
           values ($1,$2,$3,$4,$5,$6)`,
          [serverId, probe.name, probe.status, probe.latencyMs, JSON.stringify({ ...probe.evidence, legacyProfile: policy.legacyProfile }), correlationId]
        );
        await this.evaluateProbeAlert(client, serverId, code, probe, policy, correlationId);
      }
      const failures = probes.filter((probe) => probe.status !== "PASS");
      const nextProbeSeconds = Math.min(...Object.values(policy.intervals));
      await client.query(
        `update monitoring_profile
            set last_probe_at=now(),next_probe_at=now()+($2 || ' seconds')::interval,
                consecutive_failures=case when $3 then consecutive_failures+1 else 0 end,updated_at=now()
          where server_id=$1`,
        [serverId, nextProbeSeconds, failures.length > 0]
      );
      if (securityDrift) {
        await transitionServerState(client, {
          serverId,
          to: "QUARANTINED",
          actorType: "system",
          reason: `${securityDrift.name}:${typeof securityDrift.evidence.error === "string" ? securityDrift.evidence.error : "drift"}`,
          correlationId
        });
        await client.query(
          `update onboarding_job
              set state='QUARANTINED',blocking_error_code=$2,blocking_error_detail=$3,completed_at=now(),lock_version=lock_version+1
            where server_id=$1 and state='ACTIVE'`,
          [serverId, securityDrift.name, (typeof securityDrift.evidence.error === "string" ? securityDrift.evidence.error : "security drift").slice(0, 1_000)]
        );
      } else if (probes.length) {
        await setComputedOperationalState(client, {
          serverId,
          state: stateEvaluation.state,
          reason: `${stateEvaluation.reasonCode}:${failures.map((probe) => probe.name).join(",") || "none"}`,
          correlationId,
          recertification
        });
      }
      await this.evaluateSlo(client, serverId, code, policy, correlationId);
      await closeAlert(client, { serverId, alertType: "monitoring.internal_error", reason: "monitor_cycle_recovered", correlationId });
    });
    if (securityDrift) await this.oci.stop(code).catch(async (error) => this.recordInternalError(row, error));
  }

  private async evaluateProbeAlert(client: import("pg").PoolClient, serverId: string, code: string, probe: Probe, policy: MonitorPolicy, correlationId: string): Promise<void> {
    const alertType = `monitoring.${probe.name}`;
    if (probe.status === "PASS") {
      await closeAlert(client, { serverId, alertType, reason: "probe_recovered", correlationId });
      return;
    }
    const rule = policy.alertRules.find((candidate) => candidate.probeType === probe.name)
      ?? (["artifact_integrity", "contract_profile_drift"].includes(probe.name)
        ? { probeType: probe.name, severity: "CRITICAL" as const, consecutiveFailures: 1 }
        : null);
    if (!rule) return;
    const recent = await client.query(
      `select status from monitoring_probe_result
        where server_id=$1 and probe_type=$2
        order by checked_at desc,id desc limit $3`,
      [serverId, probe.name, rule.consecutiveFailures]
    );
    if (recent.rows.length < rule.consecutiveFailures || recent.rows.some((item) => item.status === "PASS")) return;
    await raiseAlert(client, {
      serverId,
      severity: rule.severity,
      alertType,
      title: `${code}: probe ${probe.name} selhal`,
      detail: { probeType: probe.name, status: probe.status, evidence: probe.evidence, consecutiveFailures: rule.consecutiveFailures },
      correlationId
    });
  }

  private async evaluateSlo(client: import("pg").PoolClient, serverId: string, code: string, policy: MonitorPolicy, correlationId: string): Promise<void> {
    if (!policy.slo) return;
    const result = await client.query(
      `select count(*)::int as total,
              count(*) filter (where status='PASS')::int as passed,
              percentile_cont(0.95) within group (order by latency_ms) filter (where latency_ms is not null) as p95_latency_ms
         from monitoring_probe_result
        where server_id=$1 and checked_at>=now()-interval '24 hours'`,
      [serverId]
    );
    const total = Number(result.rows[0].total);
    if (!total) return;
    const passed = Number(result.rows[0].passed);
    const availabilityPercent = passed / total * 100;
    const errorRatePercent = (total - passed) / total * 100;
    const p95LatencyMs = Number(result.rows[0].p95_latency_ms ?? 0);
    const breached = availabilityPercent < policy.slo.availabilityPercent
      || errorRatePercent > policy.slo.maxErrorRatePercent
      || p95LatencyMs > policy.slo.p95LatencyMs;
    if (breached) {
      await raiseAlert(client, {
        serverId,
        severity: "HIGH",
        alertType: "monitoring.slo",
        title: `${code}: SLO je porušeno`,
        detail: { availabilityPercent, errorRatePercent, p95LatencyMs, target: policy.slo },
        correlationId
      });
    } else {
      await closeAlert(client, { serverId, alertType: "monitoring.slo", reason: "slo_recovered", correlationId });
    }
  }

  private async recordInternalError(row: Record<string, unknown>, error: unknown): Promise<void> {
    const serverId = String(row.id);
    const correlationId = randomUUID();
    const message = error instanceof Error ? error.message.slice(0, 500) : "monitoring_internal_error";
    await tx(this.db, async (client) => {
      await client.query(
        `insert into monitoring_probe_result(server_id,probe_type,status,evidence,correlation_id)
         values ($1,'internal_error','FAIL',$2,$3)`,
        [serverId, JSON.stringify({ error: message }), correlationId]
      );
      const profile = await client.query("select consecutive_failures from monitoring_profile where server_id=$1 for update", [serverId]);
      const failures = Number(profile.rows[0]?.consecutive_failures ?? 0) + 1;
      const backoffSeconds = Math.min(3_600, 30 * 2 ** Math.min(failures, 7));
      await client.query(
        `update monitoring_profile
            set consecutive_failures=$2,next_probe_at=now()+($3 || ' seconds')::interval,last_probe_at=now(),updated_at=now()
          where server_id=$1`,
        [serverId, failures, backoffSeconds]
      );
      await appendAudit(client, {
        eventType: "monitoring.internal_error",
        actorType: "system",
        objectType: "mcp_server",
        objectId: serverId,
        after: { error: message, retryInSeconds: backoffSeconds },
        correlationId
      });
      await raiseAlert(client, {
        serverId,
        severity: "CRITICAL",
        alertType: "monitoring.internal_error",
        title: `${String(row.code)}: interní chyba monitoru`,
        detail: { error: message, retryInSeconds: backoffSeconds },
        correlationId
      });
    });
  }

  async run(signal: AbortSignal): Promise<void> {
    while (!signal.aborted) {
      await this.runOnce().catch((error) => {
        process.stderr.write(`${new Date().toISOString()} monitoring cycle failed: ${error instanceof Error ? error.message : "unknown"}\n`);
      });
      if (!signal.aborted) await new Promise((resolve) => setTimeout(resolve, this.config.MONITOR_INTERVAL_MS));
    }
  }
}
