import { randomUUID } from "node:crypto";
import path from "node:path";
import type { WorkerConfig } from "../config.js";
import type { Db } from "../db.js";
import { cleanupExpiredComponentOnboardings } from "../domain/component.js";
import {
  heartbeatJob,
  leaseNextJob,
  cleanupIntegrationTokens,
  pauseExpiredOnboardingJobs,
  releaseLease,
  setGate,
  transitionJob,
  type OnboardingJobState
} from "../domain/onboarding.js";
import { validateStoredOnboardingManifest, type OnboardingManifest } from "../domain/registration.js";
import { attachEgressCapabilityToServer, createEgressCapability, revokeEgressCapabilities } from "../domain/egress.js";
import { beginTrial, disableAfterFailure, registerDisabledServer, rollbackTrial, runPublicPreflight, runTrialAndActivate, type ActivationJob } from "./activation.js";
import { GitHubOnboardingClient } from "./github.js";
import { OciRuntime } from "./oci.js";

type InternalJob = {
  id: string;
  state: OnboardingJobState;
  lock_version: number;
  source_archive_path: string;
  source_digest: string;
  manifest_digest: string;
  manifest: unknown;
  code: string;
  hostname: string;
  tool_name: string;
  github_pr_number: number | null;
  source_commit: string | null;
  image_reference: string | null;
  image_digest: string | null;
  sbom_digest: string | null;
  provenance_digest: string | null;
  build_id: string | null;
  server_id: string | null;
  runtime_stopped_at: Date | string | null;
  updated_at: Date | string;
};

const QUARANTINE_ERRORS = [
  "image_signature_invalid",
  "image_digest_invalid",
  "provenance_source_commit_mismatch",
  "provenance_evidence_mismatch",
  "sbom_subject_digest_mismatch",
  "source_commit_mismatch",
  "secret_detected",
  "cross_host",
  "audience_binding",
  "protected_resource_mismatch"
];

function shouldQuarantine(error: Error): boolean {
  return QUARANTINE_ERRORS.some((code) => error.message.includes(code));
}

function isTransientBuildError(error: Error): boolean {
  return /manifest unknown|not found|unauthorized|authentication required|github_api_failed.*(?:502|503|504)|ECONN|ETIMEDOUT|fetch failed/i.test(error.message);
}

export class OnboardingWorker {
  private readonly id = `worker-${randomUUID()}`;
  private readonly github: GitHubOnboardingClient;
  private readonly oci: OciRuntime;
  private lastMaintenanceAt = 0;

  constructor(private readonly db: Db, private readonly config: WorkerConfig) {
    this.github = new GitHubOnboardingClient(config);
    this.oci = new OciRuntime(config);
  }

  private async internalJob(id: string): Promise<InternalJob> {
    const result = await this.db.query("select * from onboarding_job where id=$1", [id]);
    if (!result.rowCount) throw new Error("job_not_found");
    return result.rows[0] as InternalJob;
  }

  private activationJob(row: InternalJob, manifest: OnboardingManifest): ActivationJob {
    for (const value of [row.source_commit, row.image_reference, row.image_digest, row.sbom_digest, row.provenance_digest, row.build_id]) {
      if (!value) throw new Error("artifact_evidence_incomplete");
    }
    return {
      id: row.id,
      code: row.code,
      hostname: row.hostname,
      toolName: row.tool_name,
      manifestDigest: row.manifest_digest,
      sourceDigest: row.source_digest,
      sourceCommit: row.source_commit!,
      imageReference: row.image_reference!,
      imageDigest: row.image_digest!,
      sbomDigest: row.sbom_digest!,
      provenanceDigest: row.provenance_digest!,
      buildId: row.build_id!,
      manifest
    };
  }

  private async blockForRetry(job: InternalJob, error: Error, delaySeconds = 60): Promise<void> {
    await this.db.query(
      `update onboarding_job
          set blocking_error_code=$2, blocking_error_detail=$3,
              next_run_at=now()+($4 || ' seconds')::interval, lock_version=lock_version+1
        where id=$1`,
      [job.id, error.message.split(":")[0], error.message.slice(0, 1_000), delaySeconds]
    );
  }

  private async stopRuntime(jobId: string, code: string): Promise<void> {
    await this.oci.stop(code);
    await this.db.query("update onboarding_job set runtime_stopped_at=now() where id=$1", [jobId]);
  }

  private async fail(job: InternalJob, error: Error, correlationId: string): Promise<void> {
    const current = await this.internalJob(job.id);
    if (["ACTIVE", "FAILED", "QUARANTINED"].includes(current.state)) return;
    const quarantine = shouldQuarantine(error);
    await revokeEgressCapabilities(this.db, job.id);
    const serverId = current.server_id ?? job.server_id;
    if (serverId) {
      await disableAfterFailure(this.db, serverId, quarantine, correlationId, error.message);
    }
    await this.stopRuntime(job.id, job.code).catch(() => undefined);
    if (current.state === "CANCELLED") return;
    const target: OnboardingJobState = quarantine ? "QUARANTINED" : "FAILED";
    await transitionJob(
      this.db,
      current.id,
      Number(current.lock_version),
      target,
      quarantine ? "security.quarantined" : "pipeline.failed",
      { error: error.message.slice(0, 1_000) },
      correlationId,
      { blocking_error_code: error.message.split(":")[0], blocking_error_detail: error.message.slice(0, 1_000) }
    );
  }

  private async process(job: InternalJob): Promise<void> {
    const correlationId = randomUUID();
    const { manifest } = validateStoredOnboardingManifest(job.manifest);
    if (job.state === "SOURCE_UPLOADED") {
      const sourceDirectory = path.join(path.dirname(job.source_archive_path), "source");
      const pull = await this.github.createPullRequest({
        jobId: job.id,
        code: job.code,
        sourceDirectory,
        sourceDigest: job.source_digest,
        manifestDigest: job.manifest_digest
      });
      await setGate(this.db, job.id, "path_policy", "RUNNING", { branch: pull.branch }, correlationId);
      await transitionJob(this.db, job.id, Number(job.lock_version), "PR_CREATED", "pull_request.created", { pullNumber: pull.pullNumber }, correlationId, {
        github_branch: pull.branch,
        github_pr_number: pull.pullNumber,
        github_pr_url: pull.pullUrl,
        source_commit: pull.headSha
      });
      return;
    }
    if (job.state === "PR_CREATED") {
      await transitionJob(this.db, job.id, Number(job.lock_version), "CI_RUNNING", "ci.started", {}, correlationId);
      return;
    }
    if (job.state === "CI_RUNNING") {
      if (!job.github_pr_number) throw new Error("github_pr_missing");
      const result = await this.github.checkPullRequest(Number(job.github_pr_number));
      for (const check of result.checks) {
        const status = check.status !== "completed" ? "RUNNING" : check.conclusion === "success" ? "PASS" : "FAIL";
        const gates = check.name === "sca-license" ? ["sca", "license"] : [check.name.replaceAll("-", "_")];
        for (const gate of gates) await setGate(this.db, job.id, gate, status, { url: check.url, conclusion: check.conclusion }, correlationId);
      }
      if (result.state === "pending") return;
      if (result.state === "fail") {
        await transitionJob(this.db, job.id, Number(job.lock_version), "AWAITING_REVISION", "ci.failed", { checks: result.checks }, correlationId, {
          blocking_error_code: "ci_failed",
          blocking_error_detail: "One or more required checks failed"
        });
        return;
      }
      const merged = await this.github.mergePullRequest(Number(job.github_pr_number), result.headSha);
      await transitionJob(this.db, job.id, Number(job.lock_version), "MERGED", "pull_request.merged", { mergeSha: merged.mergeSha }, correlationId, {
        source_commit: merged.mergeSha
      });
      return;
    }
    if (job.state === "MERGED") {
      await transitionJob(this.db, job.id, Number(job.lock_version), "ARTIFACT_BUILDING", "artifact.build.started", {}, correlationId);
      return;
    }
    if (job.state === "ARTIFACT_BUILDING") {
      if (!job.source_commit) throw new Error("source_commit_missing");
      const imageReference = this.oci.imageReference(job.code, job.source_commit);
      try {
        const trustedBuild = await this.github.checkTrustedBuild(job.source_commit);
        if (trustedBuild.state === "pending") {
          await this.blockForRetry(job, new Error("trusted_build_pending"), 60);
          return;
        }
        if (trustedBuild.state === "fail" || !trustedBuild.runId) throw new Error("trusted_build_failed");
        const artifact = await this.oci.verifyArtifact(imageReference, job.source_commit, trustedBuild.runId);
        for (const gate of ["source_commit", "image_signature", "image_digest", "provenance", "sbom"]) {
          await setGate(this.db, job.id, gate, "PASS", { imageDigest: artifact.imageDigest, buildId: artifact.buildId, runUrl: trustedBuild.runUrl }, correlationId);
        }
        await transitionJob(this.db, job.id, Number(job.lock_version), "DEPLOYING", "artifact.verified", artifact, correlationId, {
          image_reference: artifact.imageReference,
          image_digest: artifact.imageDigest,
          sbom_digest: artifact.sbomDigest,
          provenance_digest: artifact.provenanceDigest,
          build_id: artifact.buildId
        });
      } catch (error) {
        if (error instanceof Error && isTransientBuildError(error) && Date.now() - new Date(job.updated_at).getTime() < 2 * 60 * 60 * 1000) {
          await this.blockForRetry(job, error);
          return;
        }
        throw error;
      }
      return;
    }
    if (job.state === "DEPLOYING") {
      const activation = this.activationJob(job, manifest);
      const egressCapabilityToken = await createEgressCapability(this.db, this.config, job.id, manifest.runtime.egressAllowlist);
      const runtime = await this.oci.deploy({ code: job.code, imageReference: activation.imageReference, imageDigest: activation.imageDigest, manifest, egressCapabilityToken });
      await this.db.query("update onboarding_job set runtime_stopped_at=null where id=$1", [job.id]);
      await setGate(this.db, job.id, "runtime_isolation", "PASS", { containerName: runtime.containerName }, correlationId);
      await setGate(this.db, job.id, "worker_readiness", "PASS", { socketPath: runtime.socketPath }, correlationId);
      const serverId = await registerDisabledServer(this.db, activation, runtime.socketPath, correlationId);
      await attachEgressCapabilityToServer(this.db, job.id, serverId);
      await transitionJob(this.db, job.id, Number(job.lock_version), "REGISTERED_DISABLED", "server.registered_disabled", { serverId }, correlationId, { server_id: serverId });
      return;
    }
    if (job.state === "REGISTERED_DISABLED") {
      if (!job.server_id) throw new Error("registered_server_missing");
      const activation = this.activationJob(job, manifest);
      try {
        await transitionJob(this.db, job.id, Number(job.lock_version), "TRIAL_TESTING", "trial.started", {}, correlationId);
        await beginTrial(this.db, job.id, job.server_id, correlationId);
        const evidence = await runPublicPreflight(this.db, this.config, job.server_id, activation, correlationId);
        for (const gate of ["dns", "tls_san", "host_routing"]) await setGate(this.db, job.id, gate, "PASS", evidence, correlationId);
      } catch (error) {
        const failure = error instanceof Error ? error : new Error("preflight_failed");
        const gate = failure.message.includes("tls") || failure.message.includes("certificate") ? "tls_san" : failure.message.includes("dns") ? "dns" : "host_routing";
        await setGate(this.db, job.id, gate, "FAIL", { error: failure.message.slice(0, 500) }, correlationId);
        await rollbackTrial(this.db, job.server_id, correlationId, `preflight_failed:${failure.message.slice(0, 300)}`);
        const current = await this.internalJob(job.id);
        if (current.state === "TRIAL_TESTING") {
          await transitionJob(this.db, job.id, Number(current.lock_version), "REGISTERED_DISABLED", "trial.preflight_failed", { error: failure.message.slice(0, 500) }, correlationId);
        }
        await this.blockForRetry(current, failure, 120);
      }
      return;
    }
    if (job.state === "TRIAL_TESTING") {
      if (!job.server_id) throw new Error("trial_server_missing");
      const activation = this.activationJob(job, manifest);
      for (const gate of ["oauth_metadata", "audience_binding", "negative_auth", "mcp_initialize", "mcp_tools_list", "safe_tools_call", "cross_host", "schema_contract", "correlation_chain", "logging_redaction", "audit_persistence", "monitoring_probes"]) {
        await setGate(this.db, job.id, gate, "RUNNING", {}, correlationId);
      }
      const evidence = await runTrialAndActivate(this.db, this.config, job.server_id, activation, correlationId);
      for (const gate of ["oauth_metadata", "audience_binding", "negative_auth", "mcp_initialize", "mcp_tools_list", "safe_tools_call", "cross_host", "schema_contract", "correlation_chain", "logging_redaction", "audit_persistence", "monitoring_probes"]) {
        await setGate(this.db, job.id, gate, "PASS", evidence, correlationId);
      }
      const current = await this.internalJob(job.id);
      await transitionJob(this.db, job.id, Number(current.lock_version), "ACTIVE", "activation.completed", evidence, correlationId);
    }
  }

  async tick(): Promise<boolean> {
    if (this.lastMaintenanceAt < Date.now() - 60_000) {
      const paused = await pauseExpiredOnboardingJobs(this.db);
      for (const job of paused) await this.stopRuntime(job.id, job.code).catch(() => undefined);
      await cleanupExpiredComponentOnboardings(this.db, randomUUID());
      const cleanup = await this.db.query(
        `select id,code from onboarding_job
          where state in ('FAILED','QUARANTINED','CANCELLED') and runtime_stopped_at is null`
      );
      for (const row of cleanup.rows) await this.stopRuntime(String(row.id), String(row.code)).catch(() => undefined);
      await cleanupIntegrationTokens(this.db);
      this.lastMaintenanceAt = Date.now();
    }
    const summary = await leaseNextJob(this.db, this.id);
    if (!summary) return false;
    let job: InternalJob | null = null;
    try {
      job = await this.internalJob(summary.id);
      await heartbeatJob(this.db, job.id, this.id);
      const heartbeatState: { failure: Error | null } = { failure: null };
      let heartbeatInFlight: Promise<void> = Promise.resolve();
      const heartbeat = () => {
        heartbeatInFlight = heartbeatInFlight.then(async () => {
          if (heartbeatState.failure) return;
          try {
            await heartbeatJob(this.db, summary.id, this.id);
          } catch (error) {
            heartbeatState.failure = error instanceof Error ? error : new Error("job_heartbeat_failed");
          }
        });
      };
      const heartbeatTimer = setInterval(heartbeat, 20_000);
      try {
        await this.process(job);
        await heartbeatInFlight;
        if (heartbeatState.failure) throw new Error(heartbeatState.failure.message, { cause: heartbeatState.failure });
      } finally {
        clearInterval(heartbeatTimer);
        await heartbeatInFlight;
      }
    } catch (error) {
      const failure = error instanceof Error ? error : new Error("onboarding_worker_failed");
      if (job && (/github_api_failed.*(?:502|503|504)|ECONN|ETIMEDOUT|fetch failed/i.test(failure.message))) await this.blockForRetry(job, failure);
      else if (job) await this.fail(job, failure, randomUUID());
    } finally {
      await releaseLease(this.db, summary.id, this.id).catch(() => undefined);
    }
    return true;
  }

  async run(signal: AbortSignal): Promise<void> {
    while (!signal.aborted) {
      const worked = await this.tick();
      if (!worked) await new Promise((resolve) => setTimeout(resolve, this.config.ONBOARDING_WORKER_INTERVAL_MS));
    }
  }
}
