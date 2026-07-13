import { randomUUID } from "node:crypto";
import dns from "node:dns/promises";
import http from "node:http";
import type { AppConfig } from "../config.js";
import type { Db } from "../db.js";
import { tx } from "../db.js";
import { appendAudit } from "../domain/audit.js";
import { validateOnboardingManifest } from "../domain/registration.js";
import { runSyntheticMonitoringProbe } from "./activation.js";
import { OciRuntime } from "./oci.js";

type Probe = { name: string; status: "PASS" | "FAIL" | "STALE"; latencyMs: number; evidence: Record<string, unknown> };

async function measured(name: string, fn: () => Promise<Record<string, unknown>>): Promise<Probe> {
  const started = Date.now();
  try {
    const evidence = await fn();
    return { name, status: "PASS", latencyMs: Date.now() - started, evidence };
  } catch (error) {
    return { name, status: "FAIL", latencyMs: Date.now() - started, evidence: { error: error instanceof Error ? error.message.slice(0, 500) : "probe_failed" } };
  }
}

function socketReady(socketPath: string): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const request = http.request({ socketPath, path: "/health", method: "GET", timeout: 3_000 }, (response) => {
      response.resume();
      if (response.statusCode === 200) resolve({ status: response.statusCode });
      else reject(new Error(`readiness_status:${response.statusCode}`));
    });
    request.on("timeout", () => request.destroy(new Error("readiness_timeout")));
    request.on("error", reject);
    request.end();
  });
}

export class MonitoringScheduler {
  private readonly oci: OciRuntime;

  constructor(private readonly db: Db, private readonly config: AppConfig) {
    this.oci = new OciRuntime(config);
  }

  async runOnce(): Promise<void> {
    const result = await this.db.query(`
      select ms.*,rr.manifest,rr.artifact_digest as revision_artifact_digest,oj.image_digest as onboarding_image_digest
        from mcp_server ms
        join monitoring_profile mp on mp.server_id=ms.id and mp.enabled=true
        join lateral (
          select manifest,artifact_digest from registration_revision where server_id=ms.id order by created_at desc limit 1
        ) rr on true
        left join onboarding_job oj on oj.server_id=ms.id
       where ms.enabled=true and ms.registration_state='ACTIVE'
    `);
    for (const row of result.rows) await this.probeServer(row as Record<string, unknown>);
  }

  private async probeServer(row: Record<string, unknown>): Promise<void> {
    const correlationId = randomUUID();
    const serverId = String(row.id);
    const hostname = String(row.hostname);
    const code = String(row.code);
    const { manifest } = validateOnboardingManifest(row.manifest);
    const probes: Probe[] = [];
    probes.push(await measured("readiness", () => socketReady(String(row.runtime_socket))));
    probes.push(await measured("dns", async () => ({ addresses: (await dns.lookup(hostname, { all: true })).map((item) => item.address) })));
    probes.push(await measured("tls_oauth_metadata", async () => {
      const response = await fetch(`https://${hostname}/.well-known/oauth-protected-resource/mcp`, { signal: AbortSignal.timeout(8_000), redirect: "manual" });
      if (response.status !== 200) throw new Error(`metadata_status:${response.status}`);
      const metadata = await response.json() as { resource?: string; authorization_servers?: string[] };
      if (metadata.resource !== `https://${hostname}/mcp` || !metadata.authorization_servers?.includes(`https://${this.config.AUTH_HOST}`)) throw new Error("metadata_mismatch");
      return { resource: metadata.resource };
    }));
    const integrity = await measured("artifact_integrity", async () => {
      const imageDigest = typeof row.image_digest === "string" ? row.image_digest : "";
      if (!imageDigest || imageDigest !== String(row.revision_artifact_digest) || imageDigest !== String(row.onboarding_image_digest)) throw new Error("artifact_digest_drift");
      const imageReference = typeof row.image_reference === "string" ? row.image_reference : "";
      if (!imageReference) throw new Error("artifact_reference_missing");
      return this.oci.verifyRunningArtifact(code, imageReference, imageDigest);
    });
    probes.push(integrity);
    probes.push(await measured("synthetic_call", async () => runSyntheticMonitoringProbe(this.db, this.config, {
      id: serverId,
      hostname,
      toolName: String(row.tool_name)
    }, manifest)));

    for (const probe of probes) {
      await this.db.query(
        `insert into monitoring_probe_result(server_id,probe_type,status,latency_ms,evidence,correlation_id)
         values ($1,$2,$3,$4,$5,$6)`,
        [serverId, probe.name, probe.status, probe.latencyMs, JSON.stringify(probe.evidence), correlationId]
      );
    }
    if (integrity.status === "FAIL") {
      const jobId = await tx(this.db, async (client) => {
        await client.query(
          "update mcp_server set enabled=false,registration_state='QUARANTINED',operational_state='QUARANTINED',revocation_epoch=gen_random_uuid(),lock_version=lock_version+1 where id=$1",
          [serverId]
        );
        await client.query("update access_token set revoked_at=coalesce(revoked_at,now()) where server_id=$1", [serverId]);
        await client.query("update egress_capability set revoked_at=coalesce(revoked_at,now()) where server_id=$1", [serverId]);
        const job = await client.query(
          `update onboarding_job
              set state='QUARANTINED',blocking_error_code='artifact_integrity_failed',
                  blocking_error_detail='The running OCI artifact failed digest or signature verification.',
                  completed_at=now(),lock_version=lock_version+1
            where server_id=$1 and state='ACTIVE' returning id`,
          [serverId]
        );
        if (job.rowCount) {
          await client.query(
            `insert into onboarding_event(job_id,from_state,to_state,event_type,detail,correlation_id)
             values ($1,'ACTIVE','QUARANTINED','monitoring.integrity_quarantined',$2,$3)`,
            [job.rows[0].id, JSON.stringify(integrity.evidence), correlationId]
          );
        }
        await appendAudit(client, {
          eventType: "mcp_server.integrity_quarantined", actorType: "system", objectType: "mcp_server", objectId: serverId,
          after: { code, evidence: integrity.evidence }, correlationId
        });
        return job.rowCount ? String(job.rows[0].id) : null;
      });
      try {
        await this.oci.stop(code);
        if (jobId) await this.db.query("update onboarding_job set runtime_stopped_at=now() where id=$1", [jobId]);
      } catch {
        // The maintenance loop retries cleanup for quarantined jobs without runtime_stopped_at.
      }
      return;
    }
    const failures = probes.filter((probe) => probe.status !== "PASS");
    const operationalState = failures.length === 0 ? "HEALTHY" : failures.some((probe) => ["readiness", "dns", "tls_oauth_metadata"].includes(probe.name)) ? "UNHEALTHY" : "DEGRADED";
    await this.db.query("update mcp_server set operational_state=$2,updated_at=now() where id=$1", [serverId, operationalState]);
  }
}
