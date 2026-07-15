import { randomUUID } from "node:crypto";
import { loadConfig } from "../config.js";
import { createDb } from "../db.js";
import { appendAudit } from "../domain/audit.js";
import { attachEgressCapabilityToServer, createEgressCapability } from "../domain/egress.js";
import { validateStoredOnboardingManifest } from "../domain/registration.js";
import { OciRuntime } from "../onboarding/oci.js";

function writeReleaseCheck(message: string): void {
  process.stdout.write(`${message}\n`);
}

async function main(): Promise<void> {
  const config = loadConfig();
  const db = createDb(config);
  const correlationId = randomUUID();
  try {
    const result = await db.query(
      `select
          server.id,
          server.code,
          server.image_reference,
          server.image_digest,
          server.runtime_socket,
          revision.manifest,
          job.id as job_id
         from mcp_server server
         join registration_revision revision
           on revision.id = server.active_revision_id
          and revision.server_id = server.id
          and revision.active = true
         left join lateral (
           select id
             from onboarding_job
            where server_id = server.id
              and state in ('DEPLOYING','REGISTERED_DISABLED','TRIAL_TESTING','ACTIVE')
            order by updated_at desc
            limit 1
         ) job on true
        where server.code = 'KCML0002'`
    );
    if (!result.rowCount) throw new Error("kcml0002_missing");
    const row = result.rows[0] as Record<string, unknown>;
    const serverId = String(row.id);
    const code = String(row.code);
    const imageReference = typeof row.image_reference === "string" ? row.image_reference : "";
    const imageDigest = typeof row.image_digest === "string" ? row.image_digest : "";
    const jobId = typeof row.job_id === "string" ? row.job_id : "";
    if (!imageReference || !imageDigest) throw new Error("kcml0002_runtime_artifact_missing");
    if (!jobId) throw new Error("kcml0002_onboarding_job_missing");
    const { manifest } = validateStoredOnboardingManifest(row.manifest);
    const egressCapabilityToken = await createEgressCapability(db, config, jobId, manifest.runtime.egressAllowlist);
    const runtime = await new OciRuntime(config).deploy({
      code,
      imageReference,
      imageDigest,
      manifest,
      egressCapabilityToken
    });
    await attachEgressCapabilityToServer(db, jobId, serverId);
    await db.query(
      `update mcp_server
          set runtime_socket = $2,
              operational_state = case
                when registration_state = 'ACTIVE'::registration_state then 'HEALTHY'::operational_state
                else 'UNKNOWN'::operational_state
              end,
              lock_version = lock_version + 1,
              updated_at = now()
        where id = $1`,
      [serverId, runtime.socketPath]
    );
    await appendAudit(db, {
      eventType: "deployment.kcml0002_runtime_refresh.passed",
      actorType: "system",
      actorId: "release-runtime-refresh",
      objectType: "mcp_server",
      objectId: serverId,
      after: {
        imageReference,
        imageDigest,
        socketPath: runtime.socketPath,
        containerName: runtime.containerName
      },
      correlationId
    });
    writeReleaseCheck(`release-check:mcp_kcml0002_runtime_refresh=PASS socket=${runtime.socketPath}`);
  } finally {
    await db.end();
  }
}

main().catch((error) => {
  process.stderr.write(`release-check:mcp_kcml0002_runtime_refresh=FAIL error=${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
