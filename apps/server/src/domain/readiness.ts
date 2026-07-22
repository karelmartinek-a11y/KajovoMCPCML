import { createHash, randomUUID } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import type { ReadinessConfig } from "../config.js";
import type { Db } from "../db.js";
import { appendAudit, verifyAuditChain } from "./audit.js";
import { ACTIVATION_GATES } from "./component.js";

const migrationDirectory = new URL("../migrations/", import.meta.url);
const EXPECTED_MIGRATIONS = readdirSync(migrationDirectory)
  .filter((name) => !name.startsWith("._") && name.endsWith(".sql"))
  .sort()
  .map((name) => ({ name, sequence: Number(name.slice(0, 3)), checksum: createHash("sha256").update(readFileSync(new URL(name, migrationDirectory))).digest("hex") }));

export type ReadinessReport = {
  ready: boolean;
  buildId: string;
  checkedAt: string;
  database: { ok: boolean };
  migrations: { ok: boolean; expected: number; applied: number; missing: string[]; unexpected: string[] };
  catalog: { ok: boolean; serverCount: number; servingCount: number; blocked: Array<{ code: string; reason: string }> };
  audit: { ok: boolean; chainValid: boolean; eventCount: number; rollbackWriteProbe: boolean; brokenEventId: number | null };
  monitor: { ok: boolean; enabled: boolean; lastCompletedAt: string | null; lastError: string | null };
  workers: { ok: boolean; entries: Array<{ kind: string; workerId: string; buildId: string; lastHeartbeatAt: string; lastError: string | null; fresh: boolean }> };
  operations: { ok: boolean; expiredDispatches: number; staleHeartbeats: number; invalidTokenBindings: number; platformWorkerAccessConfigured: boolean };
};

async function rollbackAuditWriteProbe(db: Db): Promise<boolean> {
  const client = await db.connect();
  try {
    await client.query("begin");
    await appendAudit(client, {
      eventType: "readiness.audit_write_probe",
      actorType: "system",
      objectType: "readiness",
      objectId: "rollback",
      correlationId: randomUUID()
    });
    await client.query("rollback");
    return true;
  } catch {
    await client.query("rollback").catch(() => undefined);
    return false;
  } finally {
    client.release();
  }
}

export async function buildReadinessReport(db: Db, config: ReadinessConfig): Promise<ReadinessReport> {
  const checkedAt = new Date().toISOString();
  await db.query("select 1");
  const migrationResult = await db.query("select version,sequence_number,checksum_sha256 from schema_migration order by sequence_number,version");
  const applied = migrationResult.rows.map((row) => String(row.version));
  const expected = new Map(EXPECTED_MIGRATIONS.map((migration) => [migration.name, migration]));
  const appliedSet = new Set(applied);
  const missing = EXPECTED_MIGRATIONS.map((migration) => migration.name).filter((migration) => !appliedSet.has(migration));
  const unexpected = applied.filter((migration) => !expected.has(migration));
  const ledgerMismatch = migrationResult.rows.some((row) => {
    const migration = expected.get(String(row.version));
    return migration && (Number(row.sequence_number) !== migration.sequence || String(row.checksum_sha256) !== migration.checksum);
  });
  const migrationOk = missing.length === 0 && unexpected.length === 0 && !ledgerMismatch;

  const components = await db.query(
    `select c.id,c.code,c.enabled,c.lifecycle_state,c.activation_state,c.operational_state,c.monitoring_state,
            c.active_revision_id,r.manifest_digest,rt_current.runtime_digest,
            exists(select 1 from component_runtime_target rt where rt.component_id=c.id and rt.revision_id=c.active_revision_id and rt.status='HEALTHY') runtime_healthy,
            not exists (
              select 1 from unnest($1::text[]) required(gate_key)
               where coalesce((
                 select evidence.status
                   from component_readiness_gate_evidence evidence
                  where evidence.component_id=c.id and evidence.revision_id=c.active_revision_id
                    and evidence.gate_key=required.gate_key
                    and evidence.revision_digest=r.manifest_digest
                    and evidence.runtime_digest is not distinct from rt_current.runtime_digest
                    and evidence.artifact_digest is not distinct from rt_current.runtime_digest
                  order by evidence.executed_at desc limit 1
               ),'FAIL') <> 'PASS'
               or coalesce((
                 select evidence.expires_at <= now()
                   from component_readiness_gate_evidence evidence
                  where evidence.component_id=c.id and evidence.revision_id=c.active_revision_id
                    and evidence.gate_key=required.gate_key
                    and evidence.revision_digest=r.manifest_digest
                    and evidence.runtime_digest is not distinct from rt_current.runtime_digest
                    and evidence.artifact_digest is not distinct from rt_current.runtime_digest
                  order by evidence.executed_at desc limit 1
               ),false)
            ) gates_valid
       from component c
       left join component_revision r on r.id=c.active_revision_id
       left join component_runtime_target rt_current on rt_current.component_id=c.id and rt_current.revision_id=c.active_revision_id
      where c.lifecycle_state<>'DEREGISTERED'
        and c.registration_type='GENERIC_COMPONENT'
      order by c.kcml_number`,
    [[...ACTIVATION_GATES]]
  );
  const blocked: Array<{ code: string; reason: string }> = [];
  let servingCount = 0;
  for (const row of components.rows) {
    const serving = Boolean(row.enabled) && row.lifecycle_state === "ACTIVE" && row.activation_state === "ACTIVE"
      && row.operational_state === "HEALTHY" && row.monitoring_state === "HEALTHY" && Boolean(row.runtime_healthy) && Boolean(row.gates_valid);
    if (serving) servingCount += 1;
    else if (row.lifecycle_state === "ACTIVE" || row.activation_state === "ACTIVE") {
      blocked.push({ code: String(row.code), reason: !row.gates_valid ? "active_readiness_evidence_missing" : !row.runtime_healthy ? "runtime_target_unhealthy" : "component_state_not_healthy" });
    }
  }

  const auditChain = await verifyAuditChain(db);
  const rollbackWriteProbe = await rollbackAuditWriteProbe(db);
  const monitorResult = await db.query(
    "select last_completed_at,last_error from monitoring_scheduler_heartbeat where singleton=true"
  );
  const lastCompletedAt = monitorResult.rows[0]?.last_completed_at ? new Date(monitorResult.rows[0].last_completed_at).toISOString() : null;
  const monitorFresh = !config.MONITOR_ENABLED || Boolean(lastCompletedAt
    && Date.now() - new Date(lastCompletedAt).getTime() <= Math.max(180_000, config.MONITOR_INTERVAL_MS * 3));
  const monitorOk = monitorFresh && (!config.MONITOR_ENABLED || !monitorResult.rows[0]?.last_error);
  const workerResult = await db.query("select worker_kind,worker_id,build_id,last_heartbeat_at,last_error from platform_worker_heartbeat order by worker_kind");
  const workerEntries = workerResult.rows.map((row) => ({
    kind: String(row.worker_kind), workerId: String(row.worker_id), buildId: String(row.build_id),
    lastHeartbeatAt: new Date(row.last_heartbeat_at).toISOString(), lastError: row.last_error ? String(row.last_error) : null,
    fresh: Date.now() - new Date(row.last_heartbeat_at).getTime() <= 180_000
  }));
  const requiredWorkers = new Set(["COMPONENT_CONTROL", "COMPONENT_E2E"]);
  const workersOk = workerEntries.every((entry) => entry.fresh && !entry.lastError && entry.buildId === config.BUILD_ID)
    && workerEntries.filter((entry) => requiredWorkers.has(entry.kind)).length === requiredWorkers.size;
  const operationResult = await db.query(
    `select
       (select count(*)::int from component_control_dispatch where state in ('QUEUED','CLAIMED','SENT','ACK_PENDING') and deadline_at<=now()) expired_dispatches,
       (select count(*)::int from component c where c.enabled and c.lifecycle_state='ACTIVE'
          and c.registration_type='GENERIC_COMPONENT' and
          not exists(select 1 from component_heartbeat h where h.component_id=c.id and h.validation_state='ACCEPTED' and h.heartbeat_at>now()-interval '3 minutes')) stale_heartbeats,
       (select count(*)::int from principal_access_token token left join principal p on p.id=token.source_principal_id
          where token.revoked_at is null and (p.id is null or token.issued_revocation_epoch<>p.revocation_epoch)) invalid_token_bindings,
       exists(select 1 from platform_worker_access_identity identity
         join principal_access_token token on token.id=identity.access_token_id
         join principal on principal.id=identity.principal_id
        where identity.singleton is true and token.revoked_at is null and token.expires_at>now()
          and token.issued_revocation_epoch=principal.revocation_epoch and principal.status='ACTIVE') platform_worker_access_configured`
  );
  const operations = {
    expiredDispatches: Number(operationResult.rows[0]?.expired_dispatches ?? 0),
    staleHeartbeats: Number(operationResult.rows[0]?.stale_heartbeats ?? 0),
    invalidTokenBindings: Number(operationResult.rows[0]?.invalid_token_bindings ?? 0),
    platformWorkerAccessConfigured: Boolean(operationResult.rows[0]?.platform_worker_access_configured)
  };
  const operationsOk = operations.expiredDispatches === 0 && operations.staleHeartbeats === 0
    && operations.invalidTokenBindings === 0 && operations.platformWorkerAccessConfigured;
  const ready = migrationOk && blocked.length === 0 && auditChain.valid && rollbackWriteProbe && monitorOk && workersOk && operationsOk;
  return {
    ready,
    buildId: config.BUILD_ID,
    checkedAt,
    database: { ok: true },
    migrations: { ok: migrationOk, expected: EXPECTED_MIGRATIONS.length, applied: applied.length, missing: [...missing], unexpected },
    catalog: { ok: blocked.length === 0, serverCount: components.rows.length, servingCount, blocked },
    audit: {
      ok: auditChain.valid && rollbackWriteProbe,
      chainValid: auditChain.valid,
      eventCount: auditChain.eventCount,
      rollbackWriteProbe,
      brokenEventId: auditChain.brokenEventId
    },
    monitor: { ok: monitorOk, enabled: config.MONITOR_ENABLED, lastCompletedAt, lastError: monitorResult.rows[0]?.last_error ? String(monitorResult.rows[0].last_error) : null },
    workers: { ok: workersOk, entries: workerEntries },
    operations: { ok: operationsOk, ...operations }
  };
}
