import { randomUUID } from "node:crypto";
import type { ReadinessConfig } from "../config.js";
import type { Db } from "../db.js";
import { appendAudit, verifyAuditChain } from "./audit.js";
import { listServers } from "./catalog.js";
import { evaluateRecertification } from "./recertification.js";

const EXPECTED_MIGRATIONS = [
  "001_initial.sql",
  "002_kaja_labels.sql",
  "003_kaja_lifecycle_permissions.sql",
  "004_permission_access_level.sql",
  "005_automated_onboarding.sql",
  "005_fix_mcp_hostname_constraint.sql",
  "006_invocation_latency_metrics.sql",
  "007_migration_ledger.sql",
  "008_auth_hardening.sql",
  "009_runtime_policies.sql",
  "010_permissions.sql",
  "011_admin_recovery.sql",
  "012_operational_config.sql",
  "013_integration_descriptor.sql",
  "014_recertification.sql",
  "015_monitoring_alerting.sql",
  "016_audit_and_invocation.sql",
  "017_managed_services.sql",
  "018_managed_service_backfill.sql",
  "019_postgres_http_rate_limiting.sql",
  "020_managed_service_runtime_control.sql",
  "021_external_api_runtime_enforcement.sql",
  "022_runtime_egress_capability_backfill.sql",
  "023_access_token_compatibility_and_mfa.sql",
  "024_admin_session_lookup_and_login_throttle_hardening.sql",
  "025_operational_config_versioning.sql",
  "026_mcp_runtime_invariants.sql",
  "027_admin_roles_and_bootstrap.sql",
  "028_monitoring_profile_versioning.sql",
  "029_operational_config_vault.sql",
  "030_audit_archive_outbox.sql",
  "031_admin_session_epoch.sql",
  "032_runtime_domain_migration.sql",
  "033_mfa_ciphertext_constraint.sql",
  "034_audit_writer_owner_privileges.sql",
  "035_audit_writer_returning_privilege.sql",
  "036_audit_writer_security_contract.sql",
  "037_audit_event_fk_lock_privilege.sql",
  "038_drop_legacy_operational_config_constraint.sql",
  "039_release_20260720_component_onboarding.sql",
  "040_restore_active_runtime_jobs.sql",
  "041_component_model_20260721.sql",
  "042_secret_manager_20260722.sql",
  "043_secret_reveal_binding_20260722.sql",
  "044_component_identity_legacy_insert_bridge_20260722.sql",
  "045_release_wave_blueprint_enforcement_20260723.sql",
  "046_drop_stale_component_identity_triggers_20260723.sql",
  "047_blueprint_release_generated_scope_20260723.sql",
  "048_revoke_legacy_blueprint_platform_grants_20260723.sql",
  "049_single_use_integration_tokens_20260724.sql",
  "050_component_full_contract_20260724.sql",
  "051_drop_admin_account_manual_fix_backup_20260720.sql"
] as const;

export type ReadinessReport = {
  ready: boolean;
  buildId: string;
  checkedAt: string;
  database: { ok: boolean };
  migrations: { ok: boolean; expected: number; applied: number; missing: string[]; unexpected: string[] };
  catalog: { ok: boolean; serverCount: number; servingCount: number; blocked: Array<{ code: string; reason: string }> };
  audit: { ok: boolean; chainValid: boolean; eventCount: number; rollbackWriteProbe: boolean; brokenEventId: number | null };
  monitor: { ok: boolean; enabled: boolean; lastCompletedAt: string | null; lastError: string | null };
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
  const migrationResult = await db.query("select version from schema_migration order by sequence_number,version");
  const applied = migrationResult.rows.map((row) => String(row.version));
  const expected = new Set<string>(EXPECTED_MIGRATIONS);
  const appliedSet = new Set(applied);
  const missing = EXPECTED_MIGRATIONS.filter((migration) => !appliedSet.has(migration));
  const unexpected = applied.filter((migration) => !expected.has(migration));
  const migrationOk = missing.length === 0 && unexpected.length === 0;

  const servers = await listServers(db);
  const blocked: Array<{ code: string; reason: string }> = [];
  let servingCount = 0;
  for (const server of servers) {
    const recertification = evaluateRecertification({
      activeRevisionId: server.activeRevisionId,
      validationState: server.registrationValidationState,
      approvedAt: server.reviewApprovedAt,
      reviewDueAt: server.reviewDueAt,
      reviewIntervalDays: server.reviewIntervalDays
    });
    const serving = server.enabled
      && ["ACTIVE", "TRIAL"].includes(server.registrationState)
      && server.monitoringEnabled
      && Boolean(server.monitoringProfileDigest)
      && recertification.canServeExisting;
    if (serving) servingCount += 1;
    else if (["ACTIVE", "TRIAL"].includes(server.registrationState)) {
      blocked.push({ code: server.code, reason: recertification.reason ?? "monitoring_or_runtime_gate_missing" });
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
  const ready = migrationOk && blocked.length === 0 && auditChain.valid && rollbackWriteProbe && monitorOk;
  return {
    ready,
    buildId: config.BUILD_ID,
    checkedAt,
    database: { ok: true },
    migrations: { ok: migrationOk, expected: EXPECTED_MIGRATIONS.length, applied: applied.length, missing: [...missing], unexpected },
    catalog: { ok: blocked.length === 0, serverCount: servers.length, servingCount, blocked },
    audit: {
      ok: auditChain.valid && rollbackWriteProbe,
      chainValid: auditChain.valid,
      eventCount: auditChain.eventCount,
      rollbackWriteProbe,
      brokenEventId: auditChain.brokenEventId
    },
    monitor: { ok: monitorOk, enabled: config.MONITOR_ENABLED, lastCompletedAt, lastError: monitorResult.rows[0]?.last_error ? String(monitorResult.rows[0].last_error) : null }
  };
}
