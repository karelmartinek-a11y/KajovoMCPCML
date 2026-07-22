import { randomUUID } from "node:crypto";
import { pathToFileURL } from "node:url";
import type pg from "pg";
import { loadBootstrapConfig } from "../config.js";
import { createDb, tx } from "../db.js";
import {
  requireDeploymentManagedAdminPassword,
  syncDeploymentManagedAdmin,
  type PreservedDeploymentManagedAdmin,
  verifyDeploymentManagedAdminPassword
} from "../domain/deployment-managed-admin.js";
import { loadConfigFromDb } from "../domain/operational-config.js";
import { initializePreProductionBaselineState } from "../domain/pre-production-baseline.js";

const KEEP_TABLES = new Set(["schema_migration", "operational_config_setting", "operational_config_applied"]);
const AUDIT_HEAD_TABLE = "audit_head";
const ARCHIVE_SCHEMA = "factory_reset_archive";
export const FACTORY_RESET_CONFIRMATION = "ARCHIVE_AND_RESET_KCML";

type PublicTable = {
  table_name: string;
};

type ArchiveSummary = {
  tableName: string;
  archivedTableName: string;
  rowCount: number;
};

function quoteIdentifier(value: string): string {
  return `"${value.replaceAll("\"", "\"\"")}"`;
}

function archiveTableName(sourceTable: string, runId: string): string {
  return `${sourceTable}__${runId.replaceAll("-", "_")}`;
}

export function requireFactoryResetConfirmation(env: NodeJS.ProcessEnv): void {
  if (env.KCML_FACTORY_RESET_CONFIRM !== FACTORY_RESET_CONFIRMATION) {
    throw new Error(`factory_reset_confirmation_required:${FACTORY_RESET_CONFIRMATION}`);
  }
}

async function listPublicTables(client: pg.PoolClient): Promise<string[]> {
  const result = await client.query<PublicTable>(
    `select table_name
       from information_schema.tables
      where table_schema = 'public'
        and table_type = 'BASE TABLE'
      order by table_name asc`
  );
  return result.rows
    .map((row) => row.table_name)
    .filter((tableName) => !KEEP_TABLES.has(tableName));
}

async function ensureArchiveMetadata(client: pg.PoolClient): Promise<void> {
  await client.query(`create schema if not exists ${quoteIdentifier(ARCHIVE_SCHEMA)}`);
  await client.query(
    `create table if not exists ${quoteIdentifier(ARCHIVE_SCHEMA)}.${quoteIdentifier("reset_run")} (
       run_id text primary key,
       created_at timestamptz not null default now(),
       created_by text not null,
       preserved_tables text[] not null,
       truncated_tables text[] not null
     )`
  );
}

async function archiveTable(client: pg.PoolClient, tableName: string, runId: string): Promise<ArchiveSummary> {
  const archivedTableName = archiveTableName(tableName, runId);
  await client.query(
    `create table ${quoteIdentifier(ARCHIVE_SCHEMA)}.${quoteIdentifier(archivedTableName)}
       as table public.${quoteIdentifier(tableName)} with data`
  );
  const countResult = await client.query<{ count: string }>(
    `select count(*)::bigint as count
       from ${quoteIdentifier(ARCHIVE_SCHEMA)}.${quoteIdentifier(archivedTableName)}`
  );
  return {
    tableName,
    archivedTableName,
    rowCount: Number(countResult.rows[0]?.count ?? 0)
  };
}

async function snapshotPreservedTables(client: pg.PoolClient): Promise<void> {
  await client.query("create temp table kcml_keep_schema_migration as table public.schema_migration with data");
  await client.query("create temp table kcml_keep_operational_config_setting as table public.operational_config_setting with data");
  await client.query("create temp table kcml_keep_operational_config_applied as table public.operational_config_applied with data");
}

async function restorePreservedTables(client: pg.PoolClient): Promise<void> {
  await client.query(
    `insert into public.schema_migration
     select preserved.*
       from kcml_keep_schema_migration preserved
      where not exists (
        select 1 from public.schema_migration current where current.version=preserved.version
      )`
  );
  await client.query(
    `insert into public.operational_config_setting
     select preserved.*
       from kcml_keep_operational_config_setting preserved
      where not exists (
        select 1 from public.operational_config_setting current where current.key=preserved.key
      )`
  );
  await client.query(
    `insert into public.operational_config_applied
     select preserved.*
       from kcml_keep_operational_config_applied preserved
      where not exists (
        select 1
          from public.operational_config_applied current
         where current.key=preserved.key
           and current.process_role=preserved.process_role
      )`
  );
}

export async function runFactoryReset(): Promise<void> {
  requireFactoryResetConfirmation(process.env);
  const config = loadBootstrapConfig();
  const db = createDb(config);
  const runId = randomUUID();
  const runtimeConfig = await loadConfigFromDb(db, config);
  const password = requireDeploymentManagedAdminPassword(process.env.PASS);

  try {
    const { summary, accountId, mfaEnabled } = await tx(db, async (client) => {
      await client.query("select pg_advisory_xact_lock(hashtextextended('kcml-factory-reset', 0))");
      await ensureArchiveMetadata(client);

      const allTables = await listPublicTables(client);
      const preservedTables = allTables.filter((tableName) => tableName !== AUDIT_HEAD_TABLE);
      const tablesToTruncate = allTables;
      const archiveSummaries: ArchiveSummary[] = [];
      const preservedOwnerResult = await client.query(
        "select id,mfa_enabled,mfa_secret from admin_account where username=$1",
        [runtimeConfig.ADMIN_BOOTSTRAP_USERNAME]
      );
      const preservedOwner: PreservedDeploymentManagedAdmin | null = preservedOwnerResult.rowCount
        ? {
            accountId: String(preservedOwnerResult.rows[0].id),
            mfaEnabled: Boolean(preservedOwnerResult.rows[0].mfa_enabled),
            mfaSecret: typeof preservedOwnerResult.rows[0].mfa_secret === "string"
              ? preservedOwnerResult.rows[0].mfa_secret
              : null
          }
        : null;

      await snapshotPreservedTables(client);
      for (const tableName of preservedTables) {
        archiveSummaries.push(await archiveTable(client, tableName, runId));
      }

      await client.query(
        `insert into ${quoteIdentifier(ARCHIVE_SCHEMA)}.${quoteIdentifier("reset_run")} (
           run_id, created_by, preserved_tables, truncated_tables
         ) values ($1, $2, $3::text[], $4::text[])`,
        [runId, "factory-reset", preservedTables, tablesToTruncate]
      );

      await client.query("select public.kcml_factory_reset_truncate($1::text[])", [tablesToTruncate]);
      await restorePreservedTables(client);
      await initializePreProductionBaselineState(client);

      await client.query(
        `insert into public.${quoteIdentifier(AUDIT_HEAD_TABLE)}(singleton, last_sequence, event_hash, updated_at)
         values (true, 0, null, now())
         on conflict (singleton) do update
           set last_sequence=0,
               event_hash=null,
               updated_at=now()`
      );

      const restoredOwner = await syncDeploymentManagedAdmin(client, {
        username: runtimeConfig.ADMIN_BOOTSTRAP_USERNAME,
        password,
        mfaEncryptionKey: runtimeConfig.MFA_ENCRYPTION_KEY_BASE64,
        configuredTotpSecret: runtimeConfig.ADMIN_TOTP_SECRET,
        preserved: preservedOwner,
        actorType: "factory-reset",
        eventType: "admin.factory_reset.restored",
        correlationId: randomUUID()
      });
      await verifyDeploymentManagedAdminPassword(client, restoredOwner.accountId, password, "factory-reset", randomUUID());

      return {
        summary: archiveSummaries,
        accountId: restoredOwner.accountId,
        mfaEnabled: restoredOwner.mfaEnabled
      };
    });

    const totalRows = summary.reduce((count, item) => count + item.rowCount, 0);
    process.stderr.write(
      `Factory reset completed. Archived ${summary.length} tables and ${totalRows} rows under schema ${ARCHIVE_SCHEMA} with run id ${runId}. Restored deployment-managed owner ${runtimeConfig.ADMIN_BOOTSTRAP_USERNAME} (${accountId}); MFA ${mfaEnabled ? "enabled" : "disabled"}.\n`
    );
  } finally {
    await db.end();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await runFactoryReset();
}
