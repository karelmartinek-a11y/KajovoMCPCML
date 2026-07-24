import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import type pg from "pg";
import { loadBootstrapConfig } from "../config.js";
import { createDb } from "../db.js";
import { KCML_RELEASE } from "../domain/release.js";

const MIGRATION_NAME = /^(\d{3})_([a-z0-9_]+)[.]sql$/;
const BASELINE_MIGRATION = "001_pre_production_baseline.sql";

export type MigrationFile = {
  name: string;
  sequence: number;
  sql: string;
  checksum: string;
};

export function validateMigrationNames(entries: string[]): Array<{ name: string; sequence: number }> {
  const candidates = entries.filter((entry) => !entry.startsWith("._") && entry.endsWith(".sql"));
  const parsed = candidates.map((name) => {
    const match = MIGRATION_NAME.exec(name);
    if (!match) throw new Error(`invalid_migration_filename:${name}`);
    return { name, sequence: Number(match[1]) };
  }).sort((left, right) => left.sequence - right.sequence || left.name.localeCompare(right.name));

  for (let index = 0; index < parsed.length; index += 1) {
    const expected = index + 1;
    if (parsed[index]?.sequence !== expected) {
      throw new Error(`non_contiguous_migration_sequence:expected_${String(expected).padStart(3, "0")}`);
    }
  }
  return parsed;
}

async function loadMigrations(directory: string): Promise<MigrationFile[]> {
  const parsed = validateMigrationNames(await fs.readdir(directory));
  return Promise.all(parsed.map(async ({ name, sequence }) => {
    const sql = await fs.readFile(path.join(directory, name), "utf8");
    return {
      name,
      sequence,
      sql,
      checksum: createHash("sha256").update(sql).digest("hex")
    };
  }));
}

async function appliedMigrations(client: pg.PoolClient): Promise<Map<string, { sequence: number | null; checksum: string | null }>> {
  const result = await client.query("select version,sequence_number,checksum_sha256 from public.schema_migration");
  return new Map(result.rows.map((row) => [String(row.version), {
    sequence: row.sequence_number === null ? null : Number(row.sequence_number),
    checksum: row.checksum_sha256 === null ? null : String(row.checksum_sha256)
  }]));
}

function validateAppliedSet(migrations: MigrationFile[], applied: Map<string, { sequence: number | null; checksum: string | null }>): void {
  const available = new Map(migrations.map((migration) => [migration.name, migration]));
  for (const [version, entry] of applied) {
    const migration = available.get(version);
    if (!migration) throw new Error(`unknown_applied_migration:${version}`);
    if (entry.sequence !== migration.sequence) throw new Error(`migration_sequence_changed:${version}`);
    if (!entry.checksum) throw new Error(`migration_checksum_missing:${version}`);
    if (entry.checksum !== migration.checksum) throw new Error(`migration_checksum_changed:${version}`);
  }
}

async function ensureLedgerColumns(client: pg.PoolClient): Promise<void> {
  await client.query("alter table public.schema_migration add column if not exists sequence_number integer");
  await client.query("alter table public.schema_migration add column if not exists checksum_sha256 text");
}

async function assertCompactionReady(client: pg.PoolClient): Promise<void> {
  const checks = await client.query(`
    select
      to_regclass('public.release_epoch') is not null as has_release_epoch,
      to_regclass('public.principal') is not null as has_principal,
      to_regclass('public.platform_worker_access_identity') is not null as has_platform_worker_access_identity,
      exists(
        select 1
          from information_schema.columns
         where table_schema='public'
           and table_name='admin_account'
           and column_name='session_epoch'
      ) as has_admin_session_epoch,
      exists(
        select 1
          from pg_proc
         where proname='verify_audit_chain'
           and pg_get_function_identity_arguments(oid)=''
      ) as has_verify_audit_chain
  `);
  const row = checks.rows[0];
  if (!row?.has_release_epoch || !row?.has_principal || !row?.has_platform_worker_access_identity || !row?.has_admin_session_epoch || !row?.has_verify_audit_chain) {
    throw new Error("legacy_migration_compaction_preconditions_failed");
  }
}

async function compactLegacyLedger(client: pg.PoolClient, migrations: MigrationFile[]): Promise<void> {
  await assertCompactionReady(client);
  await client.query("delete from public.schema_migration");
  for (const migration of migrations) {
    await client.query(
      `insert into public.schema_migration(version,sequence_number,checksum_sha256)
       values ($1,$2,$3)`,
      [migration.name, migration.sequence, migration.checksum]
    );
  }
}

async function ensureCanonicalReleaseEpoch(client: pg.PoolClient): Promise<void> {
  await client.query(
    `insert into public.release_epoch(
       release_version,
       blueprint_version,
       catalog_version,
       manifest_schema_version,
       pulse_envelope_version,
       policy_baseline,
       mcp_protocol_version,
       sealed_previous_epoch_hash
     )
     values ($1,$1,$1,$1,$1,$2::date,$3,'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
     on conflict (release_version) do update
       set blueprint_version=excluded.blueprint_version,
           catalog_version=excluded.catalog_version,
           manifest_schema_version=excluded.manifest_schema_version,
           pulse_envelope_version=excluded.pulse_envelope_version,
           policy_baseline=excluded.policy_baseline,
           mcp_protocol_version=excluded.mcp_protocol_version`,
    [KCML_RELEASE.catalogVersion, KCML_RELEASE.policyBaseline, KCML_RELEASE.mcpProtocolVersion]
  );

  for (const tableName of [
    "component",
    "component_onboarding_job",
    "integration_token",
    "integration_token_allowed_component",
    "integration_token_child_job",
    "mcp_server",
    "onboarding_job"
  ]) {
    const exists = await client.query("select to_regclass($1) is not null as exists", [`public.${tableName}`]);
    if (!exists.rows[0]?.exists) continue;
    await client.query(`alter table public.${tableName} alter column release_version set default '${KCML_RELEASE.catalogVersion}'::text`);
  }
}

export async function runMigrations(): Promise<void> {
  const config = loadBootstrapConfig();
  const db = createDb(config);
  const client = await db.connect();
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const directory = path.resolve(currentDir, "../migrations");
  const migrations = await loadMigrations(directory);

  try {
    await client.query("select pg_advisory_lock(hashtextextended('kcml-schema-migrations', 0))");
    await client.query("create table if not exists public.schema_migration(version text primary key, applied_at timestamptz not null default now())");
    await ensureLedgerColumns(client);
    const baseline = migrations.find((migration) => migration.name === BASELINE_MIGRATION);
    if (!baseline) throw new Error(`baseline_migration_missing:${BASELINE_MIGRATION}`);
    let applied = await appliedMigrations(client);

    if (applied.size > 0 && !applied.has(baseline.name)) {
      await client.query("begin");
      try {
        await client.query("set local lock_timeout='10s'");
        await client.query("set local statement_timeout='5min'");
        await compactLegacyLedger(client, migrations);
        await client.query("commit");
      } catch (error) {
        await client.query("rollback").catch(() => undefined);
        throw error;
      }
      applied = await appliedMigrations(client);
    }

    validateAppliedSet(migrations, applied);

    for (const migration of migrations) {
      if (applied.has(migration.name)) continue;
      await client.query("begin");
      try {
        await client.query("set local lock_timeout='10s'");
        await client.query("set local statement_timeout='5min'");
        await client.query(migration.sql);
        await client.query(
          "insert into public.schema_migration(version,sequence_number,checksum_sha256) values ($1,$2,$3)",
          [migration.name, migration.sequence, migration.checksum]
        );
        await client.query("commit");
        applied.set(migration.name, { sequence: migration.sequence, checksum: migration.checksum });
        process.stderr.write(`Applied migration ${migration.name}\n`);
      } catch (error) {
        await client.query("rollback").catch(() => undefined);
        throw error;
      }
    }

    applied = await appliedMigrations(client);
    validateAppliedSet(migrations, applied);
    await ensureCanonicalReleaseEpoch(client);
  } finally {
    await client.query("select pg_advisory_unlock(hashtextextended('kcml-schema-migrations', 0))").catch(() => undefined);
    client.release();
    await db.end();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await runMigrations();
}
