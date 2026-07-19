import { randomUUID } from "node:crypto";
import { pathToFileURL } from "node:url";
import { loadBootstrapConfig, loadConfig } from "../config.js";
import { createDb } from "../db.js";
import { operationalConfigDefinitions, updateOperationalConfig } from "../domain/operational-config.js";

export function shouldRefreshExistingOperationalSetting(input: {
  key: string;
  envKey: string;
  options: { overwrite?: boolean; refreshBuildId?: boolean };
  env?: NodeJS.ProcessEnv;
}): boolean {
  if (input.options.overwrite) return true;
  if (input.options.refreshBuildId && input.key === "buildId") return true;
  if (input.options.refreshBuildId && input.key === "adminBootstrapUsername") {
    return Object.prototype.hasOwnProperty.call(input.env ?? process.env, input.envKey);
  }
  return false;
}

export async function importOperationalConfigFromEnvironment(options: {
  overwrite?: boolean;
  refreshBuildId?: boolean;
} = {}): Promise<{ imported: number; skipped: number }> {
  const bootstrap = loadBootstrapConfig();
  const legacy = loadConfig(process.env, { allowAdminTotpSecret: true });
  const db = createDb(bootstrap);
  let imported = 0;
  let skipped = 0;
  try {
    for (const definition of operationalConfigDefinitions) {
      const raw = legacy[definition.envKey];
      if (raw === undefined || raw === null || (Buffer.isBuffer(raw) && raw.length === 0)) {
        skipped += 1;
        continue;
      }
      const current = await db.query("select version from operational_config_setting where key=$1", [definition.key]);
      const mayOverwrite = shouldRefreshExistingOperationalSetting({
        key: definition.key,
        envKey: definition.envKey,
        options
      });
      if (current.rowCount && !mayOverwrite) {
        skipped += 1;
        continue;
      }
      const value = Buffer.isBuffer(raw) ? raw.toString("base64") : raw;
      await updateOperationalConfig(
        db,
        legacy,
        null,
        randomUUID(),
        definition.key,
        value,
        current.rowCount ? Number(current.rows[0].version) : 0
      );
      imported += 1;
    }
    return { imported, skipped };
  } finally {
    await db.end();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  importOperationalConfigFromEnvironment({
    overwrite: process.argv.includes("--overwrite"),
    refreshBuildId: process.argv.includes("--refresh-build-id")
  }).then((result) => {
    process.stdout.write(`operational-config-import:OK imported=${result.imported} skipped=${result.skipped}\n`);
  }).catch((error) => {
    process.stderr.write(`operational-config-import:FAIL error=${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  });
}
