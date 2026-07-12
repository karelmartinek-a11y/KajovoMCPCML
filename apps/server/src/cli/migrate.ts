import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadConfig } from "../config.js";
import { createDb } from "../db.js";

const config = loadConfig();
const db = createDb(config);

try {
  await db.query("create table if not exists schema_migration(version text primary key, applied_at timestamptz not null default now())");
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const dir = path.resolve(currentDir, "../migrations");
  const files = (await fs.readdir(dir)).filter((file) => file.endsWith(".sql")).sort();
  for (const file of files) {
    const exists = await db.query("select 1 from schema_migration where version=$1", [file]);
    if (exists.rowCount) continue;
    const sql = await fs.readFile(path.join(dir, file), "utf8");
    await db.query("begin");
    try {
      await db.query(sql);
      await db.query("insert into schema_migration(version) values ($1)", [file]);
      await db.query("commit");
      process.stderr.write(`Applied migration ${file}\n`);
    } catch (error) {
      await db.query("rollback");
      throw error;
    }
  }
} finally {
  await db.end();
}
