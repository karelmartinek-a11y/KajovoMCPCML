import type { Db } from "../db.js";
import type { McpServer } from "./types.js";

function asTimestamp(value: unknown): string | null {
  if (!value) return null;
  if (value instanceof Date) return value.toISOString();
  if (typeof value === "string") return value;
  if (typeof value === "number") return new Date(value).toISOString();
  return null;
}

function mapServer(row: Record<string, unknown>): McpServer {
  return {
    id: String(row.id),
    code: String(row.code),
    kcmlNumber: Number(row.kcml_number),
    hostname: String(row.hostname),
    toolName: String(row.tool_name),
    displayName: String(row.display_name),
    description: String(row.description),
    enabled: Boolean(row.enabled),
    registrationState: row.registration_state as McpServer["registrationState"],
    operationalState: row.operational_state as McpServer["operationalState"],
    inputSchema: row.input_schema,
    outputSchema: row.output_schema,
    handlerKey: String(row.handler_key),
    handlerVersion: String(row.handler_version),
    contractVersion: String(row.contract_version),
    artifactDigest: String(row.artifact_digest),
    manifestDigest: String(row.manifest_digest),
    revocationEpoch: String(row.revocation_epoch),
    successCount: Number(row.success_count ?? 0),
    unauthorizedCount: Number(row.unauthorized_count ?? 0),
    failureCount: Number(row.failure_count ?? 0),
    lastSuccessAt: asTimestamp(row.last_success_at),
    lastFailureAt: asTimestamp(row.last_failure_at),
    lastUnauthorizedAt: asTimestamp(row.last_unauthorized_at),
    createdAt: asTimestamp(row.created_at) ?? "",
    updatedAt: asTimestamp(row.updated_at) ?? ""
  };
}

export async function getServerByHostname(db: Db, hostname: string): Promise<McpServer | null> {
  const result = await db.query("select * from mcp_server where lower(hostname)=lower($1)", [hostname]);
  return result.rowCount ? mapServer(result.rows[0]) : null;
}

export async function listServers(db: Db): Promise<McpServer[]> {
  const result = await db.query(`
    select
      ms.*,
      coalesce(fs.success_count, 0) as success_count,
      coalesce(fs.unauthorized_count, 0) as unauthorized_count,
      coalesce(fs.failure_count, 0) as failure_count,
      fs.last_success_at,
      fs.last_failure_at,
      fs.last_unauthorized_at
    from mcp_server ms
    left join function_statistics fs on fs.server_id = ms.id
    order by ms.kcml_number asc
  `);
  return result.rows.map(mapServer);
}

export function isKcmlHostname(hostname: string, baseDomain: string): boolean {
  return new RegExp(`^kcml[0-9]{4,}\\.(${baseDomain.replaceAll(".", "\\.")})$`, "i").test(hostname);
}

export function resourceFor(hostname: string): string {
  return `https://${hostname}/mcp`;
}
