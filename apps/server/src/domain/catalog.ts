import type { Db } from "../db.js";
import type { McpServer } from "./types.js";

function asTimestamp(value: unknown): string | null {
  if (!value) return null;
  if (value instanceof Date) return value.toISOString();
  if (typeof value === "string") return value;
  if (typeof value === "number") return new Date(value).toISOString();
  return null;
}

function optionalText(value: unknown): string | null {
  return typeof value === "string" ? value : typeof value === "number" ? String(value) : null;
}

function mapServer(row: Record<string, unknown>): McpServer {
  const evidence: {
    handlerSmoke?: { status?: string };
    identityBound?: boolean;
    uiMcpTest?: McpServer["uiMcpTest"];
    acceptancePassed?: boolean;
  } | null = row.evidence && typeof row.evidence === "object" ? row.evidence : null;
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
    imageReference: optionalText(row.image_reference),
    imageDigest: optionalText(row.image_digest),
    sbomDigest: optionalText(row.sbom_digest),
    provenanceDigest: optionalText(row.provenance_digest),
    runtimeSocket: optionalText(row.runtime_socket),
    timeoutMs: Number(row.timeout_ms ?? 30_000),
    maxConcurrency: Number(row.max_concurrency ?? 1),
    requestMaxBytes: Number(row.request_max_bytes ?? 1_048_576),
    responseMaxBytes: Number(row.response_max_bytes ?? 5_242_880),
    rateWindowSeconds: Number(row.rate_window_seconds ?? 60),
    rateMaxRequests: Number(row.rate_max_requests ?? 60),
    revocationEpoch: String(row.revocation_epoch),
    successCount: Number(row.success_count ?? 0),
    unauthorizedCount: Number(row.unauthorized_count ?? 0),
    failureCount: Number(row.failure_count ?? 0),
    lastLatencyMs: row.last_latency_ms === null || row.last_latency_ms === undefined ? null : Number(row.last_latency_ms),
    averageLatencyMs: row.average_latency_ms === null || row.average_latency_ms === undefined ? null : Number(row.average_latency_ms),
    p95LatencyMs: row.p95_latency_ms === null || row.p95_latency_ms === undefined ? null : Number(row.p95_latency_ms),
    lastSuccessAt: asTimestamp(row.last_success_at),
    lastFailureAt: asTimestamp(row.last_failure_at),
    lastUnauthorizedAt: asTimestamp(row.last_unauthorized_at),
    handlerSmokePassed: Boolean(evidence?.handlerSmoke?.status === "PASS"),
    manifestIdentityBound: Boolean(evidence?.identityBound),
    uiMcpTest: evidence?.uiMcpTest ?? null,
    acceptancePassed: Boolean(evidence?.acceptancePassed),
    createdAt: asTimestamp(row.created_at) ?? "",
    updatedAt: asTimestamp(row.updated_at) ?? ""
  };
}

export async function getServerByHostname(db: Db, hostname: string): Promise<McpServer | null> {
  const result = await db.query("select * from mcp_server where lower(hostname)=lower($1)", [hostname]);
  return result.rowCount ? mapServer(result.rows[0]) : null;
}

export async function getServerById(db: Db, id: string): Promise<McpServer | null> {
  const result = await db.query("select * from mcp_server where id=$1", [id]);
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
      fs.last_unauthorized_at,
      revision.evidence,
      latency.last_latency_ms,
      latency.average_latency_ms,
      latency.p95_latency_ms
    from mcp_server ms
    left join function_statistics fs on fs.server_id = ms.id
    left join lateral (
      select rr.evidence
      from registration_revision rr
      where rr.server_id = ms.id
      order by rr.created_at desc
      limit 1
    ) revision on true
    left join lateral (
      select
        (array_agg(metric.latency_ms order by metric.created_at desc))[1] as last_latency_ms,
        round(avg(metric.latency_ms)) as average_latency_ms,
        round(percentile_cont(0.95) within group (order by metric.latency_ms)) as p95_latency_ms
      from mcp_invocation_metric metric
      where metric.server_id = ms.id and metric.created_at >= now() - interval '30 days'
    ) latency on true
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
