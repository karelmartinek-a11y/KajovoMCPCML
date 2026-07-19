import type { Db } from "../db.js";
import { isKcmlHostname as isManagedKcmlHostname, resourceForHostname } from "./hostnames.js";
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
    registrationRevision: optionalText(row.registration_revision),
    activeRevisionId: optionalText(row.active_revision_id),
    registrationSchemaVersion: optionalText(row.registration_schema_version),
    registrationValidationState: optionalText(row.registration_validation_state),
    reviewApprovedAt: asTimestamp(row.review_approved_at),
    reviewDueAt: asTimestamp(row.review_due_at),
    reviewIntervalDays: row.review_interval_days === null || row.review_interval_days === undefined ? null : Number(row.review_interval_days),
    monitoringEnabled: Boolean(row.monitoring_enabled),
    monitoringProfileDigest: optionalText(row.monitoring_profile_digest),
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
    readOnlyHint: Boolean(row.read_only_hint),
    destructiveHint: Boolean(row.destructive_hint),
    idempotentHint: Boolean(row.idempotent_hint),
    openWorldHint: Boolean(row.open_world_hint),
    effectClass: row.effect_class as McpServer["effectClass"],
    shutdownPolicy: row.shutdown_policy as McpServer["shutdownPolicy"],
    idempotencyPolicy: typeof row.idempotency_policy === "string" ? row.idempotency_policy : "",
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
    createdAt: asTimestamp(row.created_at) ?? "",
    updatedAt: asTimestamp(row.updated_at) ?? ""
  };
}

function serverQuery(): string {
  return `
    select
      ms.*,
      rr.revision as registration_revision,
      rr.id as active_revision_id,
      rr.schema_version as registration_schema_version,
      rr.validation_state as registration_validation_state,
      rr.approved_at as review_approved_at,
      rr.review_due_at,
      rr.review_interval_days,
      coalesce(mp.enabled, false) as monitoring_enabled,
      mp.profile_digest as monitoring_profile_digest,
      coalesce(fs.success_count, 0) as success_count,
      coalesce(fs.unauthorized_count, 0) as unauthorized_count,
      coalesce(fs.failure_count, 0) as failure_count,
      fs.last_success_at,
      fs.last_failure_at,
      fs.last_unauthorized_at,
      latency.last_latency_ms,
      latency.average_latency_ms,
      latency.p95_latency_ms
    from mcp_server ms
    left join lateral (
      select id, revision, schema_version, validation_state, approved_at, review_due_at, review_interval_days
        from registration_revision
       where id = ms.active_revision_id and server_id = ms.id
    ) rr on true
    left join monitoring_profile mp on mp.server_id=ms.id and mp.registration_revision_id=rr.id
    left join function_statistics fs on fs.server_id = ms.id
    left join lateral (
      select
        (array_agg(metric.latency_ms order by metric.created_at desc))[1] as last_latency_ms,
        round(avg(metric.latency_ms)) as average_latency_ms,
        round(percentile_cont(0.95) within group (order by metric.latency_ms)) as p95_latency_ms
      from mcp_invocation_metric metric
      where metric.server_id = ms.id and metric.created_at >= now() - interval '30 days'
    ) latency on true
  `;
}

export async function getServerByHostname(db: Db, hostname: string): Promise<McpServer | null> {
  const result = await db.query(`${serverQuery()} where lower(ms.hostname)=lower($1) and ms.archived_at is null`, [hostname]);
  return result.rowCount ? mapServer(result.rows[0]) : null;
}

export async function getServerById(db: Db, id: string): Promise<McpServer | null> {
  const result = await db.query(`${serverQuery()} where ms.id=$1`, [id]);
  return result.rowCount ? mapServer(result.rows[0]) : null;
}

export async function listServers(db: Db): Promise<McpServer[]> {
  const result = await db.query(`${serverQuery()} where ms.archived_at is null order by ms.kcml_number asc`);
  return result.rows.map(mapServer);
}

export function isKcmlHostname(hostname: string, baseDomain: string): boolean {
  return isManagedKcmlHostname(hostname, baseDomain);
}

export function resourceFor(hostname: string): string {
  return resourceForHostname(hostname);
}
