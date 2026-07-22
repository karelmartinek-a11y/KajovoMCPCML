import { randomUUID } from "node:crypto";
import type pg from "pg";
import type { Db } from "../db.js";
import { tx } from "../db.js";
import { appendAudit } from "./audit.js";
import { matchExternalApiOperation, validateExternalApiManifest } from "./external-api.js";
import { evaluateRecertification } from "./recertification.js";

export type ManagedServiceSummary = {
  id: string;
  legacyMcpServerId: string | null;
  code: string;
  slug: string;
  displayName: string;
  description: string;
  serviceKind: "MCP" | "EXTERNAL_API";
  environment: string;
  enabled: boolean;
  publicHostname: string | null;
  resourceUri: string | null;
  lifecycleState: string;
  operationalState: string;
  apiState: "ENABLED" | "DISABLED";
  apiDisabledReason: string | null;
  activeRevisionId: string | null;
  activeRevisionEpoch: number;
  monitoringEnabled: boolean;
  monitoringProfileDigest: string | null;
  reviewApprovedAt: string | null;
  reviewDueAt: string | null;
  reviewIntervalDays: number | null;
  lockVersion: number;
  serviceTokenEpoch: string;
  permissionEpoch: string;
  lastPolicyInvalidationAt: string | null;
};

export type ManagedServiceDecision = {
  allow: boolean;
  reasonCode: string;
  decisionId: string;
  correlationId: string;
  serviceId: string;
  principalId: string | null;
  operationId: string | null;
  lifecycleState: string;
  apiState: string;
  serviceTokenEpoch: string;
  principalTokenEpoch: string | null;
  permissionEpoch: string;
  activeRevisionEpoch: number;
  scopes: string[];
};

function asIso(value: unknown): string | null {
  if (!value) return null;
  if (value instanceof Date) return value.toISOString();
  if (typeof value === "string") return value;
  return null;
}

function optionalText(value: unknown): string | null {
  return typeof value === "string" ? value : typeof value === "number" ? String(value) : null;
}

function sameSortedStrings(left: string[], right: string[]): boolean {
  const normalizedLeft = [...left].sort();
  const normalizedRight = [...right].sort();
  return normalizedLeft.length === normalizedRight.length
    && normalizedLeft.every((value, index) => value === normalizedRight[index]);
}

function mapManagedService(row: Record<string, unknown>): ManagedServiceSummary {
  return {
    id: String(row.id),
    legacyMcpServerId: optionalText(row.legacy_mcp_server_id),
    code: String(row.code),
    slug: String(row.slug),
    displayName: String(row.display_name),
    description: String(row.description),
    serviceKind: String(row.service_kind) as ManagedServiceSummary["serviceKind"],
    environment: String(row.environment),
    enabled: Boolean(row.enabled),
    publicHostname: optionalText(row.public_hostname),
    resourceUri: optionalText(row.resource_uri),
    lifecycleState: String(row.lifecycle_state),
    operationalState: String(row.operational_state),
    apiState: String(row.api_state) as ManagedServiceSummary["apiState"],
    apiDisabledReason: optionalText(row.api_disabled_reason),
    activeRevisionId: optionalText(row.active_revision_id),
    activeRevisionEpoch: Number(row.active_revision_epoch ?? 0),
    monitoringEnabled: Boolean(row.monitoring_enabled),
    monitoringProfileDigest: optionalText(row.monitoring_profile_digest),
    reviewApprovedAt: asIso(row.review_approved_at),
    reviewDueAt: asIso(row.review_due_at),
    reviewIntervalDays: row.review_interval_days === null || row.review_interval_days === undefined ? null : Number(row.review_interval_days),
    lockVersion: Number(row.lock_version ?? 0),
    serviceTokenEpoch: String(row.service_token_epoch),
    permissionEpoch: String(row.permission_epoch),
    lastPolicyInvalidationAt: asIso(row.last_policy_invalidation_at)
  };
}

function serviceQuery(): string {
  return `
    select
      ms.*,
      revision.validation_state as active_revision_validation_state
    from managed_service ms
    left join managed_service_revision revision
      on revision.id = ms.active_revision_id
  `;
}

export async function getManagedServiceByHostname(db: Db, hostname: string): Promise<ManagedServiceSummary | null> {
  const result = await db.query(`${serviceQuery()} where lower(ms.public_hostname)=lower($1)`, [hostname]);
  return result.rowCount ? mapManagedService(result.rows[0]) : null;
}

export async function getManagedServiceById(db: Db, id: string): Promise<ManagedServiceSummary | null> {
  const result = await db.query(`${serviceQuery()} where ms.id=$1`, [id]);
  return result.rowCount ? mapManagedService(result.rows[0]) : null;
}

export async function listManagedServices(db: Db): Promise<ManagedServiceSummary[]> {
  const result = await db.query(`${serviceQuery()} order by ms.created_at desc`);
  return result.rows.map((row) => mapManagedService(row as Record<string, unknown>));
}

export function canServeManagedService(service: ManagedServiceSummary, validationState: string | null): { ok: boolean; reason: string } {
  const recertification = evaluateRecertification({
    activeRevisionId: service.activeRevisionId,
    validationState,
    approvedAt: service.reviewApprovedAt,
    reviewDueAt: service.reviewDueAt,
    reviewIntervalDays: service.reviewIntervalDays
  });
  if (!["ACTIVE", "TRIAL"].includes(service.lifecycleState)) return { ok: false, reason: "lifecycle_inactive" };
  if (service.apiState !== "ENABLED") return { ok: false, reason: "api_disabled" };
  if (!service.monitoringEnabled || !service.monitoringProfileDigest) return { ok: false, reason: "monitoring_unavailable" };
  if (!recertification.canServeExisting) return { ok: false, reason: recertification.reason ?? "recertification_blocked" };
  return { ok: true, reason: "ok" };
}

export function assertManagedServiceRuntimeAvailable(service: ManagedServiceSummary, validationState: string | null): void {
  if (!service.enabled) throw Object.assign(new Error("service_disabled"), { statusCode: 503 });
  const availability = canServeManagedService(service, validationState);
  if (!availability.ok) throw Object.assign(new Error(availability.reason), { statusCode: 503 });
  switch (service.serviceKind) {
    case "MCP":
      if (!service.legacyMcpServerId || !service.publicHostname || !service.resourceUri) {
        throw Object.assign(new Error("runtime_configuration_missing"), { statusCode: 503 });
      }
      return;
    case "EXTERNAL_API":
      if (!service.publicHostname || !service.resourceUri) {
        throw Object.assign(new Error("runtime_configuration_missing"), { statusCode: 503 });
      }
      return;
    default:
      throw Object.assign(new Error("unsupported_service_kind"), { statusCode: 503 });
  }
}

export async function currentManagedServiceScopes(
  db: Pick<Db, "query">,
  credentialId: string,
  managedServiceId: string,
  at = "now()"
): Promise<string[]> {
  const result = await db.query(
    `select scope.scope_name
       from managed_service_permission permission
       join managed_service_scope scope on scope.id = permission.scope_id
      where permission.credential_id = $1
        and permission.managed_service_id = $2
        and permission.revoked_at is null
        and permission.state = 'GRANTED'
        and permission.valid_from <= ${at}
        and (permission.valid_to is null or permission.valid_to > ${at})
        and scope.revoked_at is null
      order by scope.scope_name`,
    [credentialId, managedServiceId]
  );
  return result.rows.map((row) => String(row.scope_name));
}

export async function authorizeManagedServiceToken(db: Db, params: {
  tokenDigest: Buffer;
  audience: string;
  environment: string;
  requiredScopes: string[];
  correlationId: string;
  operationId: string | null;
  requestMethod?: string | null;
  requestPath?: string | null;
}): Promise<ManagedServiceDecision> {
  const decisionId = randomUUID();
  const result = await db.query(
    `select
        token.credential_id,
        token.managed_service_id,
        token.expires_at,
        token.revoked_at,
        token.principal_token_epoch,
        token.service_token_epoch,
        token.permission_epoch_snapshot,
        token.active_revision_epoch_snapshot,
        token.environment as token_environment,
        kc.active as credential_active,
        kc.revoked_at as credential_revoked_at,
        kc.deleted_at as credential_deleted_at,
        kc.expires_at as credential_expires_at,
        kc.principal_token_epoch as current_principal_token_epoch,
        ms.code,
        ms.service_kind,
        ms.legacy_mcp_server_id,
        ms.public_hostname,
        ms.resource_uri,
        ms.lifecycle_state,
        ms.api_state,
        ms.enabled,
        ms.active_revision_id,
        ms.active_revision_epoch,
        ms.environment,
        ms.monitoring_enabled,
        ms.monitoring_profile_digest,
        ms.review_approved_at,
        ms.review_due_at,
        ms.review_interval_days,
        ms.service_token_epoch as current_service_token_epoch,
        ms.permission_epoch,
        revision.manifest as active_revision_manifest,
        revision.validation_state as active_revision_validation_state
      from managed_service_access_token token
      join kaja_credential kc on kc.id = token.credential_id
      join managed_service ms on ms.id = token.managed_service_id
      left join managed_service_revision revision on revision.id = ms.active_revision_id
     where token.lookup_digest = $1
       and token.audience = $2
       and token.expires_at > now()
       and token.revoked_at is null`,
    [params.tokenDigest, params.audience]
  );
  if (!result.rowCount) {
    return {
      allow: false,
      reasonCode: "invalid_token",
      decisionId,
      correlationId: params.correlationId,
      serviceId: "unknown",
      principalId: null,
      operationId: params.operationId,
      lifecycleState: "UNKNOWN",
      apiState: "UNKNOWN",
      serviceTokenEpoch: "unknown",
      principalTokenEpoch: null,
      permissionEpoch: "unknown",
      activeRevisionEpoch: -1,
      scopes: []
    };
  }
  const row = result.rows[0] as Record<string, unknown>;
  const serviceId = String(row.managed_service_id);
  const principalId = String(row.credential_id);
  const service = mapManagedService(row);
  const deny = (reasonCode: string, scopes: string[] = []): ManagedServiceDecision => ({
    allow: false,
    reasonCode,
    decisionId,
    correlationId: params.correlationId,
    serviceId,
    principalId,
    operationId: params.operationId,
    lifecycleState: service.lifecycleState,
    apiState: service.apiState,
    serviceTokenEpoch: service.serviceTokenEpoch,
    principalTokenEpoch: optionalText(row.current_principal_token_epoch),
    permissionEpoch: service.permissionEpoch,
    activeRevisionEpoch: service.activeRevisionEpoch,
    scopes
  });

  if (String(row.token_environment) !== params.environment || service.environment !== params.environment) return deny("environment_mismatch");
  if (!row.credential_active || row.credential_revoked_at || row.credential_deleted_at) return deny("principal_inactive");
  const credentialExpiresAt = asIso(row.credential_expires_at);
  if (credentialExpiresAt && new Date(credentialExpiresAt).getTime() <= Date.now()) return deny("principal_expired");
  if (String(row.principal_token_epoch) !== String(row.current_principal_token_epoch)) return deny("principal_token_epoch_mismatch");
  if (String(row.service_token_epoch) !== String(row.current_service_token_epoch)) return deny("service_token_epoch_mismatch");
  if (String(row.permission_epoch_snapshot) !== service.permissionEpoch) return deny("permission_epoch_mismatch");
  if (Number(row.active_revision_epoch_snapshot) !== service.activeRevisionEpoch) return deny("revision_epoch_mismatch");
  if (service.activeRevisionId === null) return deny("revision_missing");
  try {
    assertManagedServiceRuntimeAvailable(service, optionalText(row.active_revision_validation_state));
  } catch (error) {
    return deny(error instanceof Error ? error.message : "resource_unavailable");
  }
  if (String(row.service_kind) === "EXTERNAL_API") {
    const manifest = validateExternalApiManifest(row.active_revision_manifest).manifest;
    const staleAfterMs = manifest.monitoringProfile.staleAfterSeconds * 1000;
    const probeRows = await db.query(
      `select distinct on (probe_type) probe_type, status, checked_at
         from managed_service_probe_result
        where managed_service_id = $1
          and probe_type = any($2::text[])
        order by probe_type, checked_at desc, id desc`,
      [serviceId, ["health", "readiness", "tls", "acceptance", "internal_error"]]
    );
    const latestProbe = new Map<string, { status: string; checkedAt: number }>();
    for (const probe of probeRows.rows as Array<Record<string, unknown>>) {
      latestProbe.set(String(probe.probe_type), {
        status: String(probe.status),
        checkedAt: new Date(probe.checked_at as string | number | Date).getTime()
      });
    }
    for (const probeType of ["health", "readiness", "tls", "acceptance"]) {
      const probe = latestProbe.get(probeType);
      if (!probe) return deny("monitoring_evidence_missing");
      if (probe.status !== "PASS") return deny(probe.status === "STALE" ? "monitoring_evidence_stale" : "monitoring_probe_failed");
      if (!Number.isFinite(probe.checkedAt) || Date.now() - probe.checkedAt > staleAfterMs) return deny("monitoring_evidence_stale");
    }
    const internalError = latestProbe.get("internal_error");
    if (internalError && Number.isFinite(internalError.checkedAt) && Date.now() - internalError.checkedAt <= staleAfterMs) {
      return deny("monitoring_internal_error");
    }
    if (!params.requestMethod || !params.requestPath || !params.operationId) return deny("operation_context_missing");
    const matched = matchExternalApiOperation(manifest, params.requestMethod, params.requestPath);
    if (!matched) return deny("operation_policy_mismatch");
    if (matched.operation.operationId !== params.operationId || !sameSortedStrings(matched.operation.requiredScopes, params.requiredScopes)) {
      return deny("operation_policy_mismatch");
    }
  }
  const scopes = await currentManagedServiceScopes(db, principalId, serviceId);
  if (params.requiredScopes.some((scope) => !scopes.includes(scope))) return deny("insufficient_scope", scopes);

  await db.query(
    `update managed_service_access_token
        set last_used_at = case
          when last_used_at is null or last_used_at < now() - interval '1 minute' then now()
          else last_used_at
        end
      where lookup_digest = $1`,
    [params.tokenDigest]
  );

  return {
    allow: true,
    reasonCode: "allow",
    decisionId,
    correlationId: params.correlationId,
    serviceId,
    principalId,
    operationId: params.operationId,
    lifecycleState: service.lifecycleState,
    apiState: service.apiState,
    serviceTokenEpoch: service.serviceTokenEpoch,
    principalTokenEpoch: optionalText(row.current_principal_token_epoch),
    permissionEpoch: service.permissionEpoch,
    activeRevisionEpoch: service.activeRevisionEpoch,
    scopes
  };
}

export async function setManagedServiceApiState(db: Db, params: {
  managedServiceId: string;
  actorId: string;
  actorType: "admin" | "system";
  nextState: "ENABLED" | "DISABLED";
  reason: string;
  expectedLockVersion: number;
  correlationId: string;
}): Promise<{ state: "ENABLED" | "DISABLED"; version: number; decisionId: string }> {
  return tx(db, async (client) => {
    const locked = await client.query(
      `select
          ms.*,
          revision.validation_state as active_revision_validation_state,
          revision.manifest as active_revision_manifest,
          legacy.registration_state as legacy_registration_state,
          legacy.operational_state as legacy_operational_state
        from managed_service ms
        left join managed_service_revision revision on revision.id = ms.active_revision_id
        left join mcp_server legacy on legacy.id = ms.legacy_mcp_server_id
       where ms.id = $1
       for update of ms`,
      [params.managedServiceId]
    );
    if (!locked.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    const row = locked.rows[0] as Record<string, unknown>;
    if (Number(row.lock_version) !== params.expectedLockVersion) throw Object.assign(new Error("lock_version_conflict"), { statusCode: 409 });
    const previousState = String(row.api_state) as "ENABLED" | "DISABLED";
    if (previousState === params.nextState && !(params.nextState === "ENABLED" && row.enabled !== true)) {
      return { state: previousState, version: Number(row.lock_version), decisionId: randomUUID() };
    }
    if (params.nextState === "ENABLED") {
      const service = mapManagedService(row);
      if (!service.activeRevisionId) throw Object.assign(new Error("active_revision_required"), { statusCode: 409 });
      try {
        assertManagedServiceRuntimeAvailable({ ...service, apiState: "ENABLED" }, optionalText(row.active_revision_validation_state));
      } catch (error) {
        const reason = error instanceof Error ? error.message : "resource_unavailable";
        if (!["lifecycle_inactive", "service_disabled"].includes(reason)) throw Object.assign(new Error(reason), { statusCode: 409 });
      }
      if (row.legacy_mcp_server_id) {
        const criticalAlerts = await client.query(
          `select 1
             from operational_alert
            where server_id = $1
              and severity = 'CRITICAL'
              and closed_at is null
              and suppressed_until is null
            limit 1`,
          [row.legacy_mcp_server_id]
        );
        if (criticalAlerts.rowCount) throw Object.assign(new Error("critical_alert_open"), { statusCode: 409 });
      } else {
        const manifest = row.active_revision_manifest as Record<string, unknown> | null;
        const staleAfterSeconds = Number(
          (manifest?.monitoringProfile as { staleAfterSeconds?: unknown } | undefined)?.staleAfterSeconds ?? 0
        );
        const requiredProbes = ["health", "readiness", "tls"];
        const probes = await client.query(
          `select probe_type, status, checked_at
             from managed_service_probe_result
            where managed_service_id = $1
              and probe_type = any($2::text[])
            order by checked_at desc`,
          [params.managedServiceId, requiredProbes]
        );
        const latestByType = new Map<string, { status: string; checkedAt: number }>();
        for (const probe of probes.rows) {
          const type = String(probe.probe_type);
          if (latestByType.has(type)) continue;
          latestByType.set(type, {
            status: String(probe.status),
            checkedAt: new Date(probe.checked_at as string | number | Date).getTime()
          });
        }
        if (requiredProbes.some((type) => !latestByType.has(type))) throw Object.assign(new Error("mandatory_probe_missing"), { statusCode: 409 });
        if (requiredProbes.some((type) => latestByType.get(type)?.status !== "PASS")) throw Object.assign(new Error("mandatory_probe_failed"), { statusCode: 409 });
        if (!staleAfterSeconds || requiredProbes.some((type) => Date.now() - (latestByType.get(type)?.checkedAt ?? 0) > staleAfterSeconds * 1000)) {
          throw Object.assign(new Error("monitoring_evidence_stale"), { statusCode: 409 });
        }
      }
    }
    const decisionId = randomUUID();
    const nextLifecycleState = params.nextState === "ENABLED" && String(row.lifecycle_state) === "REGISTERED_DISABLED"
      ? "TRIAL"
      : params.nextState === "DISABLED" && ["ACTIVE", "TRIAL"].includes(String(row.lifecycle_state))
        ? "REGISTERED_DISABLED"
        : String(row.lifecycle_state);
    const updated = await client.query(
      `update managed_service
          set api_state = $2::managed_service_api_state,
              api_disabled_reason = case when $2::text = 'DISABLED' then $3 else null end,
              lifecycle_state = $4::managed_service_state,
              enabled = case when $2::text = 'ENABLED' then true else false end,
              lock_version = lock_version + 1,
              last_policy_invalidation_at = now(),
              updated_at = now()
        where id = $1
        returning api_state, lock_version, service_token_epoch`,
      [params.managedServiceId, params.nextState, params.reason, nextLifecycleState]
    );
    if (row.legacy_mcp_server_id) {
      if (params.nextState === "ENABLED" && String(row.legacy_registration_state) === "REGISTERED_DISABLED") {
        await client.query(
          `update mcp_server
              set enabled = true,
                  registration_state = 'TRIAL'::registration_state,
                  operational_state = 'UNKNOWN'::operational_state,
                  lock_version = lock_version + 1,
                  updated_at = now()
            where id = $1`,
          [row.legacy_mcp_server_id]
        );
      }
      if (params.nextState === "DISABLED" && ["TRIAL", "ACTIVE"].includes(String(row.legacy_registration_state))) {
        await client.query(
          `update mcp_server
              set enabled = false,
                  registration_state = 'REGISTERED_DISABLED'::registration_state,
                  operational_state = 'DISABLED'::operational_state,
                  lock_version = lock_version + 1,
                  updated_at = now()
            where id = $1`,
          [row.legacy_mcp_server_id]
        );
      }
    }
    await client.query(
      `update component c
          set enabled=($2::text='ENABLED'),
              ingress_enabled=($2::text='ENABLED'),
              pulse_enabled=($2::text='ENABLED'),
              egress_enabled=($2::text='ENABLED'),
              activation_state=case when $2::text='ENABLED' then 'ACTIVE' else 'READY' end,
              lifecycle_state=case when $2::text='ENABLED' then 'ACTIVE' else 'APPROVED' end,
              operational_state=case when $2::text='ENABLED' then 'HEALTHY' else 'DISABLED' end,
              monitoring_state=case when $2::text='ENABLED' then 'HEALTHY' else 'PENDING' end,
              lock_version=c.lock_version+1
         from managed_service service
        where service.id=$1 and c.id=service.component_id`,
      [params.managedServiceId, params.nextState]
    );
    await client.query(
      `insert into managed_service_api_status(managed_service_id, api_state, disabled_reason, changed_by_type, changed_by_id, correlation_id, changed_at)
       values ($1,$2,$3,$4,$5,$6,now())
       on conflict (managed_service_id) do update
         set api_state = excluded.api_state,
             disabled_reason = excluded.disabled_reason,
             changed_by_type = excluded.changed_by_type,
             changed_by_id = excluded.changed_by_id,
             correlation_id = excluded.correlation_id,
             changed_at = excluded.changed_at`,
      [params.managedServiceId, params.nextState, params.nextState === "DISABLED" ? params.reason : null, params.actorType, params.actorId, params.correlationId]
    );
    await client.query(
      `insert into managed_service_api_status_history(
          managed_service_id, previous_state, current_state, reason, actor_type, actor_id, lock_version, correlation_id, decision_id
       ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [params.managedServiceId, previousState, params.nextState, params.reason, params.actorType, params.actorId, updated.rows[0].lock_version, params.correlationId, decisionId]
    );
    await client.query(
      `insert into managed_service_policy_event(managed_service_id, event_type, correlation_id, detail)
       values ($1,$2,$3,$4)`,
      [params.managedServiceId, `api_state.${params.nextState.toLowerCase()}`, params.correlationId, JSON.stringify({ reason: params.reason, decisionId })]
    );
    await appendAudit(client, {
      eventType: `managed_service.api.${params.nextState.toLowerCase()}`,
      actorType: params.actorType,
      actorId: params.actorId,
      objectType: "managed_service",
      objectId: params.managedServiceId,
      before: { apiState: previousState, lifecycleState: String(row.lifecycle_state), lockVersion: Number(row.lock_version) },
      after: { apiState: params.nextState, lifecycleState: nextLifecycleState, reason: params.reason, decisionId, lockVersion: Number(updated.rows[0].lock_version) },
      correlationId: params.correlationId
    });
    return { state: updated.rows[0].api_state, version: Number(updated.rows[0].lock_version), decisionId };
  });
}

export async function managedServiceStateView(db: Db, managedServiceId: string): Promise<Record<string, unknown>> {
  const result = await db.query(
    `select
        ms.*,
        revision.validation_state as active_revision_validation_state,
        status.changed_at as api_status_changed_at,
        status.changed_by_type,
        status.changed_by_id,
        status.correlation_id as api_status_correlation_id
      from managed_service ms
      left join managed_service_revision revision on revision.id = ms.active_revision_id
      left join managed_service_api_status status on status.managed_service_id = ms.id
     where ms.id = $1`,
    [managedServiceId]
  );
  if (!result.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
  const row = result.rows[0] as Record<string, unknown>;
  const service = mapManagedService(row);
  return {
    ...service,
    activeRevisionValidationState: optionalText(row.active_revision_validation_state),
    apiStatusChangedAt: asIso(row.api_status_changed_at),
    apiStatusChangedByType: optionalText(row.changed_by_type),
    apiStatusChangedById: optionalText(row.changed_by_id),
    apiStatusCorrelationId: optionalText(row.api_status_correlation_id)
  };
}

export async function managedServiceLogs(db: Db, params: {
  managedServiceId: string;
  limit: number;
  before?: string | null;
}): Promise<Array<Record<string, unknown>>> {
  const limit = Math.max(1, Math.min(200, params.limit));
  const result = await db.query(
    `select created_at, level, event_name, fields, correlation_id
       from managed_service_runtime_log_event
      where managed_service_id = $1
        and ($2::timestamptz is null or created_at < $2::timestamptz)
      order by created_at desc, id desc
      limit $3`,
    [params.managedServiceId, params.before ?? null, limit]
  );
  return result.rows.map((row) => ({
    createdAt: asIso(row.created_at),
    level: String(row.level),
    eventName: String(row.event_name),
    fields: row.fields as Record<string, unknown>,
    correlationId: String(row.correlation_id)
  }));
}

export async function bumpManagedServicePermissionEpoch(
  client: pg.PoolClient,
  managedServiceIds: string[],
  correlationId: string,
  detail: Record<string, unknown>
): Promise<void> {
  if (!managedServiceIds.length) return;
  await client.query(
    `update managed_service
        set permission_epoch = gen_random_uuid(),
            last_policy_invalidation_at = now(),
            updated_at = now()
      where id = any($1::uuid[])`,
    [managedServiceIds]
  );
  await client.query(
    `insert into managed_service_policy_event(managed_service_id, event_type, correlation_id, detail)
     select id, 'permission_epoch.bumped', $2, $3
       from managed_service
      where id = any($1::uuid[])`,
    [managedServiceIds, correlationId, JSON.stringify(detail)]
  );
}
