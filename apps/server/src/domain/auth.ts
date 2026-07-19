import type pg from "pg";
import type { Db } from "../db.js";
import { tx } from "../db.js";
import { hmacToken, issueOpaqueSecret, hashPasswordLikeSecret, verifyPasswordLikeSecret, fingerprintSecret } from "../security/secrets.js";
import { appendAudit } from "./audit.js";
import { resourceFor } from "./catalog.js";
import {
  assertManagedServiceRuntimeAvailable,
  authorizeManagedServiceToken,
  bumpManagedServicePermissionEpoch,
  currentManagedServiceScopes
} from "./managed-service.js";

function normalizeScopeNames(scopeNames: string[]): string[] {
  return [...new Set(scopeNames.map((scopeName) => scopeName.trim()).filter(Boolean))].sort();
}

function sameStringSet(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

export type KajaCredentialSummary = {
  id: string;
  publicId: string;
  label: string;
  fingerprint: string;
  active: boolean;
  revokedAt: string | null;
  deletedAt: string | null;
  createdAt: string;
  updatedAt: string;
  expiresAt: string | null;
  permissionCount: number;
  activeAccessTokenCount: number;
  lastTokenIssuedAt: string | null;
  lastTokenExpiresAt: string | null;
  lastUsedAt: string | null;
};

export type KajaPermissionSummary = {
  serverId: string;
  code: string;
  hostname: string;
  displayName: string;
  granted: boolean;
  accessLevel: "EXECUTE" | null;
  grantedAt: string | null;
};

export type KajaPermissionInput = {
  serverId: string;
  accessLevel: "EXECUTE";
};

export type ManagedServicePermissionSummary = {
  managedServiceId: string;
  code: string;
  displayName: string;
  serviceKind: string;
  scopes: string[];
};

export type ManagedServicePermissionInput = {
  managedServiceId: string;
  scopeNames: string[];
};

export async function createKajaCredential(
  db: Db,
  actorId: string,
  correlationId: string,
  label: string,
  expiresAt: string | null
): Promise<{ publicId: string; label: string; clientSecret: string; fingerprint: string; expiresAt: string | null }> {
  const secret = issueOpaqueSecret();
  const hash = await hashPasswordLikeSecret(secret.value);
  return tx(db, async (client) => {
    const result = await client.query("select nextval('kaja_number_seq') as number");
    const publicId = `Kaja${String(Number(result.rows[0].number)).padStart(4, "0")}`;
    const inserted = await client.query(
      "insert into kaja_credential(public_id, label, secret_hash, secret_fingerprint, expires_at) values ($1,$2,$3,$4,$5) returning id, expires_at",
      [publicId, label, hash, secret.fingerprint, expiresAt]
    );
    await appendAudit(client, {
      eventType: "kaja.created",
      actorType: "admin",
      actorId,
      objectType: "kaja_credential",
      objectId: inserted.rows[0].id,
      after: { publicId, label, fingerprint: secret.fingerprint, expiresAt },
      correlationId
    });
    return {
      publicId,
      label,
      clientSecret: secret.value,
      fingerprint: secret.fingerprint,
      expiresAt: inserted.rows[0].expires_at ? String(inserted.rows[0].expires_at) : null
    };
  });
}

export async function listKajaCredentials(db: Db): Promise<KajaCredentialSummary[]> {
  const result = await db.query(`
    select
      kc.id,
      kc.public_id,
      kc.label,
      kc.secret_fingerprint,
      kc.active,
      kc.revoked_at,
      kc.deleted_at,
      kc.created_at,
      kc.updated_at,
      kc.expires_at,
      count(distinct kp.id) filter (where kp.revoked_at is null) as permission_count,
      count(distinct at.lookup_digest) filter (where at.revoked_at is null and at.expires_at > now()) as active_access_token_count,
      max(at.issued_at) as last_token_issued_at,
      max(at.expires_at) as last_token_expires_at,
      max(at.last_used_at) as last_used_at
    from kaja_credential kc
    left join kaja_permission kp on kp.credential_id = kc.id
    left join managed_service_access_token at on at.credential_id = kc.id
    where kc.deleted_at is null
    group by kc.id
    order by kc.created_at desc
  `);
  return result.rows.map((row) => ({
    id: String(row.id),
    publicId: String(row.public_id),
    label: String(row.label),
    fingerprint: String(row.secret_fingerprint),
    active: Boolean(row.active),
    revokedAt: row.revoked_at ? String(row.revoked_at) : null,
    deletedAt: row.deleted_at ? String(row.deleted_at) : null,
    createdAt: String(row.created_at),
    updatedAt: String(row.updated_at),
    expiresAt: row.expires_at ? String(row.expires_at) : null,
    permissionCount: Number(row.permission_count),
    activeAccessTokenCount: Number(row.active_access_token_count),
    lastTokenIssuedAt: row.last_token_issued_at ? String(row.last_token_issued_at) : null,
    lastTokenExpiresAt: row.last_token_expires_at ? String(row.last_token_expires_at) : null,
    lastUsedAt: row.last_used_at ? String(row.last_used_at) : null
  }));
}

export async function revokeKajaCredential(db: Db, actorId: string, correlationId: string, credentialId: string): Promise<void> {
  await tx(db, async (client) => {
    const result = await updateCredentialLifecycle(client, credentialId, { deleted: false });
    await appendAudit(client, {
      eventType: "kaja.revoked",
      actorType: "admin",
      actorId,
      objectType: "kaja_credential",
      objectId: credentialId,
      after: { publicId: result.publicId, label: result.label },
      correlationId
    });
  });
}

export async function deleteKajaCredential(db: Db, actorId: string, correlationId: string, credentialId: string): Promise<void> {
  await tx(db, async (client) => {
    const result = await updateCredentialLifecycle(client, credentialId, { deleted: true });
    await appendAudit(client, {
      eventType: "kaja.deleted",
      actorType: "admin",
      actorId,
      objectType: "kaja_credential",
      objectId: credentialId,
      after: { publicId: result.publicId, label: result.label },
      correlationId
    });
  });
}

export async function listKajaPermissions(db: Db, credentialId: string): Promise<KajaPermissionSummary[]> {
  const credential = await db.query("select 1 from kaja_credential where id=$1 and deleted_at is null", [credentialId]);
  if (!credential.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
  const result = await db.query(`
    select
      ms.id as server_id,
      ms.code,
      ms.hostname,
      ms.display_name,
      kp.access_level,
      kp.granted_at,
      (kp.id is not null and kp.revoked_at is null) as granted
    from mcp_server ms
    left join kaja_permission kp on kp.server_id = ms.id and kp.credential_id = $1
    where ms.archived_at is null
    order by ms.kcml_number asc
  `, [credentialId]);
  return result.rows.map((row) => ({
    serverId: String(row.server_id),
    code: String(row.code),
    hostname: String(row.hostname),
    displayName: String(row.display_name),
    granted: Boolean(row.granted),
    accessLevel: row.access_level ? row.access_level as KajaPermissionSummary["accessLevel"] : null,
    grantedAt: row.granted_at ? String(row.granted_at) : null
  }));
}

export async function replaceKajaPermissions(db: Db, actorId: string, correlationId: string, credentialId: string, permissions: KajaPermissionInput[]): Promise<void> {
  await tx(db, async (client) => {
    const credential = await client.query(
      "select id, public_id from kaja_credential where id=$1 and deleted_at is null and revoked_at is null and active is true for update",
      [credentialId]
    );
    if (!credential.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    const previousResult = await client.query("select server_id,access_level from kaja_permission where credential_id=$1 and revoked_at is null", [credentialId]);
    const previous = new Map(previousResult.rows.map((row) => [String(row.server_id), String(row.access_level)]));
    const desired = new Map<string, KajaPermissionInput>();
    for (const permission of permissions) desired.set(permission.serverId, permission);
    const normalized = [...desired.values()].sort((left, right) => left.serverId.localeCompare(right.serverId));
    const serverIds = normalized.map((permission) => permission.serverId);
    if (serverIds.length) {
      const validServers = await client.query("select id from mcp_server where id = any($1::uuid[]) and archived_at is null", [serverIds]);
      if (validServers.rowCount !== serverIds.length) throw Object.assign(new Error("invalid_server"), { statusCode: 400 });
    }
    const touchedServerIds = [...new Set([...previous.keys(), ...serverIds])];
    const managedMappings = touchedServerIds.length
      ? await client.query(
        `select legacy_mcp_server_id, id
           from managed_service
          where legacy_mcp_server_id = any($1::uuid[])`,
        [touchedServerIds]
      )
      : { rowCount: 0, rows: [] };
    const managedByLegacy = new Map<string, string>();
    for (const row of managedMappings.rows) managedByLegacy.set(String(row.legacy_mcp_server_id), String(row.id));
    if (managedByLegacy.size !== touchedServerIds.length) {
      throw Object.assign(new Error("legacy_mapping_missing"), { statusCode: 409 });
    }
    await client.query("update kaja_permission set revoked_at=coalesce(revoked_at, now()) where credential_id=$1", [credentialId]);
    for (const permission of normalized) {
      await client.query(
        `insert into kaja_permission(credential_id, server_id, access_level, revoked_at)
         values ($1,$2,$3,null)
         on conflict (credential_id, server_id) do update set revoked_at=null, granted_at=now(), access_level=excluded.access_level`,
        [credentialId, permission.serverId, permission.accessLevel]
      );
    }
    for (const legacyServerId of touchedServerIds) {
      await client.query(
        `update managed_service_permission
            set revoked_at = coalesce(revoked_at, now()),
                state = 'REVOKED',
                valid_to = coalesce(valid_to, now()),
                permission_version = permission_version + 1
          where credential_id = $1
            and managed_service_id = $2
            and revoked_at is null`,
        [credentialId, managedByLegacy.get(legacyServerId)]
      );
    }
    for (const permission of normalized) {
      const managedServiceId = managedByLegacy.get(permission.serverId);
      await client.query(
        `insert into managed_service_permission(
            credential_id, managed_service_id, scope_id, granted_at, revoked_at, state, valid_from, valid_to, permission_version, audit_metadata
         )
         select $1, $2, scope.id, now(), null, 'GRANTED', now(), null, 0, $3::jsonb
           from managed_service_scope scope
          where scope.managed_service_id = $2
            and scope.scope_name = 'mcp.invoke'
            and scope.revoked_at is null
         on conflict (credential_id, managed_service_id, scope_id) do update
           set revoked_at = null,
               state = 'GRANTED',
               valid_from = now(),
               valid_to = null,
               permission_version = managed_service_permission.permission_version + 1,
               audit_metadata = excluded.audit_metadata,
               granted_at = now()`,
        [credentialId, managedServiceId, JSON.stringify({ actorId, correlationId, accessLevel: permission.accessLevel })]
      );
    }
    const added = normalized.filter((permission) => !previous.has(permission.serverId));
    const removed = [...previous.keys()].filter((serverId) => !desired.has(serverId));
    const unchanged = normalized.filter((permission) => previous.get(permission.serverId) === permission.accessLevel);
    if (touchedServerIds.length) {
      await bumpManagedServicePermissionEpoch(client, [...new Set(touchedServerIds.map((serverId) => managedByLegacy.get(serverId) ?? ""))].filter(Boolean), correlationId, {
        actorId,
        credentialId,
        source: "replaceKajaPermissions"
      });
    }
    await appendAudit(client, {
      eventType: "kaja.permissions.updated",
      actorType: "admin",
      actorId,
      objectType: "kaja_credential",
      objectId: credentialId,
      after: {
        publicId: credential.rows[0].public_id,
        diff: {
          added,
          unchanged,
          removed: removed.map((serverId) => ({ serverId, accessLevel: previous.get(serverId) })),
          changed: []
        }
      },
      correlationId
    });
  });
}

export async function listManagedServicePermissions(db: Db, credentialId: string): Promise<ManagedServicePermissionSummary[]> {
  const credential = await db.query("select 1 from kaja_credential where id=$1 and deleted_at is null", [credentialId]);
  if (!credential.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
  const result = await db.query(
    `select
        service.id as managed_service_id,
        service.code,
        service.display_name,
        service.service_kind,
        array_remove(array_agg(scope.scope_name order by scope.scope_name), null) as scopes
      from managed_service service
      left join managed_service_permission permission
        on permission.managed_service_id = service.id
       and permission.credential_id = $1
       and permission.revoked_at is null
       and permission.state = 'GRANTED'
      left join managed_service_scope scope on scope.id = permission.scope_id
      group by service.id
      order by service.created_at desc`,
    [credentialId]
  );
  return result.rows.map((row) => ({
    managedServiceId: String(row.managed_service_id),
    code: String(row.code),
    displayName: String(row.display_name),
    serviceKind: String(row.service_kind),
    scopes: (row.scopes as string[] | null) ?? []
  }));
}

export async function replaceManagedServicePermissions(
  db: Db,
  actorId: string,
  correlationId: string,
  credentialId: string,
  permissions: ManagedServicePermissionInput[]
): Promise<void> {
  await tx(db, async (client) => {
    const credential = await client.query(
      "select id, public_id from kaja_credential where id=$1 and deleted_at is null and revoked_at is null and active is true for update",
      [credentialId]
    );
    if (!credential.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    const previousResult = await client.query(
      `select permission.managed_service_id, array_agg(scope.scope_name order by scope.scope_name) as scope_names
         from managed_service_permission permission
         join managed_service_scope scope on scope.id = permission.scope_id
        where permission.credential_id = $1
          and permission.revoked_at is null
          and permission.state = 'GRANTED'
          and scope.revoked_at is null
        group by permission.managed_service_id`,
      [credentialId]
    );
    const previous = new Map<string, string[]>(
      previousResult.rows.map((row) => [String(row.managed_service_id), normalizeScopeNames((row.scope_names as string[] | null) ?? [])])
    );
    const normalized = new Map<string, string[]>();
    for (const permission of permissions) {
      const scopes = normalizeScopeNames(permission.scopeNames);
      const existing = normalized.get(permission.managedServiceId);
      if (existing && !sameStringSet(existing, scopes)) {
        throw Object.assign(new Error("duplicate_managed_service_permission"), { statusCode: 400 });
      }
      normalized.set(permission.managedServiceId, scopes);
    }
    const serviceIds = [...normalized.keys()].sort();
    if (serviceIds.length) {
      const valid = await client.query("select id from managed_service where id = any($1::uuid[])", [serviceIds]);
      if (valid.rowCount !== serviceIds.length) throw Object.assign(new Error("invalid_managed_service"), { statusCode: 400 });
    }
    const touchedServiceIds = [...new Set([...previous.keys(), ...serviceIds])].sort();
    const diff = {
      added: [] as Array<{ managedServiceId: string; scopeNames: string[] }>,
      changed: [] as Array<{ managedServiceId: string; before: string[]; after: string[] }>,
      unchanged: [] as Array<{ managedServiceId: string; scopeNames: string[] }>,
      removed: [] as Array<{ managedServiceId: string; scopeNames: string[] }>
    };
    for (const managedServiceId of touchedServiceIds) {
      const before = previous.get(managedServiceId) ?? [];
      const after = normalized.get(managedServiceId) ?? [];
      if (!before.length && after.length) diff.added.push({ managedServiceId, scopeNames: after });
      else if (before.length && !after.length) diff.removed.push({ managedServiceId, scopeNames: before });
      else if (sameStringSet(before, after)) diff.unchanged.push({ managedServiceId, scopeNames: after });
      else diff.changed.push({ managedServiceId, before, after });
    }
    for (const managedServiceId of touchedServiceIds) {
      const requestedScopes = normalized.get(managedServiceId) ?? [];
      const scopes = requestedScopes.length
        ? await client.query(
          `select id, scope_name
             from managed_service_scope
            where managed_service_id = $1
              and scope_name = any($2::text[])
              and revoked_at is null`,
          [managedServiceId, requestedScopes]
        )
        : { rowCount: 0, rows: [] };
      if (requestedScopes.length && scopes.rowCount !== requestedScopes.length) throw Object.assign(new Error("invalid_scope"), { statusCode: 400 });
      await client.query(
        `update managed_service_permission
            set revoked_at = coalesce(revoked_at, now()),
                state = 'REVOKED',
                valid_to = coalesce(valid_to, now()),
                permission_version = permission_version + 1
          where credential_id = $1
            and managed_service_id = $2
            and revoked_at is null`,
        [credentialId, managedServiceId]
      );
      for (const row of scopes.rows) {
        await client.query(
          `insert into managed_service_permission(
              credential_id, managed_service_id, scope_id, granted_at, revoked_at, state, valid_from, valid_to, permission_version, audit_metadata
           ) values ($1,$2,$3,now(),null,'GRANTED',now(),null,0,$4)
           on conflict (credential_id, managed_service_id, scope_id) do update
             set revoked_at = null,
                 state = 'GRANTED',
                 valid_from = now(),
                 valid_to = null,
                 permission_version = managed_service_permission.permission_version + 1,
                 audit_metadata = excluded.audit_metadata,
                 granted_at = now()`,
          [credentialId, managedServiceId, row.id, JSON.stringify({ actorId, correlationId, scopeName: row.scope_name })]
        );
      }
    }
    await bumpManagedServicePermissionEpoch(client, touchedServiceIds, correlationId, { actorId, credentialId, source: "replaceManagedServicePermissions" });
    await appendAudit(client, {
      eventType: "kaja.managed_service_permissions.updated",
      actorType: "admin",
      actorId,
      objectType: "kaja_credential",
      objectId: credentialId,
      after: { publicId: credential.rows[0].public_id, diff },
      correlationId
    });
  });
}

export async function renameKajaCredential(db: Db, actorId: string, correlationId: string, credentialId: string, label: string): Promise<void> {
  const normalizedLabel = label.trim();
  if (normalizedLabel.length < 1 || normalizedLabel.length > 120) {
    throw Object.assign(new Error("invalid_label"), { statusCode: 400 });
  }
  await tx(db, async (client) => {
    const current = await client.query(
      `select public_id,label,active,revoked_at,deleted_at
         from kaja_credential
        where id=$1
        for update`,
      [credentialId]
    );
    if (!current.rowCount || current.rows[0].deleted_at) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    if (!current.rows[0].active || current.rows[0].revoked_at) throw Object.assign(new Error("credential_immutable"), { statusCode: 409 });
    const result = await client.query(
      `update kaja_credential
          set label=$2,updated_at=now()
        where id=$1 and deleted_at is null and revoked_at is null and active is true
        returning public_id, label`,
      [credentialId, normalizedLabel]
    );
    if (!result.rowCount) throw Object.assign(new Error("credential_immutable"), { statusCode: 409 });
    await appendAudit(client, {
      eventType: "kaja.label.updated",
      actorType: "admin",
      actorId,
      objectType: "kaja_credential",
      objectId: credentialId,
      before: { publicId: current.rows[0].public_id, label: current.rows[0].label },
      after: { publicId: result.rows[0].public_id, label: result.rows[0].label },
      correlationId
    });
  });
}

export async function issueAccessToken(db: Db, params: {
  clientId: string;
  clientSecret: string;
  resource: string;
  hmacKey: Buffer;
  keyId: string;
  correlationId: string;
}): Promise<{ access_token: string; token_type: "Bearer"; expires_in: number; scope: string }> {
  return tx(db, async (client) => {
    const credentialResult = await client.query("select * from kaja_credential where public_id=$1 and deleted_at is null for update", [params.clientId]);
    if (!credentialResult.rowCount) throw Object.assign(new Error("invalid_client"), { statusCode: 401 });
    const credential = credentialResult.rows[0];
    if (!credential.active || credential.revoked_at || (credential.expires_at && new Date(String(credential.expires_at)).getTime() <= Date.now())) {
      throw Object.assign(new Error("invalid_client"), { statusCode: 401 });
    }
    const verified = await verifyPasswordLikeSecret(String(credential.secret_hash), params.clientSecret);
    if (!verified) throw Object.assign(new Error("invalid_client"), { statusCode: 401 });

    const serviceResult = await client.query(
      `select
          ms.id,
          ms.code,
          ms.service_kind,
          ms.legacy_mcp_server_id,
          ms.resource_uri,
          ms.public_hostname,
          ms.environment,
          ms.enabled,
          ms.active_revision_id,
          ms.service_token_epoch,
          ms.permission_epoch,
          ms.active_revision_epoch,
          revision.validation_state as active_revision_validation_state,
          ms.lifecycle_state,
          ms.api_state,
          ms.monitoring_enabled,
          ms.monitoring_profile_digest,
          ms.review_approved_at,
          ms.review_due_at,
          ms.review_interval_days
        from managed_service ms
        left join managed_service_revision revision on revision.id = ms.active_revision_id
       where ms.resource_uri = $1
       for update of ms`,
      [params.resource]
    );
    if (!serviceResult.rowCount) throw Object.assign(new Error("invalid_resource"), { statusCode: 400 });
    const service = serviceResult.rows[0];
    assertManagedServiceRuntimeAvailable({
      id: String(service.id),
      legacyMcpServerId: typeof service.legacy_mcp_server_id === "string" ? service.legacy_mcp_server_id : null,
      code: String(service.code),
      slug: String(service.code).toLowerCase(),
      displayName: String(service.code),
      description: String(service.code),
      serviceKind: String(service.service_kind) as "MCP" | "EXTERNAL_API",
      environment: String(service.environment),
      enabled: Boolean(service.enabled),
      publicHostname: typeof service.public_hostname === "string" ? service.public_hostname : null,
      resourceUri: typeof service.resource_uri === "string" ? service.resource_uri : null,
      lifecycleState: String(service.lifecycle_state),
      operationalState: "UNKNOWN",
      apiState: String(service.api_state) as "ENABLED" | "DISABLED",
      apiDisabledReason: null,
      activeRevisionId: typeof service.active_revision_id === "string" ? service.active_revision_id : null,
      activeRevisionEpoch: Number(service.active_revision_epoch),
      monitoringEnabled: Boolean(service.monitoring_enabled),
      monitoringProfileDigest: typeof service.monitoring_profile_digest === "string" ? service.monitoring_profile_digest : null,
      reviewApprovedAt: typeof service.review_approved_at === "string" ? service.review_approved_at : service.review_approved_at ? new Date(service.review_approved_at as Date).toISOString() : null,
      reviewDueAt: typeof service.review_due_at === "string" ? service.review_due_at : service.review_due_at ? new Date(service.review_due_at as Date).toISOString() : null,
      reviewIntervalDays: service.review_interval_days === null || service.review_interval_days === undefined ? null : Number(service.review_interval_days),
      lockVersion: 0,
      serviceTokenEpoch: String(service.service_token_epoch),
      permissionEpoch: String(service.permission_epoch),
      lastPolicyInvalidationAt: null
    }, typeof service.active_revision_validation_state === "string" ? service.active_revision_validation_state : null);

    const scopes = await currentManagedServiceScopes(client, String(credential.id), String(service.id));
    if (!scopes.length) throw Object.assign(new Error("insufficient_scope"), { statusCode: 403 });

    const token = issueOpaqueSecret();
    const ttlSeconds = 15 * 60;
    const digest = hmacToken(token.value, params.hmacKey);
    const managedInsert = await client.query(
      `insert into managed_service_access_token
       (lookup_digest, legacy_access_token_digest, key_id, fingerprint, credential_id, managed_service_id, audience, scope_names, expires_at,
         credential_revocation_epoch, service_revocation_epoch, environment, principal_token_epoch, service_token_epoch,
         permission_epoch_snapshot, active_revision_epoch_snapshot)
       select
         $1::bytea,
         case when ms.legacy_mcp_server_id is null then null else $1::bytea end,
         $2::text,
         $3::text,
         kc.id,
         ms.id,
         $4::text,
         $5::text[],
         now() + ($6 || ' seconds')::interval,
         kc.revocation_epoch,
         ms.service_token_epoch,
         ms.environment,
         kc.principal_token_epoch,
         ms.service_token_epoch,
         ms.permission_epoch,
         ms.active_revision_epoch
       from kaja_credential kc
       join managed_service ms on ms.id = $8::uuid
      where kc.id = $7::uuid
        and kc.active = true
        and kc.deleted_at is null
        and kc.revoked_at is null
        and (kc.expires_at is null or kc.expires_at > now())
        and kc.revocation_epoch = $9::uuid
        and kc.principal_token_epoch = $10::uuid
        and ms.service_token_epoch = $11::uuid
        and ms.permission_epoch = $12::uuid
        and ms.active_revision_epoch = $13::bigint
        and ms.environment = $14::text
        and ms.api_state = 'ENABLED'
        and ms.enabled = true
        and ms.active_revision_id is not null
        and exists (
          select 1
            from managed_service_permission permission
            join managed_service_scope scope on scope.id = permission.scope_id
           where permission.credential_id = kc.id
             and permission.managed_service_id = ms.id
             and permission.revoked_at is null
             and permission.state = 'GRANTED'
             and permission.valid_from <= now()
             and (permission.valid_to is null or permission.valid_to > now())
             and scope.revoked_at is null
             and scope.scope_name = any($5::text[])
         )`,
      [
        digest,
        params.keyId,
        token.fingerprint,
        params.resource,
        scopes,
        ttlSeconds,
        credential.id,
        service.id,
        credential.revocation_epoch,
        credential.principal_token_epoch,
        service.service_token_epoch,
        service.permission_epoch,
        service.active_revision_epoch,
        service.environment
      ]
    );
    if (!managedInsert.rowCount) throw Object.assign(new Error("stale_authorization_snapshot"), { statusCode: 409 });
    if (service.legacy_mcp_server_id) {
      await client.query(
        `insert into access_token
          (lookup_digest, key_id, fingerprint, credential_id, server_id, audience, expires_at, credential_revocation_epoch, server_revocation_epoch)
         values ($1,$2,$3,$4,$5,$6, now() + ($7 || ' seconds')::interval, $8, $9)`,
        [digest, params.keyId, token.fingerprint, credential.id, service.legacy_mcp_server_id, params.resource, ttlSeconds, credential.revocation_epoch, service.service_token_epoch]
      );
    }
    await appendAudit(client, {
      eventType: "access_token.issued",
      actorType: "kaja",
      actorId: credential.id,
      objectType: "managed_service",
      objectId: service.id,
      after: {
        resource: params.resource,
        fingerprint: token.fingerprint,
        expiresIn: ttlSeconds,
        scopes,
        snapshot: {
          credentialRevocationEpoch: credential.revocation_epoch,
          principalTokenEpoch: credential.principal_token_epoch,
          serviceTokenEpoch: service.service_token_epoch,
          permissionEpoch: service.permission_epoch,
          activeRevisionEpoch: Number(service.active_revision_epoch)
        }
      },
      correlationId: params.correlationId
    });
    return { access_token: token.value, token_type: "Bearer", expires_in: ttlSeconds, scope: scopes.join(" ") };
  });
}

export async function validateBearer(db: Db, token: string, hostname: string, hmacKey: Buffer): Promise<{ credentialId: string; serverId: string; code: string; toolName: string }> {
  const digest = hmacToken(token, hmacKey);
  const resource = resourceFor(hostname);
  const decision = await authorizeManagedServiceToken(db, {
      tokenDigest: digest,
      audience: resource,
      environment: "production",
      requiredScopes: ["mcp.invoke"],
      correlationId: fingerprintSecret(token),
      operationId: "mcp.invoke"
    });
  if (!decision.allow) {
    throw Object.assign(new Error("invalid_token"), {
      statusCode: 401,
      fingerprint: fingerprintSecret(token),
      reasonCode: decision.reasonCode
    });
  }
  const result = await db.query(
    `select legacy.id as server_id, legacy.code, legacy.tool_name
       from managed_service ms
       join mcp_server legacy on legacy.id = ms.legacy_mcp_server_id
      where ms.id = $1`,
    [decision.serviceId]
  );
  if (!result.rowCount) {
    throw Object.assign(new Error("invalid_token"), {
      statusCode: 401,
      fingerprint: fingerprintSecret(token),
      reasonCode: "legacy_mapping_missing"
    });
  }
  return {
    credentialId: decision.principalId ?? "",
    serverId: result.rows[0].server_id,
    code: result.rows[0].code,
    toolName: result.rows[0].tool_name
  };
}

async function updateCredentialLifecycle(
  client: pg.PoolClient,
  credentialId: string,
  options: { deleted: boolean }
): Promise<{ publicId: string; label: string }> {
  const result = await client.query(
    `update kaja_credential
        set active=false,
            revoked_at=coalesce(revoked_at, now()),
            deleted_at=case when $2 then coalesce(deleted_at, now()) else deleted_at end,
            revocation_epoch=gen_random_uuid()
      where id=$1 and deleted_at is null
      returning public_id, label`,
    [credentialId, options.deleted]
  );
  if (!result.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
  await client.query("update kaja_permission set revoked_at=coalesce(revoked_at, now()) where credential_id=$1", [credentialId]);
  await client.query("update managed_service_permission set revoked_at=coalesce(revoked_at, now()), state='REVOKED', valid_to=coalesce(valid_to, now()) where credential_id=$1", [credentialId]);
  await client.query("update access_token set revoked_at=coalesce(revoked_at, now()) where credential_id=$1", [credentialId]);
  await client.query("update managed_service_access_token set revoked_at=coalesce(revoked_at, now()) where credential_id=$1", [credentialId]);
  return {
    publicId: String(result.rows[0].public_id),
    label: String(result.rows[0].label)
  };
}
