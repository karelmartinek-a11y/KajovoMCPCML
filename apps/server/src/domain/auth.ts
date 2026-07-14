import type pg from "pg";
import type { Db } from "../db.js";
import { tx } from "../db.js";
import { hmacToken, issueOpaqueSecret, hashPasswordLikeSecret, verifyPasswordLikeSecret, fingerprintSecret } from "../security/secrets.js";
import { appendAudit } from "./audit.js";
import { resourceFor } from "./catalog.js";
import {
  authorizeManagedServiceToken,
  bumpManagedServicePermissionEpoch,
  currentManagedServiceScopes
} from "./managed-service.js";
import { evaluateRecertification } from "./recertification.js";

function timestamp(value: unknown): string | null {
  if (value instanceof Date) return value.toISOString();
  if (typeof value === "string" && value) return value;
  return null;
}

function scalarText(value: unknown): string | null {
  return typeof value === "string" || typeof value === "number" ? String(value) : null;
}

function assertRuntimeAvailable(row: Record<string, unknown>): void {
  const recertification = evaluateRecertification({
    activeRevisionId: scalarText(row.active_revision_id),
    validationState: scalarText(row.validation_state),
    approvedAt: timestamp(row.approved_at),
    reviewDueAt: timestamp(row.review_due_at),
    reviewIntervalDays: row.review_interval_days === null || row.review_interval_days === undefined
      ? null
      : Number(row.review_interval_days)
  });
  if (!row.enabled
    || !["ACTIVE", "TRIAL"].includes(String(row.registration_state))
    || !row.monitoring_enabled
    || !row.monitoring_profile_digest
    || !recertification.canServeExisting) {
    throw Object.assign(new Error("resource_unavailable"), { statusCode: 503 });
  }
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
  const result = await db.query("select nextval('kaja_number_seq') as number");
  const publicId = `Kaja${String(Number(result.rows[0].number)).padStart(4, "0")}`;
  const inserted = await db.query(
    "insert into kaja_credential(public_id, label, secret_hash, secret_fingerprint, expires_at) values ($1,$2,$3,$4,$5) returning id, expires_at",
    [publicId, label, hash, secret.fingerprint, expiresAt]
  );
  await appendAudit(db, {
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
    left join access_token at on at.credential_id = kc.id
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
    const previousResult = await client.query(
      "select server_id,access_level from kaja_permission where credential_id=$1 and revoked_at is null",
      [credentialId]
    );
    const previousExecutable = new Set(previousResult.rows.map((row) => String(row.server_id)));
    const byServer = new Map<string, KajaPermissionInput>();
    for (const permission of permissions) byServer.set(permission.serverId, permission);
    const normalized = Array.from(byServer.values());
    const serverIds = normalized.map((permission) => permission.serverId);
    if (serverIds.length) {
      const validServers = await client.query("select id from mcp_server where id = any($1::uuid[])", [serverIds]);
      if (validServers.rowCount !== serverIds.length) throw Object.assign(new Error("invalid_server"), { statusCode: 400 });
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
    const currentExecutable = new Set(normalized.map((permission) => permission.serverId));
    const removedExecutable = [...previousExecutable].filter((serverId) => !currentExecutable.has(serverId));
    const changedServerIds = new Set<string>([...removedExecutable, ...normalized.map((permission) => permission.serverId)]);
    if (changedServerIds.size) {
      const managedMappings = await client.query(
        `select legacy_mcp_server_id, id
           from managed_service
          where legacy_mcp_server_id = any($1::uuid[])`,
        [[...changedServerIds]]
      );
      const managedByLegacy = new Map<string, string>();
      for (const row of managedMappings.rows) {
        managedByLegacy.set(String(row.legacy_mcp_server_id), String(row.id));
      }
      for (const legacyServerId of changedServerIds) {
        const managedServiceId = managedByLegacy.get(legacyServerId);
        if (!managedServiceId) continue;
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
      }
      for (const permission of normalized) {
        const managedServiceId = managedByLegacy.get(permission.serverId);
        if (!managedServiceId) continue;
        await client.query(
          `insert into managed_service_permission(
              credential_id, managed_service_id, scope_id, granted_at, revoked_at, state, valid_from, valid_to, permission_version, audit_metadata
           )
           select $1, $2, scope.id, now(), null, 'GRANTED', now(), null, 0, $4
             from managed_service_scope scope
            where scope.managed_service_id = $2
              and scope.scope_name = 'mcp.invoke'
           on conflict (credential_id, managed_service_id, scope_id) do update
             set revoked_at = null,
                 state = 'GRANTED',
                 valid_from = now(),
                 valid_to = null,
                 permission_version = managed_service_permission.permission_version + 1,
                 audit_metadata = excluded.audit_metadata,
                 granted_at = now()`,
          [credentialId, managedServiceId, permission.accessLevel, JSON.stringify({ actorId, correlationId, accessLevel: permission.accessLevel })]
        );
      }
      await bumpManagedServicePermissionEpoch(client, [...managedByLegacy.values()], correlationId, { actorId, credentialId });
    }
    for (const serverId of removedExecutable) {
      await appendAudit(client, {
        eventType: "permission.revoked",
        actorType: "admin",
        actorId,
        objectType: "mcp_server",
        objectId: serverId,
        after: { credentialId },
        correlationId
      });
    }
    for (const permission of normalized) {
      if (!previousExecutable.has(permission.serverId) && currentExecutable.has(permission.serverId)) {
        await appendAudit(client, {
          eventType: "permission.granted",
          actorType: "admin",
          actorId,
          objectType: "mcp_server",
          objectId: permission.serverId,
          after: { credentialId, accessLevel: permission.accessLevel },
          correlationId
        });
      }
    }
    await appendAudit(client, {
      eventType: "kaja.permissions.updated",
      actorType: "admin",
      actorId,
      objectType: "kaja_credential",
      objectId: credentialId,
      after: { publicId: credential.rows[0].public_id, permissions: normalized },
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
    const normalized = new Map<string, string[]>();
    for (const permission of permissions) normalized.set(permission.managedServiceId, [...new Set(permission.scopeNames)].sort());
    const serviceIds = [...normalized.keys()];
    if (serviceIds.length) {
      const valid = await client.query("select id from managed_service where id = any($1::uuid[])", [serviceIds]);
      if (valid.rowCount !== serviceIds.length) throw Object.assign(new Error("invalid_managed_service"), { statusCode: 400 });
    }
    for (const managedServiceId of serviceIds) {
      const requestedScopes = normalized.get(managedServiceId) ?? [];
      const scopes = await client.query(
        `select id, scope_name
           from managed_service_scope
          where managed_service_id = $1
            and scope_name = any($2::text[])
            and revoked_at is null`,
        [managedServiceId, requestedScopes]
      );
      if (scopes.rowCount !== requestedScopes.length) throw Object.assign(new Error("invalid_scope"), { statusCode: 400 });
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
      await appendAudit(client, {
        eventType: "managed_service.permissions.updated",
        actorType: "admin",
        actorId,
        objectType: "managed_service",
        objectId: managedServiceId,
        after: { credentialId, scopeNames: requestedScopes },
        correlationId
      });
    }
    await bumpManagedServicePermissionEpoch(client, serviceIds, correlationId, { actorId, credentialId });
    await appendAudit(client, {
      eventType: "kaja.managed_service_permissions.updated",
      actorType: "admin",
      actorId,
      objectType: "kaja_credential",
      objectId: credentialId,
      after: { publicId: credential.rows[0].public_id, permissions: [...normalized.entries()].map(([managedServiceId, scopeNames]) => ({ managedServiceId, scopeNames })) },
      correlationId
    });
  });
}

export async function renameKajaCredential(db: Db, actorId: string, correlationId: string, credentialId: string, label: string): Promise<void> {
  await tx(db, async (client) => {
    const result = await client.query(
      `update kaja_credential
          set label=$2
        where id=$1 and deleted_at is null
        returning public_id, label`,
      [credentialId, label]
    );
    if (!result.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    await appendAudit(client, {
      eventType: "kaja.label.updated",
      actorType: "admin",
      actorId,
      objectType: "kaja_credential",
      objectId: credentialId,
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
  const credentialResult = await db.query("select * from kaja_credential where public_id=$1 and deleted_at is null", [params.clientId]);
  if (!credentialResult.rowCount) throw Object.assign(new Error("invalid_client"), { statusCode: 401 });
  const credential = credentialResult.rows[0];
  if (!credential.active || credential.revoked_at || (credential.expires_at && new Date(String(credential.expires_at)).getTime() <= Date.now())) {
    throw Object.assign(new Error("invalid_client"), { statusCode: 401 });
  }
  const verified = await verifyPasswordLikeSecret(String(credential.secret_hash), params.clientSecret);
  if (!verified) throw Object.assign(new Error("invalid_client"), { statusCode: 401 });

  const serviceResult = await db.query(
    `select
        ms.id, ms.code, ms.service_kind, ms.legacy_mcp_server_id, ms.resource_uri, ms.environment, ms.service_token_epoch, ms.permission_epoch, ms.active_revision_epoch,
        revision.validation_state as active_revision_validation_state,
        ms.lifecycle_state as registration_state, ms.api_state, ms.monitoring_enabled, ms.monitoring_profile_digest,
        ms.review_approved_at as approved_at, ms.review_due_at, ms.review_interval_days
      from managed_service ms
      left join managed_service_revision revision on revision.id = ms.active_revision_id
     where ms.resource_uri = $1`,
    [params.resource]
  );
  if (!serviceResult.rowCount) throw Object.assign(new Error("invalid_resource"), { statusCode: 400 });
  const service = serviceResult.rows[0];
  if (service.service_kind === "MCP") {
    assertRuntimeAvailable({
      enabled: service.api_state === "ENABLED",
      registration_state: service.registration_state,
      monitoring_enabled: service.monitoring_enabled,
      monitoring_profile_digest: service.monitoring_profile_digest,
      active_revision_id: true,
      validation_state: service.active_revision_validation_state,
      approved_at: service.approved_at,
      review_due_at: service.review_due_at,
      review_interval_days: service.review_interval_days
    });
  }
  const scopes = await currentManagedServiceScopes(db, String(credential.id), String(service.id));
  if (!scopes.length) throw Object.assign(new Error("insufficient_scope"), { statusCode: 403 });

  const token = issueOpaqueSecret();
  const ttlSeconds = 15 * 60;
  const digest = hmacToken(token.value, params.hmacKey);
  await db.query(
    `insert into managed_service_access_token
      (lookup_digest, key_id, fingerprint, credential_id, managed_service_id, audience, scope_names, expires_at,
       credential_revocation_epoch, service_revocation_epoch, environment, principal_token_epoch, service_token_epoch,
       permission_epoch_snapshot, active_revision_epoch_snapshot)
     values ($1,$2,$3,$4,$5,$6,$7, now() + ($8 || ' seconds')::interval, $9, $10, $11, $12, $13, $14, $15)`,
    [
      digest,
      params.keyId,
      token.fingerprint,
      credential.id,
      service.id,
      params.resource,
      scopes,
      ttlSeconds,
      credential.revocation_epoch,
      service.service_token_epoch,
      service.environment,
      credential.principal_token_epoch,
      service.service_token_epoch,
      service.permission_epoch,
      service.active_revision_epoch
    ]
  );
  if (service.legacy_mcp_server_id) {
    await db.query(
      `insert into access_token
        (lookup_digest, key_id, fingerprint, credential_id, server_id, audience, expires_at, credential_revocation_epoch, server_revocation_epoch)
       values ($1,$2,$3,$4,$5,$6, now() + ($7 || ' seconds')::interval, $8, $9)`,
      [digest, params.keyId, token.fingerprint, credential.id, service.legacy_mcp_server_id, params.resource, ttlSeconds, credential.revocation_epoch, service.service_token_epoch]
    );
  }
  await appendAudit(db, {
    eventType: "access_token.issued",
    actorType: "kaja",
    actorId: credential.id,
    objectType: "managed_service",
    objectId: service.id,
    after: { resource: params.resource, fingerprint: token.fingerprint, expiresIn: ttlSeconds, scopes },
    correlationId: params.correlationId
  });
  return { access_token: token.value, token_type: "Bearer", expires_in: ttlSeconds, scope: scopes.join(" ") };
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
    throw Object.assign(new Error("invalid_token"), { statusCode: 401, fingerprint: fingerprintSecret(token) });
  }
  const result = await db.query(
    `select legacy.id as server_id, legacy.code, legacy.tool_name
       from managed_service ms
       join mcp_server legacy on legacy.id = ms.legacy_mcp_server_id
      where ms.id = $1`,
    [decision.serviceId]
  );
  if (!result.rowCount) throw Object.assign(new Error("invalid_token"), { statusCode: 401, fingerprint: fingerprintSecret(token) });
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
