import { createHash, randomUUID } from "node:crypto";
import argon2 from "argon2";
import { authenticator } from "otplib";
import type pg from "pg";
import type { Db } from "../db.js";
import { tx } from "../db.js";
import {
  decryptManagedSecret,
  encryptManagedSecret,
  fingerprintSecret,
  hmacToken,
  decryptMfaSecret,
  verifyPasswordLikeSecret
} from "../security/secrets.js";
import { appendAudit } from "./audit.js";

export const SECRET_MANAGER_CATALOG_VERSION = "2026.07.22";
const NAME_PATTERN = /^[A-Z][A-Z0-9_]{2,127}$/;
const REVEAL_GRANT_MS = 15_000;

export type SecretSummary = {
  id: string;
  stableName: string;
  displayName: string;
  description: string;
  ownerKind: string;
  ownerId: string | null;
  status: string;
  activeVersionId: string | null;
  activeVersionNumber: number | null;
  activeFingerprint: string | null;
  grantCount: number;
  lockVersion: number;
  createdAt: string;
  updatedAt: string;
  deletedAt: string | null;
};

export type SecretGrantSummary = {
  id: string;
  principalKind: "KAJA" | "COMPONENT" | "INTEGRATION_TOKEN";
  principalId: string | null;
  principalPublicId: string | null;
  allSecrets: boolean;
  grantedAt: string;
  revokedAt: string | null;
};

export type SecretVersionSummary = {
  id: string;
  versionNumber: number;
  fingerprint: string;
  keyId: string;
  algorithm: string;
  createdAt: string;
  activatedAt: string | null;
  retiredAt: string | null;
  active: boolean;
};

export type SecretPrincipal = {
  kind: "KAJA" | "COMPONENT" | "INTEGRATION_TOKEN";
  id: string | null;
  publicId: string;
  auditActorType: "kaja" | "component" | "integration_token";
  tokenKind?: string;
};

type SecretManagerConfig = {
  CONFIG_VAULT_MASTER_KEY_BASE64: Buffer;
  CONFIG_VAULT_MASTER_KEY_ID: string;
  ACCESS_TOKEN_HMAC_KEY_BASE64: Buffer;
  INTEGRATION_TOKEN_HMAC_KEY_BASE64: Buffer;
  INTEGRATION_TOKEN_HMAC_KEY_ID: string;
  MFA_ENCRYPTION_KEY_BASE64?: Buffer;
  MFA_ALLOW_PLAINTEXT_LEGACY?: boolean;
};

function normalizeName(value: string): string {
  const name = value.trim().toUpperCase();
  if (!NAME_PATTERN.test(name)) throw Object.assign(new Error("invalid_secret_name"), { statusCode: 400 });
  return name;
}

function assertMasterKey(config: SecretManagerConfig): void {
  if (config.CONFIG_VAULT_MASTER_KEY_BASE64.length !== 32) {
    throw Object.assign(new Error("secret_manager_key_unavailable"), { statusCode: 503 });
  }
}

function normalizeText(value: string, code: string, max = 2000): string {
  const text = value.trim();
  if (!text || text.length > max) throw Object.assign(new Error(code), { statusCode: 400 });
  return text;
}

export function normalizeSecretPrincipalPublicId(value?: string | null): string | null {
  const publicId = value?.trim() || null;
  if (!publicId) return null;
  if (publicId.startsWith("kci_")) {
    throw Object.assign(new Error("secret_principal_public_id_must_not_be_token"), { statusCode: 400 });
  }
  return publicId;
}

function revealPurposeAudit(purpose: string): { purposeDigest: string; purposeLength: number } {
  return {
    purposeDigest: secretRequestDigest({ purpose }),
    purposeLength: purpose.length
  };
}

function activeSecretSelect(): string {
  return `
    select s.*, v.id as version_id, v.version_number, v.ciphertext, v.key_id, v.fingerprint
      from secret_record s
      join secret_version v on v.id=s.active_version_id
     where s.stable_name=$1 and s.status='ACTIVE' and s.deleted_at is null
  `;
}

function text(value: unknown): string {
  return typeof value === "string" || typeof value === "number" || typeof value === "boolean" ? String(value) : "";
}

function optionalText(value: unknown): string | null {
  const resolved = text(value);
  return resolved || null;
}

function mapSummary(row: Record<string, unknown>): SecretSummary {
  return {
    id: String(row.id),
    stableName: String(row.stable_name),
    displayName: String(row.display_name),
    description: text(row.description),
    ownerKind: String(row.owner_kind),
    ownerId: optionalText(row.owner_id),
    status: String(row.status),
    activeVersionId: optionalText(row.active_version_id),
    activeVersionNumber: row.active_version_number === null || row.active_version_number === undefined ? null : Number(row.active_version_number),
    activeFingerprint: optionalText(row.active_fingerprint),
    grantCount: Number(row.grant_count ?? 0),
    lockVersion: Number(row.lock_version ?? 0),
    createdAt: String(row.created_at),
    updatedAt: String(row.updated_at),
    deletedAt: optionalText(row.deleted_at)
  };
}

export async function listSecrets(db: Db): Promise<SecretSummary[]> {
  const result = await db.query(`
    select s.*,
           v.version_number as active_version_number,
           v.fingerprint as active_fingerprint,
           count(g.id) filter (where g.revoked_at is null) as grant_count
      from secret_record s
      left join secret_version v on v.id=s.active_version_id
      left join secret_grant g on g.secret_id=s.id
     group by s.id, v.version_number, v.fingerprint
     order by s.updated_at desc
  `);
  return result.rows.map((row) => mapSummary(row));
}

export async function listSecretGrants(db: Db, secretId: string): Promise<SecretGrantSummary[]> {
  const result = await db.query(
    `select * from secret_grant where secret_id=$1 order by granted_at desc`,
    [secretId]
  );
  return result.rows.map((row) => ({
    id: String(row.id),
    principalKind: String(row.principal_kind) as SecretGrantSummary["principalKind"],
    principalId: row.principal_id ? String(row.principal_id) : null,
    principalPublicId: row.principal_public_id ? String(row.principal_public_id) : null,
    allSecrets: Boolean(row.all_secrets),
    grantedAt: String(row.granted_at),
    revokedAt: row.revoked_at ? String(row.revoked_at) : null
  }));
}

export async function listSecretVersions(db: Db, secretId: string): Promise<SecretVersionSummary[]> {
  const result = await db.query(
    `select v.id,v.version_number,v.fingerprint,v.key_id,v.algorithm,v.created_at,v.activated_at,v.retired_at,
            (s.active_version_id=v.id) as active
       from secret_version v
       join secret_record s on s.id=v.secret_id
      where v.secret_id=$1
      order by v.version_number desc`,
    [secretId]
  );
  return result.rows.map((row) => ({
    id: String(row.id),
    versionNumber: Number(row.version_number),
    fingerprint: String(row.fingerprint),
    keyId: String(row.key_id),
    algorithm: String(row.algorithm),
    createdAt: String(row.created_at),
    activatedAt: row.activated_at ? String(row.activated_at) : null,
    retiredAt: row.retired_at ? String(row.retired_at) : null,
    active: Boolean(row.active)
  }));
}

async function insertSecretVersion(client: pg.PoolClient, config: SecretManagerConfig, params: {
  secretId: string;
  stableName: string;
  ownerKind: string;
  ownerId: string | null;
  value: string;
  actorId: string;
  versionNumber: number;
}): Promise<{ id: string; fingerprint: string; versionNumber: number }> {
  const versionId = randomUUID();
  const ciphertext = encryptManagedSecret(params.value, config.CONFIG_VAULT_MASTER_KEY_BASE64, {
    keyId: config.CONFIG_VAULT_MASTER_KEY_ID,
    secretId: params.secretId,
    stableName: params.stableName,
    versionId,
    versionNumber: params.versionNumber,
    ownerKind: params.ownerKind,
    ownerId: params.ownerId
  });
  const fingerprint = fingerprintSecret(params.value);
  await client.query(
    `insert into secret_version(id, secret_id, version_number, ciphertext, key_id, fingerprint, created_by, activated_at)
     values ($1,$2,$3,$4,$5,$6,$7,now())`,
    [versionId, params.secretId, params.versionNumber, ciphertext, config.CONFIG_VAULT_MASTER_KEY_ID, fingerprint, params.actorId]
  );
  return { id: versionId, fingerprint, versionNumber: params.versionNumber };
}

export async function createSecret(db: Db, config: SecretManagerConfig, actorId: string, correlationId: string, input: {
  stableName: string;
  displayName: string;
  description?: string;
  value: string;
  ownerKind?: string;
  ownerId?: string | null;
}): Promise<SecretSummary> {
  assertMasterKey(config);
  const stableName = normalizeName(input.stableName);
  const displayName = normalizeText(input.displayName, "invalid_secret_display_name", 160);
  const value = normalizeText(input.value, "invalid_secret_value", 64 * 1024);
  const ownerKind = input.ownerKind ?? "PLATFORM";
  if (!["PLATFORM", "COMPONENT", "MANAGED_SERVICE", "KAJA"].includes(ownerKind)) throw Object.assign(new Error("invalid_secret_owner"), { statusCode: 400 });
  return tx(db, async (client) => {
    const inserted = await client.query(
      `insert into secret_record(stable_name, display_name, description, owner_kind, owner_id, created_by, updated_by)
       values ($1,$2,$3,$4,$5,$6,$6)
       returning *`,
      [stableName, displayName, input.description?.trim() ?? "", ownerKind, input.ownerId ?? null, actorId]
    );
    const secret = inserted.rows[0];
    const version = await insertSecretVersion(client, config, {
      secretId: String(secret.id),
      stableName,
      ownerKind,
      ownerId: input.ownerId ?? null,
      value,
      actorId,
      versionNumber: 1
    });
    const updated = await client.query(
      `update secret_record set active_version_id=$2, lock_version=lock_version+1, updated_at=now()
        where id=$1 returning *,
          $3::int as active_version_number,
          $4::text as active_fingerprint,
          0::int as grant_count`,
      [secret.id, version.id, version.versionNumber, version.fingerprint]
    );
    await appendAudit(client, {
      eventType: "secret.created",
      actorType: "admin",
      actorId,
      objectType: "secret",
      objectId: String(secret.id),
      after: { stableName, displayName, fingerprint: version.fingerprint, catalogVersion: SECRET_MANAGER_CATALOG_VERSION },
      correlationId
    });
    return mapSummary(updated.rows[0]);
  });
}

export async function rotateSecret(db: Db, config: SecretManagerConfig, actorId: string, correlationId: string, secretId: string, input: {
  value: string;
  expectedVersion: number;
}): Promise<SecretSummary> {
  assertMasterKey(config);
  const value = normalizeText(input.value, "invalid_secret_value", 64 * 1024);
  return tx(db, async (client) => {
    const current = await client.query("select * from secret_record where id=$1 and deleted_at is null for update", [secretId]);
    if (!current.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    if (Number(current.rows[0].lock_version) !== input.expectedVersion) throw Object.assign(new Error("secret_version_conflict"), { statusCode: 409 });
    const latest = await client.query("select coalesce(max(version_number),0)::int as max from secret_version where secret_id=$1", [secretId]);
    const nextNumber = Number(latest.rows[0].max) + 1;
    const version = await insertSecretVersion(client, config, {
      secretId,
      stableName: String(current.rows[0].stable_name),
      ownerKind: String(current.rows[0].owner_kind),
      ownerId: current.rows[0].owner_id ? String(current.rows[0].owner_id) : null,
      value,
      actorId,
      versionNumber: nextNumber
    });
    await client.query("update secret_version set retired_at=now() where secret_id=$1 and id<>$2 and retired_at is null", [secretId, version.id]);
    const updated = await client.query(
      `update secret_record set active_version_id=$2, lock_version=lock_version+1, updated_by=$3, updated_at=now()
        where id=$1 returning *,
          $4::int as active_version_number,
          $5::text as active_fingerprint,
          (select count(*) from secret_grant where secret_id=$1 and revoked_at is null)::int as grant_count`,
      [secretId, version.id, actorId, version.versionNumber, version.fingerprint]
    );
    await appendAudit(client, {
      eventType: "secret.rotated",
      actorType: "admin",
      actorId,
      objectType: "secret",
      objectId: secretId,
      after: { stableName: current.rows[0].stable_name, fingerprint: version.fingerprint, versionNumber: version.versionNumber },
      correlationId
    });
    return mapSummary(updated.rows[0]);
  });
}

export async function deleteSecret(db: Db, actorId: string, correlationId: string, secretId: string, expectedVersion: number): Promise<void> {
  await tx(db, async (client) => {
    const updated = await client.query(
      `update secret_record
          set status='DELETED', deleted_at=now(), updated_by=$3, updated_at=now(), lock_version=lock_version+1
        where id=$1 and deleted_at is null and lock_version=$2
        returning stable_name`,
      [secretId, expectedVersion, actorId]
    );
    if (!updated.rowCount) throw Object.assign(new Error("secret_version_conflict"), { statusCode: 409 });
    await client.query("update secret_grant set revoked_at=coalesce(revoked_at, now()), revoked_by=$2 where secret_id=$1", [secretId, actorId]);
    await appendAudit(client, {
      eventType: "secret.deleted",
      actorType: "admin",
      actorId,
      objectType: "secret",
      objectId: secretId,
      after: { stableName: updated.rows[0].stable_name },
      correlationId
    });
  });
}

export async function setSecretStatus(db: Db, actorId: string, correlationId: string, secretId: string, expectedVersion: number, status: "ACTIVE" | "DISABLED"): Promise<SecretSummary> {
  await tx(db, async (client) => {
    const updated = await client.query(
      `update secret_record
          set status=$3, updated_by=$4, updated_at=now(), lock_version=lock_version+1
        where id=$1 and deleted_at is null and lock_version=$2
        returning stable_name,status`,
      [secretId, expectedVersion, status, actorId]
    );
    if (!updated.rowCount) throw Object.assign(new Error("secret_version_conflict"), { statusCode: 409 });
    await appendAudit(client, {
      eventType: status === "ACTIVE" ? "secret.activated" : "secret.deactivated",
      actorType: "admin",
      actorId,
      objectType: "secret",
      objectId: secretId,
      after: { stableName: updated.rows[0].stable_name, status },
      correlationId
    });
  });
  const listed = await listSecrets(db);
  const secret = listed.find((item) => item.id === secretId);
  if (!secret) throw Object.assign(new Error("not_found"), { statusCode: 404 });
  return secret;
}

export async function restoreSecret(db: Db, actorId: string, correlationId: string, secretId: string, expectedVersion: number): Promise<SecretSummary> {
  await tx(db, async (client) => {
    const updated = await client.query(
      `update secret_record
          set status='DISABLED', deleted_at=null, updated_by=$3, updated_at=now(), lock_version=lock_version+1
        where id=$1 and status='DELETED' and lock_version=$2
        returning stable_name`,
      [secretId, expectedVersion, actorId]
    );
    if (!updated.rowCount) throw Object.assign(new Error("secret_version_conflict"), { statusCode: 409 });
    await appendAudit(client, {
      eventType: "secret.restored",
      actorType: "admin",
      actorId,
      objectType: "secret",
      objectId: secretId,
      after: { stableName: updated.rows[0].stable_name, status: "DISABLED", grantsRestored: false },
      correlationId
    });
  });
  const listed = await listSecrets(db);
  const secret = listed.find((item) => item.id === secretId);
  if (!secret) throw Object.assign(new Error("not_found"), { statusCode: 404 });
  return secret;
}

export async function grantSecret(db: Db, actorId: string, correlationId: string, secretId: string, input: {
  principalKind: "KAJA" | "COMPONENT" | "INTEGRATION_TOKEN";
  principalId?: string | null;
  principalPublicId?: string | null;
  allSecrets?: boolean;
}): Promise<SecretGrantSummary[]> {
  await tx(db, async (client) => {
    const secret = await client.query("select stable_name from secret_record where id=$1 and deleted_at is null for update", [secretId]);
    if (!secret.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    if (!["KAJA", "COMPONENT", "INTEGRATION_TOKEN"].includes(input.principalKind)) throw Object.assign(new Error("invalid_secret_principal"), { statusCode: 400 });
    const principalPublicId = normalizeSecretPrincipalPublicId(input.principalPublicId);
    if (!input.principalId && !principalPublicId) throw Object.assign(new Error("invalid_secret_principal"), { statusCode: 400 });
    const allSecrets = input.allSecrets === true;
    const existing = await client.query(
      `select id from secret_grant
        where secret_id=$1 and principal_kind=$2 and revoked_at is null and all_secrets=$5
          and coalesce(principal_id::text, '')=coalesce($3::uuid::text, '')
          and coalesce(principal_public_id::text, '')=coalesce($4::text, '')
        for update`,
      [secretId, input.principalKind, input.principalId ?? null, principalPublicId, allSecrets]
    );
    if (!existing.rowCount) {
      await client.query(
        `insert into secret_grant(secret_id, principal_kind, principal_id, principal_public_id, granted_by, all_secrets)
         values ($1,$2,$3,$4,$5,$6)`,
        [secretId, input.principalKind, input.principalId ?? null, principalPublicId, actorId, allSecrets]
      );
    }
    await appendAudit(client, {
      eventType: "secret.grant.created",
      actorType: "admin",
      actorId,
      objectType: "secret",
      objectId: secretId,
      after: { stableName: secret.rows[0].stable_name, principalKind: input.principalKind, principalId: input.principalId ?? null, principalPublicId, allSecrets },
      correlationId
    });
  });
  return listSecretGrants(db, secretId);
}

export async function revokeSecretGrant(db: Db, actorId: string, correlationId: string, grantId: string): Promise<void> {
  await tx(db, async (client) => {
    const updated = await client.query(
      "update secret_grant set revoked_at=coalesce(revoked_at,now()), revoked_by=$2 where id=$1 returning secret_id, principal_kind, principal_id, principal_public_id",
      [grantId, actorId]
    );
    if (!updated.rowCount) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    await appendAudit(client, {
      eventType: "secret.grant.revoked",
      actorType: "admin",
      actorId,
      objectType: "secret",
      objectId: String(updated.rows[0].secret_id),
      after: {
        grantId,
        principalKind: updated.rows[0].principal_kind,
        principalId: updated.rows[0].principal_id,
        principalPublicId: updated.rows[0].principal_public_id
      },
      correlationId
    });
  });
}

export async function authenticateClientSecret(db: Db, config: SecretManagerConfig, clientId: string, clientSecret: string): Promise<SecretPrincipal | null> {
  if (!clientId || !clientSecret) return null;
  if (/^KCML[0-9]{4,}-C[0-9]{2,}$/i.test(clientId)) {
    const digest = hmacToken(clientSecret, config.ACCESS_TOKEN_HMAC_KEY_BASE64);
    const result = await db.query(
      `select credential.id, credential.component_id, credential.public_id,
              component.enabled, component.activation_state, component.lifecycle_state, component.operational_state,
              component.egress_enabled, component.deregistered_at
         from component_credential credential
         join component on component.id=credential.component_id
        where credential.public_id=$1
          and credential.secret_digest=$2
          and credential.status='ACTIVE'
          and credential.revoked_at is null
          and (credential.expires_at is null or credential.expires_at > now())
          and component.enabled is true
          and component.egress_enabled is true
          and component.activation_state='ACTIVE'
          and component.lifecycle_state='ACTIVE'
          and component.operational_state not in ('QUARANTINED','RETIRED')
          and component.deregistered_at is null`,
      [clientId, digest]
    );
    if (!result.rowCount) return null;
    await db.query("update component_credential set last_used_at=now() where id=$1", [result.rows[0].id]);
    return { kind: "COMPONENT", id: String(result.rows[0].component_id), publicId: String(result.rows[0].public_id), auditActorType: "component" };
  }
  const result = await db.query(
    `select id, public_id, secret_hash
       from kaja_credential
      where public_id=$1
        and active=true
        and revoked_at is null
        and deleted_at is null
        and (expires_at is null or expires_at > now())`,
    [clientId]
  );
  if (!result.rowCount) return null;
  const verified = await verifyPasswordLikeSecret(String(result.rows[0].secret_hash), clientSecret);
  if (!verified) return null;
  return { kind: "KAJA", id: String(result.rows[0].id), publicId: String(result.rows[0].public_id), auditActorType: "kaja" };
}

export async function authenticateSecretIntegrationToken(db: Db, token: string, config: SecretManagerConfig): Promise<SecretPrincipal | null> {
  if (!token.startsWith("kci_") || token.length < 80 || token.length > 100) return null;
  const digest = hmacToken(token, config.INTEGRATION_TOKEN_HMAC_KEY_BASE64);
  const result = await db.query(
    `select it.id, it.fingerprint, it.token_kind
       from integration_token it
      where it.lookup_digest=$1
        and it.key_id=$2
        and it.revoked_at is null
        and it.deleted_at is null
        and it.expires_at > now()`,
    [digest, config.INTEGRATION_TOKEN_HMAC_KEY_ID]
  );
  if (!result.rowCount) return null;
  await db.query("update integration_token set last_used_at=now(), usage_count=usage_count+1 where id=$1", [result.rows[0].id]);
  return {
    kind: "INTEGRATION_TOKEN",
    id: String(result.rows[0].id),
    publicId: String(result.rows[0].fingerprint),
    auditActorType: "integration_token",
    tokenKind: String(result.rows[0].token_kind ?? "SINGLE_COMPONENT")
  };
}

async function assertGrant(client: pg.PoolClient, secretId: string, principal: SecretPrincipal): Promise<boolean> {
  const result = await client.query(
    `select 1 from secret_grant
      where principal_kind=$2 and revoked_at is null
        and (secret_id=$1 or all_secrets is true)
        and (
          (principal_id is not null and principal_id=$3)
          or (principal_public_id is not null and principal_public_id=$4)
        )`,
    [secretId, principal.kind, principal.id, principal.publicId]
  );
  return Boolean(result.rowCount);
}

export async function resolveSecret(db: Db, config: SecretManagerConfig, principal: SecretPrincipal, stableNameInput: string, correlationId: string): Promise<{
  name: string;
  value: string;
  version: number;
  fingerprint: string;
  correlationId: string;
}> {
  assertMasterKey(config);
  const stableName = normalizeName(stableNameInput);
  return tx(db, async (client) => {
    const result = await client.query(`${activeSecretSelect()} for update of s`, [stableName]);
    if (!result.rowCount || !await assertGrant(client, String(result.rows[0].id), principal)) {
      await appendAudit(client, {
        eventType: "secret.resolve.denied",
        actorType: principal.auditActorType,
        actorId: principal.id ?? principal.publicId,
        objectType: "secret",
        objectId: null,
        after: { stableName, reason: "not_found_or_ungranted" },
        correlationId
      });
      throw Object.assign(new Error("secret_unavailable"), { statusCode: 404 });
    }
    const row = result.rows[0];
    const value = decryptManagedSecret(String(row.ciphertext), new Map([[config.CONFIG_VAULT_MASTER_KEY_ID, config.CONFIG_VAULT_MASTER_KEY_BASE64]]), {
      secretId: String(row.id),
      stableName: String(row.stable_name),
      versionId: String(row.version_id),
      versionNumber: Number(row.version_number),
      ownerKind: String(row.owner_kind),
      ownerId: row.owner_id ? String(row.owner_id) : null
    });
    await appendAudit(client, {
      eventType: "secret.resolve.allowed",
      actorType: principal.auditActorType,
      actorId: principal.id ?? principal.publicId,
      objectType: "secret",
      objectId: String(row.id),
      after: { stableName, versionNumber: Number(row.version_number), fingerprint: row.fingerprint },
      correlationId
    });
    return { name: stableName, value, version: Number(row.version_number), fingerprint: String(row.fingerprint), correlationId };
  });
}

export async function createRevealGrant(db: Db, config: SecretManagerConfig, actorId: string, correlationId: string, secretId: string, input: {
  password: string;
  totp: string;
  sessionId: string;
  purpose: string;
}): Promise<{ revealGrantId: string; expiresAt: string }> {
  const purpose = normalizeText(input.purpose, "invalid_reveal_purpose", 240);
  const purposeAudit = revealPurposeAudit(purpose);
  if (!config.MFA_ENCRYPTION_KEY_BASE64) {
    await appendAudit(db, { eventType: "secret.reveal_mfa.failed", actorType: "admin", actorId, objectType: "secret", objectId: secretId, after: { reason: "mfa_key_unavailable", ...purposeAudit }, correlationId });
    throw Object.assign(new Error("mfa_required"), { statusCode: 428 });
  }
  const account = await db.query("select password_hash,mfa_enabled,mfa_secret from admin_account where id=$1", [actorId]);
  if (!account.rowCount || !account.rows[0].mfa_enabled) {
    await appendAudit(db, { eventType: "secret.reveal_mfa.failed", actorType: "admin", actorId, objectType: "secret", objectId: secretId, after: { reason: "mfa_not_enabled", ...purposeAudit }, correlationId });
    throw Object.assign(new Error("mfa_required"), { statusCode: 428 });
  }
  const passwordOk = await argon2.verify(String(account.rows[0].password_hash), input.password);
  if (!passwordOk) {
    await appendAudit(db, { eventType: "secret.reveal_mfa.failed", actorType: "admin", actorId, objectType: "secret", objectId: secretId, after: { reason: "password_failed", ...purposeAudit }, correlationId });
    throw Object.assign(new Error("reauthentication_failed"), { statusCode: 401 });
  }
  const totpOk = decryptMfaSecret(String(account.rows[0].mfa_secret), config.MFA_ENCRYPTION_KEY_BASE64, {
    allowLegacyPlaintext: config.MFA_ALLOW_PLAINTEXT_LEGACY,
    subjectId: actorId,
    purpose: "admin_totp"
  });
  if (!authenticator.check(input.totp.trim(), totpOk)) {
    await appendAudit(db, { eventType: "secret.reveal_mfa.failed", actorType: "admin", actorId, objectType: "secret", objectId: secretId, after: { reason: "totp_failed", ...purposeAudit }, correlationId });
    throw Object.assign(new Error("reauthentication_failed"), { statusCode: 401 });
  }
  return tx(db, async (client) => {
    const secret = await client.query("select active_version_id,stable_name from secret_record where id=$1 and status='ACTIVE' and deleted_at is null", [secretId]);
    if (!secret.rowCount || !secret.rows[0].active_version_id) throw Object.assign(new Error("not_found"), { statusCode: 404 });
    const revealGrantId = randomUUID();
    const expiresAt = new Date(Date.now() + REVEAL_GRANT_MS).toISOString();
    await client.query(
      `insert into secret_admin_reveal_grant(id, secret_version_id, admin_account_id, admin_session_id, purpose, correlation_id, expires_at)
       values ($1,$2,$3,$4,$5,$6,$7)`,
      [revealGrantId, secret.rows[0].active_version_id, actorId, input.sessionId, purpose, correlationId, expiresAt]
    );
    await appendAudit(client, {
      eventType: "secret.reveal_grant.created",
      actorType: "admin",
      actorId,
      objectType: "secret",
      objectId: secretId,
      after: { stableName: secret.rows[0].stable_name, expiresAt, ...purposeAudit, sessionId: input.sessionId },
      correlationId
    });
    return { revealGrantId, expiresAt };
  });
}

export async function consumeRevealGrant(db: Db, config: SecretManagerConfig, actorId: string, sessionId: string, correlationId: string, secretId: string, revealGrantId: string): Promise<{
  value: string;
  expiresAt: string;
  version: number;
  fingerprint: string;
}> {
  assertMasterKey(config);
  return tx(db, async (client) => {
    const result = await client.query(
      `select grant.expires_at, version.*, secret.stable_name, secret.owner_kind, secret.owner_id
         from secret_admin_reveal_grant grant
         join secret_version version on version.id=grant.secret_version_id
         join secret_record secret on secret.id=version.secret_id
        where grant.id=$1 and grant.admin_account_id=$2 and grant.admin_session_id=$3 and secret.id=$4
          and grant.consumed_at is null and grant.expires_at > now()
          and secret.status='ACTIVE' and secret.deleted_at is null
        for update of grant`,
      [revealGrantId, actorId, sessionId, secretId]
    );
    if (!result.rowCount) {
      const expired = await client.query(
        `select grant.expires_at, secret.stable_name
           from secret_admin_reveal_grant grant
           join secret_version version on version.id=grant.secret_version_id
           join secret_record secret on secret.id=version.secret_id
          where grant.id=$1 and grant.admin_account_id=$2 and grant.admin_session_id=$3 and secret.id=$4
            and grant.consumed_at is null and grant.expires_at <= now()`,
        [revealGrantId, actorId, sessionId, secretId]
      );
      await appendAudit(client, {
        eventType: expired.rowCount ? "secret.reveal_grant.expired" : "secret.reveal_grant.invalid",
        actorType: "admin",
        actorId,
        objectType: "secret",
        objectId: secretId,
        after: { revealGrantId, sessionId, stableName: expired.rows[0]?.stable_name ?? null, expiresAt: expired.rows[0]?.expires_at ?? null },
        correlationId
      });
      throw Object.assign(new Error("reveal_grant_invalid"), { statusCode: 410 });
    }
    await client.query("update secret_admin_reveal_grant set consumed_at=now() where id=$1", [revealGrantId]);
    const row = result.rows[0];
    const value = decryptManagedSecret(String(row.ciphertext), new Map([[config.CONFIG_VAULT_MASTER_KEY_ID, config.CONFIG_VAULT_MASTER_KEY_BASE64]]), {
      secretId,
      stableName: String(row.stable_name),
      versionId: String(row.id),
      versionNumber: Number(row.version_number),
      ownerKind: String(row.owner_kind),
      ownerId: row.owner_id ? String(row.owner_id) : null
    });
    await appendAudit(client, {
      eventType: "secret.revealed",
      actorType: "admin",
      actorId,
      objectType: "secret",
      objectId: secretId,
      after: { stableName: row.stable_name, versionNumber: Number(row.version_number), fingerprint: row.fingerprint },
      correlationId
    });
    return { value, expiresAt: String(row.expires_at), version: Number(row.version_number), fingerprint: String(row.fingerprint) };
  });
}

export async function auditRevealUiEvent(db: Db, actorId: string, sessionId: string, correlationId: string, secretId: string, input: {
  revealGrantId?: string | null;
  eventType: "copy" | "cut" | "contextmenu" | "blur" | "visibility_hidden" | "expired" | "cleared";
}): Promise<void> {
  await tx(db, async (client) => {
    if (input.revealGrantId) {
      await client.query(
        "update secret_admin_reveal_grant set ui_event_count=ui_event_count+1 where id=$1 and admin_account_id=$2 and admin_session_id=$3",
        [input.revealGrantId, actorId, sessionId]
      );
    }
    await appendAudit(client, {
      eventType: `secret.reveal_ui.${input.eventType}`,
      actorType: "admin",
      actorId,
      objectType: "secret",
      objectId: secretId,
      after: { revealGrantId: input.revealGrantId ?? null, sessionId },
      correlationId
    });
  });
}

export function secretRequestDigest(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
