import argon2 from "argon2";
import { randomUUID } from "node:crypto";
import type pg from "pg";
import { encryptMfaSecret } from "../security/secrets.js";
import { appendAudit } from "./audit.js";

export type PreservedDeploymentManagedAdmin = {
  accountId: string;
  mfaEnabled: boolean;
  mfaSecret: string | null;
};

export type DeploymentManagedAdminSyncInput = {
  username: string;
  password: string;
  mfaEncryptionKey: Buffer;
  configuredTotpSecret?: string | undefined;
  preserved?: PreservedDeploymentManagedAdmin | null;
  actorType: "deployment" | "factory-reset";
  eventType: string;
  correlationId: string;
};

export type DeploymentManagedAdminSyncResult = {
  accountId: string;
  mfaEnabled: boolean;
  mfaSource: "configured" | "preserved" | "disabled";
  sessionEpoch: string;
};

export function canonicalAdminPassword(value: string): string {
  let end = value.length;
  while (end > 0 && (value.charCodeAt(end - 1) === 10 || value.charCodeAt(end - 1) === 13)) {
    end -= 1;
  }
  return end === value.length ? value : value.slice(0, end);
}

export function requireDeploymentManagedAdminPassword(pass: string | undefined): string {
  if (pass === undefined || pass.length === 0) throw new Error("PASS must not be empty");
  const password = canonicalAdminPassword(pass);
  if (password.length === 0) throw new Error("PASS must not be empty after removing trailing line endings");
  return password;
}

async function hashAdminPassword(password: string): Promise<string> {
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 1
  });
}

function resolveManagedAdminMfa(
  accountId: string,
  configuredTotpSecret: string | undefined,
  encryptionKey: Buffer,
  preserved: PreservedDeploymentManagedAdmin | null | undefined
): { enabled: boolean; secret: string | null; source: "configured" | "preserved" | "disabled" } {
  const trimmedConfiguredSecret = configuredTotpSecret?.trim();
  if (trimmedConfiguredSecret) {
    return {
      enabled: true,
      secret: encryptMfaSecret(trimmedConfiguredSecret, encryptionKey, { subjectId: accountId, purpose: "admin_totp" }),
      source: "configured"
    };
  }
  if (preserved?.mfaEnabled) {
    if (!preserved.mfaSecret) {
      throw new Error("deployment_managed_admin_mfa_secret_missing");
    }
    return {
      enabled: true,
      secret: preserved.mfaSecret,
      source: "preserved"
    };
  }
  return {
    enabled: false,
    secret: null,
    source: "disabled"
  };
}

export async function syncDeploymentManagedAdmin(
  client: pg.PoolClient,
  input: DeploymentManagedAdminSyncInput
): Promise<DeploymentManagedAdminSyncResult> {
  const passwordHash = await hashAdminPassword(input.password);
  const existing = await client.query(
    "select id,mfa_enabled,mfa_secret from admin_account where username=$1 for update",
    [input.username]
  );
  const accountId = existing.rowCount
    ? String(existing.rows[0].id)
    : input.preserved?.accountId ?? randomUUID();
  if (!existing.rowCount) {
    await client.query(
      `insert into admin_account(id,username,mfa_enabled,role,active,activated_at)
       values ($1,$2,false,'OWNER',true,now())
       on conflict (username) do nothing`,
      [accountId, input.username]
    );
  }
  const preserved = existing.rowCount
    ? {
        accountId,
        mfaEnabled: Boolean(existing.rows[0].mfa_enabled),
        mfaSecret: typeof existing.rows[0].mfa_secret === "string" ? existing.rows[0].mfa_secret : null
      }
    : input.preserved ?? null;
  const resolvedMfa = resolveManagedAdminMfa(accountId, input.configuredTotpSecret, input.mfaEncryptionKey, preserved);
  const nextSessionEpoch = randomUUID();
  await client.query(
    `update admin_account
        set password_hash=$2,
            password_changed_at=now(),
            mfa_enabled=$3,
            mfa_secret=$4,
            active=true,
            activated_at=coalesce(activated_at,now()),
            updated_at=now(),
            role='OWNER',
            session_epoch=$5
      where id=$1`,
    [accountId, passwordHash, resolvedMfa.enabled, resolvedMfa.secret, nextSessionEpoch]
  );
  await client.query("update admin_session set revoked_at=now() where account_id=$1 and revoked_at is null", [accountId]);
  await appendAudit(client, {
    eventType: input.eventType,
    actorType: input.actorType,
    objectType: "admin_account",
    objectId: accountId,
    after: {
      username: input.username,
      mfaEnabled: resolvedMfa.enabled,
      mfaSource: resolvedMfa.source,
      sessionsRevoked: true,
      sessionEpochRotated: true
    },
    correlationId: input.correlationId
  });
  return {
    accountId,
    mfaEnabled: resolvedMfa.enabled,
    mfaSource: resolvedMfa.source,
    sessionEpoch: nextSessionEpoch
  };
}

export async function verifyDeploymentManagedAdminPassword(
  client: pg.PoolClient,
  accountId: string,
  password: string,
  actorType: "deployment" | "factory-reset",
  correlationId: string
): Promise<void> {
  const smoke = await client.query("select password_hash from admin_account where id=$1 and active=true", [accountId]);
  if (!smoke.rowCount || !await argon2.verify(String(smoke.rows[0].password_hash), password)) {
    throw new Error("deployment_managed_admin_password_smoke_failed");
  }
  await appendAudit(client, {
    eventType: "admin.password.sync_smoke_passed",
    actorType,
    objectType: "admin_account",
    objectId: accountId,
    correlationId
  });
}
