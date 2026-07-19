import { createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";
import argon2 from "argon2";

export const SECRET_BYTES = 64;

export type IssuedSecret = {
  value: string;
  fingerprint: string;
};

export function issueOpaqueSecret(): IssuedSecret {
  const raw = randomBytes(SECRET_BYTES);
  const value = raw.toString("base64url");
  return {
    value,
    fingerprint: fingerprintSecret(value)
  };
}

export function fingerprintSecret(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 32);
}

export async function hashPasswordLikeSecret(value: string): Promise<string> {
  return argon2.hash(value, {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 1
  });
}

export async function verifyPasswordLikeSecret(hash: string, value: string): Promise<boolean> {
  return argon2.verify(hash, value);
}

export function hmacToken(value: string, key: Buffer): Buffer {
  return createHmac("sha256", key).update(value).digest();
}

export function safeEqual(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

const ENCRYPTED_MFA_V1_PREFIX = "enc:v1";
const ENCRYPTED_MFA_V2_PREFIX = "enc:v2";
const VAULT_ENVELOPE_PREFIX = "vault:v1";
const MANAGED_SECRET_ENVELOPE_PREFIX = "kcml-secret:v1";

type MfaSecretContext = {
  subjectId: string;
  purpose?: string;
  keyId?: string;
};

function mfaAad(context: Required<MfaSecretContext>): Buffer {
  return Buffer.from(JSON.stringify({
    subjectId: context.subjectId,
    purpose: context.purpose,
    keyId: context.keyId
  }), "utf8");
}

function normalizeMfaContext(context: MfaSecretContext): Required<MfaSecretContext> {
  const subjectId = context.subjectId.trim();
  const purpose = (context.purpose ?? "admin_totp").trim();
  const keyId = (context.keyId ?? "mfa-v1").trim();
  if (!subjectId) throw new Error("invalid_mfa_subject");
  if (!purpose) throw new Error("invalid_mfa_purpose");
  if (!keyId) throw new Error("invalid_mfa_key_id");
  return { subjectId, purpose, keyId };
}

function mfaCipherKey(key: Buffer): Buffer {
  if (key.length !== 32) throw new Error("invalid_mfa_encryption_key_length");
  return key;
}

export function encryptMfaSecret(secret: string, key: Buffer, context?: MfaSecretContext): string {
  const resolved = context ? normalizeMfaContext(context) : null;
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", mfaCipherKey(key), iv);
  if (resolved) cipher.setAAD(mfaAad(resolved));
  const ciphertext = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  if (!resolved) {
    return `${ENCRYPTED_MFA_V1_PREFIX}:${iv.toString("base64url")}:${ciphertext.toString("base64url")}:${tag.toString("base64url")}`;
  }
  return [
    ENCRYPTED_MFA_V2_PREFIX,
    Buffer.from(resolved.keyId, "utf8").toString("base64url"),
    Buffer.from(resolved.subjectId, "utf8").toString("base64url"),
    Buffer.from(resolved.purpose, "utf8").toString("base64url"),
    iv.toString("base64url"),
    ciphertext.toString("base64url"),
    tag.toString("base64url")
  ].join(":");
}

export function decryptMfaSecret(secret: string, key: Buffer, options: {
  allowLegacyPlaintext?: boolean;
  subjectId?: string;
  purpose?: string;
  keyId?: string;
} = {}): string {
  if (!secret.startsWith(`${ENCRYPTED_MFA_V1_PREFIX}:`) && !secret.startsWith(`${ENCRYPTED_MFA_V2_PREFIX}:`)) {
    if (options.allowLegacyPlaintext) return secret;
    throw new Error("plaintext_mfa_secret_rejected");
  }
  const parts = secret.split(":");
  if (parts[1] === "v2") {
    const [, version, keyIdRaw, subjectRaw, purposeRaw, ivRaw, payloadRaw, tagRaw] = parts;
    if (version !== "v2" || !keyIdRaw || !subjectRaw || !purposeRaw || !ivRaw || !payloadRaw || !tagRaw) {
      throw new Error("invalid_mfa_secret_format");
    }
    const subjectId = Buffer.from(subjectRaw, "base64url").toString("utf8");
    const purpose = Buffer.from(purposeRaw, "base64url").toString("utf8");
    const keyId = Buffer.from(keyIdRaw, "base64url").toString("utf8");
    const resolved = normalizeMfaContext({
      subjectId: options.subjectId ?? subjectId,
      purpose: options.purpose ?? purpose,
      keyId: options.keyId ?? keyId
    });
    if (resolved.subjectId !== subjectId || resolved.purpose !== purpose || resolved.keyId !== keyId) {
      throw new Error("mfa_secret_context_mismatch");
    }
    const decipher = createDecipheriv("aes-256-gcm", mfaCipherKey(key), Buffer.from(ivRaw, "base64url"));
    decipher.setAAD(mfaAad(resolved));
    decipher.setAuthTag(Buffer.from(tagRaw, "base64url"));
    return Buffer.concat([
      decipher.update(Buffer.from(payloadRaw, "base64url")),
      decipher.final()
    ]).toString("utf8");
  }
  const [, version, ivRaw, payloadRaw, tagRaw] = parts;
  if (version !== "v1" || !ivRaw || !payloadRaw || !tagRaw) throw new Error("invalid_mfa_secret_format");
  const decipher = createDecipheriv("aes-256-gcm", mfaCipherKey(key), Buffer.from(ivRaw, "base64url"));
  decipher.setAuthTag(Buffer.from(tagRaw, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(payloadRaw, "base64url")),
    decipher.final()
  ]).toString("utf8");
}

type VaultSecretContext = {
  keyId: string;
  settingKey: string;
};

function vaultAad(context: VaultSecretContext): Buffer {
  return Buffer.from(JSON.stringify({ version: 1, keyId: context.keyId, settingKey: context.settingKey, purpose: "operational-config" }), "utf8");
}

export function encryptVaultSecret(value: string, masterKey: Buffer, context: VaultSecretContext): string {
  if (masterKey.length !== 32) throw new Error("invalid_config_vault_master_key_length");
  if (!context.keyId.trim() || !context.settingKey.trim()) throw new Error("invalid_config_vault_context");
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", masterKey, nonce);
  cipher.setAAD(vaultAad(context));
  const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return [
    VAULT_ENVELOPE_PREFIX,
    Buffer.from(context.keyId, "utf8").toString("base64url"),
    nonce.toString("base64url"),
    ciphertext.toString("base64url"),
    cipher.getAuthTag().toString("base64url")
  ].join(":");
}

export function decryptVaultSecret(envelope: string, keyring: ReadonlyMap<string, Buffer>, settingKey: string): string {
  const [prefix, version, keyIdRaw, nonceRaw, ciphertextRaw, tagRaw] = envelope.split(":");
  if (`${prefix}:${version}` !== VAULT_ENVELOPE_PREFIX || !keyIdRaw || !nonceRaw || !ciphertextRaw || !tagRaw) {
    throw new Error("invalid_config_vault_envelope");
  }
  const keyId = Buffer.from(keyIdRaw, "base64url").toString("utf8");
  const masterKey = keyring.get(keyId);
  if (!masterKey || masterKey.length !== 32) throw new Error("config_vault_key_unavailable");
  const decipher = createDecipheriv("aes-256-gcm", masterKey, Buffer.from(nonceRaw, "base64url"));
  decipher.setAAD(vaultAad({ keyId, settingKey }));
  decipher.setAuthTag(Buffer.from(tagRaw, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(ciphertextRaw, "base64url")),
    decipher.final()
  ]).toString("utf8");
}

export type ManagedSecretEncryptionContext = {
  keyId: string;
  secretId: string;
  stableName: string;
  versionId: string;
  versionNumber: number;
  ownerKind: string;
  ownerId: string | null;
};

function managedSecretAad(context: ManagedSecretEncryptionContext): Buffer {
  return Buffer.from(JSON.stringify({
    version: 1,
    purpose: "kcml-managed-secret",
    keyId: context.keyId,
    secretId: context.secretId,
    stableName: context.stableName,
    versionId: context.versionId,
    versionNumber: context.versionNumber,
    ownerKind: context.ownerKind,
    ownerId: context.ownerId,
    algorithm: "AES-256-GCM"
  }), "utf8");
}

function managedSecretCipherKey(masterKey: Buffer): Buffer {
  if (masterKey.length !== 32) throw new Error("invalid_secret_manager_master_key_length");
  return Buffer.from(hkdfSync("sha256", masterKey, Buffer.from("kcml-secret-manager:v1", "utf8"), Buffer.from("aes-256-gcm", "utf8"), 32));
}

export function encryptManagedSecret(value: string, masterKey: Buffer, context: ManagedSecretEncryptionContext): string {
  if (!context.keyId.trim() || !context.secretId.trim() || !context.stableName.trim() || !context.versionId.trim()) {
    throw new Error("invalid_secret_manager_context");
  }
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", managedSecretCipherKey(masterKey), nonce);
  cipher.setAAD(managedSecretAad(context));
  const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return [
    MANAGED_SECRET_ENVELOPE_PREFIX,
    Buffer.from(context.keyId, "utf8").toString("base64url"),
    nonce.toString("base64url"),
    ciphertext.toString("base64url"),
    cipher.getAuthTag().toString("base64url")
  ].join(":");
}

export function decryptManagedSecret(envelope: string, keyring: ReadonlyMap<string, Buffer>, context: Omit<ManagedSecretEncryptionContext, "keyId">): string {
  const [prefix, version, keyIdRaw, nonceRaw, ciphertextRaw, tagRaw] = envelope.split(":");
  if (`${prefix}:${version}` !== MANAGED_SECRET_ENVELOPE_PREFIX || !keyIdRaw || !nonceRaw || !ciphertextRaw || !tagRaw) {
    throw new Error("invalid_secret_manager_envelope");
  }
  const keyId = Buffer.from(keyIdRaw, "base64url").toString("utf8");
  const masterKey = keyring.get(keyId);
  if (!masterKey || masterKey.length !== 32) throw new Error("secret_manager_key_unavailable");
  const resolved = { ...context, keyId };
  const decipher = createDecipheriv("aes-256-gcm", managedSecretCipherKey(masterKey), Buffer.from(nonceRaw, "base64url"));
  decipher.setAAD(managedSecretAad(resolved));
  decipher.setAuthTag(Buffer.from(tagRaw, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(ciphertextRaw, "base64url")),
    decipher.final()
  ]).toString("utf8");
}

export function redact(input: unknown): unknown {
  if (typeof input === "string") {
    return input
      .replace(/authorization:\s*[^\r\n]+/gi, "authorization: [REDACTED]")
      .replace(/cookie:\s*[^\r\n]+/gi, "cookie: [REDACTED]")
      .replace(/(Bearer\s+)([^\s,;]+)/gi, "$1[REDACTED]")
      .replace(/\bkc[ie]_[A-Za-z0-9_-]{40,}\b/g, "[REDACTED]");
  }
  if (Array.isArray(input)) return input.map(redact);
  if (input && typeof input === "object") {
    return Object.fromEntries(
      Object.entries(input).map(([key, value]) => {
        if (/secret|token|password|authorization|cookie|credential|clientsecret|privatekey|(?:^|_)key$|mfa|otp|totp|signature|digest|session|csrf/i.test(key)) {
          return [key, "[REDACTED]"];
        }
        return [key, redact(value)];
      })
    );
  }
  return input;
}
