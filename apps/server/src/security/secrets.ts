import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
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
  return createHash("sha256").update(value).digest("hex").slice(0, 16);
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

export function redact(input: unknown): unknown {
  if (typeof input === "string") {
    return input
      .replace(/(Bearer\s+)[A-Za-z0-9_-]+/gi, "$1[REDACTED]")
      .replace(/\bkc[ie]_[A-Za-z0-9_-]{40,}\b/g, "[REDACTED]");
  }
  if (Array.isArray(input)) return input.map(redact);
  if (input && typeof input === "object") {
    return Object.fromEntries(
      Object.entries(input).map(([key, value]) => {
        if (/secret|token|password|authorization|cookie/i.test(key)) return [key, "[REDACTED]"];
        return [key, redact(value)];
      })
    );
  }
  return input;
}
