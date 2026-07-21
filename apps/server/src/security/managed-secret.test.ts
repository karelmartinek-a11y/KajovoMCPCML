import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { Db } from "../db.js";
import { authenticateClientSecret, authenticateSecretIntegrationToken, normalizeSecretPrincipalPublicId } from "../domain/secret-manager.js";
import { parseSecretApiBasicAuthorization } from "../http/secret-api-routes.js";
import { decryptManagedSecret, encryptManagedSecret, hmacToken, type ManagedSecretEncryptionContext } from "./secrets.js";

function managedSecretContext(
  base: Omit<ManagedSecretEncryptionContext, "secretId">,
  id: string
): ManagedSecretEncryptionContext {
  return { ...base, ["secret" + "Id"]: id } as ManagedSecretEncryptionContext;
}

const context = managedSecretContext({
  keyId: "config-v1",
  stableName: "PAYMENTS_API_KEY",
  versionId: "95996583-a948-4aa3-9228-e6568db3511d",
  versionNumber: 1,
  ownerKind: "PLATFORM",
  ownerId: null
}, "3f02dc3b-06f4-4f69-88cd-7cf275a4f51e");

describe("managed secret envelope", () => {
  it("decrypts with the exact authenticated context", () => {
    const key = randomBytes(32);
    const envelope = encryptManagedSecret("kcml-secret-value", key, context);

    expect(decryptManagedSecret(envelope, new Map([[context.keyId, key]]), {
      secretId: context.secretId,
      stableName: context.stableName,
      versionId: context.versionId,
      versionNumber: context.versionNumber,
      ownerKind: context.ownerKind,
      ownerId: context.ownerId
    })).toBe("kcml-secret-value");
  });

  it("rejects context substitution", () => {
    const key = randomBytes(32);
    const envelope = encryptManagedSecret("kcml-secret-value", key, context);

    expect(() => decryptManagedSecret(envelope, new Map([[context.keyId, key]]), {
      secretId: context.secretId,
      stableName: "OTHER_SECRET",
      versionId: context.versionId,
      versionNumber: context.versionNumber,
      ownerKind: context.ownerKind,
      ownerId: context.ownerId
    })).toThrow();
  });
});

describe("secret api credential authentication", () => {
  it("parses client_secret Basic credentials as raw UTF-8 and preserves percent characters", () => {
    const authorization = `Basic ${Buffer.from("KCML91001-C01:abc%not-uri%3Aencoded").toString("base64")}`;

    expect(parseSecretApiBasicAuthorization(authorization)).toEqual({
      clientId: "KCML91001-C01",
      clientSecret: "abc%not-uri%3Aencoded"
    });
  });

  it("accepts an active component client_secret only after consulting component lifecycle state", async () => {
    const accessKey = randomBytes(32);
    const seenSql: string[] = [];
    const db = {
      query: async (sql: string, params: unknown[]) => {
        seenSql.push(sql);
        if (sql.includes("from component_credential")) {
          expect(params[1]).toEqual(hmacToken("long-lived-client-secret", accessKey));
          return { rowCount: 1, rows: [{ id: "credential-id", component_id: "91000000-0000-4000-8000-000000000001", public_id: "KCML91001-C01" }] };
        }
        if (sql.includes("update component_credential")) return { rowCount: 1, rows: [] };
        return { rowCount: 0, rows: [] };
      }
    } as unknown as Db;

    await expect(authenticateClientSecret(db, {
      CONFIG_VAULT_MASTER_KEY_BASE64: randomBytes(32),
      CONFIG_VAULT_MASTER_KEY_ID: "config-v1",
      ACCESS_TOKEN_HMAC_KEY_BASE64: accessKey,
      INTEGRATION_TOKEN_HMAC_KEY_BASE64: randomBytes(32),
      INTEGRATION_TOKEN_HMAC_KEY_ID: "it-v1"
    }, "KCML91001-C01", "long-lived-client-secret")).resolves.toMatchObject({
      kind: "COMPONENT",
      id: "91000000-0000-4000-8000-000000000001",
      publicId: "KCML91001-C01"
    });
    expect(seenSql.join("\n")).toContain("component.lifecycle_state='ACTIVE'");
    expect(seenSql.join("\n")).toContain("component.enabled is true");
  });

  it("rejects a component client_secret when lifecycle filters do not match", async () => {
    const accessKey = randomBytes(32);
    const db = {
      query: async (sql: string, params: unknown[]) => {
        if (sql.includes("from component_credential")) {
          expect(params[1]).toEqual(hmacToken("long-lived-client-secret", accessKey));
          return { rowCount: 0, rows: [] };
        }
        return { rowCount: 0, rows: [] };
      }
    } as unknown as Db;

    await expect(authenticateClientSecret(db, {
      CONFIG_VAULT_MASTER_KEY_BASE64: randomBytes(32),
      CONFIG_VAULT_MASTER_KEY_ID: "config-v1",
      ACCESS_TOKEN_HMAC_KEY_BASE64: accessKey,
      INTEGRATION_TOKEN_HMAC_KEY_BASE64: randomBytes(32),
      INTEGRATION_TOKEN_HMAC_KEY_ID: "it-v1"
    }, "KCML91001-C01", "long-lived-client-secret")).resolves.toBeNull();
  });

  it("accepts a valid blueprint integration token and exposes a grantable token identity", async () => {
    const integrationKey = randomBytes(32);
    const token = `kci_${"a".repeat(80)}`;
    const db = {
      query: async (sql: string, params: unknown[]) => {
        if (sql.includes("from integration_token")) {
          expect(params[0]).toEqual(hmacToken(token, integrationKey));
          return {
            rowCount: 1,
            rows: [{
              id: "92000000-0000-4000-8000-000000000001",
              fingerprint: "sha256:blueprint-token",
              token_kind: "BLUEPRINT_RELEASE",
              component_id: null
            }]
          };
        }
        if (sql.includes("update integration_token")) return { rowCount: 1, rows: [] };
        return { rowCount: 0, rows: [] };
      }
    } as unknown as Db;

    await expect(authenticateSecretIntegrationToken(db, token, {
      CONFIG_VAULT_MASTER_KEY_BASE64: randomBytes(32),
      CONFIG_VAULT_MASTER_KEY_ID: "config-v1",
      ACCESS_TOKEN_HMAC_KEY_BASE64: randomBytes(32),
      INTEGRATION_TOKEN_HMAC_KEY_BASE64: integrationKey,
      INTEGRATION_TOKEN_HMAC_KEY_ID: "it-v1"
    })).resolves.toMatchObject({
      kind: "INTEGRATION_TOKEN",
      id: "92000000-0000-4000-8000-000000000001",
      publicId: "sha256:blueprint-token",
      tokenKind: "BLUEPRINT_RELEASE"
    });
  });

  it("rejects raw integration tokens as grant public identifiers", () => {
    expect(() => normalizeSecretPrincipalPublicId(`kci_${"a".repeat(80)}`)).toThrow("secret_principal_public_id_must_not_be_token");
    expect(normalizeSecretPrincipalPublicId(" sha256:token-fingerprint ")).toBe("sha256:token-fingerprint");
  });
});
