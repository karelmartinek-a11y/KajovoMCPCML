import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { Db } from "../db.js";
import { authenticatePrincipalAccessToken, normalizeSecretPrincipalPublicId } from "../domain/secret-manager.js";
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
  it("accepts only a scoped long-lived access token after consulting current component state", async () => {
    const accessKey = randomBytes(32);
    const token = `kca_${"a".repeat(80)}`;
    const seenSql: string[] = [];
    const db = {
      query: async (sql: string, params: unknown[]) => {
        seenSql.push(sql);
        if (sql.includes("from principal_access_token")) {
          expect(params[0]).toEqual(hmacToken(token, accessKey));
          return { rowCount: 1, rows: [{
            id: "access-id", scope_names: ["secret.resolve"], issued_policy_epoch: 4, issued_revocation_epoch: 7,
            principal_id: "91000000-0000-4000-8000-000000000002", public_id: "KCML91001", status: "ACTIVE",
            policy_epoch: 4, revocation_epoch: 7, component_id: "91000000-0000-4000-8000-000000000001",
            enabled: true, egress_enabled: true, activation_state: "ACTIVE", lifecycle_state: "ACTIVE",
            operational_state: "HEALTHY", deregistered_at: null
          }] };
        }
        if (sql.includes("update principal_access_token")) return { rowCount: 1, rows: [] };
        return { rowCount: 0, rows: [] };
      }
    } as unknown as Db;

    await expect(authenticatePrincipalAccessToken(db, token, {
      CONFIG_VAULT_MASTER_KEY_BASE64: randomBytes(32),
      CONFIG_VAULT_MASTER_KEY_ID: "config-v1",
      ACCESS_TOKEN_HMAC_KEY_BASE64: accessKey,
      INTEGRATION_TOKEN_HMAC_KEY_BASE64: randomBytes(32),
      INTEGRATION_TOKEN_HMAC_KEY_ID: "it-v1"
    })).resolves.toMatchObject({
      kind: "COMPONENT",
      id: "91000000-0000-4000-8000-000000000001",
      publicId: "KCML91001"
    });
    expect(seenSql.join("\n")).toContain("join component on component.principal_id=principal.id");
    expect(seenSql.join("\n")).toContain("update principal_access_token set last_used_at=now()");
  });

  it("rejects access tokens without the live secret resolution scope", async () => {
    const accessKey = randomBytes(32);
    const token = `kca_${"b".repeat(80)}`;
    const db = {
      query: async (sql: string) => {
        if (sql.includes("from principal_access_token")) {
          return { rowCount: 1, rows: [{
            id: "access-id", scope_names: ["mcp.tools.call"], issued_policy_epoch: 1, issued_revocation_epoch: 1,
            principal_id: "91000000-0000-4000-8000-000000000002", public_id: "KCML91001", status: "ACTIVE",
            policy_epoch: 1, revocation_epoch: 1, component_id: "91000000-0000-4000-8000-000000000001",
            enabled: true, egress_enabled: true, activation_state: "ACTIVE", lifecycle_state: "ACTIVE",
            operational_state: "HEALTHY", deregistered_at: null
          }] };
        }
        return { rowCount: 0, rows: [] };
      }
    } as unknown as Db;

    await expect(authenticatePrincipalAccessToken(db, token, {
      CONFIG_VAULT_MASTER_KEY_BASE64: randomBytes(32),
      CONFIG_VAULT_MASTER_KEY_ID: "config-v1",
      ACCESS_TOKEN_HMAC_KEY_BASE64: accessKey,
      INTEGRATION_TOKEN_HMAC_KEY_BASE64: randomBytes(32),
      INTEGRATION_TOKEN_HMAC_KEY_ID: "it-v1"
    })).resolves.toBeNull();
  });

  it("rejects raw integration tokens as grant public identifiers", () => {
    expect(() => normalizeSecretPrincipalPublicId(`kci_${"a".repeat(80)}`)).toThrow("secret_principal_public_id_must_not_be_token");
    expect(normalizeSecretPrincipalPublicId(" sha256:token-fingerprint ")).toBe("sha256:token-fingerprint");
  });
});
