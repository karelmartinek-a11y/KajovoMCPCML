import { describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";

const secret = Buffer.alloc(32, 1).toString("base64");

describe("configuration gates", () => {
  it("requires independent secrets for production runtime", () => {
    expect(() => loadConfig({
      DATABASE_URL: "postgres://localhost/kcml",
      ACCESS_TOKEN_HMAC_KEY_BASE64: secret,
      INTEGRATION_TOKEN_HMAC_KEY_BASE64: Buffer.alloc(32, 2).toString("base64"),
      EGRESS_CAPABILITY_HMAC_KEY_BASE64: Buffer.alloc(32, 3).toString("base64"),
      SESSION_SECRET_BASE64: secret,
      CSRF_SECRET_BASE64: secret,
      MFA_ENCRYPTION_KEY_BASE64: secret
    })).not.toThrow();
  });

  it("rejects undersized secret material", () => {
    expect(() => loadConfig({
      DATABASE_URL: "postgres://localhost/kcml",
      ACCESS_TOKEN_HMAC_KEY_BASE64: Buffer.alloc(8).toString("base64"),
      INTEGRATION_TOKEN_HMAC_KEY_BASE64: Buffer.alloc(32, 2).toString("base64"),
      EGRESS_CAPABILITY_HMAC_KEY_BASE64: Buffer.alloc(32, 3).toString("base64"),
      SESSION_SECRET_BASE64: secret,
      CSRF_SECRET_BASE64: secret,
      MFA_ENCRYPTION_KEY_BASE64: secret
    })).toThrow();
  });

  it("accepts the existing GitHub API authorization for the onboarding worker", () => {
    expect(() => loadConfig({
      DATABASE_URL: "postgres://localhost/kcml",
      ACCESS_TOKEN_HMAC_KEY_BASE64: secret,
      INTEGRATION_TOKEN_HMAC_KEY_BASE64: Buffer.alloc(32, 2).toString("base64"),
      EGRESS_CAPABILITY_HMAC_KEY_BASE64: Buffer.alloc(32, 3).toString("base64"),
      SESSION_SECRET_BASE64: secret,
      CSRF_SECRET_BASE64: secret,
      MFA_ENCRYPTION_KEY_BASE64: secret,
      ONBOARDING_WORKER_ENABLED: "true",
      GITHUB_OWNER: "example",
      GITHUB_REPO: "repository",
      GITHUB_TOKEN: "github-token-with-sufficient-length",
      OCI_IMAGE_NAMESPACE: "example/handlers",
      OCI_SIGNING_PUBLIC_KEY: "/tmp/cosign.pub"
    })).not.toThrow();
  });

  it("rejects an enabled onboarding worker without GitHub API authorization", () => {
    expect(() => loadConfig({
      DATABASE_URL: "postgres://localhost/kcml",
      ACCESS_TOKEN_HMAC_KEY_BASE64: secret,
      INTEGRATION_TOKEN_HMAC_KEY_BASE64: Buffer.alloc(32, 2).toString("base64"),
      EGRESS_CAPABILITY_HMAC_KEY_BASE64: Buffer.alloc(32, 3).toString("base64"),
      SESSION_SECRET_BASE64: secret,
      CSRF_SECRET_BASE64: secret,
      MFA_ENCRYPTION_KEY_BASE64: secret,
      ONBOARDING_WORKER_ENABLED: "true",
      GITHUB_OWNER: "example",
      GITHUB_REPO: "repository",
      OCI_IMAGE_NAMESPACE: "example/handlers",
      OCI_SIGNING_PUBLIC_KEY: "/tmp/cosign.pub"
    })).toThrow();
  });
});
