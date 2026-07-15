import { mkdtemp, rm, symlink, writeFile, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";

const secret = Buffer.alloc(32, 1).toString("base64");
const envBase = {
  DATABASE_URL: "postgres://localhost/kcml"
};
const tempDirs: string[] = [];

async function tempFile(name: string, value: string, mode = 0o600): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), "kcml-config-test-"));
  tempDirs.push(dir);
  const file = path.join(dir, name);
  await writeFile(file, value, "utf8");
  await chmod(file, mode);
  return file;
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0, tempDirs.length).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("configuration gates", () => {
  it("accepts canonical base64 secrets and rejects non-canonical padding", () => {
    expect(() => loadConfig({
      ...envBase,
      ACCESS_TOKEN_HMAC_KEY_BASE64: secret,
      INTEGRATION_TOKEN_HMAC_KEY_BASE64: Buffer.alloc(32, 2).toString("base64"),
      EGRESS_CAPABILITY_HMAC_KEY_BASE64: Buffer.alloc(32, 3).toString("base64"),
      SESSION_SECRET_BASE64: Buffer.alloc(32, 4).toString("base64"),
      CSRF_SECRET_BASE64: Buffer.alloc(32, 5).toString("base64"),
      MFA_ENCRYPTION_KEY_BASE64: Buffer.alloc(32, 6).toString("base64")
    })).not.toThrow();
    expect(() => loadConfig({
      ...envBase,
      ACCESS_TOKEN_HMAC_KEY_BASE64: `${secret}\n`,
      INTEGRATION_TOKEN_HMAC_KEY_BASE64: Buffer.alloc(32, 2).toString("base64"),
      EGRESS_CAPABILITY_HMAC_KEY_BASE64: Buffer.alloc(32, 3).toString("base64"),
      SESSION_SECRET_BASE64: Buffer.alloc(32, 4).toString("base64"),
      CSRF_SECRET_BASE64: Buffer.alloc(32, 5).toString("base64"),
      MFA_ENCRYPTION_KEY_BASE64: Buffer.alloc(32, 6).toString("base64")
    })).toThrow();
  });

  it("rejects undersized secret material", () => {
    expect(() => loadConfig({
      ...envBase,
      ACCESS_TOKEN_HMAC_KEY_BASE64: Buffer.alloc(8).toString("base64"),
      INTEGRATION_TOKEN_HMAC_KEY_BASE64: Buffer.alloc(32, 2).toString("base64"),
      EGRESS_CAPABILITY_HMAC_KEY_BASE64: Buffer.alloc(32, 3).toString("base64"),
      SESSION_SECRET_BASE64: Buffer.alloc(32, 4).toString("base64"),
      CSRF_SECRET_BASE64: Buffer.alloc(32, 5).toString("base64"),
      MFA_ENCRYPTION_KEY_BASE64: Buffer.alloc(32, 6).toString("base64")
    })).toThrow();
  });

  it("accepts the existing GitHub API authorization for the onboarding worker", () => {
    expect(() => loadConfig({
      ...envBase,
      ACCESS_TOKEN_HMAC_KEY_BASE64: secret,
      INTEGRATION_TOKEN_HMAC_KEY_BASE64: Buffer.alloc(32, 2).toString("base64"),
      EGRESS_CAPABILITY_HMAC_KEY_BASE64: Buffer.alloc(32, 3).toString("base64"),
      SESSION_SECRET_BASE64: Buffer.alloc(32, 4).toString("base64"),
      CSRF_SECRET_BASE64: Buffer.alloc(32, 5).toString("base64"),
      MFA_ENCRYPTION_KEY_BASE64: Buffer.alloc(32, 6).toString("base64"),
      ONBOARDING_WORKER_ENABLED: "true",
      GITHUB_OWNER: "example",
      GITHUB_REPO: "repository",
      GITHUB_TOKEN: "github-token-with-sufficient-length",
      OCI_IMAGE_NAMESPACE: "example/handlers",
      OCI_CERTIFICATE_IDENTITY: "https://github.com/example/repository/.github/workflows/onboarding-build.yml@refs/heads/main"
    })).not.toThrow();
  });

  it("requires least-privilege secret matrices per role", () => {
    expect(() => loadConfig({
      KCML_PROCESS_ROLE: "worker",
      ...envBase,
      EGRESS_CAPABILITY_HMAC_KEY_BASE64: Buffer.alloc(32, 3).toString("base64"),
      ONBOARDING_WORKER_ENABLED: "true",
      GITHUB_OWNER: "example",
      GITHUB_REPO: "repository",
      GITHUB_TOKEN: "github-token-with-sufficient-length",
      OCI_IMAGE_NAMESPACE: "example/handlers",
      OCI_CERTIFICATE_IDENTITY: "https://github.com/example/repository/.github/workflows/onboarding-build.yml@refs/heads/main"
    })).not.toThrow();
    expect(() => loadConfig({
      KCML_PROCESS_ROLE: "web",
      ...envBase,
      ACCESS_TOKEN_HMAC_KEY_BASE64: secret,
      INTEGRATION_TOKEN_HMAC_KEY_BASE64: Buffer.alloc(32, 2).toString("base64")
    })).toThrow();
    expect(() => loadConfig({
      KCML_PROCESS_ROLE: "migrate",
      ...envBase,
      ONBOARDING_WORKER_ENABLED: "true"
    })).not.toThrow();
  });

  it("rejects reused security keys and invalid log levels", () => {
    expect(() => loadConfig({
      ...envBase,
      ACCESS_TOKEN_HMAC_KEY_BASE64: secret,
      INTEGRATION_TOKEN_HMAC_KEY_BASE64: secret,
      EGRESS_CAPABILITY_HMAC_KEY_BASE64: Buffer.alloc(32, 3).toString("base64"),
      SESSION_SECRET_BASE64: Buffer.alloc(32, 4).toString("base64"),
      CSRF_SECRET_BASE64: Buffer.alloc(32, 5).toString("base64"),
      MFA_ENCRYPTION_KEY_BASE64: Buffer.alloc(32, 6).toString("base64")
    })).toThrow();
    expect(() => loadConfig({
      ...envBase,
      ACCESS_TOKEN_HMAC_KEY_BASE64: secret,
      INTEGRATION_TOKEN_HMAC_KEY_BASE64: Buffer.alloc(32, 2).toString("base64"),
      EGRESS_CAPABILITY_HMAC_KEY_BASE64: Buffer.alloc(32, 3).toString("base64"),
      SESSION_SECRET_BASE64: Buffer.alloc(32, 4).toString("base64"),
      CSRF_SECRET_BASE64: Buffer.alloc(32, 5).toString("base64"),
      MFA_ENCRYPTION_KEY_BASE64: Buffer.alloc(32, 6).toString("base64"),
      LOG_LEVEL: "verbose"
    })).toThrow();
  });

  it("requires explicit production hosts and rejects invalid hostnames and ports", () => {
    expect(() => loadConfig({
      ...envBase,
      NODE_ENV: "production",
      KCML_PROCESS_ROLE: "web",
      ACCESS_TOKEN_HMAC_KEY_BASE64: secret,
      INTEGRATION_TOKEN_HMAC_KEY_BASE64: Buffer.alloc(32, 2).toString("base64"),
      EGRESS_CAPABILITY_HMAC_KEY_BASE64: Buffer.alloc(32, 3).toString("base64"),
      SESSION_SECRET_BASE64: Buffer.alloc(32, 4).toString("base64"),
      CSRF_SECRET_BASE64: Buffer.alloc(32, 5).toString("base64"),
      MFA_ENCRYPTION_KEY_BASE64: Buffer.alloc(32, 6).toString("base64"),
      BUILD_ID: "release-1"
    })).toThrow();
    expect(() => loadConfig({
      ...envBase,
      NODE_ENV: "production",
      KCML_PROCESS_ROLE: "web",
      PUBLIC_BASE_DOMAIN: "hcasc.cz",
      ADMIN_HOST: "https://admin.hcasc.cz",
      AUTH_HOST: "auth.hcasc.cz",
      REGISTER_HOST: "register.hcasc.cz",
      ACCESS_TOKEN_HMAC_KEY_BASE64: secret,
      INTEGRATION_TOKEN_HMAC_KEY_BASE64: Buffer.alloc(32, 2).toString("base64"),
      EGRESS_CAPABILITY_HMAC_KEY_BASE64: Buffer.alloc(32, 3).toString("base64"),
      SESSION_SECRET_BASE64: Buffer.alloc(32, 4).toString("base64"),
      CSRF_SECRET_BASE64: Buffer.alloc(32, 5).toString("base64"),
      MFA_ENCRYPTION_KEY_BASE64: Buffer.alloc(32, 6).toString("base64"),
      BUILD_ID: "release-1"
    })).toThrow();
    expect(() => loadConfig({
      ...envBase,
      PORT: "65536",
      ACCESS_TOKEN_HMAC_KEY_BASE64: secret,
      INTEGRATION_TOKEN_HMAC_KEY_BASE64: Buffer.alloc(32, 2).toString("base64"),
      EGRESS_CAPABILITY_HMAC_KEY_BASE64: Buffer.alloc(32, 3).toString("base64"),
      SESSION_SECRET_BASE64: Buffer.alloc(32, 4).toString("base64"),
      CSRF_SECRET_BASE64: Buffer.alloc(32, 5).toString("base64"),
      MFA_ENCRYPTION_KEY_BASE64: Buffer.alloc(32, 6).toString("base64")
    })).toThrow();
  });

  it("rejects direct production ADMIN_TOTP_SECRET env and accepts secure *_FILE input", async () => {
    const totpFile = await tempFile("admin_totp", "JBSWY3DPEHPK3PXP");
    expect(() => loadConfig({
      ...envBase,
      NODE_ENV: "production",
      KCML_PROCESS_ROLE: "web",
      PUBLIC_BASE_DOMAIN: "hcasc.cz",
      ADMIN_HOST: "admin.hcasc.cz",
      AUTH_HOST: "auth.hcasc.cz",
      REGISTER_HOST: "register.hcasc.cz",
      BUILD_ID: "release-1",
      ACCESS_TOKEN_HMAC_KEY_BASE64: secret,
      INTEGRATION_TOKEN_HMAC_KEY_BASE64: Buffer.alloc(32, 2).toString("base64"),
      EGRESS_CAPABILITY_HMAC_KEY_BASE64: Buffer.alloc(32, 3).toString("base64"),
      SESSION_SECRET_BASE64: Buffer.alloc(32, 4).toString("base64"),
      CSRF_SECRET_BASE64: Buffer.alloc(32, 5).toString("base64"),
      MFA_ENCRYPTION_KEY_BASE64: Buffer.alloc(32, 6).toString("base64"),
      ADMIN_TOTP_SECRET: "JBSWY3DPEHPK3PXP"
    })).toThrow();
    expect(() => loadConfig({
      ...envBase,
      NODE_ENV: "production",
      KCML_PROCESS_ROLE: "web",
      PUBLIC_BASE_DOMAIN: "hcasc.cz",
      ADMIN_HOST: "admin.hcasc.cz",
      AUTH_HOST: "auth.hcasc.cz",
      REGISTER_HOST: "register.hcasc.cz",
      BUILD_ID: "release-1",
      ACCESS_TOKEN_HMAC_KEY_BASE64: secret,
      INTEGRATION_TOKEN_HMAC_KEY_BASE64: Buffer.alloc(32, 2).toString("base64"),
      EGRESS_CAPABILITY_HMAC_KEY_BASE64: Buffer.alloc(32, 3).toString("base64"),
      SESSION_SECRET_BASE64: Buffer.alloc(32, 4).toString("base64"),
      CSRF_SECRET_BASE64: Buffer.alloc(32, 5).toString("base64"),
      MFA_ENCRYPTION_KEY_BASE64: Buffer.alloc(32, 6).toString("base64"),
      ADMIN_TOTP_SECRET_FILE: totpFile
    })).not.toThrow();
    expect(() => loadConfig({
      ...envBase,
      NODE_ENV: "production",
      KCML_PROCESS_ROLE: "migrate",
      BUILD_ID: "release-1",
      ACCESS_TOKEN_HMAC_KEY_BASE64: secret,
      INTEGRATION_TOKEN_HMAC_KEY_BASE64: Buffer.alloc(32, 2).toString("base64"),
      EGRESS_CAPABILITY_HMAC_KEY_BASE64: Buffer.alloc(32, 3).toString("base64"),
      SESSION_SECRET_BASE64: Buffer.alloc(32, 4).toString("base64"),
      CSRF_SECRET_BASE64: Buffer.alloc(32, 5).toString("base64"),
      MFA_ENCRYPTION_KEY_BASE64: Buffer.alloc(32, 6).toString("base64")
    })).not.toThrow();
  });

  it("rejects unsafe production secret files", async () => {
    const worldReadable = await tempFile("secret", secret, 0o644);
    const oversized = await tempFile("oversized", "A".repeat(SECRET_FILE_BYTES));
    const symlinkDir = await mkdtemp(path.join(tmpdir(), "kcml-config-symlink-"));
    tempDirs.push(symlinkDir);
    const symlinkPath = path.join(symlinkDir, "secret-link");
    await symlink(worldReadable, symlinkPath);
    const productionBase = {
      ...envBase,
      NODE_ENV: "production",
      PUBLIC_BASE_DOMAIN: "hcasc.cz",
      ADMIN_HOST: "admin.hcasc.cz",
      AUTH_HOST: "auth.hcasc.cz",
      REGISTER_HOST: "register.hcasc.cz",
      BUILD_ID: "release-1"
    };
    expect(() => loadConfig({
      ...productionBase,
      ACCESS_TOKEN_HMAC_KEY_BASE64_FILE: worldReadable,
      INTEGRATION_TOKEN_HMAC_KEY_BASE64: Buffer.alloc(32, 2).toString("base64"),
      EGRESS_CAPABILITY_HMAC_KEY_BASE64: Buffer.alloc(32, 3).toString("base64"),
      SESSION_SECRET_BASE64: Buffer.alloc(32, 4).toString("base64"),
      CSRF_SECRET_BASE64: Buffer.alloc(32, 5).toString("base64"),
      MFA_ENCRYPTION_KEY_BASE64: Buffer.alloc(32, 6).toString("base64")
    })).toThrow();
    expect(() => loadConfig({
      ...productionBase,
      ACCESS_TOKEN_HMAC_KEY_BASE64_FILE: symlinkPath,
      INTEGRATION_TOKEN_HMAC_KEY_BASE64: Buffer.alloc(32, 2).toString("base64"),
      EGRESS_CAPABILITY_HMAC_KEY_BASE64: Buffer.alloc(32, 3).toString("base64"),
      SESSION_SECRET_BASE64: Buffer.alloc(32, 4).toString("base64"),
      CSRF_SECRET_BASE64: Buffer.alloc(32, 5).toString("base64"),
      MFA_ENCRYPTION_KEY_BASE64: Buffer.alloc(32, 6).toString("base64")
    })).toThrow();
    expect(() => loadConfig({
      ...productionBase,
      ACCESS_TOKEN_HMAC_KEY_BASE64_FILE: oversized,
      INTEGRATION_TOKEN_HMAC_KEY_BASE64: Buffer.alloc(32, 2).toString("base64"),
      EGRESS_CAPABILITY_HMAC_KEY_BASE64: Buffer.alloc(32, 3).toString("base64"),
      SESSION_SECRET_BASE64: Buffer.alloc(32, 4).toString("base64"),
      CSRF_SECRET_BASE64: Buffer.alloc(32, 5).toString("base64"),
      MFA_ENCRYPTION_KEY_BASE64: Buffer.alloc(32, 6).toString("base64")
    })).toThrow();
  });
});

const SECRET_FILE_BYTES = 16 * 1024 + 1;
