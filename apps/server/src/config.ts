import { timingSafeEqual } from "node:crypto";
import { lstatSync, readFileSync, statSync } from "node:fs";
import { z } from "zod";

const LOG_LEVELS = ["fatal", "error", "warn", "info", "debug", "trace", "silent"] as const;
const HOSTNAME_PATTERN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const CANONICAL_BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:|[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)$/;
const SECRET_FILE_MAX_BYTES = 16 * 1024;

type Base64Rule = {
  exactBytes?: number;
  minBytes?: number;
};

function assertCanonicalBase64(value: string, rule: Base64Rule, label: string): Buffer {
  if (!value) {
    if (rule.exactBytes === 0 || rule.minBytes === 0) return Buffer.alloc(0);
    throw new Error(`${label} must not be empty`);
  }
  if (/\s/.test(value)) throw new Error(`${label} must not contain whitespace`);
  if (!CANONICAL_BASE64_PATTERN.test(value)) throw new Error(`${label} must be canonical base64`);
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value) throw new Error(`${label} must round-trip as canonical base64`);
  if (rule.exactBytes !== undefined && decoded.length !== rule.exactBytes) {
    throw new Error(`${label} must decode to exactly ${rule.exactBytes} bytes`);
  }
  if (rule.minBytes !== undefined && decoded.length < rule.minBytes) {
    throw new Error(`${label} must decode to at least ${rule.minBytes} bytes`);
  }
  return decoded;
}

function requiredBase64SecretSchema(rule: Base64Rule) {
  const base = z.string().optional().default("");
  return base.transform((value, ctx) => {
    if (!value) return Buffer.alloc(0);
    try {
      return assertCanonicalBase64(value, rule, "secret");
    } catch (error) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: error instanceof Error ? error.message : "invalid secret"
      });
      return z.NEVER;
    }
  });
}

function optionalBase64SecretSchema(rule: Base64Rule) {
  const base = z.string().optional();
  return base.transform((value, ctx) => {
    if (!value) return undefined;
    try {
      return assertCanonicalBase64(value, rule, "secret");
    } catch (error) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: error instanceof Error ? error.message : "invalid secret"
      });
      return z.NEVER;
    }
  });
}

function normalizeHostname(value: string, label: string): string {
  const trimmed = value.trim();
  const normalized = trimmed.toLowerCase();
  if (!normalized) throw new Error(`${label} is required`);
  if (trimmed !== normalized) throw new Error(`${label} must be lowercase`);
  if (normalized.endsWith(".")) throw new Error(`${label} must not have a trailing dot`);
  if (/[/?#:\s]/.test(normalized) || normalized.includes("://")) throw new Error(`${label} must be a bare hostname`);
  if (!HOSTNAME_PATTERN.test(normalized)) throw new Error(`${label} must be a valid DNS hostname`);
  return normalized;
}

function hostnameSchema(label: string, defaultValue?: string) {
  const schema = defaultValue === undefined ? z.string() : z.string().default(defaultValue);
  return schema.transform((value, ctx) => {
    try {
      return normalizeHostname(value, label);
    } catch (error) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: error instanceof Error ? error.message : `invalid ${label}`
      });
      return z.NEVER;
    }
  });
}

function validateGitHubToken(value: string): string {
  if (!value.trim()) throw new Error("GITHUB_TOKEN must not be blank");
  if (/\s/.test(value)) throw new Error("GITHUB_TOKEN must not contain whitespace");
  if (value.length < 20) throw new Error("GITHUB_TOKEN is too short");
  return value;
}

function readSecretFile(env: NodeJS.ProcessEnv, key: string): string | undefined {
  const file = env[`${key}_FILE`];
  if (!file) return undefined;
  const strict = (env.NODE_ENV ?? "development") === "production";
  const metadata = lstatSync(file);
  if (strict && metadata.isSymbolicLink()) throw new Error(`${key}_FILE must not be a symlink in production`);
  const target = metadata.isSymbolicLink() ? statSync(file) : metadata;
  if (!target.isFile()) throw new Error(`${key}_FILE must point to a regular file`);
  if (strict) {
    const ownerOk = target.uid === process.getuid?.() || target.uid === 0;
    if (!ownerOk) throw new Error(`${key}_FILE has an unexpected owner`);
    if ((target.mode & 0o077) !== 0) throw new Error(`${key}_FILE must not be group/world readable`);
  }
  if (target.size > SECRET_FILE_MAX_BYTES) throw new Error(`${key}_FILE exceeds the maximum supported size`);
  const value = readFileSync(file, "utf8").trim();
  if (!value) throw new Error(`${key}_FILE is empty`);
  return value;
}

function sameSecretBytes(left: Buffer, right: Buffer): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
}

const optionalBase64Secret = optionalBase64SecretSchema({ minBytes: 32 });
const roleBase64Secret = requiredBase64SecretSchema({ minBytes: 32 });
const exactMfaKey = z.string().optional().default("").transform((value, ctx) => {
  if (!value) return Buffer.alloc(0);
  try {
    return assertCanonicalBase64(value, { exactBytes: 32 }, "MFA_ENCRYPTION_KEY_BASE64");
  } catch (error) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: error instanceof Error ? error.message : "invalid MFA key"
    });
    return z.NEVER;
  }
});

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  KCML_PROCESS_ROLE: z.enum(["all", "web", "worker", "monitor", "egress", "migrate", "admin-sync"]).default("all"),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  PUBLIC_BASE_DOMAIN: hostnameSchema("PUBLIC_BASE_DOMAIN", "hcasc.cz"),
  DATABASE_URL: z.string().min(1),
  ACCESS_TOKEN_HMAC_KEY_BASE64: roleBase64Secret,
  ACCESS_TOKEN_HMAC_KEY_ID: z.string().min(1).default("v1"),
  INTEGRATION_TOKEN_HMAC_KEY_BASE64: roleBase64Secret,
  INTEGRATION_TOKEN_HMAC_KEY_ID: z.string().min(1).default("v1"),
  EGRESS_CAPABILITY_HMAC_KEY_BASE64: roleBase64Secret,
  SESSION_SECRET_BASE64: roleBase64Secret,
  CSRF_SECRET_BASE64: roleBase64Secret,
  MFA_ENCRYPTION_KEY_BASE64: exactMfaKey,
  ADMIN_BOOTSTRAP_USERNAME: z.literal("karmar78").default("karmar78"),
  ADMIN_TOTP_SECRET: z.string().min(16).optional(),
  ADMIN_HOST: hostnameSchema("ADMIN_HOST", "admin.hcasc.cz"),
  AUTH_HOST: hostnameSchema("AUTH_HOST", "auth.hcasc.cz"),
  REGISTER_HOST: hostnameSchema("REGISTER_HOST", "register.hcasc.cz"),
  QUARANTINE_ROOT: z.string().default("/var/lib/kcml/onboarding"),
  ONBOARDING_WORKER_ENABLED: z.string().optional().transform((value) => value === "true"),
  ONBOARDING_WORKER_INTERVAL_MS: z.coerce.number().int().min(1_000).default(15_000),
  MONITOR_ENABLED: z.string().optional().transform((value) => value === "true"),
  MONITOR_INTERVAL_MS: z.coerce.number().int().min(15_000).max(900_000).default(60_000),
  ALERT_PRIMARY_WEBHOOK_URL: z.string().url().startsWith("https://").optional(),
  ALERT_PRIMARY_HMAC_KEY_BASE64: optionalBase64Secret,
  ALERT_BACKUP_WEBHOOK_URL: z.string().url().startsWith("https://").optional(),
  ALERT_BACKUP_HMAC_KEY_BASE64: optionalBase64Secret,
  GITHUB_OWNER: z.string().min(1).optional(),
  GITHUB_REPO: z.string().min(1).optional(),
  GITHUB_TOKEN: z.string().optional().transform((value, ctx) => {
    if (!value) return undefined;
    try {
      return validateGitHubToken(value);
    } catch (error) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: error instanceof Error ? error.message : "invalid GITHUB_TOKEN" });
      return z.NEVER;
    }
  }),
  GITHUB_APP_ID: z.string().min(1).optional(),
  GITHUB_APP_INSTALLATION_ID: z.string().min(1).optional(),
  GITHUB_APP_PRIVATE_KEY_BASE64: z.string().min(1).optional(),
  OCI_REGISTRY: z.string().default("ghcr.io"),
  OCI_IMAGE_NAMESPACE: z.string().min(1).optional(),
  OCI_CERTIFICATE_IDENTITY: z.string().url().startsWith("https://github.com/").optional(),
  OCI_CERTIFICATE_OIDC_ISSUER: z.string().url().default("https://token.actions.githubusercontent.com"),
  PODMAN_BINARY: z.string().default("podman"),
  COSIGN_BINARY: z.string().default("cosign"),
  RUNTIME_SOCKET_ROOT: z.string().default("/var/lib/kcml/runtime"),
  EGRESS_PROXY_SOCKET_PATH: z.string().default("/var/lib/kcml/egress/proxy.sock"),
  WILDCARD_TLS_CERT_PATH: z.string().default("/etc/letsencrypt/live/wildcard.hcasc.cz/fullchain.pem"),
  TRUSTED_PROXY_CIDRS: z.string().default("127.0.0.1,::1").transform((value) => value.split(",").map((item) => item.trim()).filter(Boolean)),
  BUILD_ID: z.string().min(1).default("local"),
  LOG_LEVEL: z.enum(LOG_LEVELS).default("info"),
  MFA_ALLOW_PLAINTEXT_LEGACY: z.string().optional().transform((value) => value === "true")
}).superRefine((config, ctx) => {
  const requiredSecrets: Partial<Record<typeof config.KCML_PROCESS_ROLE, Array<keyof typeof config>>> = {
    all: ["ACCESS_TOKEN_HMAC_KEY_BASE64", "INTEGRATION_TOKEN_HMAC_KEY_BASE64", "EGRESS_CAPABILITY_HMAC_KEY_BASE64", "SESSION_SECRET_BASE64", "CSRF_SECRET_BASE64", "MFA_ENCRYPTION_KEY_BASE64"],
    web: ["ACCESS_TOKEN_HMAC_KEY_BASE64", "INTEGRATION_TOKEN_HMAC_KEY_BASE64", "EGRESS_CAPABILITY_HMAC_KEY_BASE64", "SESSION_SECRET_BASE64", "CSRF_SECRET_BASE64", "MFA_ENCRYPTION_KEY_BASE64"],
    monitor: ["EGRESS_CAPABILITY_HMAC_KEY_BASE64"],
    worker: ["EGRESS_CAPABILITY_HMAC_KEY_BASE64"],
    egress: ["EGRESS_CAPABILITY_HMAC_KEY_BASE64"],
    "admin-sync": ["MFA_ENCRYPTION_KEY_BASE64"]
  };
  for (const key of requiredSecrets[config.KCML_PROCESS_ROLE] ?? []) {
    const value = config[key];
    if (!Buffer.isBuffer(value) || value.length < 32) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: [key], message: `${String(key)} is required for ${config.KCML_PROCESS_ROLE}` });
    }
  }
  const independentKeyPairs = [
    ["ACCESS_TOKEN_HMAC_KEY_BASE64", "INTEGRATION_TOKEN_HMAC_KEY_BASE64"],
    ["ACCESS_TOKEN_HMAC_KEY_BASE64", "EGRESS_CAPABILITY_HMAC_KEY_BASE64"],
    ["ACCESS_TOKEN_HMAC_KEY_BASE64", "SESSION_SECRET_BASE64"],
    ["ACCESS_TOKEN_HMAC_KEY_BASE64", "CSRF_SECRET_BASE64"],
    ["ACCESS_TOKEN_HMAC_KEY_BASE64", "MFA_ENCRYPTION_KEY_BASE64"],
    ["INTEGRATION_TOKEN_HMAC_KEY_BASE64", "EGRESS_CAPABILITY_HMAC_KEY_BASE64"],
    ["INTEGRATION_TOKEN_HMAC_KEY_BASE64", "SESSION_SECRET_BASE64"],
    ["INTEGRATION_TOKEN_HMAC_KEY_BASE64", "CSRF_SECRET_BASE64"],
    ["INTEGRATION_TOKEN_HMAC_KEY_BASE64", "MFA_ENCRYPTION_KEY_BASE64"],
    ["EGRESS_CAPABILITY_HMAC_KEY_BASE64", "SESSION_SECRET_BASE64"],
    ["EGRESS_CAPABILITY_HMAC_KEY_BASE64", "CSRF_SECRET_BASE64"],
    ["EGRESS_CAPABILITY_HMAC_KEY_BASE64", "MFA_ENCRYPTION_KEY_BASE64"],
    ["SESSION_SECRET_BASE64", "CSRF_SECRET_BASE64"],
    ["SESSION_SECRET_BASE64", "MFA_ENCRYPTION_KEY_BASE64"],
    ["CSRF_SECRET_BASE64", "MFA_ENCRYPTION_KEY_BASE64"],
    ["ALERT_PRIMARY_HMAC_KEY_BASE64", "ALERT_BACKUP_HMAC_KEY_BASE64"],
    ["ALERT_PRIMARY_HMAC_KEY_BASE64", "EGRESS_CAPABILITY_HMAC_KEY_BASE64"],
    ["ALERT_BACKUP_HMAC_KEY_BASE64", "EGRESS_CAPABILITY_HMAC_KEY_BASE64"]
  ] as const;
  for (const [leftKey, rightKey] of independentKeyPairs) {
    const left = config[leftKey];
    const right = config[rightKey];
    if (Buffer.isBuffer(left) && Buffer.isBuffer(right) && left.length && right.length && sameSecretBytes(left, right)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: [rightKey],
        message: `${leftKey} and ${rightKey} must be independent`
      });
    }
  }
  if (config.ONBOARDING_WORKER_ENABLED && ["all", "worker"].includes(config.KCML_PROCESS_ROLE)) {
    for (const key of ["GITHUB_OWNER", "GITHUB_REPO", "OCI_IMAGE_NAMESPACE", "OCI_CERTIFICATE_IDENTITY"] as const) {
      if (!config[key]) ctx.addIssue({ code: z.ZodIssueCode.custom, path: [key], message: `${key} is required when onboarding worker is enabled` });
    }
    if (!config.GITHUB_TOKEN) {
      for (const key of ["GITHUB_APP_ID", "GITHUB_APP_INSTALLATION_ID", "GITHUB_APP_PRIVATE_KEY_BASE64"] as const) {
        if (!config[key]) ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: [key],
          message: `${key} is required when onboarding worker uses GitHub App authentication`
        });
      }
    }
  }
  if (config.MONITOR_ENABLED && ["all", "monitor"].includes(config.KCML_PROCESS_ROLE)) {
    for (const key of ["ALERT_PRIMARY_WEBHOOK_URL", "ALERT_PRIMARY_HMAC_KEY_BASE64", "ALERT_BACKUP_WEBHOOK_URL", "ALERT_BACKUP_HMAC_KEY_BASE64"] as const) {
      if (!config[key]) ctx.addIssue({ code: z.ZodIssueCode.custom, path: [key], message: `${key} is required when monitor is enabled` });
    }
    if (config.ALERT_PRIMARY_WEBHOOK_URL === config.ALERT_BACKUP_WEBHOOK_URL) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["ALERT_BACKUP_WEBHOOK_URL"], message: "backup alert webhook must be independent" });
    }
  }
  if (![config.ADMIN_HOST, config.AUTH_HOST, config.REGISTER_HOST].every((host) => host.endsWith(`.${config.PUBLIC_BASE_DOMAIN}`))) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["PUBLIC_BASE_DOMAIN"], message: "admin/auth/register hosts must be subdomains of PUBLIC_BASE_DOMAIN" });
  }
  if (new Set([config.ADMIN_HOST, config.AUTH_HOST, config.REGISTER_HOST]).size !== 3) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["ADMIN_HOST"], message: "ADMIN_HOST, AUTH_HOST and REGISTER_HOST must be distinct" });
  }
  if (config.NODE_ENV === "production" && config.BUILD_ID === "local") {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["BUILD_ID"], message: "BUILD_ID is required in production" });
  }
  if (config.NODE_ENV === "production" && config.MFA_ALLOW_PLAINTEXT_LEGACY) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["MFA_ALLOW_PLAINTEXT_LEGACY"], message: "legacy plaintext MFA mode is not allowed in production" });
  }
});

export type AppConfig = z.infer<typeof envSchema>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const resolved = { ...env };
  for (const key of [
    "DATABASE_URL",
    "ACCESS_TOKEN_HMAC_KEY_BASE64",
    "INTEGRATION_TOKEN_HMAC_KEY_BASE64",
    "EGRESS_CAPABILITY_HMAC_KEY_BASE64",
    "SESSION_SECRET_BASE64",
    "CSRF_SECRET_BASE64",
    "MFA_ENCRYPTION_KEY_BASE64",
    "ADMIN_TOTP_SECRET",
    "ALERT_PRIMARY_HMAC_KEY_BASE64",
    "ALERT_BACKUP_HMAC_KEY_BASE64",
    "GITHUB_TOKEN",
    "GITHUB_APP_PRIVATE_KEY_BASE64"
  ] as const) {
    if (!resolved[key]) resolved[key] = readSecretFile(env, key);
  }
  const config = envSchema.parse(resolved);
  if (config.NODE_ENV === "production") {
    const requiredProductionKeys: Array<keyof AppConfig> = ["BUILD_ID"];
    if (["web", "worker", "monitor", "egress"].includes(config.KCML_PROCESS_ROLE)) {
      requiredProductionKeys.push("PUBLIC_BASE_DOMAIN");
    }
    if (["web", "monitor"].includes(config.KCML_PROCESS_ROLE)) {
      requiredProductionKeys.push("ADMIN_HOST", "AUTH_HOST", "REGISTER_HOST");
    }
    for (const key of requiredProductionKeys) {
      if (!env[key]) throw new Error(`${key} must be explicitly set in production`);
    }
    if (env.ADMIN_TOTP_SECRET) throw new Error("ADMIN_TOTP_SECRET must not be provided directly in production");
  }
  return config;
}
