import { readFileSync } from "node:fs";
import { z } from "zod";

const optionalBase64Secret = z.string().min(32).optional().transform((value, ctx) => {
  if (!value) return undefined;
  const decoded = Buffer.from(value, "base64");
  if (decoded.length < 32) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "secret must decode to at least 32 bytes" });
    return z.NEVER;
  }
  return decoded;
});
const roleBase64Secret = z.string().optional().default("").transform((value, ctx) => {
  if (!value) return Buffer.alloc(0);
  const decoded = Buffer.from(value, "base64");
  if (decoded.length < 32) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "secret must decode to at least 32 bytes" });
    return z.NEVER;
  }
  return decoded;
});

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  KCML_PROCESS_ROLE: z.enum(["all", "web", "worker", "monitor", "egress", "migrate", "admin-sync"]).default("all"),
  PORT: z.coerce.number().int().positive().default(3000),
  PUBLIC_BASE_DOMAIN: z.string().default("hcasc.cz"),
  DATABASE_URL: z.string().min(1),
  ACCESS_TOKEN_HMAC_KEY_BASE64: roleBase64Secret,
  ACCESS_TOKEN_HMAC_KEY_ID: z.string().min(1).default("v1"),
  INTEGRATION_TOKEN_HMAC_KEY_BASE64: roleBase64Secret,
  INTEGRATION_TOKEN_HMAC_KEY_ID: z.string().min(1).default("v1"),
  EGRESS_CAPABILITY_HMAC_KEY_BASE64: roleBase64Secret,
  SESSION_SECRET_BASE64: roleBase64Secret,
  CSRF_SECRET_BASE64: roleBase64Secret,
  MFA_ENCRYPTION_KEY_BASE64: roleBase64Secret,
  ADMIN_BOOTSTRAP_USERNAME: z.literal("karmar78").default("karmar78"),
  ADMIN_TOTP_SECRET: z.string().min(16).optional(),
  ADMIN_HOST: z.string().default("admin.hcasc.cz"),
  AUTH_HOST: z.string().default("auth.hcasc.cz"),
  REGISTER_HOST: z.string().default("register.hcasc.cz"),
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
  GITHUB_TOKEN: z.string().min(20).optional(),
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
  LOG_LEVEL: z.string().default("info")
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
  if (config.ACCESS_TOKEN_HMAC_KEY_BASE64.length && config.ACCESS_TOKEN_HMAC_KEY_BASE64.equals(config.INTEGRATION_TOKEN_HMAC_KEY_BASE64)) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["INTEGRATION_TOKEN_HMAC_KEY_BASE64"], message: "integration token HMAC key must be independent" });
  }
  if (config.EGRESS_CAPABILITY_HMAC_KEY_BASE64.length && (config.EGRESS_CAPABILITY_HMAC_KEY_BASE64.equals(config.INTEGRATION_TOKEN_HMAC_KEY_BASE64)
      || config.EGRESS_CAPABILITY_HMAC_KEY_BASE64.equals(config.ACCESS_TOKEN_HMAC_KEY_BASE64))) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["EGRESS_CAPABILITY_HMAC_KEY_BASE64"], message: "egress capability HMAC key must be independent" });
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
  if (config.NODE_ENV === "production" && config.BUILD_ID === "local") {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["BUILD_ID"], message: "BUILD_ID is required in production" });
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
    const file = env[`${key}_FILE`];
    if (!resolved[key] && file) {
      const value = readFileSync(file, "utf8").trim();
      if (value) resolved[key] = value;
    }
  }
  return envSchema.parse(resolved);
}
