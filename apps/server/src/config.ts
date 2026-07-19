import { timingSafeEqual } from "node:crypto";
import { lstatSync, readFileSync, statSync } from "node:fs";
import { isAbsolute, relative, resolve } from "node:path";
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

function validateTimeZone(value: string): string {
  const normalized = value.trim();
  try {
    new Intl.DateTimeFormat("en", { timeZone: normalized }).format(0);
  } catch {
    throw new Error("UI_TIME_ZONE must be a valid IANA time zone");
  }
  return normalized;
}

function normalizeAdminUsername(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length < 3 || trimmed.length > 120) throw new Error("ADMIN_BOOTSTRAP_USERNAME must be 3-120 characters long");
  if (trimmed !== trimmed.toLowerCase()) throw new Error("ADMIN_BOOTSTRAP_USERNAME must be lowercase");
  if (!/^[a-z0-9._-]+$/.test(trimmed)) throw new Error("ADMIN_BOOTSTRAP_USERNAME contains unsupported characters");
  return trimmed;
}

function isWithinDirectory(file: string, directory: string): boolean {
  const relativePath = relative(resolve(directory), resolve(file));
  return relativePath !== "" && !relativePath.startsWith("..") && !isAbsolute(relativePath);
}

function isSystemdCredentialFile(env: NodeJS.ProcessEnv, file: string): boolean {
  const credentialsDirectory = env.CREDENTIALS_DIRECTORY;
  return Boolean(credentialsDirectory && isWithinDirectory(file, credentialsDirectory));
}

function readSecretFile(env: NodeJS.ProcessEnv, key: string): string | undefined {
  const file = env[`${key}_FILE`];
  if (!file) return undefined;
  const strict = (env.NODE_ENV ?? "development") === "production";
  const systemdCredential = strict && isSystemdCredentialFile(env, file);
  const metadata = lstatSync(file);
  if (strict && metadata.isSymbolicLink()) throw new Error(`${key}_FILE must not be a symlink in production`);
  const target = metadata.isSymbolicLink() ? statSync(file) : metadata;
  if (!target.isFile()) throw new Error(`${key}_FILE must point to a regular file`);
  if (strict) {
    const ownerOk = target.uid === process.getuid?.() || target.uid === 0;
    if (!ownerOk) throw new Error(`${key}_FILE has an unexpected owner`);
    if (systemdCredential) {
      const credentialsDirectory = env.CREDENTIALS_DIRECTORY!;
      const credentialsMetadata = lstatSync(credentialsDirectory);
      if (!credentialsMetadata.isDirectory()) throw new Error("CREDENTIALS_DIRECTORY must be a directory");
      if (credentialsMetadata.isSymbolicLink()) throw new Error("CREDENTIALS_DIRECTORY must not be a symlink in production");
      const credentialsOwnerOk = credentialsMetadata.uid === process.getuid?.() || credentialsMetadata.uid === 0;
      if (!credentialsOwnerOk) throw new Error("CREDENTIALS_DIRECTORY has an unexpected owner");
      if ((target.mode & 0o007) !== 0) throw new Error(`${key}_FILE must not be world accessible`);
    } else if ((target.mode & 0o077) !== 0) {
      throw new Error(`${key}_FILE must not be group/world readable`);
    }
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
const vaultMasterKey = z.string().optional().default("").transform((value, ctx) => {
  if (!value) return Buffer.alloc(0);
  try {
    return assertCanonicalBase64(value, { exactBytes: 32 }, "CONFIG_VAULT_MASTER_KEY_BASE64");
  } catch (error) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: error instanceof Error ? error.message : "invalid config vault key" });
    return z.NEVER;
  }
});
const adminBootstrapUsername = z.string().default("owner").transform((value, ctx) => {
  try {
    return normalizeAdminUsername(value);
  } catch (error) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: error instanceof Error ? error.message : "invalid ADMIN_BOOTSTRAP_USERNAME"
    });
    return z.NEVER;
  }
});

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  KCML_PROCESS_ROLE: z.enum(["all", "web", "worker", "monitor", "egress", "migrate", "admin-sync"]).default("all"),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  PUBLIC_BASE_DOMAIN: hostnameSchema("PUBLIC_BASE_DOMAIN", "example.invalid"),
  DATABASE_URL: z.string().min(1),
  CONFIG_VAULT_MASTER_KEY_BASE64: vaultMasterKey,
  CONFIG_VAULT_MASTER_KEY_ID: z.string().trim().min(1).max(120).default("config-v1"),
  ACCESS_TOKEN_HMAC_KEY_BASE64: roleBase64Secret,
  ACCESS_TOKEN_HMAC_KEY_ID: z.string().min(1).default("v1"),
  INTEGRATION_TOKEN_HMAC_KEY_BASE64: roleBase64Secret,
  INTEGRATION_TOKEN_HMAC_KEY_ID: z.string().min(1).default("v1"),
  EGRESS_CAPABILITY_HMAC_KEY_BASE64: roleBase64Secret,
  SESSION_SECRET_BASE64: roleBase64Secret,
  CSRF_SECRET_BASE64: roleBase64Secret,
  MFA_ENCRYPTION_KEY_BASE64: exactMfaKey,
  ADMIN_BOOTSTRAP_USERNAME: adminBootstrapUsername,
  ADMIN_BOOTSTRAP_SECRET: z.string().min(32).max(512).optional(),
  ADMIN_TOTP_SECRET: z.string().min(16).optional(),
  ADMIN_HOST: hostnameSchema("ADMIN_HOST", "admin.example.invalid"),
  AUTH_HOST: hostnameSchema("AUTH_HOST", "auth.example.invalid"),
  REGISTER_HOST: hostnameSchema("REGISTER_HOST", "register.example.invalid"),
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
  WILDCARD_TLS_CERT_PATH: z.string().default("/etc/kcml/tls/fullchain.pem"),
  TRUSTED_PROXY_CIDRS: z.string().default("127.0.0.1,::1").transform((value) => value.split(",").map((item) => item.trim()).filter(Boolean)),
  BUILD_ID: z.string().min(1).default("local"),
  LOG_LEVEL: z.enum(LOG_LEVELS).default("info"),
  AUDIT_ARCHIVE_PATH: z.string().min(1).default("/var/lib/kcml/audit/archive.jsonl"),
  UI_TIME_ZONE: z.string().default("Europe/Prague").transform((value, ctx) => {
    try {
      return validateTimeZone(value);
    } catch (error) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: error instanceof Error ? error.message : "invalid time zone" });
      return z.NEVER;
    }
  }),
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

type ParsedEnvConfig = z.infer<typeof envSchema>;
export type MutableRuntimeConfigKey = "ONBOARDING_WORKER_INTERVAL_MS" | "MONITOR_INTERVAL_MS" | "LOG_LEVEL" | "UI_TIME_ZONE";

const mutableRuntimeConfigKeys = ["ONBOARDING_WORKER_INTERVAL_MS", "MONITOR_INTERVAL_MS", "LOG_LEVEL", "UI_TIME_ZONE"] as const satisfies ReadonlyArray<MutableRuntimeConfigKey>;

const bootstrapEnvSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  KCML_PROCESS_ROLE: z.enum(["all", "web", "worker", "monitor", "egress", "migrate", "admin-sync"]).default("all"),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  DATABASE_URL: z.string().min(1),
  CONFIG_VAULT_MASTER_KEY_BASE64: vaultMasterKey,
  CONFIG_VAULT_MASTER_KEY_ID: z.string().trim().min(1).max(120).default("config-v1")
}).superRefine((config, ctx) => {
  if (config.NODE_ENV === "production" && config.KCML_PROCESS_ROLE !== "migrate" && config.CONFIG_VAULT_MASTER_KEY_BASE64.length !== 32) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["CONFIG_VAULT_MASTER_KEY_BASE64"], message: "config vault master key is required in production" });
  }
});

export type BootstrapConfig = z.infer<typeof bootstrapEnvSchema>;
export type RuntimeConfig = ParsedEnvConfig;
export type AppConfig = ParsedEnvConfig;
export type RuntimeDefaultsConfig = Partial<Pick<RuntimeConfig, MutableRuntimeConfigKey>>;
export type DatabaseConfig = Pick<BootstrapConfig, "DATABASE_URL">;
export type HostRoutingConfig = Pick<AppConfig, "PUBLIC_BASE_DOMAIN" | "ADMIN_HOST" | "AUTH_HOST" | "REGISTER_HOST">;
export type WebAppConfig = HostRoutingConfig & Pick<AppConfig, "NODE_ENV" | "LOG_LEVEL" | "TRUSTED_PROXY_CIDRS" | "SESSION_SECRET_BASE64">;
export type OAuthConfig = Pick<AppConfig, "AUTH_HOST" | "ACCESS_TOKEN_HMAC_KEY_BASE64" | "ACCESS_TOKEN_HMAC_KEY_ID">;
export type ReferenceExternalApiConfig = Pick<AppConfig, "PUBLIC_BASE_DOMAIN">;
export type McpHttpConfig = Pick<AppConfig, "PUBLIC_BASE_DOMAIN" | "AUTH_HOST" | "ACCESS_TOKEN_HMAC_KEY_BASE64">;
export type IntegrationTokenConfig = Pick<AppConfig, "INTEGRATION_TOKEN_HMAC_KEY_BASE64" | "INTEGRATION_TOKEN_HMAC_KEY_ID">;
export type EgressClientConfig = Pick<AppConfig, "EGRESS_PROXY_SOCKET_PATH" | "EGRESS_CAPABILITY_HMAC_KEY_BASE64">;
export type OnboardingRouteConfig = HostRoutingConfig & IntegrationTokenConfig & Pick<AppConfig, "QUARANTINE_ROOT" | "ONBOARDING_WORKER_ENABLED" | "MFA_ENCRYPTION_KEY_BASE64" | "MFA_ALLOW_PLAINTEXT_LEGACY" | "SESSION_SECRET_BASE64" | "EGRESS_PROXY_SOCKET_PATH" | "EGRESS_CAPABILITY_HMAC_KEY_BASE64">;
export type ExternalApiRegistrationConfig = Pick<AppConfig, "PUBLIC_BASE_DOMAIN"> & EgressClientConfig;
export type ReadinessConfig = Pick<AppConfig, "MONITOR_ENABLED" | "MONITOR_INTERVAL_MS" | "BUILD_ID">;
export type AdminSessionConfig = Pick<AppConfig, "SESSION_SECRET_BASE64">;
export type AdminReauthConfig = Pick<AppConfig, "MFA_ENCRYPTION_KEY_BASE64" | "MFA_ALLOW_PLAINTEXT_LEGACY">;
export type AdminRoutesConfig = HostRoutingConfig
  & AdminSessionConfig
  & AdminReauthConfig
  & ReadinessConfig
  & Pick<AppConfig, "ADMIN_BOOTSTRAP_USERNAME" | "ADMIN_BOOTSTRAP_SECRET" | "BUILD_ID" | "CONFIG_VAULT_MASTER_KEY_BASE64" | "CONFIG_VAULT_MASTER_KEY_ID" | "ACCESS_TOKEN_HMAC_KEY_BASE64" | "INTEGRATION_TOKEN_HMAC_KEY_BASE64" | "INTEGRATION_TOKEN_HMAC_KEY_ID">;
export type ExternalApiGatewayConfig = Pick<AppConfig, "PUBLIC_BASE_DOMAIN" | "ACCESS_TOKEN_HMAC_KEY_BASE64"> & EgressClientConfig;
export type AlertDeliveryConfig = Pick<AppConfig, "ALERT_PRIMARY_WEBHOOK_URL" | "ALERT_PRIMARY_HMAC_KEY_BASE64" | "ALERT_BACKUP_WEBHOOK_URL" | "ALERT_BACKUP_HMAC_KEY_BASE64">;
export type GitHubOnboardingConfig = Pick<AppConfig, "GITHUB_TOKEN" | "GITHUB_APP_ID" | "GITHUB_APP_INSTALLATION_ID" | "GITHUB_APP_PRIVATE_KEY_BASE64" | "GITHUB_OWNER" | "GITHUB_REPO">;
export type ActivationConfig = Pick<AppConfig, "AUTH_HOST" | "PUBLIC_BASE_DOMAIN">;
export type EgressProxyConfig = EgressClientConfig & Pick<AppConfig, "NODE_ENV">;
export type OciRuntimeConfig = Pick<AppConfig, "OCI_IMAGE_NAMESPACE" | "OCI_REGISTRY" | "OCI_CERTIFICATE_IDENTITY" | "OCI_CERTIFICATE_OIDC_ISSUER" | "PODMAN_BINARY" | "COSIGN_BINARY" | "RUNTIME_SOCKET_ROOT" | "EGRESS_PROXY_SOCKET_PATH">;
export type WorkerConfig = GitHubOnboardingConfig & ActivationConfig & EgressClientConfig & OciRuntimeConfig & Pick<AppConfig, "ONBOARDING_WORKER_INTERVAL_MS">;
export type MonitoringConfig = AlertDeliveryConfig & EgressClientConfig & OciRuntimeConfig & Pick<AppConfig, "AUTH_HOST" | "MONITOR_INTERVAL_MS" | "AUDIT_ARCHIVE_PATH">;
export type AppServerConfig = WebAppConfig
  & AdminRoutesConfig
  & OAuthConfig
  & McpHttpConfig
  & ExternalApiGatewayConfig
  & OnboardingRouteConfig;

export function runtimeConfigDefaults(config: RuntimeDefaultsConfig = {}): Pick<RuntimeConfig, MutableRuntimeConfigKey> {
  return {
    ONBOARDING_WORKER_INTERVAL_MS: config.ONBOARDING_WORKER_INTERVAL_MS ?? 15_000,
    MONITOR_INTERVAL_MS: config.MONITOR_INTERVAL_MS ?? 60_000,
    LOG_LEVEL: config.LOG_LEVEL ?? "info",
    UI_TIME_ZONE: config.UI_TIME_ZONE ?? "Europe/Prague"
  };
}

function parseConfig(env: NodeJS.ProcessEnv, options: { allowAdminTotpSecret?: boolean } = {}): ParsedEnvConfig {
  const resolved = { ...env };
  for (const key of [
    "DATABASE_URL",
    "CONFIG_VAULT_MASTER_KEY_BASE64",
    "ACCESS_TOKEN_HMAC_KEY_BASE64",
    "INTEGRATION_TOKEN_HMAC_KEY_BASE64",
    "EGRESS_CAPABILITY_HMAC_KEY_BASE64",
    "SESSION_SECRET_BASE64",
    "CSRF_SECRET_BASE64",
    "MFA_ENCRYPTION_KEY_BASE64",
    "ADMIN_BOOTSTRAP_SECRET",
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
    if (["all", "web", "worker", "monitor", "egress"].includes(config.KCML_PROCESS_ROLE)) {
      requiredProductionKeys.push("PUBLIC_BASE_DOMAIN");
    }
    if (["all", "web", "monitor"].includes(config.KCML_PROCESS_ROLE)) {
      requiredProductionKeys.push("ADMIN_HOST", "AUTH_HOST", "REGISTER_HOST");
    }
    for (const key of requiredProductionKeys) {
      if (!env[key]) throw new Error(`${key} must be explicitly set in production`);
    }
    if (env.ADMIN_TOTP_SECRET && !options.allowAdminTotpSecret) {
      throw new Error("ADMIN_TOTP_SECRET must not be provided directly in production");
    }
  }
  return config;
}

export function loadBootstrapConfig(env: NodeJS.ProcessEnv = process.env): BootstrapConfig {
  const resolved = { ...env };
  if (!resolved.DATABASE_URL) resolved.DATABASE_URL = readSecretFile(env, "DATABASE_URL");
  if (!resolved.CONFIG_VAULT_MASTER_KEY_BASE64) {
    resolved.CONFIG_VAULT_MASTER_KEY_BASE64 = readSecretFile(env, "CONFIG_VAULT_MASTER_KEY_BASE64");
  }
  return bootstrapEnvSchema.parse(resolved);
}

// Legacy environment parsing is intentionally explicit and is only used by
// migration tooling and tests. Production runtime entry points use the DB provider.
export function loadConfig(env: NodeJS.ProcessEnv, options: { allowAdminTotpSecret?: boolean } = {}): AppConfig {
  return parseConfig(env, options);
}

export function parseStoredRuntimeConfig(bootstrap: BootstrapConfig, values: NodeJS.ProcessEnv): AppConfig {
  return envSchema.parse({
    ...values,
    NODE_ENV: bootstrap.NODE_ENV,
    KCML_PROCESS_ROLE: bootstrap.KCML_PROCESS_ROLE,
    PORT: String(bootstrap.PORT),
    DATABASE_URL: bootstrap.DATABASE_URL,
    CONFIG_VAULT_MASTER_KEY_BASE64: bootstrap.CONFIG_VAULT_MASTER_KEY_BASE64.toString("base64"),
    CONFIG_VAULT_MASTER_KEY_ID: bootstrap.CONFIG_VAULT_MASTER_KEY_ID
  });
}

export const mutableRuntimeConfigEnvKeys = [...mutableRuntimeConfigKeys];
