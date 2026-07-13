import { z } from "zod";

const base64Secret = z.string().min(32).transform((value, ctx) => {
  const decoded = Buffer.from(value, "base64");
  if (decoded.length < 32) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "secret must decode to at least 32 bytes" });
    return z.NEVER;
  }
  return decoded;
});

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().positive().default(3000),
  PUBLIC_BASE_DOMAIN: z.string().default("hcasc.cz"),
  DATABASE_URL: z.string().min(1),
  ACCESS_TOKEN_HMAC_KEY_BASE64: base64Secret,
  ACCESS_TOKEN_HMAC_KEY_ID: z.string().min(1).default("v1"),
  INTEGRATION_TOKEN_HMAC_KEY_BASE64: base64Secret,
  INTEGRATION_TOKEN_HMAC_KEY_ID: z.string().min(1).default("v1"),
  EGRESS_CAPABILITY_HMAC_KEY_BASE64: base64Secret,
  SESSION_SECRET_BASE64: base64Secret,
  CSRF_SECRET_BASE64: base64Secret,
  MFA_ENCRYPTION_KEY_BASE64: base64Secret,
  ADMIN_TOTP_SECRET: z.string().min(16).optional(),
  ADMIN_HOST: z.string().default("admin.hcasc.cz"),
  AUTH_HOST: z.string().default("auth.hcasc.cz"),
  REGISTER_HOST: z.string().default("register.hcasc.cz"),
  QUARANTINE_ROOT: z.string().default("/var/lib/kcml/onboarding"),
  ONBOARDING_WORKER_ENABLED: z.string().optional().transform((value) => value === "true"),
  ONBOARDING_WORKER_INTERVAL_MS: z.coerce.number().int().min(1_000).default(15_000),
  GITHUB_OWNER: z.string().min(1).optional(),
  GITHUB_REPO: z.string().min(1).optional(),
  GITHUB_APP_ID: z.string().min(1).optional(),
  GITHUB_APP_INSTALLATION_ID: z.string().min(1).optional(),
  GITHUB_APP_PRIVATE_KEY_BASE64: z.string().min(1).optional(),
  OCI_REGISTRY: z.string().default("ghcr.io"),
  OCI_IMAGE_NAMESPACE: z.string().min(1).optional(),
  OCI_SIGNING_PUBLIC_KEY: z.string().min(1).optional(),
  PODMAN_BINARY: z.string().default("podman"),
  COSIGN_BINARY: z.string().default("cosign"),
  RUNTIME_SOCKET_ROOT: z.string().default("/var/lib/kcml/runtime"),
  EGRESS_PROXY_SOCKET_PATH: z.string().default("/var/lib/kcml/egress/proxy.sock"),
  WILDCARD_TLS_CERT_PATH: z.string().default("/etc/letsencrypt/live/wildcard.hcasc.cz/fullchain.pem"),
  LOG_LEVEL: z.string().default("info")
}).superRefine((config, ctx) => {
  if (config.ACCESS_TOKEN_HMAC_KEY_BASE64.equals(config.INTEGRATION_TOKEN_HMAC_KEY_BASE64)) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["INTEGRATION_TOKEN_HMAC_KEY_BASE64"], message: "integration token HMAC key must be independent" });
  }
  if (config.EGRESS_CAPABILITY_HMAC_KEY_BASE64.equals(config.INTEGRATION_TOKEN_HMAC_KEY_BASE64)
      || config.EGRESS_CAPABILITY_HMAC_KEY_BASE64.equals(config.ACCESS_TOKEN_HMAC_KEY_BASE64)) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["EGRESS_CAPABILITY_HMAC_KEY_BASE64"], message: "egress capability HMAC key must be independent" });
  }
  if (!config.ONBOARDING_WORKER_ENABLED) return;
  for (const key of [
    "GITHUB_OWNER",
    "GITHUB_REPO",
    "GITHUB_APP_ID",
    "GITHUB_APP_INSTALLATION_ID",
    "GITHUB_APP_PRIVATE_KEY_BASE64",
    "OCI_IMAGE_NAMESPACE",
    "OCI_SIGNING_PUBLIC_KEY"
  ] as const) {
    if (!config[key]) ctx.addIssue({ code: z.ZodIssueCode.custom, path: [key], message: `${key} is required when onboarding worker is enabled` });
  }
});

export type AppConfig = z.infer<typeof envSchema>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  return envSchema.parse(env);
}
