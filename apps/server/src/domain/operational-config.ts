import { createHash } from "node:crypto";
import type { AppConfig, BootstrapConfig } from "../config.js";
import { parseStoredRuntimeConfig } from "../config.js";
import type { Db } from "../db.js";
import { tx } from "../db.js";
import { decryptMfaSecret, decryptVaultSecret, encryptMfaSecret, encryptVaultSecret } from "../security/secrets.js";
import { appendAudit } from "./audit.js";
import { controlPlaneHostnames, normalizeBaseDomain } from "./hostnames.js";

type ConfigKind = "string" | "number" | "boolean" | "stringList" | "secret";
type OperationalConfigCategory = "network" | "security" | "runtime" | "integrations" | "observability" | "presentation";
type ProcessRole = "web" | "worker" | "monitor" | "egress";
type EditableEnvKey = Exclude<keyof AppConfig,
  "NODE_ENV" | "KCML_PROCESS_ROLE" | "PORT" | "DATABASE_URL" | "CONFIG_VAULT_MASTER_KEY_BASE64" | "CONFIG_VAULT_MASTER_KEY_ID">;
type SecretFormat = "base64-min-32" | "base64-exact-32" | "opaque";

export type OperationalConfigDefinition = {
  key: string;
  envKey: EditableEnvKey;
  label: string;
  description: string;
  kind: ConfigKind;
  category: OperationalConfigCategory;
  appliesTo: ProcessRole[];
  restartRequired: boolean;
  defaultValue?: unknown;
  requiredInProduction?: boolean;
  secretFormat?: SecretFormat;
};

export type OperationalConfigView = {
  key: string;
  envKey: string;
  label: string;
  description: string;
  kind: ConfigKind;
  category: OperationalConfigCategory;
  appliesTo: ProcessRole[];
  restartRequired: boolean;
  bootstrapOnly: false;
  source: "database" | "default";
  value: string | number | boolean | string[] | null;
  configured: boolean;
  version: number;
  fingerprint: string;
  restartPending: boolean;
  updatedAt: string | null;
};

const definition = (
  key: string,
  envKey: EditableEnvKey,
  label: string,
  kind: ConfigKind,
  category: OperationalConfigCategory,
  appliesTo: ProcessRole[],
  options: Partial<Pick<OperationalConfigDefinition, "description" | "restartRequired" | "defaultValue" | "requiredInProduction" | "secretFormat">> = {}
): OperationalConfigDefinition => ({
  key,
  envKey,
  label,
  description: options.description ?? label,
  kind,
  category,
  appliesTo,
  restartRequired: options.restartRequired ?? true,
  defaultValue: options.defaultValue,
  requiredInProduction: options.requiredInProduction,
  secretFormat: options.secretFormat
});

const allRoles: ProcessRole[] = ["web", "worker", "monitor", "egress"];

export const operationalConfigDefinitions: OperationalConfigDefinition[] = [
  definition("publicBaseDomain", "PUBLIC_BASE_DOMAIN", "Veřejná základní doména", "string", "network", ["web", "worker"], { defaultValue: "example.invalid", requiredInProduction: true }),
  definition("adminHost", "ADMIN_HOST", "Hostname administrace", "string", "network", ["web"], { defaultValue: "admin.example.invalid", requiredInProduction: true }),
  definition("authHost", "AUTH_HOST", "Hostname autorizace", "string", "network", ["web", "worker", "monitor"], { defaultValue: "auth.example.invalid", requiredInProduction: true }),
  definition("registerHost", "REGISTER_HOST", "Hostname registrace", "string", "network", ["web"], { defaultValue: "register.example.invalid", requiredInProduction: true }),
  definition("trustedProxyCidrs", "TRUSTED_PROXY_CIDRS", "Důvěryhodné proxy sítě", "stringList", "network", ["web"], { defaultValue: ["127.0.0.1", "::1"] }),
  definition("wildcardTlsCertPath", "WILDCARD_TLS_CERT_PATH", "Cesta k TLS certifikátu", "string", "network", ["web"], { defaultValue: "/etc/kcml/tls/fullchain.pem" }),

  definition("accessTokenHmacKey", "ACCESS_TOKEN_HMAC_KEY_BASE64", "HMAC klíč přístupových tokenů", "secret", "security", ["web"], { secretFormat: "base64-min-32" }),
  definition("accessTokenHmacKeyId", "ACCESS_TOKEN_HMAC_KEY_ID", "ID HMAC klíče přístupových tokenů", "string", "security", ["web"], { defaultValue: "v1" }),
  definition("integrationTokenHmacKey", "INTEGRATION_TOKEN_HMAC_KEY_BASE64", "HMAC klíč integračních tokenů", "secret", "security", ["web"], { secretFormat: "base64-min-32" }),
  definition("integrationTokenHmacKeyId", "INTEGRATION_TOKEN_HMAC_KEY_ID", "ID HMAC klíče integračních tokenů", "string", "security", ["web"], { defaultValue: "v1" }),
  definition("egressCapabilityHmacKey", "EGRESS_CAPABILITY_HMAC_KEY_BASE64", "HMAC klíč egress capability", "secret", "security", allRoles, { secretFormat: "base64-min-32" }),
  definition("sessionSecret", "SESSION_SECRET_BASE64", "Klíč administrátorských relací", "secret", "security", ["web"], { secretFormat: "base64-min-32" }),
  definition("csrfSecret", "CSRF_SECRET_BASE64", "CSRF klíč", "secret", "security", ["web"], { secretFormat: "base64-min-32" }),
  definition("mfaEncryptionKey", "MFA_ENCRYPTION_KEY_BASE64", "Šifrovací klíč MFA", "secret", "security", ["web"], { secretFormat: "base64-exact-32" }),
  definition("adminBootstrapSecret", "ADMIN_BOOTSTRAP_SECRET", "Jednorázový bootstrap secret", "secret", "security", ["web"], { secretFormat: "opaque" }),
  definition("adminTotpSecret", "ADMIN_TOTP_SECRET", "Deployment MFA secret", "secret", "security", ["web"], { secretFormat: "opaque" }),
  definition("adminBootstrapUsername", "ADMIN_BOOTSTRAP_USERNAME", "Deployment admin účet", "string", "security", ["web"], { defaultValue: "karmar78" }),
  definition("mfaAllowPlaintextLegacy", "MFA_ALLOW_PLAINTEXT_LEGACY", "Povolit legacy plaintext MFA", "boolean", "security", ["web"], { defaultValue: false }),

  definition("quarantineRoot", "QUARANTINE_ROOT", "Kořen karantény", "string", "runtime", ["web", "worker"], { defaultValue: "/var/lib/kcml/onboarding" }),
  definition("onboardingWorkerEnabled", "ONBOARDING_WORKER_ENABLED", "Povolit onboarding worker", "boolean", "runtime", ["worker"], { defaultValue: false, restartRequired: true }),
  definition("onboardingWorkerIntervalMs", "ONBOARDING_WORKER_INTERVAL_MS", "Interval onboarding workeru", "number", "runtime", ["worker"], { defaultValue: 15_000 }),
  definition("podmanBinary", "PODMAN_BINARY", "Podman binary", "string", "runtime", ["worker", "monitor"], { defaultValue: "podman" }),
  definition("cosignBinary", "COSIGN_BINARY", "Cosign binary", "string", "runtime", ["worker", "monitor"], { defaultValue: "cosign" }),
  definition("runtimeSocketRoot", "RUNTIME_SOCKET_ROOT", "Kořen runtime socketů", "string", "runtime", ["worker", "monitor"], { defaultValue: "/var/lib/kcml/runtime" }),
  definition("egressProxySocketPath", "EGRESS_PROXY_SOCKET_PATH", "Socket egress proxy", "string", "runtime", allRoles, { defaultValue: "/var/lib/kcml/egress/proxy.sock" }),

  definition("githubOwner", "GITHUB_OWNER", "GitHub owner", "string", "integrations", ["worker"]),
  definition("githubRepo", "GITHUB_REPO", "GitHub repozitář", "string", "integrations", ["worker"]),
  definition("githubToken", "GITHUB_TOKEN", "GitHub token", "secret", "integrations", ["worker"], { secretFormat: "opaque" }),
  definition("githubAppId", "GITHUB_APP_ID", "GitHub App ID", "string", "integrations", ["worker"]),
  definition("githubAppInstallationId", "GITHUB_APP_INSTALLATION_ID", "GitHub App installation ID", "string", "integrations", ["worker"]),
  definition("githubAppPrivateKey", "GITHUB_APP_PRIVATE_KEY_BASE64", "GitHub App private key", "secret", "integrations", ["worker"], { secretFormat: "opaque" }),
  definition("ociRegistry", "OCI_REGISTRY", "OCI registry", "string", "integrations", ["worker", "monitor"], { defaultValue: "ghcr.io" }),
  definition("ociImageNamespace", "OCI_IMAGE_NAMESPACE", "OCI image namespace", "string", "integrations", ["worker", "monitor"]),
  definition("ociCertificateIdentity", "OCI_CERTIFICATE_IDENTITY", "OCI certificate identity", "string", "integrations", ["worker", "monitor"]),
  definition("ociCertificateOidcIssuer", "OCI_CERTIFICATE_OIDC_ISSUER", "OCI OIDC issuer", "string", "integrations", ["worker", "monitor"], { defaultValue: "https://token.actions.githubusercontent.com" }),

  definition("monitorEnabled", "MONITOR_ENABLED", "Povolit monitor", "boolean", "observability", ["monitor"], { defaultValue: false }),
  definition("monitorIntervalMs", "MONITOR_INTERVAL_MS", "Interval monitoru", "number", "observability", ["monitor"], { defaultValue: 60_000 }),
  definition("alertPrimaryWebhookUrl", "ALERT_PRIMARY_WEBHOOK_URL", "Primární alert webhook", "secret", "observability", ["monitor"], { secretFormat: "opaque" }),
  definition("alertPrimaryHmacKey", "ALERT_PRIMARY_HMAC_KEY_BASE64", "Primární alert HMAC klíč", "secret", "observability", ["monitor"], { secretFormat: "base64-min-32" }),
  definition("alertBackupWebhookUrl", "ALERT_BACKUP_WEBHOOK_URL", "Záložní alert webhook", "secret", "observability", ["monitor"], { secretFormat: "opaque" }),
  definition("alertBackupHmacKey", "ALERT_BACKUP_HMAC_KEY_BASE64", "Záložní alert HMAC klíč", "secret", "observability", ["monitor"], { secretFormat: "base64-min-32" }),
  definition("logLevel", "LOG_LEVEL", "Úroveň logování", "string", "observability", allRoles, { defaultValue: "info" }),
  definition("buildId", "BUILD_ID", "ID sestavení", "string", "observability", allRoles, { defaultValue: "local", requiredInProduction: true }),
  definition("auditArchivePath", "AUDIT_ARCHIVE_PATH", "Cesta externího auditního archivu", "string", "observability", ["monitor"], { defaultValue: "/var/lib/kcml/audit/archive.jsonl" }),
  definition("uiTimeZone", "UI_TIME_ZONE", "Časové pásmo administrace", "string", "presentation", ["web"], { defaultValue: "Europe/Prague", restartRequired: false })
];

function canonicalBase64(value: string, exactBytes?: number): boolean {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:|[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)$/.test(value)) return false;
  const decoded = Buffer.from(value, "base64");
  return decoded.toString("base64") === value && (exactBytes === undefined ? decoded.length >= 32 : decoded.length === exactBytes);
}

function parseValue(definitionValue: OperationalConfigDefinition, value: unknown): string | number | boolean | string[] {
  if (definitionValue.kind === "number") {
    const parsed = Number(value);
    const minimum = definitionValue.envKey === "MONITOR_INTERVAL_MS" ? 15_000 : 1_000;
    if (!Number.isInteger(parsed) || parsed < minimum || parsed > 900_000) throw Object.assign(new Error("config_invalid_interval"), { statusCode: 400 });
    return parsed;
  }
  if (definitionValue.kind === "boolean") {
    if (typeof value === "boolean") return value;
    if (value === "true" || value === "false") return value === "true";
    throw Object.assign(new Error("config_invalid_boolean"), { statusCode: 400 });
  }
  if (definitionValue.kind === "stringList") {
    const list = Array.isArray(value) ? value : String(value).split(",");
    const normalized = [...new Set(list.map((entry) => String(entry).trim()).filter(Boolean))];
    if (!normalized.length || normalized.length > 100) throw Object.assign(new Error("config_invalid_list"), { statusCode: 400 });
    return normalized;
  }
  const parsed = String(value).trim();
  if (!parsed) throw Object.assign(new Error("config_value_required"), { statusCode: 400 });
  if (definitionValue.kind === "secret") {
    if (definitionValue.secretFormat === "base64-min-32" && !canonicalBase64(parsed)) throw Object.assign(new Error("config_invalid_secret"), { statusCode: 400 });
    if (definitionValue.secretFormat === "base64-exact-32" && !canonicalBase64(parsed, 32)) throw Object.assign(new Error("config_invalid_secret"), { statusCode: 400 });
    if (definitionValue.secretFormat === "opaque" && parsed.length < 16) throw Object.assign(new Error("config_invalid_secret"), { statusCode: 400 });
    return parsed;
  }
  if (["PUBLIC_BASE_DOMAIN", "ADMIN_HOST", "AUTH_HOST", "REGISTER_HOST"].includes(definitionValue.envKey)
    && !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(parsed)) {
    throw Object.assign(new Error("config_invalid_hostname"), { statusCode: 400 });
  }
  if (definitionValue.envKey === "LOG_LEVEL" && !["fatal", "error", "warn", "info", "debug", "trace", "silent"].includes(parsed.toLowerCase())) {
    throw Object.assign(new Error("config_invalid_log_level"), { statusCode: 400 });
  }
  if (definitionValue.envKey === "UI_TIME_ZONE") {
    try { new Intl.DateTimeFormat("en", { timeZone: parsed }).format(0); } catch { throw Object.assign(new Error("config_invalid_time_zone"), { statusCode: 400 }); }
  }
  return definitionValue.envKey === "LOG_LEVEL" ? parsed.toLowerCase() : parsed;
}

function envValue(value: unknown): string | undefined {
  if (value === null || value === undefined) return undefined;
  if (Array.isArray(value)) return value.join(",");
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") return String(value);
  return JSON.stringify(value);
}

function roleNeeds(definitionValue: OperationalConfigDefinition, bootstrap: BootstrapConfig): boolean {
  if (bootstrap.KCML_PROCESS_ROLE === "all") return definitionValue.appliesTo.length > 0;
  return definitionValue.appliesTo.includes(bootstrap.KCML_PROCESS_ROLE as ProcessRole);
}

function developmentSecret(definitionValue: OperationalConfigDefinition): string | undefined {
  const index = operationalConfigDefinitions.indexOf(definitionValue) + 1;
  if (definitionValue.secretFormat === "base64-min-32" || definitionValue.secretFormat === "base64-exact-32") {
    return Buffer.alloc(32, index % 255 || 1).toString("base64");
  }
  return undefined;
}

export async function loadConfigFromDb(db: Db, bootstrap: BootstrapConfig): Promise<AppConfig> {
  const result = await db.query("select key,value_json,secret_ciphertext,is_secret,version from operational_config_setting");
  const rows = new Map(result.rows.map((row) => [String(row.key), row]));
  const runtimeValues: NodeJS.ProcessEnv = {};
  const keyring = new Map([[bootstrap.CONFIG_VAULT_MASTER_KEY_ID, bootstrap.CONFIG_VAULT_MASTER_KEY_BASE64]]);
  for (const definitionValue of operationalConfigDefinitions) {
    const row = rows.get(definitionValue.key);
    let value: unknown;
    if (row) {
      if (definitionValue.kind === "secret") {
        if (!row.secret_ciphertext || !row.is_secret) throw new Error(`operational_config_secret_invalid:${definitionValue.key}`);
        value = decryptVaultSecret(String(row.secret_ciphertext), keyring, definitionValue.key);
      } else {
        if (row.is_secret) throw new Error(`operational_config_value_invalid:${definitionValue.key}`);
        value = parseValue(definitionValue, row.value_json);
      }
    } else {
      value = definitionValue.defaultValue;
      if (definitionValue.kind === "secret" && bootstrap.NODE_ENV !== "production") value = developmentSecret(definitionValue);
      if (bootstrap.NODE_ENV === "production" && definitionValue.requiredInProduction && roleNeeds(definitionValue, bootstrap)) {
        throw new Error(`operational_config_missing:${definitionValue.key}`);
      }
    }
    const serialized = envValue(value);
    if (serialized !== undefined) runtimeValues[definitionValue.envKey] = serialized;
  }
  const config = parseStoredRuntimeConfig(bootstrap, runtimeValues);
  const appliedRoles = bootstrap.KCML_PROCESS_ROLE === "all"
    ? allRoles
    : allRoles.filter((role) => role === bootstrap.KCML_PROCESS_ROLE);
  for (const role of appliedRoles) {
    for (const [key, row] of rows) {
      const definitionValue = operationalConfigDefinitions.find((item) => item.key === key);
      if (!definitionValue?.appliesTo.includes(role)) continue;
      await db.query(
        `insert into operational_config_applied(key,process_role,version,applied_at)
         values ($1,$2,$3,now())
         on conflict (key,process_role) do update set version=excluded.version,applied_at=now()`,
        [key, role, Number(row.version ?? 0)]
      );
    }
  }
  return config;
}

export async function listOperationalConfig(db: Db, config: Partial<AppConfig>): Promise<OperationalConfigView[]> {
  const [settings, applied] = await Promise.all([
    db.query("select key,value_json,secret_ciphertext,is_secret,updated_at,version from operational_config_setting"),
    db.query("select key,process_role,version from operational_config_applied")
  ]);
  const rows = new Map(settings.rows.map((row) => [String(row.key), row]));
  const appliedVersions = new Map(applied.rows.map((row) => [`${String(row.key)}:${String(row.process_role)}`, Number(row.version)]));
  return operationalConfigDefinitions.map((definitionValue) => {
    const row = rows.get(definitionValue.key);
    const version = row ? Number(row.version ?? 0) : 0;
    const isSecret = definitionValue.kind === "secret";
    const configured = Boolean(row && (isSecret ? row.secret_ciphertext : row.value_json !== null));
    const currentValue = isSecret
      ? null
      : row ? parseValue(definitionValue, row.value_json) : (config[definitionValue.envKey] as unknown ?? definitionValue.defaultValue) as string | number | boolean | string[] | null;
    const restartPending = Boolean(row) && definitionValue.restartRequired
      && definitionValue.appliesTo.some((role) => (appliedVersions.get(`${definitionValue.key}:${role}`) ?? -1) < version);
    return {
      key: definitionValue.key,
      envKey: definitionValue.envKey,
      label: definitionValue.label,
      description: definitionValue.description,
      kind: definitionValue.kind,
      category: definitionValue.category,
      appliesTo: definitionValue.appliesTo,
      restartRequired: definitionValue.restartRequired,
      bootstrapOnly: false,
      source: row ? "database" : "default",
      value: Buffer.isBuffer(currentValue) ? null : currentValue,
      configured,
      version,
      fingerprint: isSecret && row?.secret_ciphertext
        ? createHash("sha256").update(String(row.secret_ciphertext)).digest("hex").slice(0, 16)
        : `${definitionValue.key}:v${version}`,
      restartPending,
      updatedAt: row?.updated_at ? String(row.updated_at) : null
    };
  });
}

export async function updateOperationalConfig(
  db: Db,
  config: Pick<AppConfig, "CONFIG_VAULT_MASTER_KEY_BASE64" | "CONFIG_VAULT_MASTER_KEY_ID">,
  actorId: string | null,
  correlationId: string,
  key: string,
  value: unknown,
  expectedVersion: number
): Promise<void> {
  const definitionValue = operationalConfigDefinitions.find((item) => item.key === key);
  if (!definitionValue) throw Object.assign(new Error("config_key_not_found"), { statusCode: 404 });
  const storedValue = parseValue(definitionValue, value);
  const secretCiphertext = definitionValue.kind === "secret"
    ? encryptVaultSecret(String(storedValue), config.CONFIG_VAULT_MASTER_KEY_BASE64, { keyId: config.CONFIG_VAULT_MASTER_KEY_ID, settingKey: definitionValue.key })
    : null;

  await tx(db, async (client) => {
    const current = await client.query(
      "select value_json,secret_ciphertext,is_secret,version from operational_config_setting where key=$1 for update",
      [definitionValue.key]
    );
    const currentVersion = current.rowCount ? Number(current.rows[0].version ?? 0) : 0;
    if (expectedVersion !== currentVersion) throw Object.assign(new Error("config_version_conflict"), { statusCode: 409 });
    const nextVersion = currentVersion + 1;
    await client.query(
      `insert into operational_config_setting(key,value_json,secret_ciphertext,is_secret,updated_by,version)
       values ($1,$2,$3,$4,$5,$6)
       on conflict (key) do update
         set value_json=excluded.value_json,secret_ciphertext=excluded.secret_ciphertext,is_secret=excluded.is_secret,
             updated_by=excluded.updated_by,version=excluded.version,updated_at=now()`,
      [definitionValue.key, definitionValue.kind === "secret" ? null : JSON.stringify(storedValue), secretCiphertext, definitionValue.kind === "secret", actorId, nextVersion]
    );
    const previousFingerprint = current.rows[0]?.secret_ciphertext
      ? createHash("sha256").update(String(current.rows[0].secret_ciphertext)).digest("hex").slice(0, 16)
      : null;
    const nextFingerprint = secretCiphertext ? createHash("sha256").update(secretCiphertext).digest("hex").slice(0, 16) : null;
    await appendAudit(client, {
      eventType: "operational_config.updated",
      actorType: "admin",
      actorId,
      objectType: "operational_config",
      objectId: definitionValue.key,
      before: {
        envKey: definitionValue.envKey,
        kind: definitionValue.kind,
        version: currentVersion,
        value: definitionValue.kind === "secret" ? { configured: Boolean(current.rows[0]?.secret_ciphertext), fingerprint: previousFingerprint } : current.rows[0]?.value_json ?? null
      },
      after: {
        envKey: definitionValue.envKey,
        kind: definitionValue.kind,
        category: definitionValue.category,
        appliesTo: definitionValue.appliesTo,
        restartRequired: definitionValue.restartRequired,
        version: nextVersion,
        value: definitionValue.kind === "secret" ? { configured: true, fingerprint: nextFingerprint } : storedValue
      },
      correlationId
    });
  });
}

const domainSettingKeys = ["publicBaseDomain", "adminHost", "authHost", "registerHost"] as const;

export async function updateDomainConfiguration(
  db: Db,
  actorId: string,
  correlationId: string,
  baseDomainValue: unknown,
  expectedVersions: Record<string, number>
): Promise<{ baseDomain: string; migratedServers: number }> {
  const baseDomain = normalizeBaseDomain(String(baseDomainValue));
  const controlPlane = controlPlaneHostnames(baseDomain);
  const values: Record<(typeof domainSettingKeys)[number], string> = {
    publicBaseDomain: baseDomain,
    ...controlPlane
  };
  return tx(db, async (client) => {
    const current = await client.query(
      `select key,value_json,version
         from operational_config_setting
        where key=any($1::text[])
        order by key
        for update`,
      [domainSettingKeys]
    );
    const rows = new Map(current.rows.map((row) => [String(row.key), row]));
    for (const key of domainSettingKeys) {
      const currentVersion = Number(rows.get(key)?.version ?? 0);
      if (expectedVersions[key] !== currentVersion) {
        throw Object.assign(new Error("config_version_conflict"), { statusCode: 409 });
      }
    }
    for (const key of domainSettingKeys) {
      const nextVersion = Number(rows.get(key)?.version ?? 0) + 1;
      await client.query(
        `insert into operational_config_setting(key,value_json,secret_ciphertext,is_secret,updated_by,version)
         values ($1,$2,null,false,$3,$4)
         on conflict (key) do update
           set value_json=excluded.value_json,secret_ciphertext=null,is_secret=false,
               updated_by=excluded.updated_by,version=excluded.version,updated_at=now()`,
        [key, JSON.stringify(values[key]), actorId, nextVersion]
      );
    }
    const migrated = await client.query<{ id: string }>(
      `update mcp_server
          set hostname=lower(code::text)||'.'||$1,
              revocation_epoch=gen_random_uuid(),lock_version=lock_version+1,updated_at=now()
        where lower(hostname::text)<>lower(code::text)||'.'||$1
        returning id`,
      [baseDomain]
    );
    await client.query(
      `update onboarding_job
          set hostname=lower(code::text)||'.'||$1,lock_version=lock_version+1,updated_at=now()
        where code is not null and hostname is not null
          and lower(hostname::text)<>lower(code::text)||'.'||$1`,
      [baseDomain]
    );
    await client.query(
      `update managed_service service
          set public_hostname=server.hostname,
              base_url='https://'||server.hostname,
              resource_uri='https://'||server.hostname||'/mcp',
              revocation_epoch=gen_random_uuid(),service_token_epoch=gen_random_uuid(),
              last_policy_invalidation_at=now(),lock_version=lock_version+1,updated_at=now()
         from mcp_server server
        where service.legacy_mcp_server_id=server.id`,
      []
    );
    const serverIds = migrated.rows.map((row) => row.id);
    if (serverIds.length) {
      await client.query(
        "update access_token set revoked_at=coalesce(revoked_at,now()) where server_id=any($1::uuid[])",
        [serverIds]
      );
      await client.query(
        `update managed_service_access_token token
            set revoked_at=coalesce(token.revoked_at,now())
           from managed_service service
          where token.managed_service_id=service.id
            and service.legacy_mcp_server_id=any($1::uuid[])`,
        [serverIds]
      );
    }
    await appendAudit(client, {
      eventType: "operational_config.domain_migrated",
      actorType: "admin",
      actorId,
      objectType: "operational_config",
      objectId: "publicBaseDomain",
      before: Object.fromEntries(domainSettingKeys.map((key) => [key, rows.get(key)?.value_json ?? null])),
      after: { ...values, migratedServers: migrated.rowCount ?? 0, accessTokensInvalidated: serverIds.length > 0 },
      correlationId
    });
    return { baseDomain, migratedServers: migrated.rowCount ?? 0 };
  });
}

export async function rotateMfaEncryptionKey(
  db: Db,
  config: Pick<AppConfig, "CONFIG_VAULT_MASTER_KEY_BASE64" | "CONFIG_VAULT_MASTER_KEY_ID" | "MFA_ENCRYPTION_KEY_BASE64" | "MFA_ALLOW_PLAINTEXT_LEGACY">,
  actorId: string,
  correlationId: string,
  value: unknown,
  expectedVersion: number
): Promise<{ reencryptedAccounts: number }> {
  const definitionValue = operationalConfigDefinitions.find((item) => item.key === "mfaEncryptionKey")!;
  const encodedKey = String(parseValue(definitionValue, value));
  const nextKey = Buffer.from(encodedKey, "base64");
  return tx(db, async (client) => {
    const current = await client.query(
      "select secret_ciphertext,version from operational_config_setting where key='mfaEncryptionKey' for update"
    );
    const currentVersion = current.rowCount ? Number(current.rows[0].version ?? 0) : 0;
    if (currentVersion !== expectedVersion) throw Object.assign(new Error("config_version_conflict"), { statusCode: 409 });
    const accounts = await client.query(
      `select id,mfa_secret
         from admin_account
        where mfa_enabled=true and mfa_secret is not null
        order by id
        for update`
    );
    const plaintext = accounts.rows.map((row) => ({
      id: String(row.id),
      secret: decryptMfaSecret(String(row.mfa_secret), config.MFA_ENCRYPTION_KEY_BASE64, {
        allowLegacyPlaintext: config.MFA_ALLOW_PLAINTEXT_LEGACY,
        subjectId: String(row.id),
        purpose: "admin_totp"
      })
    }));
    const nextVersion = currentVersion + 1;
    const keyId = `mfa-config-v${nextVersion}`;
    for (const account of plaintext) {
      const encrypted = encryptMfaSecret(account.secret, nextKey, { subjectId: account.id, purpose: "admin_totp", keyId });
      await client.query("update admin_account set mfa_secret=$2,updated_at=now() where id=$1", [account.id, encrypted]);
    }
    const vaultCiphertext = encryptVaultSecret(encodedKey, config.CONFIG_VAULT_MASTER_KEY_BASE64, {
      keyId: config.CONFIG_VAULT_MASTER_KEY_ID,
      settingKey: definitionValue.key
    });
    await client.query(
      `insert into operational_config_setting(key,value_json,secret_ciphertext,is_secret,updated_by,version)
       values ('mfaEncryptionKey',null,$1,true,$2,$3)
       on conflict (key) do update
         set value_json=null,secret_ciphertext=excluded.secret_ciphertext,is_secret=true,
             updated_by=excluded.updated_by,version=excluded.version,updated_at=now()`,
      [vaultCiphertext, actorId, nextVersion]
    );
    await appendAudit(client, {
      eventType: "operational_config.mfa_key_rotated",
      actorType: "admin",
      actorId,
      objectType: "operational_config",
      objectId: definitionValue.key,
      before: { version: currentVersion, configured: (current.rowCount ?? 0) > 0 },
      after: {
        version: nextVersion,
        keyId,
        reencryptedAccounts: plaintext.length,
        fingerprint: createHash("sha256").update(vaultCiphertext).digest("hex").slice(0, 16),
        restartRequired: true
      },
      correlationId
    });
    return { reencryptedAccounts: plaintext.length };
  });
}
