export type Page = "components" | "monitoring" | "integration" | "secrets" | "tokens" | "permissions" | "audit" | "config" | "security" | "admins";
export type AdminRole = "OWNER" | "ADMIN" | "AUDITOR";
export type Session = { authenticated: boolean; account: string | null; role: AdminRole | null; bootstrapRequired?: boolean };
export type ReleaseInfo = {
  applicationVersion: string;
  blueprintVersion: string;
  catalogVersion: string;
  manifestSchemaVersion: string;
  pulseEnvelopeVersion: string;
  policyBaseline: string;
  mcpProtocolVersion: string;
  buildId: string;
  commitSha: string;
};
export type Server = {
  id: string;
  code: string;
  hostname: string;
  displayName: string;
  description: string;
  toolName: string;
  registrationState: string;
  operationalState: string;
  enabled: boolean;
  handlerKey: string;
  handlerVersion: string;
  contractVersion: string;
  inputSchema: unknown;
  outputSchema: unknown;
  artifactDigest: string;
  manifestDigest: string;
  successCount: number;
  unauthorizedCount: number;
  failureCount: number;
  lastLatencyMs: number | null;
  averageLatencyMs: number | null;
  p95LatencyMs: number | null;
  lastSuccessAt: string | null;
  lastFailureAt: string | null;
  lastUnauthorizedAt: string | null;
  registrationRevision: string | null;
  activeRevisionId: string | null;
  registrationSchemaVersion: string | null;
  registrationValidationState: string | null;
  reviewApprovedAt: string | null;
  reviewDueAt: string | null;
  reviewIntervalDays: number | null;
  monitoringEnabled: boolean;
  monitoringProfileDigest: string | null;
  recertification: {
    phase: "VALID" | "WARNING" | "GRACE" | "SUSPENDED" | "INVALID";
    canServeExisting: boolean;
    canActivate: boolean;
    shouldSuspend: boolean;
    reason: string | null;
    reviewDueAt: string | null;
    secondsToBoundary: number | null;
  };
  createdAt: string;
  updatedAt: string;
};
export type ComponentPermission = {
  id: string;
  source_component_id: string;
  target_component_id: string;
  route_pattern: string;
  scope_name: string;
  access_level: string;
  granted_at: string;
  revoked_at: string | null;
};
export type ComponentCredential = {
  id: string;
  public_id: string;
  secret_fingerprint: string;
  status: string;
  issued_at: string;
  expires_at: string | null;
  last_used_at: string | null;
  revoked_at: string | null;
};
export type Component = {
  id: string;
  code: string;
  hostname: string;
  displayName: string;
  description: string;
  category: string;
  registrationType: string;
  role: string;
  owners: Record<string, unknown>;
  contacts: Record<string, unknown>;
  lifecycleState: string;
  activationState: string;
  operationalState: string;
  monitoringState: string;
  recertificationState: string;
  enabled: boolean;
  ingressEnabled: boolean;
  pulseEnabled: boolean;
  egressEnabled: boolean;
  revision: string | null;
  capabilities: string[];
  protocols: string[];
  transports: string[];
  permissionCount: number;
  credentialCount: number;
  policyEpoch: number;
  audit: { gapState: string; highestReceivedSequence: number; highestAcknowledgedSequence: number };
  releaseVersion: string;
  createdAt: string;
  updatedAt: string;
  permissions?: ComponentPermission[];
  credentials?: ComponentCredential[];
};
export type ManagedSecret = {
  id: string;
  stableName: string;
  displayName: string;
  description: string;
  ownerKind: string;
  ownerId: string | null;
  status: string;
  activeVersionId: string | null;
  activeVersionNumber: number | null;
  activeFingerprint: string | null;
  grantCount: number;
  lockVersion: number;
  createdAt: string;
  updatedAt: string;
  deletedAt: string | null;
};
export type SecretGrant = {
  id: string;
  principalKind: "KAJA" | "COMPONENT" | "INTEGRATION_TOKEN";
  principalId: string | null;
  principalPublicId: string | null;
  grantedAt: string;
  revokedAt: string | null;
};
export type SecretVersion = {
  id: string;
  versionNumber: number;
  fingerprint: string;
  keyId: string;
  algorithm: string;
  createdAt: string;
  activatedAt: string | null;
  retiredAt: string | null;
  active: boolean;
};
export type KajaCredential = {
  id: string;
  publicId: string;
  label: string;
  fingerprint: string;
  active: boolean;
  revokedAt: string | null;
  deletedAt: string | null;
  createdAt: string;
  updatedAt: string;
  expiresAt: string | null;
  permissionCount: number;
  activeAccessTokenCount: number;
  lastTokenIssuedAt: string | null;
  lastTokenExpiresAt: string | null;
  lastUsedAt: string | null;
};
export type AccessLevel = "EXECUTE";
export type KajaPermission = {
  serverId: string;
  code: string;
  hostname: string;
  displayName: string;
  granted: boolean;
  accessLevel: AccessLevel | null;
  grantedAt: string | null;
};
export type AuditEvent = {
  id: number;
  event_type: string;
  actor_type: string;
  actor_id?: string | null;
  object_type: string;
  object_id: string;
  correlation_id: string;
  created_at: string;
  before_json?: unknown;
  after_json?: unknown;
  chain: {
    sequence: number | null;
    previousHash: string | null;
    eventHash: string | null;
  };
};
export type SecretResult = { publicId: string; label: string; clientSecret: string; fingerprint: string; expiresAt: string | null };
export type IntegrationToken = {
  id: string;
  label: string;
  fingerprint: string;
  descriptor: {
    summary: string;
    businessPurpose: string;
    serviceOwner: string;
    technicalOwner: string;
    criticality: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  };
  serviceKind?: "MCP" | "EXTERNAL_API";
  allowedPipeline?: "MCP_ONBOARDING" | "EXTERNAL_API_REGISTRATION";
  tokenKind?: "SINGLE_COMPONENT" | "BLUEPRINT_RELEASE";
  releaseVersion?: string;
  releaseWaveKey?: string | null;
  maxChildJobs?: number;
  allowedBlueprintComponents?: Array<{
    componentId: string;
    registrationType: string;
    releaseVersion: string;
    releaseWaveKey: string | null;
  }>;
  jobId: string | null;
  issuedAt: string;
  initialExpiresAt: string;
  expiresAt: string;
  maxExpiresAt: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
  active: boolean;
  jobState: string | null;
  code: string | null;
  hostname: string | null;
  heartbeatAt: string | null;
  tokenExtendedAt: string | null;
};
export type IntegrationSecret = IntegrationToken & {
  token: string;
  onboardingCatalogUrl: string;
  onboardingCatalogFileName: string;
  programmerApiUrl: string;
  intakeUrls?: {
    recommendedIntakeUrl: string;
    nativeComponentIntakeUrl: string;
    legacyServiceIntakeUrl: string;
    externalApiIntakeUrl: string;
    componentCatalogUrl: string;
    externalApiCatalogUrl: string;
  };
};
export type OnboardingGate = { gate_name: string; stage: string; status: string; evidence: Record<string, unknown>; correlation_id: string; started_at: string | null; completed_at: string | null };
export type OnboardingEvent = { id: number; from_state: string | null; to_state: string; event_type: string; detail: Record<string, unknown>; correlation_id: string; created_at: string };
export type OnboardingJob = {
  id: string;
  state: string;
  correlationId: string;
  lockVersion: number;
  sourceRevision: number;
  code: string | null;
  hostname: string | null;
  resource: string | null;
  toolName: string | null;
  serverId: string | null;
  githubPrUrl: string | null;
  imageDigest: string | null;
  sbomDigest: string | null;
  blockingErrorCode: string | null;
  blockingErrorDetail: string | null;
  createdAt: string | null;
  updatedAt: string | null;
  completedAt: string | null;
  gates?: OnboardingGate[];
  events?: OnboardingEvent[];
};
export type MonitoringProbe = { id: number; server_id: string; code: string; hostname: string; probe_type: string; status: string; latency_ms: number | null; evidence?: Record<string, unknown>; correlation_id: string; checked_at: string };
export type OperationalAlert = {
  id: string;
  server_id: string | null;
  code: string | null;
  hostname: string | null;
  severity: "WARNING" | "HIGH" | "CRITICAL";
  alert_type: string;
  status: "OPEN" | "ACKNOWLEDGED" | "SUPPRESSED" | "CLOSED";
  title: string;
  detail: Record<string, unknown>;
  correlation_id: string;
  first_seen_at: string;
  last_seen_at: string;
  suppressed_until: string | null;
};
export type AlertDelivery = {
  id: string;
  alert_id: string;
  code: string | null;
  severity: string;
  alert_type: string;
  channel: "PRIMARY" | "BACKUP";
  idempotency_key: string;
  attempt_count: number;
  state: "PENDING" | "DELIVERED" | "RETRY" | "DEAD_LETTER";
  last_http_status: number | null;
  last_error: string | null;
  next_attempt_at: string;
  delivered_at: string | null;
  created_at: string;
};
export type ServerStateHistory = {
  id: number;
  server_id: string;
  code: string;
  registration_state: string;
  operational_state: string;
  recertification_phase: string;
  reason: string;
  correlation_id: string;
  recorded_at: string;
};
export type MonitoringOverview = {
  alerts: OperationalAlert[];
  deliveries: AlertDelivery[];
  stateHistory: ServerStateHistory[];
  scheduler: { worker_id: string; last_started_at: string; last_completed_at: string | null; last_error: string | null } | null;
};
export type AuditResponse = { events: AuditEvent[]; nextCursor: string | null };
export type AuditIntegrity = {
  valid: boolean;
  eventCount: number;
  latestEventId: number | null;
  brokenEventId: number | null;
};
export type AdminSecurity = {
  username: string;
  role: AdminRole;
  active: boolean;
  deploymentManaged: boolean;
  mfaEnabled: boolean;
  passwordChangedAt: string | null;
  sessions: Array<{
    id: string;
    createdAt: string;
    expiresAt: string;
    current: boolean;
  }>;
};
export type AdminAccount = {
  id: string;
  username: string;
  deploymentManaged: boolean;
  passwordChangedAt: string | null;
  mfaEnabled: boolean;
  createdAt: string;
  activeSessionCount: number;
  recoveryCodeCount: number;
  current: boolean;
  role: AdminRole;
  active: boolean;
};
export type MonitoringProfile = {
  enabled: boolean;
  version: number;
  profile: {
    sloTargets: Record<string, unknown>;
    probeIntervals: Record<string, unknown>;
    alertRules: Array<Record<string, unknown>>;
    runbookRef: string;
    primaryAlertChannel: string;
    backupAlertChannel: string;
    staleAfterSeconds: number;
    retentionDays: number;
  };
};
export type OperationalConfigSetting = {
  key: string;
  envKey: string;
  label: string;
  description: string;
  kind: "string" | "number" | "boolean" | "stringList" | "secret";
  category: "network" | "security" | "runtime" | "integrations" | "observability" | "presentation";
  appliesTo: Array<"web" | "worker" | "monitor" | "egress">;
  restartRequired: boolean;
  bootstrapOnly: boolean;
  source: "database" | "default";
  value: string | number | boolean | string[] | null;
  configured: boolean;
  version: number;
  fingerprint: string;
  restartPending: boolean;
  updatedAt: string | null;
};
export type OnboardingDescriptor = {
  summary: string;
  businessPurpose: string;
  serviceOwner: string;
  technicalOwner: string;
  criticality: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
};

export const pageNames: Record<Page, string> = {
  components: "Katalog komponent",
  monitoring: "Monitoring komponent",
  integration: "Implementační tokeny",
  secrets: "Správa tajemství",
  tokens: "Klientská pověření Kaja",
  permissions: "Správa oprávnění",
  audit: "Audit",
  config: "Konfigurace",
  security: "Bezpečnost",
  admins: "Administrátoři"
};

export const accessLabels: Record<AccessLevel, string> = {
  EXECUTE: "Spouštění"
};
