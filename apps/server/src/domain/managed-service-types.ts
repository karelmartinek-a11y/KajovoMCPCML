export const MANAGED_SERVICE_KINDS = ["MCP", "EXTERNAL_API"] as const;
export type ManagedServiceKind = (typeof MANAGED_SERVICE_KINDS)[number];

export const MANAGED_SERVICE_STATES = [
  "DRAFT",
  "REGISTERED_DISABLED",
  "TRIAL",
  "ACTIVE",
  "SUSPENDED",
  "QUARANTINED",
  "RETIRED"
] as const;
export type ManagedServiceState = (typeof MANAGED_SERVICE_STATES)[number];

export const MANAGED_SERVICE_AUTH_MODES = [
  "OAUTH2_CLIENT_CREDENTIALS",
  "STATIC_BEARER",
  "STATIC_API_KEY",
  "MTLS",
  "NONE"
] as const;
export type ManagedServiceAuthMode = (typeof MANAGED_SERVICE_AUTH_MODES)[number];

export const MANAGED_SERVICE_API_STATES = ["ENABLED", "DISABLED"] as const;
export type ManagedServiceApiState = (typeof MANAGED_SERVICE_API_STATES)[number];

export const SERVICE_PIPELINE_KINDS = ["MCP_ONBOARDING", "EXTERNAL_API_REGISTRATION"] as const;
export type ServicePipelineKind = (typeof SERVICE_PIPELINE_KINDS)[number];

export const MANAGED_SERVICE_SCOPE_LEVELS = [
  "DISCOVER",
  "MONITOR",
  "INVOKE",
  "READ",
  "WRITE",
  "ADMIN"
] as const;
export type ManagedServiceScopeLevel = (typeof MANAGED_SERVICE_SCOPE_LEVELS)[number];

export const MANAGED_SERVICE_USAGE_OUTCOMES = [
  "ACCEPTED",
  "SUCCEEDED",
  "FAILED",
  "UNAUTHORIZED",
  "RATE_LIMITED"
] as const;
export type ManagedServiceUsageOutcome = (typeof MANAGED_SERVICE_USAGE_OUTCOMES)[number];

export type ManagedServiceOwnerSet = {
  service: string | null;
  technical: string | null;
  security: string | null;
  operations: string | null;
};

export type ManagedServiceContactSet = {
  serviceEmail: string | null;
  technicalEmail: string | null;
  securityEmail: string | null;
  operationsOnCall: string | null;
};

export type ManagedServiceGovernance = {
  criticality: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  classification: string | null;
  containsPersonalData: boolean | null;
  exportAllowed: boolean | null;
  retentionDays: number | null;
  loggingPolicy: string | null;
  redactionFields: string[];
};

export type ManagedService = {
  id: string;
  legacyMcpServerId: string | null;
  code: string;
  slug: string;
  displayName: string;
  description: string;
  serviceKind: ManagedServiceKind;
  lifecycleState: ManagedServiceState;
  operationalState: "UNKNOWN" | "DISABLED" | "HEALTHY" | "DEGRADED" | "UNHEALTHY" | "QUARANTINED" | "MAINTENANCE" | "RETIRED";
  enabled: boolean;
  publicHostname: string | null;
  baseUrl: string | null;
  resourceUri: string | null;
  authMode: ManagedServiceAuthMode;
  apiState: ManagedServiceApiState;
  apiDisabledReason: string | null;
  owners: ManagedServiceOwnerSet;
  contacts: ManagedServiceContactSet;
  governance: ManagedServiceGovernance;
  activeRevisionId: string | null;
  monitoringEnabled: boolean;
  monitoringProfileDigest: string | null;
  reviewApprovedAt: string | null;
  reviewDueAt: string | null;
  reviewIntervalDays: number | null;
  revocationEpoch: string;
  createdAt: string;
  updatedAt: string;
  retiredAt: string | null;
};

export type ManagedServiceRevision = {
  id: string;
  managedServiceId: string;
  revision: string;
  schemaVersion: string;
  serviceKind: ManagedServiceKind;
  validationState: string;
  manifest: Record<string, unknown>;
  manifestDigest: string;
  artifactDigest: string | null;
  contractDigest: string | null;
  sbomDigest: string | null;
  provenanceDigest: string | null;
  evidence: Record<string, unknown>;
  approvedAt: string | null;
  reviewDueAt: string | null;
  reviewIntervalDays: number | null;
  active: boolean;
  createdAt: string;
};

export type ManagedServiceScope = {
  id: string;
  managedServiceId: string;
  scopeName: string;
  level: ManagedServiceScopeLevel;
  description: string;
  constraints: Record<string, unknown>;
  createdAt: string;
  revokedAt: string | null;
};

export type ManagedServicePermission = {
  id: string;
  credentialId: string;
  managedServiceId: string;
  scopeId: string;
  scopeName: string;
  grantedAt: string;
  revokedAt: string | null;
};

export type ManagedServiceAccessToken = {
  fingerprint: string;
  credentialId: string;
  managedServiceId: string;
  audience: string;
  scopeNames: string[];
  issuedAt: string;
  expiresAt: string;
  revokedAt: string | null;
  lastUsedAt: string | null;
  credentialRevocationEpoch: string;
  serviceRevocationEpoch: string;
};

export type ManagedServiceApiStatus = {
  managedServiceId: string;
  apiState: ManagedServiceApiState;
  disabledReason: string | null;
  changedByType: string;
  changedById: string | null;
  correlationId: string | null;
  changedAt: string;
};

export type ManagedServiceUsageEvent = {
  id: number;
  managedServiceId: string;
  credentialId: string | null;
  scopeName: string | null;
  requestDigest: string | null;
  responseDigest: string | null;
  outcome: ManagedServiceUsageOutcome;
  latencyMs: number | null;
  classification: string | null;
  correlationId: string;
  createdAt: string;
};

export type ManagedServiceRuntimeLogEvent = {
  id: number;
  managedServiceId: string;
  level: "info" | "warn" | "error";
  eventName: string;
  fields: Record<string, unknown>;
  correlationId: string;
  createdAt: string;
};

export type ManagedServiceProbeResult = {
  id: number;
  managedServiceId: string;
  probeType: string;
  status: "PASS" | "FAIL" | "STALE";
  latencyMs: number | null;
  evidence: Record<string, unknown>;
  correlationId: string;
  checkedAt: string;
};

export type ExternalApiServiceProfile = {
  managedServiceId: string;
  baseUrl: string;
  healthcheckUrl: string | null;
  readinessUrl: string | null;
  tokenEndpointUrl: string | null;
  jwksUrl: string | null;
  authMetadataUrl: string | null;
  apiStyle: "REST" | "GRAPHQL" | "CUSTOM_HTTP";
  authHeaderName: string;
  authHeaderScheme: string | null;
  tokenForwardingMode: "BEARER" | "HEADER_VALUE" | "QUERY_FORBIDDEN";
  rateWindowSeconds: number | null;
  rateMaxRequests: number | null;
  timeoutMs: number | null;
  upstreamContract: Record<string, unknown>;
  monitoringContract: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
};

export type ServicePipelineRun = {
  id: string;
  managedServiceId: string | null;
  integrationTokenId: string | null;
  pipelineKind: ServicePipelineKind;
  state: string;
  sourceRevision: number;
  lockVersion: number;
  requestDigest: string | null;
  blockingErrorCode: string | null;
  blockingErrorDetail: string | null;
  correlationId: string;
  createdAt: string;
  updatedAt: string;
  completedAt: string | null;
};

export type ServicePipelineEvent = {
  id: number;
  pipelineRunId: string;
  fromState: string | null;
  toState: string;
  eventType: string;
  detail: Record<string, unknown>;
  correlationId: string;
  createdAt: string;
};

export type ExternalApiRegistrationManifest = {
  schemaVersion: "1.0";
  serviceKind: "EXTERNAL_API";
  environment: "production" | "staging";
  registrationRevision: string;
  displayName: string;
  description: string;
  serviceIdentity: {
    slug: string;
    region: string;
    basePath: string;
  };
  owners: ManagedServiceOwnerSet;
  contacts: ManagedServiceContactSet;
  governance: ManagedServiceGovernance;
  review: {
    intervalDays: number;
    approvedAt: string;
    reviewDueAt: string;
  };
  auth: {
    mode: ManagedServiceAuthMode;
    tokenEndpointUrl: string | null;
    jwksUrl: string | null;
    authMetadataUrl: string | null;
    gatewayEnforced: boolean;
  };
  endpoints: {
    baseUrl: string;
    healthcheckUrl: string | null;
    readinessUrl: string | null;
  };
  operations: Array<{
    operationId: string;
    method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
    path: string;
    requiredScopes: string[];
    idempotency: "READ_ONLY" | "IDEMPOTENT" | "NON_IDEMPOTENT";
    requestSchema: Record<string, unknown>;
    responseSchema: Record<string, unknown>;
    timeoutMs: number;
    maxPayloadBytes: number;
  }>;
  rateLimit: {
    windowSeconds: number;
    maxRequests: number;
  };
  timeoutMs: number;
  monitoringProfile: {
    staleAfterSeconds: number;
    probeIntervals: {
      healthSeconds: number;
      readinessSeconds: number;
      tlsSeconds: number;
      acceptanceSeconds: number;
    };
    alertRules: Array<{
      probeType: string;
      severity: "WARNING" | "HIGH" | "CRITICAL";
      consecutiveFailures: number;
    }>;
    runbookRef: string;
  };
  loggingContract: {
    correlationHeader: string;
    redactHeaders: string[];
  };
  stateContract: {
    operationalStatePath: string;
    apiAcceptancePath: string;
  };
  egressPolicy: {
    redirectsAllowed: false;
    allowlist: string[];
  };
  errorCatalog: Array<{
    code: string;
    description: string;
    classification: "FIXABLE" | "TRANSIENT" | "SECURITY_BLOCKER" | "INTERNAL";
    retryable: boolean;
  }>;
  evidence: {
    contractRefs: string[];
    securityRefs: string[];
    runbookRefs: string[];
  };
};
