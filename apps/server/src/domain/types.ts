export const REGISTRATION_STATES = [
  "DRAFT",
  "DOCUMENTATION_INCOMPLETE",
  "PENDING_TECH_REVIEW",
  "PENDING_SECURITY_REVIEW",
  "PENDING_TEST",
  "TEST_FAILED",
  "APPROVED",
  "REGISTERED_DISABLED",
  "TRIAL",
  "ACTIVE",
  "SUSPENDED",
  "QUARANTINED",
  "REJECTED",
  "RETIRED"
] as const;

export type RegistrationState = (typeof REGISTRATION_STATES)[number];

export const OPERATIONAL_STATES = ["UNKNOWN", "DISABLED", "HEALTHY", "DEGRADED", "UNHEALTHY", "QUARANTINED", "MAINTENANCE", "RETIRED"] as const;
export type OperationalState = (typeof OPERATIONAL_STATES)[number];

export type McpServer = {
  id: string;
  code: string;
  kcmlNumber: number;
  hostname: string;
  toolName: string;
  displayName: string;
  description: string;
  enabled: boolean;
  registrationState: RegistrationState;
  operationalState: OperationalState;
  inputSchema: unknown;
  outputSchema: unknown;
  handlerKey: string;
  handlerVersion: string;
  contractVersion: string;
  artifactDigest: string;
  manifestDigest: string;
  imageReference: string | null;
  imageDigest: string | null;
  sbomDigest: string | null;
  provenanceDigest: string | null;
  runtimeSocket: string | null;
  timeoutMs: number;
  maxConcurrency: number;
  requestMaxBytes: number;
  responseMaxBytes: number;
  rateWindowSeconds: number;
  rateMaxRequests: number;
  revocationEpoch: string;
  successCount: number;
  unauthorizedCount: number;
  failureCount: number;
  lastSuccessAt: string | null;
  lastFailureAt: string | null;
  lastUnauthorizedAt: string | null;
  createdAt: string;
  updatedAt: string;
};

export type KajaCredential = {
  id: string;
  publicId: string;
  secretHash: string;
  active: boolean;
  revokedAt: string | null;
  deletedAt: string | null;
  revocationEpoch: string;
};
