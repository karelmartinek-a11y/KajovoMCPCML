import { randomUUID } from "node:crypto";
import type { ExternalApiRegistrationManifest } from "./managed-service-types.js";

export const REFERENCE_EXTERNAL_API_SUBDOMAIN = "reference-api";

type ReferenceRequestLog = {
  observedAt: string;
  method: string;
  path: string;
  status: number;
  directBypassBlocked: boolean;
  correlationId: string | null;
  operationId: string | null;
  principalId: string | null;
};

const requestLog: ReferenceRequestLog[] = [];

export function referenceExternalApiHostname(baseDomain: string): string {
  return `${REFERENCE_EXTERNAL_API_SUBDOMAIN}.${baseDomain}`.toLowerCase();
}

export function isReferenceExternalApiHostname(hostname: string, baseDomain: string): boolean {
  return hostname.toLowerCase() === referenceExternalApiHostname(baseDomain);
}

function recordReferenceRequest(entry: ReferenceRequestLog): void {
  requestLog.unshift(entry);
  if (requestLog.length > 100) requestLog.length = 100;
}

export function referenceExternalApiState(): {
  healthy: boolean;
  ready: boolean;
  recentRequests: ReferenceRequestLog[];
} {
  return {
    healthy: true,
    ready: true,
    recentRequests: [...requestLog]
  };
}

export function referenceAcceptanceContract(baseDomain: string): Record<string, unknown> {
  const host = referenceExternalApiHostname(baseDomain);
  return {
    serviceKind: "EXTERNAL_API",
    schemaVersion: "1.0",
    baseUrl: `https://${host}`,
    gatewayEnforced: true,
    directBypassBlocked: true,
    requiredGatewayHeaders: [
      "x-kcml-gateway-mode",
      "x-kcml-managed-service",
      "x-kcml-principal-id",
      "x-kcml-operation-id",
      "x-correlation-id"
    ],
    operations: [
      {
        operationId: "reference.listShifts",
        method: "GET",
        path: "/v1/shifts/{employeeId}",
        requiredScopes: ["reference.shifts.read"]
      },
      {
        operationId: "reference.requestTimeOff",
        method: "POST",
        path: "/v1/time-off",
        requiredScopes: ["reference.time_off.write"]
      }
    ],
    logging: {
      correlationHeader: "x-correlation-id",
      redactHeaders: ["authorization", "cookie", "set-cookie"]
    },
    stateContracts: {
      operationalStatePath: "/state/operational",
      apiAcceptancePath: "/state/api-acceptance"
    },
    monitoring: {
      staleAfterSeconds: 300,
      probeIntervals: {
        healthSeconds: 30,
        readinessSeconds: 30,
        tlsSeconds: 300,
        acceptanceSeconds: 60
      }
    },
    disableMode: "CENTRAL_GATEWAY",
    permissionMutationMode: "KCML_PERMISSION_EPOCH",
    redirectsAllowed: false,
    maxSupportedTimeoutMs: 8000
  };
}

export function referenceExternalApiManifest(baseDomain: string): ExternalApiRegistrationManifest {
  const host = referenceExternalApiHostname(baseDomain);
  return {
    schemaVersion: "1.0",
    serviceKind: "EXTERNAL_API",
    environment: "production",
    registrationRevision: "reference-api-1.0.0",
    displayName: "KCML Reference External API",
    description: "Reference HTTPS backend for KCML managed-service onboarding, monitoring, gateway enforcement and production smoke validation.",
    serviceIdentity: {
      slug: "reference-external-api",
      region: "eu-central-1",
      basePath: "/v1"
    },
    owners: {
      service: "KCML Managed Services",
      technical: "KCML Managed Services",
      security: "KCML Security",
      operations: "KCML Operations"
    },
    contacts: {
      serviceEmail: "service@hcasc.cz",
      technicalEmail: "platform@hcasc.cz",
      securityEmail: "security@hcasc.cz",
      operationsOnCall: "KCML on-call"
    },
    governance: {
      criticality: "HIGH",
      classification: "CONFIDENTIAL",
      containsPersonalData: true,
      exportAllowed: false,
      retentionDays: 365,
      loggingPolicy: "Gateway headers must be logged centrally with auth material redacted before ingestion.",
      redactionFields: ["authorization", "cookie", "set-cookie", "employeeId"]
    },
    review: {
      intervalDays: 90,
      approvedAt: "2026-07-15T00:00:00.000Z",
      reviewDueAt: "2026-10-13T00:00:00.000Z"
    },
    auth: {
      mode: "NONE",
      tokenEndpointUrl: null,
      jwksUrl: null,
      authMetadataUrl: null,
      gatewayEnforced: true
    },
    endpoints: {
      baseUrl: `https://${host}`,
      healthcheckUrl: `https://${host}/health`,
      readinessUrl: `https://${host}/ready`
    },
    operations: [
      {
        operationId: "reference.listShifts",
        method: "GET",
        path: "/v1/shifts/{employeeId}",
        requiredScopes: ["reference.shifts.read"],
        idempotency: "READ_ONLY",
        requestSchema: {
          type: "object",
          properties: {},
          additionalProperties: false
        },
        responseSchema: {
          type: "object",
          properties: {
            items: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  employeeId: { type: "string" },
                  shiftDate: { type: "string" },
                  start: { type: "string" },
                  end: { type: "string" }
                },
                required: ["employeeId", "shiftDate", "start", "end"],
                additionalProperties: false
              }
            }
          },
          required: ["items"],
          additionalProperties: false
        },
        timeoutMs: 5000,
        maxPayloadBytes: 65536
      },
      {
        operationId: "reference.requestTimeOff",
        method: "POST",
        path: "/v1/time-off",
        requiredScopes: ["reference.time_off.write"],
        idempotency: "NON_IDEMPOTENT",
        requestSchema: {
          type: "object",
          properties: {
            employeeId: { type: "string" },
            days: { type: "integer", minimum: 1, maximum: 30 }
          },
          required: ["employeeId", "days"],
          additionalProperties: false
        },
        responseSchema: {
          type: "object",
          properties: {
            requestId: { type: "string" },
            accepted: { type: "boolean" }
          },
          required: ["requestId", "accepted"],
          additionalProperties: false
        },
        timeoutMs: 8000,
        maxPayloadBytes: 131072
      }
    ],
    rateLimit: {
      windowSeconds: 60,
      maxRequests: 120
    },
    timeoutMs: 8000,
    monitoringProfile: {
      staleAfterSeconds: 300,
      probeIntervals: {
        healthSeconds: 30,
        readinessSeconds: 30,
        tlsSeconds: 300,
        acceptanceSeconds: 60
      },
      alertRules: [
        { probeType: "health", severity: "HIGH", consecutiveFailures: 2 },
        { probeType: "readiness", severity: "HIGH", consecutiveFailures: 2 },
        { probeType: "tls", severity: "CRITICAL", consecutiveFailures: 1 },
        { probeType: "acceptance", severity: "CRITICAL", consecutiveFailures: 1 }
      ],
      runbookRef: "evidence/runbooks/reference-external-api.md"
    },
    loggingContract: {
      correlationHeader: "x-correlation-id",
      redactHeaders: ["authorization", "cookie", "set-cookie"]
    },
    stateContract: {
      operationalStatePath: "/state/operational",
      apiAcceptancePath: "/state/api-acceptance"
    },
    egressPolicy: {
      redirectsAllowed: false,
      allowlist: [`${host}:443`]
    },
    errorCatalog: [
      {
        code: "REFERENCE_DIRECT_BYPASS_BLOCKED",
        description: "The reference backend rejected a direct request that did not carry the KCML gateway headers.",
        classification: "SECURITY_BLOCKER",
        retryable: false
      },
      {
        code: "REFERENCE_EMPLOYEE_NOT_FOUND",
        description: "The requested employee record does not exist in the reference backend.",
        classification: "FIXABLE",
        retryable: false
      },
      {
        code: "REFERENCE_BACKEND_INTERNAL",
        description: "The reference backend encountered an unexpected internal condition.",
        classification: "INTERNAL",
        retryable: true
      }
    ],
    evidence: {
      contractRefs: ["evidence/contracts/reference-external-api-openapi.json"],
      securityRefs: ["evidence/security/reference-external-api-threat-model.md"],
      runbookRefs: ["evidence/runbooks/reference-external-api.md"]
    }
  };
}

export function requireGatewayHeaders(headers: Record<string, unknown>): {
  ok: boolean;
  correlationId: string | null;
  operationId: string | null;
  principalId: string | null;
} {
  const gatewayMode = typeof headers["x-kcml-gateway-mode"] === "string" ? headers["x-kcml-gateway-mode"] : null;
  const managedService = typeof headers["x-kcml-managed-service"] === "string" ? headers["x-kcml-managed-service"] : null;
  const correlationId = typeof headers["x-correlation-id"] === "string" ? headers["x-correlation-id"] : null;
  const operationId = typeof headers["x-kcml-operation-id"] === "string" ? headers["x-kcml-operation-id"] : null;
  const principalId = typeof headers["x-kcml-principal-id"] === "string" ? headers["x-kcml-principal-id"] : null;
  return {
    ok: gatewayMode === "managed-service"
      && Boolean(managedService)
      && Boolean(correlationId)
      && Boolean(operationId)
      && Boolean(principalId),
    correlationId,
    operationId,
    principalId
  };
}

export function listReferenceShifts(employeeId: string): Record<string, unknown> {
  return {
    items: [
      {
        employeeId,
        shiftDate: "2026-07-15",
        start: "08:00",
        end: "16:00"
      }
    ]
  };
}

export function acceptReferenceTimeOff(employeeId: string, days: number): Record<string, unknown> {
  return {
    requestId: `rto_${employeeId}_${days}_${randomUUID().slice(0, 8)}`,
    accepted: true
  };
}

export function appendReferenceRequestLog(entry: Omit<ReferenceRequestLog, "observedAt">): void {
  recordReferenceRequest({ ...entry, observedAt: new Date().toISOString() });
}
