import type { AlertDelivery, Component, MonitoringProfile, OperationalAlert, Server } from "./types.js";
import { api, csrf } from "./ui-helpers.js";

const mutationHeaders = (): HeadersInit => ({ "x-csrf-token": csrf() });

export type ServerTestCheckpointKey =
  | "contract"
  | "input_validation"
  | "runtime_lease"
  | "handler_run"
  | "output_validation"
  | "result_match"
  | "activation";

export type ServerTestCheckpoint = {
  key: ServerTestCheckpointKey;
  label: string;
  description: string;
  status: "PENDING" | "PASSED" | "FAILED" | "SKIPPED";
  detail?: string;
  durationMs?: number;
};

export type ServerTestResult = {
  ok: boolean;
  status: "PASSED" | "EXPECTED_RESULT_MISMATCH" | "FAILED";
  correlationId: string;
  latencyMs: number;
  activeRevisionId: string;
  manifestDigest: string;
  checkpoints: ServerTestCheckpoint[];
  errorCode?: string;
  errorMessage?: string;
  failedCheckpointKey?: ServerTestCheckpointKey;
  output?: unknown;
};

export async function setServerEnabled(server: Server, enabled: boolean): Promise<void> {
  await api(`/api/mcp-servers/${server.id}/enabled`, {
    method: "POST",
    headers: mutationHeaders(),
    body: JSON.stringify({ enabled })
  });
}

export async function setComponentEnabled(component: Component, enabled: boolean): Promise<Component> {
  const response = await api<{ component: Component }>(`/api/components/${component.id}/activation`, {
    method: "POST",
    headers: mutationHeaders(),
    body: JSON.stringify({ enabled })
  });
  return response.component;
}

export async function setComponentLifecycle(component: Component, action: "QUARANTINE" | "RESTORE" | "RETIRE" | "DEREGISTER"): Promise<Component> {
  const response = await api<{ component: Component }>(`/api/components/${component.id}/lifecycle`, {
    method: "POST", headers: mutationHeaders(), body: JSON.stringify({ action })
  });
  return response.component;
}

export async function setComponentPermission(component: Component, permissionId: string, enabled: boolean): Promise<Component> {
  const response = await api<{ component: Component }>(`/api/components/${component.id}/permissions/${permissionId}`, {
    method: "POST", headers: mutationHeaders(), body: JSON.stringify({ enabled })
  });
  return response.component;
}

export async function revokeComponentCredential(component: Component, credentialId: string): Promise<Component> {
  const response = await api<{ component: Component }>(`/api/components/${component.id}/credentials/${credentialId}/revoke`, {
    method: "POST", headers: mutationHeaders(), body: "{}"
  });
  return response.component;
}

export async function rotateComponentCredential(component: Component, credentialId: string): Promise<{
  component: Component;
  credential: { clientId: string; clientSecret: string; fingerprint: string };
}> {
  return api(`/api/components/${component.id}/credentials/${credentialId}/rotate`, {
    method: "POST", headers: mutationHeaders(), body: "{}"
  });
}

export async function runRegisteredServerTest(server: Server): Promise<ServerTestResult> {
  return api<ServerTestResult>(`/api/mcp-servers/${server.id}/test`, {
    method: "POST",
    headers: mutationHeaders(),
    body: "{}"
  });
}

export function getMonitoringProfile(server: Server): Promise<MonitoringProfile> {
  return api<MonitoringProfile>(`/api/mcp-servers/${server.id}/monitoring-profile`);
}

export async function persistMonitoringProfile(server: Server, profile: MonitoringProfile): Promise<void> {
  const body = JSON.stringify({ enabled: true, expectedVersion: profile.version, profile: profile.profile });
  await api(`/api/mcp-servers/${server.id}/monitoring-profile/preview`, {
    method: "POST",
    headers: mutationHeaders(),
    body
  });
  await api(`/api/mcp-servers/${server.id}/monitoring-profile`, {
    method: "PUT",
    headers: mutationHeaders(),
    body
  });
}

export async function createServerRevision(server: Server): Promise<string> {
  const result = await api<{ jobId: string }>(`/api/mcp-servers/${server.id}/revisions`, {
    method: "POST",
    headers: mutationHeaders(),
    body: "{}"
  });
  return result.jobId;
}

export async function testAlertChannels(): Promise<void> {
  await api("/api/alerts/test", { method: "POST", headers: mutationHeaders(), body: "{}" });
}

export async function acknowledgeOperationalAlert(alert: OperationalAlert): Promise<void> {
  await api(`/api/alerts/${alert.id}/acknowledge`, { method: "POST", headers: mutationHeaders(), body: "{}" });
}

export async function suppressOperationalAlert(alert: OperationalAlert, reason: string, until: string): Promise<void> {
  await api(`/api/alerts/${alert.id}/suppress`, {
    method: "POST",
    headers: mutationHeaders(),
    body: JSON.stringify({ reason, until })
  });
}

export async function retryAlertDelivery(delivery: AlertDelivery): Promise<void> {
  await api(`/api/alert-deliveries/${delivery.id}/retry`, { method: "POST", headers: mutationHeaders(), body: "{}" });
}
