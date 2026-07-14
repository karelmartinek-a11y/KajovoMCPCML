#!/usr/bin/env node
import { appendFile, mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const required = [
  "KCML_BASE_URL",
  "KCML_AUTH_HOST",
  "KCML_PUBLIC_HOSTNAME",
  "KCML_RESOURCE_URI",
  "KCML_CLIENT_ID",
  "KCML_CLIENT_SECRET"
];

for (const key of required) {
  if (!process.env[key]) {
    process.stderr.write(`missing_required_env:${key}\n`);
    process.exit(1);
  }
}

const config = {
  baseUrl: process.env.KCML_BASE_URL,
  authHost: process.env.KCML_AUTH_HOST,
  adminHost: process.env.KCML_ADMIN_HOST ?? "admin.hcasc.cz",
  publicHostname: process.env.KCML_PUBLIC_HOSTNAME,
  resourceUri: process.env.KCML_RESOURCE_URI,
  clientId: process.env.KCML_CLIENT_ID,
  clientSecret: process.env.KCML_CLIENT_SECRET,
  adminUsername: process.env.KCML_ADMIN_USERNAME ?? "karmar78",
  adminPassword: process.env.KCML_ADMIN_PASSWORD ?? null,
  managedServiceId: process.env.KCML_MANAGED_SERVICE_ID ?? null,
  credentialId: process.env.KCML_KAJA_CREDENTIAL_ID ?? null,
  outputDir: resolve(process.env.KCML_OUTPUT_DIR ?? process.cwd()),
  durationHours: Number(process.env.KCML_DURATION_HOURS ?? 72),
  intervalSeconds: Number(process.env.KCML_INTERVAL_SECONDS ?? 60),
  disableEveryMinutes: Number(process.env.KCML_DISABLE_EVERY_MINUTES ?? 180),
  permissionChurnEveryMinutes: Number(process.env.KCML_PERMISSION_CHURN_EVERY_MINUTES ?? 240)
};

const startedAt = new Date();
const endAt = new Date(startedAt.getTime() + config.durationHours * 60 * 60 * 1000);
const jsonlPath = resolve(config.outputDir, `external-api-soak-${startedAt.toISOString().replaceAll(":", "-")}.jsonl`);
const summaryPath = `${jsonlPath}.summary.json`;
const state = {
  disableEnabled: false,
  writePermissionEnabled: true,
  requestCount: 0,
  failureCount: 0
};

await mkdir(config.outputDir, { recursive: true });

function sleep(ms) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}

async function logEvent(event) {
  await appendFile(jsonlPath, `${JSON.stringify({ observedAt: new Date().toISOString(), ...event })}\n`, "utf8");
}

async function oauthToken() {
  const basic = Buffer.from(`${encodeURIComponent(config.clientId)}:${encodeURIComponent(config.clientSecret)}`).toString("base64");
  const response = await fetch(`${config.baseUrl}/oauth/token`, {
    method: "POST",
    headers: {
      host: config.authHost,
      authorization: `Basic ${basic}`,
      "content-type": "application/x-www-form-urlencoded"
    },
    body: `grant_type=client_credentials&resource=${encodeURIComponent(config.resourceUri)}`
  });
  if (!response.ok) throw new Error(`oauth_token_${response.status}`);
  return response.json();
}

async function loginAdmin() {
  if (!config.adminPassword) return null;
  const response = await fetch(`${config.baseUrl}/api/login`, {
    method: "POST",
    headers: {
      host: config.adminHost,
      "content-type": "application/json"
    },
    body: JSON.stringify({ username: config.adminUsername, password: config.adminPassword })
  });
  if (!response.ok) throw new Error(`admin_login_${response.status}`);
  const rawCookie = response.headers.get("set-cookie") ?? "";
  const csrfToken = (await response.json()).csrfToken;
  return { cookie: rawCookie.split(";")[0], csrfToken };
}

async function adminRequest(session, path, options = {}) {
  if (!session) throw new Error("admin_session_unavailable");
  const response = await fetch(`${config.baseUrl}${path}`, {
    method: options.method ?? "GET",
    headers: {
      host: config.adminHost,
      cookie: session.cookie,
      "x-csrf-token": session.csrfToken,
      "content-type": options.body ? "application/json" : undefined,
      "if-match": options.ifMatch ? `"${options.ifMatch}"` : undefined
    },
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  if (!response.ok) throw new Error(`admin_request_${path}_${response.status}`);
  return response.json();
}

async function gatewayRequest(accessToken, method, path, body) {
  const response = await fetch(`${config.baseUrl}${path}`, {
    method,
    headers: {
      host: config.publicHostname,
      authorization: `Bearer ${accessToken}`,
      "content-type": body ? "application/json" : undefined
    },
    body: body ? JSON.stringify(body) : undefined
  });
  const text = await response.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = { raw: text };
  }
  if (!response.ok) throw Object.assign(new Error(`gateway_${method}_${path}_${response.status}`), { response: json });
  return json;
}

async function maybeToggleDisable(session) {
  if (!session || !config.managedServiceId || !config.adminPassword) return;
  const minutesSinceStart = (Date.now() - startedAt.getTime()) / 60_000;
  if (Math.floor(minutesSinceStart) === 0 || Math.floor(minutesSinceStart) % config.disableEveryMinutes !== 0) return;
  const stateView = await adminRequest(session, `/api/managed-services/${config.managedServiceId}/state`);
  const nextState = state.disableEnabled ? "enable" : "disable";
  await adminRequest(session, `/api/managed-services/${config.managedServiceId}/api:${nextState}`, {
    method: "POST",
    ifMatch: stateView.lockVersion,
    body: { reason: `soak_${nextState}`, password: config.adminPassword }
  });
  state.disableEnabled = !state.disableEnabled;
  await logEvent({ phase: "admin.disable_toggle", nextState });
}

async function maybeChurnPermissions(session) {
  if (!session || !config.managedServiceId || !config.credentialId) return;
  const minutesSinceStart = (Date.now() - startedAt.getTime()) / 60_000;
  if (Math.floor(minutesSinceStart) === 0 || Math.floor(minutesSinceStart) % config.permissionChurnEveryMinutes !== 0) return;
  const scopeNames = state.writePermissionEnabled
    ? ["reference.shifts.read"]
    : ["reference.shifts.read", "reference.time_off.write"];
  await adminRequest(session, `/api/kaja/${config.credentialId}/managed-service-permissions`, {
    method: "PUT",
    body: {
      permissions: [{ managedServiceId: config.managedServiceId, scopeNames }]
    }
  });
  state.writePermissionEnabled = !state.writePermissionEnabled;
  await logEvent({ phase: "admin.permission_churn", scopeNames });
}

const adminSession = await loginAdmin().catch(async (error) => {
  await logEvent({ phase: "admin.login_failed", error: error instanceof Error ? error.message : "admin_login_failed" });
  return null;
});

while (Date.now() < endAt.getTime()) {
  const loopStarted = Date.now();
  try {
    const token = await oauthToken();
    await gatewayRequest(token.access_token, "GET", "/v1/shifts/soak-user", null);
    if (state.writePermissionEnabled) {
      await gatewayRequest(token.access_token, "POST", "/v1/time-off", { employeeId: "soak-user", days: 1 });
    }
    if (adminSession && config.managedServiceId) {
      await adminRequest(adminSession, `/api/managed-services/${config.managedServiceId}/logs?limit=20`);
    }
    await maybeToggleDisable(adminSession);
    await maybeChurnPermissions(adminSession);
    state.requestCount += 1;
    await logEvent({ phase: "loop.ok", requestCount: state.requestCount });
  } catch (error) {
    state.failureCount += 1;
    await logEvent({
      phase: "loop.failed",
      requestCount: state.requestCount,
      failureCount: state.failureCount,
      error: error instanceof Error ? error.message : "unknown"
    });
  }
  const elapsed = Date.now() - loopStarted;
  await sleep(Math.max(0, config.intervalSeconds * 1000 - elapsed));
}

const completed72h = Date.now() - startedAt.getTime() >= 72 * 60 * 60 * 1000;
await writeFile(summaryPath, JSON.stringify({
  startedAt: startedAt.toISOString(),
  endedAt: new Date().toISOString(),
  durationHoursRequested: config.durationHours,
  requestCount: state.requestCount,
  failureCount: state.failureCount,
  implementationStatus: completed72h ? "COMPLETED" : "PARTIALLY_IMPLEMENTED"
}, null, 2));
