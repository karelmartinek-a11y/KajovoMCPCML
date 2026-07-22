import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { authenticator } from "otplib";
import { loadBootstrapConfig } from "../config.js";
import { createDb } from "../db.js";
import { requireDeploymentManagedAdminPassword } from "../domain/deployment-managed-admin.js";
import { loadConfigFromDb } from "../domain/operational-config.js";

const SESSION_COOKIE = "__Host-kcml_session";
const CSRF_COOKIE = "__Host-kcml_csrf";
const LOGIN_CHALLENGE_COOKIE = "__Host-kcml_login_challenge";

function getSetCookieHeaders(headers: Headers): string[] {
  const headerValue = headers.get("set-cookie");
  const custom = (headers as Headers & { getSetCookie?: () => string[] }).getSetCookie?.();
  if (custom && custom.length > 0) return custom;
  return headerValue ? [headerValue] : [];
}

function findCookie(headers: Headers, name: string): string | null {
  for (const cookie of getSetCookieHeaders(headers)) {
    const match = new RegExp(`(?:^|,\\s*)${name}=([^;]+)`).exec(cookie);
    if (match?.[1]) return match[1];
  }
  return null;
}

async function postJson(baseUrl: string, host: string, path: string, body: unknown, cookieHeader?: string): Promise<Response> {
  const url = new URL(path, baseUrl);
  const transport = url.protocol === "https:" ? httpsRequest : httpRequest;
  const payload = JSON.stringify(body);

  return new Promise<Response>((resolve, reject) => {
    const request = transport(url, {
      method: "POST",
      headers: {
        host,
        "content-type": "application/json",
        "content-length": Buffer.byteLength(payload).toString()
      }
    }, (incoming) => {
      const chunks: Buffer[] = [];
      incoming.on("data", (chunk) => {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      });
      incoming.on("end", () => {
        const headers = new Headers();
        for (const [key, value] of Object.entries(incoming.headers)) {
          if (Array.isArray(value)) {
            for (const item of value) headers.append(key, item);
          } else if (value) {
            headers.set(key, value);
          }
        }
        resolve(new Response(Buffer.concat(chunks), {
          status: incoming.statusCode ?? 500,
          statusText: incoming.statusMessage ?? "",
          headers
        }));
      });
    });

    request.on("error", reject);
    if (cookieHeader) request.setHeader("cookie", cookieHeader);
    request.write(payload);
    request.end();
  });
}

const bootstrap = loadBootstrapConfig();
const db = createDb(bootstrap);

try {
  const config = await loadConfigFromDb(db, bootstrap);
  const password = requireDeploymentManagedAdminPassword(process.env.PASS);
  const baseUrl = process.env.KCML_LOGIN_SMOKE_BASE_URL ?? `http://127.0.0.1:${bootstrap.PORT}`;
  const host = process.env.KCML_LOGIN_SMOKE_HOST ?? config.ADMIN_HOST;
  const username = process.env.ADMIN_BOOTSTRAP_USERNAME ?? config.ADMIN_BOOTSTRAP_USERNAME;

  const loginResponse = await postJson(baseUrl, host, "/api/login", { username, password });
  const loginBody = await loginResponse.json() as Record<string, unknown>;
  if (!loginResponse.ok) {
    throw new Error(`admin_login_smoke_failed:${loginResponse.status}`);
  }

  let finalBody = loginBody;
  let finalHeaders = loginResponse.headers;
  if (loginBody.mfaRequired === true) {
    if (!config.ADMIN_TOTP_SECRET) {
      throw new Error("admin_login_smoke_mfa_secret_missing");
    }
    const challengeCookie = findCookie(loginResponse.headers, LOGIN_CHALLENGE_COOKIE);
    if (!challengeCookie) {
      throw new Error("admin_login_smoke_challenge_cookie_missing");
    }
    const mfaResponse = await postJson(
      baseUrl,
      host,
      "/api/login/mfa",
      { code: authenticator.generate(config.ADMIN_TOTP_SECRET) },
      `${LOGIN_CHALLENGE_COOKIE}=${challengeCookie}`
    );
    finalBody = await mfaResponse.json() as Record<string, unknown>;
    finalHeaders = mfaResponse.headers;
    if (!mfaResponse.ok || finalBody.ok !== true) {
      throw new Error(`admin_login_smoke_mfa_failed:${mfaResponse.status}`);
    }
  } else if (loginBody.ok !== true) {
    throw new Error("admin_login_smoke_unexpected_response");
  }

  const sessionCookie = findCookie(finalHeaders, SESSION_COOKIE);
  const csrfCookie = findCookie(finalHeaders, CSRF_COOKIE);
  if (!sessionCookie || !csrfCookie || typeof finalBody.csrfToken !== "string" || finalBody.csrfToken !== csrfCookie) {
    throw new Error("admin_login_smoke_cookie_contract_failed");
  }

  process.stdout.write(`${JSON.stringify({
    ok: true,
    username,
    mfaUsed: loginBody.mfaRequired === true,
    csrfToken: finalBody.csrfToken,
    sessionCookie,
    csrfCookie
  })}\n`);
} finally {
  await db.end();
}
