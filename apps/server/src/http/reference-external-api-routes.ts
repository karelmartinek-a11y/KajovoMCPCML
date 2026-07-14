import type { FastifyInstance } from "fastify";
import type { AppConfig } from "../config.js";
import {
  acceptReferenceTimeOff,
  appendReferenceRequestLog,
  isReferenceExternalApiHostname,
  listReferenceShifts,
  referenceAcceptanceContract,
  referenceExternalApiState,
  requireGatewayHeaders
} from "../domain/reference-external-api.js";
import { hostOf, sendError } from "./errors.js";

export function registerReferenceExternalApiRoutes(app: FastifyInstance, config: AppConfig): void {
  app.get("/ready", async (request, reply) => {
    if (!isReferenceExternalApiHostname(hostOf(request.headers.host), config.PUBLIC_BASE_DOMAIN)) {
      return sendError(reply, 404, "not_found");
    }
    return reply.send({ ok: true, service: "reference-external-api" });
  });

  app.get("/state/operational", async (request, reply) => {
    if (!isReferenceExternalApiHostname(hostOf(request.headers.host), config.PUBLIC_BASE_DOMAIN)) {
      return sendError(reply, 404, "not_found");
    }
    return reply.send({
      service: "reference-external-api",
      ...referenceExternalApiState()
    });
  });

  app.get("/state/api-acceptance", async (request, reply) => {
    if (!isReferenceExternalApiHostname(hostOf(request.headers.host), config.PUBLIC_BASE_DOMAIN)) {
      return sendError(reply, 404, "not_found");
    }
    return reply.send(referenceAcceptanceContract(config.PUBLIC_BASE_DOMAIN));
  });

  app.get("/v1/shifts/:employeeId", async (request, reply) => {
    if (!isReferenceExternalApiHostname(hostOf(request.headers.host), config.PUBLIC_BASE_DOMAIN)) {
      return sendError(reply, 404, "not_found");
    }
    const gateway = requireGatewayHeaders(request.headers);
    if (!gateway.ok) {
      appendReferenceRequestLog({
        method: "GET",
        path: `/v1/shifts/${(request.params as { employeeId: string }).employeeId}`,
        status: 403,
        directBypassBlocked: true,
        correlationId: gateway.correlationId,
        operationId: gateway.operationId,
        principalId: gateway.principalId
      });
      return reply.code(403).send({
        code: "REFERENCE_DIRECT_BYPASS_BLOCKED",
        accepted: false
      });
    }
    const body = listReferenceShifts((request.params as { employeeId: string }).employeeId);
    appendReferenceRequestLog({
      method: "GET",
      path: `/v1/shifts/${(request.params as { employeeId: string }).employeeId}`,
      status: 200,
      directBypassBlocked: false,
      correlationId: gateway.correlationId,
      operationId: gateway.operationId,
      principalId: gateway.principalId
    });
    return reply.send(body);
  });

  app.post("/v1/time-off", async (request, reply) => {
    if (!isReferenceExternalApiHostname(hostOf(request.headers.host), config.PUBLIC_BASE_DOMAIN)) {
      return sendError(reply, 404, "not_found");
    }
    const gateway = requireGatewayHeaders(request.headers);
    if (!gateway.ok) {
      appendReferenceRequestLog({
        method: "POST",
        path: "/v1/time-off",
        status: 403,
        directBypassBlocked: true,
        correlationId: gateway.correlationId,
        operationId: gateway.operationId,
        principalId: gateway.principalId
      });
      return reply.code(403).send({
        code: "REFERENCE_DIRECT_BYPASS_BLOCKED",
        accepted: false
      });
    }
    const body = request.body as { employeeId?: string; days?: number };
    const response = acceptReferenceTimeOff(String(body.employeeId ?? ""), Number(body.days ?? 0));
    appendReferenceRequestLog({
      method: "POST",
      path: "/v1/time-off",
      status: 200,
      directBypassBlocked: false,
      correlationId: gateway.correlationId,
      operationId: gateway.operationId,
      principalId: gateway.principalId
    });
    return reply.send(response);
  });
}
