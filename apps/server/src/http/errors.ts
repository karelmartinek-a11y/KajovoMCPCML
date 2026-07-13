import type { FastifyReply } from "fastify";
import { randomUUID } from "node:crypto";

export function sendError(reply: FastifyReply, statusCode: number, error: string, message?: string, correlationId: string = randomUUID()): FastifyReply {
  return reply.code(statusCode).send({
    error,
    message: message ?? error,
    correlationId
  });
}

export function hostOf(headersHost: string | undefined): string {
  return (headersHost ?? "").split(":")[0]?.toLowerCase() ?? "";
}
