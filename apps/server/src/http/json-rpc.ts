import type { FastifyReply } from "fastify";

export type JsonRpcId = string | number | null;
export type JsonRpcError = {
  jsonrpc: "2.0";
  id: JsonRpcId;
  error: {
    code: number;
    message: string;
    data: Record<string, unknown>;
  };
};
export type JsonRpcResponse = JsonRpcError | {
  jsonrpc: "2.0";
  id: JsonRpcId;
  result: Record<string, unknown>;
};

export function normalizedJsonRpcId(id: unknown): JsonRpcId {
  return typeof id === "string" || typeof id === "number" || id === null ? id : null;
}

function defaultApplicationCode(code: number): string {
  if (code === -32700) return "PARSE_ERROR";
  if (code === -32600) return "INVALID_REQUEST";
  if (code === -32601) return "METHOD_NOT_FOUND";
  if (code === -32602) return "INVALID_PARAMS";
  if (code === -32001) return "REQUEST_TOO_LARGE";
  if (code === -32002) return "RATE_LIMITED";
  if (code === -32003) return "HANDLER_UNAVAILABLE";
  if (code === -32004) return "CONCURRENCY_LIMIT_EXCEEDED";
  if (code === -32005) return "HANDLER_TIMEOUT";
  if (code === -32006) return "RESPONSE_TOO_LARGE";
  if (code === -32007) return "IDEMPOTENCY_CONFLICT";
  if (code === -32008) return "REQUEST_CANCELLED";
  return "INTERNAL_ERROR";
}

function defaultRetryable(code: number): boolean {
  return [-32002, -32004, -32005].includes(code);
}

export function jsonRpcError(id: unknown, code: number, message: string, correlationId: string, extra?: Record<string, unknown>): JsonRpcError {
  const applicationCode = typeof extra?.code === "string" ? extra.code : defaultApplicationCode(code);
  const retryable = typeof extra?.retryable === "boolean" ? extra.retryable : defaultRetryable(code);
  return {
    jsonrpc: "2.0",
    id: normalizedJsonRpcId(id),
    error: {
      code,
      message,
      data: {
        code: applicationCode,
        retryable,
        correlation_id: correlationId,
        correlationId,
        ...(extra ?? {})
      }
    }
  };
}

export function jsonRpcResult(id: unknown, result: Record<string, unknown>): JsonRpcResponse {
  return { jsonrpc: "2.0", id: normalizedJsonRpcId(id), result };
}

export function sendJsonRpc(reply: FastifyReply, payload: JsonRpcResponse): FastifyReply {
  reply.header("content-type", "application/json; charset=utf-8");
  return reply.send(payload);
}

export function respondToJsonRpc(reply: FastifyReply, requestId: unknown, payload: JsonRpcResponse): FastifyReply {
  if (requestId === undefined) return reply.code(202).send();
  return sendJsonRpc(reply, payload);
}

export function mapMcpRuntimeError(error: unknown): { code: number; message: string; classification: string; eventType: string } {
  const errorCode = error instanceof Error ? error.message : "unknown";
  const classification = typeof error === "object" && error && "classification" in error
    ? String(error.classification)
    : errorCode === "output_schema_failed" ? "schema" : "handler";
  if (classification === "timeout") return { code: -32005, message: "Handler timed out", classification, eventType: "mcp.timeout" };
  if (classification === "cancelled") return { code: -32008, message: "Request was cancelled", classification, eventType: "mcp.cancelled" };
  if (classification === "size") return { code: -32006, message: "Handler response exceeded the registered limit", classification, eventType: "mcp.response_too_large" };
  if (classification === "schema") return { code: -32603, message: "Output schema validation failed", classification, eventType: "mcp.output_schema_failed" };
  if (classification === "saturation") return { code: -32004, message: "Registered tool concurrency limit exceeded", classification, eventType: "mcp.concurrency_rejected" };
  if (classification === "upstream") return { code: -32603, message: "Handler failed", classification, eventType: "mcp.upstream_failed" };
  return { code: -32603, message: "Handler failed", classification, eventType: "mcp.invocation.failed" };
}
