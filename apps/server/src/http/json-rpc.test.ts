import { describe, expect, it } from "vitest";
import { jsonRpcError, jsonRpcResult, mapMcpRuntimeError, normalizedJsonRpcId } from "./json-rpc.js";

describe("JSON-RPC response mapping", () => {
  it("normalizes only protocol-valid identifiers", () => {
    expect(normalizedJsonRpcId("request-1")).toBe("request-1");
    expect(normalizedJsonRpcId(3)).toBe(3);
    expect(normalizedJsonRpcId(null)).toBeNull();
    expect(normalizedJsonRpcId({})).toBeNull();
  });

  it("always includes correlation metadata", () => {
    expect(jsonRpcError(1, -32602, "Invalid params", "correlation-1")).toMatchObject({
      jsonrpc: "2.0",
      id: 1,
      error: {
        code: -32602,
        data: {
          code: "INVALID_PARAMS",
          retryable: false,
          correlation_id: "correlation-1",
          correlationId: "correlation-1"
        }
      }
    });
    expect(jsonRpcResult(1, { ok: true })).toEqual({ jsonrpc: "2.0", id: 1, result: { ok: true } });
  });

  it.each([
    [Object.assign(new Error("handler_timeout"), { classification: "timeout" }), -32005, "mcp.timeout"],
    [Object.assign(new Error("handler_cancelled"), { classification: "cancelled" }), -32008, "mcp.cancelled"],
    [Object.assign(new Error("worker_response_too_large"), { classification: "size" }), -32006, "mcp.response_too_large"],
    [new Error("output_schema_failed"), -32603, "mcp.output_schema_failed"],
    [new Error("unexpected"), -32603, "mcp.invocation.failed"]
  ])("maps runtime failures without exposing internal details", (error, code, eventType) => {
    expect(mapMcpRuntimeError(error)).toMatchObject({ code, eventType });
  });
});
