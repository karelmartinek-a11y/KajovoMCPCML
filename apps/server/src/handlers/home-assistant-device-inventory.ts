import { registerHandler, type KcmlHandler } from "./registry.js";

export const HOME_ASSISTANT_INVENTORY_HANDLER_KEY = "home_assistant_device_inventory";
export const HOME_ASSISTANT_INVENTORY_HANDLER_VERSION = "1.0.0";
export const HOME_ASSISTANT_INVENTORY_TOOL_NAME = "get_home_assistant_device_inventory";
export const HOME_ASSISTANT_INVENTORY_UPSTREAM = "http://127.0.0.1:8103/internal/device-inventory";

export const HOME_ASSISTANT_INVENTORY_INPUT_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  properties: {},
  required: [],
  additionalProperties: false
} as const;

const rowProperties = {
  device_name: { type: "string" },
  area: { type: "string" },
  device_type: { type: "string" },
  manufacturer: { type: "string" },
  model: { type: "string" },
  availability: { type: "string" },
  current_state: { type: "string" },
  controls: { type: "string" },
  target_values: { type: "string" },
  readable_information: { type: "string" }
} as const;

export const HOME_ASSISTANT_INVENTORY_OUTPUT_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  properties: {
    generated_at: { type: "string" },
    home_assistant_version: { type: "string" },
    columns: { type: "array", items: { type: "string" }, minItems: 10, maxItems: 10 },
    summary: {
      type: "object",
      properties: {
        device_count: { type: "integer", minimum: 0 },
        entity_count: { type: "integer", minimum: 0 },
        controllable_device_count: { type: "integer", minimum: 0 },
        unassigned_device_count: { type: "integer", minimum: 0 }
      },
      required: ["device_count", "entity_count", "controllable_device_count", "unassigned_device_count"],
      additionalProperties: false
    },
    rows: {
      type: "array",
      items: {
        type: "object",
        properties: rowProperties,
        required: Object.keys(rowProperties),
        additionalProperties: false
      }
    },
    markdown_table: { type: "string" }
  },
  required: ["generated_at", "home_assistant_version", "columns", "summary", "rows", "markdown_table"],
  additionalProperties: false
} as const;

export type HomeAssistantInventoryOutput = {
  generated_at: string;
  home_assistant_version: string;
  columns: string[];
  summary: {
    device_count: number;
    entity_count: number;
    controllable_device_count: number;
    unassigned_device_count: number;
  };
  rows: Array<Record<keyof typeof rowProperties, string>>;
  markdown_table: string;
};

const activeByServer = new Map<string, number>();
const invocationsByServer = new Map<string, number[]>();

function reserveInvocation(serverId: string): () => void {
  const now = Date.now();
  const recent = (invocationsByServer.get(serverId) ?? []).filter((timestamp) => timestamp > now - 60_000);
  if (recent.length >= 10) throw Object.assign(new Error("home_assistant_inventory_rate_limited"), { classification: "rate_limit" });
  const active = activeByServer.get(serverId) ?? 0;
  if (active >= 2) throw Object.assign(new Error("home_assistant_inventory_concurrency_limited"), { classification: "rate_limit" });
  recent.push(now);
  invocationsByServer.set(serverId, recent);
  activeByServer.set(serverId, active + 1);
  return () => activeByServer.set(serverId, Math.max(0, (activeByServer.get(serverId) ?? 1) - 1));
}

export async function fetchHomeAssistantInventory(correlationId: string, fetchImpl: typeof fetch = fetch): Promise<HomeAssistantInventoryOutput> {
  try {
    const response = await fetchImpl(HOME_ASSISTANT_INVENTORY_UPSTREAM, {
      method: "GET",
      headers: { accept: "application/json", "x-correlation-id": correlationId },
      signal: AbortSignal.timeout(15_000)
    });
    if (!response.ok) {
      throw Object.assign(new Error(`home_assistant_inventory_upstream_${response.status}`), { classification: "upstream" });
    }
    const text = await response.text();
    if (Buffer.byteLength(text, "utf8") > 2 * 1024 * 1024) {
      throw Object.assign(new Error("home_assistant_inventory_response_too_large"), { classification: "schema" });
    }
    try {
      return JSON.parse(text) as HomeAssistantInventoryOutput;
    } catch {
      throw Object.assign(new Error("home_assistant_inventory_invalid_json"), { classification: "schema" });
    }
  } catch (error) {
    if (typeof error === "object" && error && "classification" in error) throw error;
    const name = error instanceof Error ? error.name : "";
    if (["AbortError", "TimeoutError"].includes(name)) {
      throw Object.assign(new Error("home_assistant_inventory_timeout"), { classification: "timeout" });
    }
    throw Object.assign(new Error("home_assistant_inventory_connection_failed"), { classification: "upstream" });
  }
}

export const homeAssistantDeviceInventoryHandler: KcmlHandler = {
  key: HOME_ASSISTANT_INVENTORY_HANDLER_KEY,
  version: HOME_ASSISTANT_INVENTORY_HANDLER_VERSION,
  async invoke(_input, context) {
    void context.logger.info({ correlationId: context.correlationId, upstreamSystem: "home-assistant-agent" }, "device inventory requested");
    const release = reserveInvocation(context.server.id);
    try {
      return await fetchHomeAssistantInventory(context.correlationId);
    } finally {
      release();
    }
  }
};

registerHandler(homeAssistantDeviceInventoryHandler);
