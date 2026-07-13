import { describe, expect, it, vi } from "vitest";
import {
  HOME_ASSISTANT_INVENTORY_UPSTREAM,
  fetchHomeAssistantInventory,
  homeAssistantDeviceInventoryHandler
} from "./home-assistant-device-inventory.js";

const output = {
  generated_at: "2026-07-13T00:00:00.000Z",
  home_assistant_version: "2026.6.4",
  columns: Array.from({ length: 10 }, (_, index) => `column-${index}`),
  summary: { device_count: 1, entity_count: 2, controllable_device_count: 1, unassigned_device_count: 0 },
  rows: [{
    device_name: "Lamp",
    area: "Room",
    device_type: "Světlo",
    manufacturer: "Test",
    model: "L1",
    availability: "Aktivní",
    current_state: "zapnuto",
    controls: "Napájení",
    target_values: "zapnuto / vypnuto",
    readable_information: "Stav"
  }],
  markdown_table: "| table |"
};

describe("home assistant inventory handler", () => {
  it("uses only the loopback inventory upstream and returns its structured result", async () => {
    const fetchImpl = vi.fn(async (input: string | URL | Request) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      expect(url).toBe(HOME_ASSISTANT_INVENTORY_UPSTREAM);
      return new Response(JSON.stringify(output), { status: 200, headers: { "content-type": "application/json" } });
    }) as unknown as typeof fetch;
    await expect(fetchHomeAssistantInventory(fetchImpl)).resolves.toEqual(output);
    expect(homeAssistantDeviceInventoryHandler.key).toBe("home_assistant_device_inventory");
  });

  it("fails closed when the upstream is unavailable", async () => {
    const fetchImpl = vi.fn(async () => new Response("unavailable", { status: 503 })) as unknown as typeof fetch;
    await expect(fetchHomeAssistantInventory(fetchImpl)).rejects.toThrow("home_assistant_inventory_upstream_503");
  });
});
