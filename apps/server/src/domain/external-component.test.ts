import { describe, expect, it } from "vitest";
import { assertSafeExternalTarget } from "./external-component.js";

describe("external component target validation", () => {
  it.each([
    "http://api.example.test",
    "https://127.0.0.1",
    "https://10.0.0.1",
    "https://169.254.169.254",
    "https://[::1]"
  ])("rejects unsafe external target %s", async (url) => {
    await expect(assertSafeExternalTarget(url)).rejects.toMatchObject({ message: expect.stringMatching(/^external_target_(url_invalid|ssrf_denied)$/) });
  });
});
