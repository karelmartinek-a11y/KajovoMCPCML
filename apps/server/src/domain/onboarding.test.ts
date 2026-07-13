import { describe, expect, it } from "vitest";
import {
  assertTransition,
  issueIntegrationSecret,
  nextHeartbeatExpiry,
  requestDigest,
  tokenDeadlines
} from "./onboarding.js";

describe("automated onboarding token policy", () => {
  it("issues a prefixed secret with 512 bits of random material", () => {
    const issued = issueIntegrationSecret();
    expect(issued.value).toMatch(/^kci_[A-Za-z0-9_-]+$/);
    expect(Buffer.from(issued.value.slice(4), "base64url")).toHaveLength(64);
    expect(issued.fingerprint).toHaveLength(16);
  });

  it("sets an initial two-hour TTL and a hard 24-hour ceiling", () => {
    const issuedAt = new Date("2026-07-13T10:00:00.000Z");
    const deadlines = tokenDeadlines(issuedAt);
    expect(deadlines.expiresAt.toISOString()).toBe("2026-07-13T12:00:00.000Z");
    expect(deadlines.maxExpiresAt.toISOString()).toBe("2026-07-14T10:00:00.000Z");
  });

  it("extends only forward and never beyond the 24-hour maximum", () => {
    const current = new Date("2026-07-13T12:00:00.000Z");
    const maximum = new Date("2026-07-14T10:00:00.000Z");
    expect(nextHeartbeatExpiry(new Date("2026-07-13T11:00:00.000Z"), current, maximum).toISOString()).toBe("2026-07-13T13:00:00.000Z");
    expect(nextHeartbeatExpiry(new Date("2026-07-14T09:30:00.000Z"), current, maximum).toISOString()).toBe(maximum.toISOString());
    expect(nextHeartbeatExpiry(new Date("2026-07-13T09:00:00.000Z"), current, maximum).toISOString()).toBe(current.toISOString());
  });

  it("enforces the state machine and deterministic request digests", () => {
    expect(() => assertTransition("SOURCE_UPLOADED", "PR_CREATED")).not.toThrow();
    expect(() => assertTransition("DEPLOYING", "CANCELLED")).not.toThrow();
    expect(() => assertTransition("TRIAL_TESTING", "CANCELLED")).not.toThrow();
    expect(() => assertTransition("SOURCE_UPLOADED", "ACTIVE")).toThrow("invalid_state_transition");
    expect(requestDigest(`sha256:${"a".repeat(64)}`, `sha256:${"b".repeat(64)}`)).toMatch(/^sha256:[a-f0-9]{64}$/);
  });
});
