import { describe, expect, it } from "vitest";
import { formatMinuteSecondCountdown, getIntegrationTokenLifecycle } from "./integration-token-lifecycle.js";

const baseToken = {
  issuedAt: "2026-07-13T10:00:00.000Z",
  expiresAt: "2026-07-13T13:00:00.000Z",
  maxExpiresAt: "2026-07-14T10:00:00.000Z",
  revokedAt: null,
  jobId: "job-1",
  jobState: "CI_RUNNING",
  heartbeatAt: "2026-07-13T11:00:00.000Z"
};

describe("integration token lifecycle presentation", () => {
  it("shows a running integration without claiming extension protection", () => {
    const lifecycle = getIntegrationTokenLifecycle(baseToken, Date.parse("2026-07-13T11:00:30.000Z"));
    expect(lifecycle.runState).toBe("running");
    expect(lifecycle.protectionActive).toBe(false);
    expect(lifecycle.protectionLabel).toContain("24hodinové");
    expect(lifecycle.currentRemainingMs).toBe(7_170_000);
  });

  it("does not depend on heartbeat freshness", () => {
    const lifecycle = getIntegrationTokenLifecycle(baseToken, Date.parse("2026-07-13T11:02:00.000Z"));
    expect(lifecycle.runState).toBe("running");
    expect(lifecycle.protectionActive).toBe(false);
  });

  it("marks failed or cancelled work as incomplete", () => {
    const lifecycle = getIntegrationTokenLifecycle({ ...baseToken, jobState: "FAILED" }, Date.parse("2026-07-13T11:00:30.000Z"));
    expect(lifecycle.runState).toBe("paused");
    expect(lifecycle.runLabel).toBe("Integrace nedokončena");
    expect(lifecycle.protectionActive).toBe(false);
  });

  it("warns during the final two hours of the hard 24-hour lifetime", () => {
    const lifecycle = getIntegrationTokenLifecycle(baseToken, Date.parse("2026-07-14T08:30:00.000Z"));
    expect(lifecycle.nearMaximum).toBe(true);
    expect(lifecycle.maximumRemainingMs).toBe(5_400_000);
    expect(lifecycle.maximumProgressPercent).toBeCloseTo(93.75);
  });

  it("formats the live countdown strictly in minutes and seconds", () => {
    expect(formatMinuteSecondCountdown(7_170_000)).toBe("119 min 30 s");
    expect(formatMinuteSecondCountdown(999)).toBe("0 min 01 s");
    expect(formatMinuteSecondCountdown(0)).toBe("0 min 00 s");
  });
});
