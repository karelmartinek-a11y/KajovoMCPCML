import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { digestCanonicalJson } from "../domain/registration.js";
import {
  expectedMonitoringProfileDigest,
  LEGACY_MONITORING_INTERVALS,
  LEGACY_MONITORING_STALE_AFTER_SECONDS
} from "./monitoring.js";

describe("monitoring profile digest compatibility", () => {
  const profile = { runbookRef: "runbook.md", probeIntervals: { syntheticSeconds: 300 } };
  const postgresJsonbText = '{"runbookRef": "runbook.md", "probeIntervals": {"syntheticSeconds": 300}}';

  it("uses the historical PostgreSQL jsonb digest for manifest 1.4", () => {
    const expected = `sha256:${createHash("sha256").update(postgresJsonbText).digest("hex")}`;
    expect(expectedMonitoringProfileDigest("1.4", profile, postgresJsonbText)).toBe(expected);
  });

  it("uses the canonical manifest digest for manifest 1.5", () => {
    expect(expectedMonitoringProfileDigest("1.5", profile, postgresJsonbText)).toBe(digestCanonicalJson(profile));
  });

  it("fails closed when legacy profile evidence is missing", () => {
    expect(() => expectedMonitoringProfileDigest("1.4", profile, null)).toThrow("legacy_monitoring_profile_text_missing");
  });
});

describe("legacy monitoring scheduling", () => {
  it("never marks a sample stale before its longest scheduled interval", () => {
    expect(LEGACY_MONITORING_STALE_AFTER_SECONDS).toBeGreaterThanOrEqual(
      Math.max(...Object.values(LEGACY_MONITORING_INTERVALS))
    );
  });
});
