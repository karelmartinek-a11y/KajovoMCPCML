import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { digestCanonicalJson, reviewMetadataForManifest, validateOnboardingManifest, validateStoredOnboardingManifest } from "./registration.js";
import { KCML_RELEASE } from "./release.js";

const genericManifest = JSON.parse(readFileSync(new URL(`../../../../docs/onboarding-manifest-${KCML_RELEASE.manifestSchemaVersion}.example.json`, import.meta.url), "utf8")) as Record<string, unknown>;
const archivedManifest = JSON.parse(readFileSync(new URL("../../../../docs/archive/pre-2026.07.20/onboarding-manifest-v1.5.example.json", import.meta.url), "utf8")) as Record<string, unknown>;

describe("retired registration adapter", () => {
  it("requires the generic manifest to use /v2/component-onboardings", () => {
    expect(() => validateOnboardingManifest(genericManifest)).toThrow("legacy_registration_intake_retired");
  });

  it("does not accept an archived schema for a new registration", () => {
    expect(() => validateOnboardingManifest(archivedManifest)).toThrow("old_manifest_schema_not_accepted");
  });

  it("keeps immutable stored manifests readable for rollback and audit", () => {
    const stored = validateStoredOnboardingManifest(archivedManifest);
    expect(stored.manifest.schemaVersion).toBe("1.5");
    expect(reviewMetadataForManifest(stored.manifest).intervalDays).toBeGreaterThan(0);
  });

  it("keeps canonical evidence digests content-bound", () => {
    expect(digestCanonicalJson({ a: 1 })).not.toBe(digestCanonicalJson({ a: 2 }));
  });
});
