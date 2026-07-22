import { createHash } from "node:crypto";
import { KCML_RELEASE } from "./release.js";

export const MCP_CATALOG_VERSION = KCML_RELEASE.catalogVersion;
export const MCP_MANIFEST_SCHEMA_VERSION = KCML_RELEASE.manifestSchemaVersion;
export const MCP_CATALOG_PATH = `docs/onboarding-catalogs/component-${MCP_CATALOG_VERSION}.json`;
export const MCP_CONNECT_FILE = `component-${MCP_CATALOG_VERSION}.json`;

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([key]) => key !== "canonicalDigest")
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nested]) => [key, canonicalize(nested)])
    );
  }
  return value;
}

export function onboardingCatalogDigest(catalog: unknown): string {
  const canonical = JSON.stringify(canonicalize(catalog));
  return `sha256:${createHash("sha256").update(canonical).digest("hex")}`;
}

export function verifyMcpOnboardingCatalog(input: unknown): Record<string, unknown> {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("onboarding_catalog_invalid");
  const catalog = input as Record<string, unknown>;
  if (catalog.version !== MCP_CATALOG_VERSION
    || catalog.serviceKind !== "COMPONENT"
    || catalog.manifestSchemaVersion !== MCP_MANIFEST_SCHEMA_VERSION
    || typeof catalog.canonicalDigest !== "string"
    || catalog.canonicalDigest !== onboardingCatalogDigest(catalog)) {
    throw new Error("onboarding_catalog_invalid");
  }
  return catalog;
}
