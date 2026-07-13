import { describe, expect, it } from "vitest";
import { verifyAttestationEvidence } from "./oci.js";

function envelope(statement: unknown): string {
  return JSON.stringify({ payload: Buffer.from(JSON.stringify(statement)).toString("base64") });
}

const imageDigest = `sha256:${"a".repeat(64)}`;
const subject = [{ name: "handler-image", digest: { sha256: "a".repeat(64) } }];

describe("OCI attestation evidence", () => {
  it("binds SBOM and provenance to the exact digest, commit and Actions run", () => {
    const sbom = envelope({ subject, predicate: { packages: [] } });
    const provenance = envelope({
      subject,
      predicate: {
        invocation: { configSource: { digest: { sha1: "commit-123" } } },
        metadata: { buildInvocationID: "98765" }
      }
    });
    expect(() => verifyAttestationEvidence(sbom, provenance, imageDigest, "commit-123", "98765")).not.toThrow();
  });

  it("rejects an attestation copied from another build", () => {
    const sbom = envelope({ subject, predicate: { packages: [] } });
    const provenance = envelope({
      subject,
      predicate: {
        invocation: { configSource: { digest: { sha1: "commit-123" } } },
        metadata: { buildInvocationID: "different-run" }
      }
    });
    expect(() => verifyAttestationEvidence(sbom, provenance, imageDigest, "commit-123", "98765"))
      .toThrow("provenance_evidence_mismatch");
  });
});
