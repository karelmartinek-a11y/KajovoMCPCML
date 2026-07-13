import { describe, expect, it } from "vitest";
import {
  rootlessContainerUserArgs,
  rootlessPodmanServiceInvocation,
  sanitizeCommandFailure,
  verifyAttestationEvidence,
  verifyLocalRuntimeEvidence
} from "./oci.js";

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

describe("local runtime integrity evidence", () => {
  const expectedDigest = `sha256:${"b".repeat(64)}`;
  const expectedImageName = `ghcr.io/example/private-handler@${expectedDigest}`;

  it("accepts the exact locally running immutable artifact", () => {
    expect(() => verifyLocalRuntimeEvidence({
      actualDigest: expectedDigest,
      expectedDigest,
      runtimeDigestLabel: expectedDigest,
      actualImageName: expectedImageName,
      expectedImageName
    })).not.toThrow();
  });

  it.each([
    ["digest", { actualDigest: `sha256:${"c".repeat(64)}` }, "artifact_digest_drift"],
    ["label", { runtimeDigestLabel: `sha256:${"c".repeat(64)}` }, "artifact_label_drift"],
    ["reference", { actualImageName: "ghcr.io/example/other@sha256:deadbeef" }, "artifact_reference_drift"]
  ])("rejects %s drift", (_name, override, code) => {
    expect(() => verifyLocalRuntimeEvidence({
      actualDigest: expectedDigest,
      expectedDigest,
      runtimeDigestLabel: expectedDigest,
      actualImageName: expectedImageName,
      expectedImageName,
      ...override
    })).toThrow(code);
  });
});

describe("OCI command error redaction", () => {
  it("removes capabilities and tokens from subprocess output", () => {
    const value = sanitizeCommandFailure("failed kce_secret-value kci_another-secret Kaja0002:client-secret ghp_github-secret");
    expect(value).toBe("failed [REDACTED] [REDACTED] [REDACTED] [REDACTED]");
  });
});

describe("rootless container user mapping", () => {
  it("keeps Podman rootless while mapping container root to the service account", () => {
    expect(rootlessContainerUserArgs(993, 985)).toEqual(["--userns", "host", "--user", "0:0"]);
  });

  it("rejects a rootful Podman worker", () => {
    expect(() => rootlessContainerUserArgs(0, 0)).toThrow("rootless_runtime_user_required");
  });
});

describe("rootless Podman user-manager execution", () => {
  it("submits Podman to the persistent user manager with only required environment", () => {
    const invocation = rootlessPodmanServiceInvocation({
      binary: "/usr/bin/podman",
      args: ["image", "inspect", "example"],
      runtimeUid: 993,
      unitId: "test-id",
      env: {
        HOME: "/var/lib/kcml/podman",
        USER: "kcml",
        LOGNAME: "kcml",
        XDG_DATA_HOME: "/var/lib/kcml/podman/data",
        XDG_CONFIG_HOME: "/var/lib/kcml/podman/config",
        XDG_RUNTIME_DIR: "/run/kcml-podman",
        DBUS_SESSION_BUS_ADDRESS: "unix:path=/run/kcml-podman/bus",
        REGISTRY_AUTH_FILE: "/var/lib/kcml/podman/auth.json",
        UNRELATED_SECRET: "must-not-be-forwarded"
      }
    });
    expect(invocation.binary).toBe("/usr/bin/systemd-run");
    expect(invocation.args).toContain("--unit=kcml-podman-test-id");
    expect(invocation.args).toContain("KillMode=process");
    expect(invocation.args).toContain("XDG_RUNTIME_DIR=/run/user/993");
    expect(invocation.args).toContain("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/993/bus");
    expect(invocation.args).toContain("REGISTRY_AUTH_FILE=/var/lib/kcml/podman/auth.json");
    expect(invocation.args).not.toContain("UNRELATED_SECRET=must-not-be-forwarded");
    expect(invocation.args.slice(-4)).toEqual(["/usr/bin/podman", "image", "inspect", "example"]);
  });

  it("rejects a rootful caller", () => {
    expect(() => rootlessPodmanServiceInvocation({
      binary: "podman",
      args: [],
      runtimeUid: 0,
      unitId: "test-id",
      env: {}
    })).toThrow("rootless_runtime_user_required");
  });
});
