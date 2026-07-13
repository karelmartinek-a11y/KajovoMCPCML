import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { promisify } from "node:util";
import type { AppConfig } from "../config.js";
import type { OnboardingManifest } from "../domain/registration.js";

const execFileAsync = promisify(execFile);

async function command(binary: string, args: string[], timeout = 120_000): Promise<string> {
  const result = await execFileAsync(binary, args, { timeout, maxBuffer: 10 * 1024 * 1024, encoding: "utf8" });
  return result.stdout.trim();
}

function evidenceDigest(value: string): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function withoutTag(reference: string): string {
  const slash = reference.lastIndexOf("/");
  const colon = reference.lastIndexOf(":");
  return colon > slash ? reference.slice(0, colon) : reference;
}

function digestFromRepoReference(reference: string): string {
  const at = reference.lastIndexOf("@");
  return at >= 0 ? reference.slice(at + 1) : "";
}

function decodedAttestationPayloads(value: string): string[] {
  const results: string[] = [];
  for (const line of value.split("\n").filter(Boolean)) {
    try {
      const item = JSON.parse(line) as { payload?: string };
      if (item.payload) results.push(Buffer.from(item.payload, "base64").toString("utf8"));
    } catch {
      // cosign versions may emit an already-decoded statement.
      results.push(line);
    }
  }
  return results;
}

type AttestationStatement = {
  subject?: Array<{ digest?: { sha256?: string } }>;
  predicate?: {
    invocation?: { configSource?: { digest?: { sha1?: string } } };
    metadata?: { buildInvocationId?: string | number };
  };
};

function statements(value: string): AttestationStatement[] {
  return decodedAttestationPayloads(value).flatMap((payload) => {
    try {
      return [JSON.parse(payload) as AttestationStatement];
    } catch {
      return [];
    }
  });
}

function hasSubject(statement: AttestationStatement, imageDigest: string): boolean {
  const expected = imageDigest.replace(/^sha256:/, "");
  return statement.subject?.some((subject) => subject.digest?.sha256 === expected) ?? false;
}

export function verifyAttestationEvidence(
  sbomOutput: string,
  provenanceOutput: string,
  imageDigest: string,
  expectedSourceCommit: string,
  expectedBuildId: string
): void {
  if (!statements(sbomOutput).some((statement) => hasSubject(statement, imageDigest))) {
    throw new Error("sbom_subject_digest_mismatch");
  }
  const provenance = statements(provenanceOutput).find((statement) =>
    hasSubject(statement, imageDigest)
    && statement.predicate?.invocation?.configSource?.digest?.sha1 === expectedSourceCommit
    && String(statement.predicate?.metadata?.buildInvocationId ?? "") === expectedBuildId
  );
  if (!provenance) throw new Error("provenance_evidence_mismatch");
}

function socketHealth(socketPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = http.request({ socketPath, path: "/health", method: "GET", timeout: 2_000 }, (response) => {
      response.resume();
      if (response.statusCode === 200) resolve();
      else reject(new Error("worker_readiness_failed"));
    });
    request.on("timeout", () => request.destroy(new Error("worker_readiness_timeout")));
    request.on("error", reject);
    request.end();
  });
}

export class OciRuntime {
  constructor(private readonly config: AppConfig) {}

  imageReference(code: string, sourceCommit: string): string {
    if (!this.config.OCI_IMAGE_NAMESPACE) throw new Error("oci_namespace_not_configured");
    return `${this.config.OCI_REGISTRY}/${this.config.OCI_IMAGE_NAMESPACE}/${code.toLowerCase()}:${sourceCommit}`;
  }

  async verifyArtifact(imageReference: string, expectedSourceCommit: string, expectedBuildId: string): Promise<{
    imageReference: string;
    imageDigest: string;
    sbomDigest: string;
    provenanceDigest: string;
    buildId: string;
  }> {
    if (!this.config.OCI_SIGNING_PUBLIC_KEY) throw new Error("oci_signing_key_not_configured");
    await command(this.config.PODMAN_BINARY, ["pull", imageReference], 300_000);
    const repoDigest = await command(this.config.PODMAN_BINARY, ["image", "inspect", imageReference, "--format", "{{index .RepoDigests 0}}"]);
    const imageDigest = digestFromRepoReference(repoDigest);
    if (!/^sha256:[a-f0-9]{64}$/.test(imageDigest)) throw new Error("image_digest_invalid");
    const immutable = `${withoutTag(imageReference)}@${imageDigest}`;
    const signature = await command(this.config.COSIGN_BINARY, ["verify", "--key", this.config.OCI_SIGNING_PUBLIC_KEY, "--output", "json", immutable]);
    const signatures = JSON.parse(signature) as Array<{ critical?: { image?: { "docker-manifest-digest"?: string } } }>;
    if (!Array.isArray(signatures) || !signatures.some((item) => item.critical?.image?.["docker-manifest-digest"] === imageDigest)) throw new Error("image_signature_invalid");
    const sbom = await command(this.config.COSIGN_BINARY, ["verify-attestation", "--key", this.config.OCI_SIGNING_PUBLIC_KEY, "--type", "spdxjson", immutable]);
    const provenance = await command(this.config.COSIGN_BINARY, ["verify-attestation", "--key", this.config.OCI_SIGNING_PUBLIC_KEY, "--type", "slsaprovenance", immutable]);
    verifyAttestationEvidence(sbom, provenance, imageDigest, expectedSourceCommit, expectedBuildId);
    return {
      imageReference,
      imageDigest,
      sbomDigest: evidenceDigest(sbom),
      provenanceDigest: evidenceDigest(provenance),
      buildId: expectedBuildId
    };
  }

  async verifyRunningArtifact(code: string, imageReference: string, expectedDigest: string): Promise<Record<string, unknown>> {
    if (!this.config.OCI_SIGNING_PUBLIC_KEY) throw new Error("oci_signing_key_not_configured");
    const containerName = `kcml-${code.toLowerCase()}`;
    const imageId = await command(this.config.PODMAN_BINARY, ["container", "inspect", containerName, "--format", "{{.Image}}"]);
    if (!imageId) throw new Error("running_image_missing");
    const repoDigest = await command(this.config.PODMAN_BINARY, ["image", "inspect", imageId, "--format", "{{index .RepoDigests 0}}"]);
    const actualDigest = digestFromRepoReference(repoDigest);
    if (actualDigest !== expectedDigest) throw new Error("artifact_digest_drift");
    const immutable = `${withoutTag(imageReference)}@${expectedDigest}`;
    const signature = await command(this.config.COSIGN_BINARY, ["verify", "--key", this.config.OCI_SIGNING_PUBLIC_KEY, "--output", "json", immutable]);
    const signatures = JSON.parse(signature) as Array<{ critical?: { image?: { "docker-manifest-digest"?: string } } }>;
    if (!Array.isArray(signatures) || !signatures.some((item) => item.critical?.image?.["docker-manifest-digest"] === expectedDigest)) {
      throw new Error("running_image_signature_invalid");
    }
    return { containerName, imageId, imageDigest: actualDigest, signatureVerified: true };
  }

  async deploy(input: {
    code: string;
    imageReference: string;
    imageDigest: string;
    manifest: OnboardingManifest;
    egressCapabilityToken: string | null;
  }): Promise<{ socketPath: string; containerName: string }> {
    const runtimeUid = process.getuid?.();
    const runtimeGid = process.getgid?.();
    if (runtimeUid === undefined || runtimeGid === undefined || runtimeUid === 0) throw new Error("rootless_runtime_user_required");
    const immutable = `${withoutTag(input.imageReference)}@${input.imageDigest}`;
    const socketDirectory = path.join(this.config.RUNTIME_SOCKET_ROOT, input.code.toLowerCase());
    const socketPath = path.join(socketDirectory, "worker.sock");
    const containerName = `kcml-${input.code.toLowerCase()}`;
    await fs.mkdir(socketDirectory, { recursive: true, mode: 0o700 });
    await fs.rm(socketPath, { force: true });
    const egress = input.manifest.runtime.egressAllowlist.length > 0;
    if (egress && !input.egressCapabilityToken) throw new Error("egress_capability_missing");
    const args = [
      "run", "--detach", "--replace", "--restart", "on-failure:5", "--name", containerName,
      "--label", `cz.hcasc.kcml.code=${input.code}`,
      "--label", `cz.hcasc.kcml.image-digest=${input.imageDigest}`,
      "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
      "--log-driver", "none",
      "--pids-limit", String(input.manifest.runtime.pidsLimit),
      "--memory", `${input.manifest.runtime.memoryMb}m`,
      "--cpus", String(input.manifest.runtime.cpuCores),
      "--userns", "keep-id", "--user", `${runtimeUid}:${runtimeGid}`,
      "--network", "none",
      "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
      "--volume", `${socketDirectory}:/run/kcml:rw,z`,
      "--env", "KCML_SOCKET_PATH=/run/kcml/worker.sock",
      "--env", `KCML_SERVER_CODE=${input.code}`,
      "--env", `KCML_IMAGE_DIGEST=${input.imageDigest}`,
      "--env", `KCML_HANDLER_TIMEOUT_MS=${input.manifest.behavior.timeoutMs}`,
      "--env", `KCML_REQUEST_MAX_BYTES=${input.manifest.behavior.requestMaxBytes}`,
      "--env", `KCML_RESPONSE_MAX_BYTES=${input.manifest.behavior.responseMaxBytes}`
    ];
    if (egress) {
      const proxyDirectory = path.dirname(this.config.EGRESS_PROXY_SOCKET_PATH);
      await fs.access(this.config.EGRESS_PROXY_SOCKET_PATH);
      args.push("--volume", `${proxyDirectory}:/run/kcml-egress:ro`);
      args.push("--env", `KCML_EGRESS_CAPABILITY=${input.egressCapabilityToken}`);
      args.push("--env", "KCML_EGRESS_SOCKET_PATH=/run/kcml-egress/proxy.sock");
    }
    args.push(immutable);
    await command(this.config.PODMAN_BINARY, args, 300_000);
    const deadline = Date.now() + 30_000;
    while (Date.now() < deadline) {
      try {
        await fs.access(socketPath);
        await socketHealth(socketPath);
        return { socketPath, containerName };
      } catch {
        await new Promise((resolve) => setTimeout(resolve, 500));
      }
    }
    await this.stop(input.code).catch(() => undefined);
    throw new Error("worker_readiness_timeout");
  }

  async stop(code: string): Promise<void> {
    await command(this.config.PODMAN_BINARY, ["rm", "--force", "--ignore", `kcml-${code.toLowerCase()}`], 30_000);
  }
}
