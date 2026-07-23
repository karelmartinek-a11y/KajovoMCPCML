#!/usr/bin/env node
import fs from "node:fs/promises";

function decodedAttestationPayloads(value) {
  const results = [];
  for (const line of value.split("\n").filter(Boolean)) {
    try {
      const item = JSON.parse(line);
      if (item && typeof item.payload === "string") {
        results.push(Buffer.from(item.payload, "base64").toString("utf8"));
        continue;
      }
    } catch {
      // Fall through to already-decoded payload handling.
    }
    results.push(line);
  }
  return results;
}

function statements(value) {
  return decodedAttestationPayloads(value).flatMap((payload) => {
    try {
      return [JSON.parse(payload)];
    } catch {
      return [];
    }
  });
}

function hasSubject(statement, imageDigest) {
  const expected = imageDigest.replace(/^sha256:/, "");
  return statement.subject?.some((subject) => subject.digest?.sha256 === expected) ?? false;
}

async function main() {
  const [sbomPath, provenancePath, imageDigest, expectedSourceCommit, expectedBuildRunId] = process.argv.slice(2);
  if (!sbomPath || !provenancePath || !imageDigest || !expectedSourceCommit || !expectedBuildRunId) {
    throw new Error("usage: verify-repository-component-attestations <sbom> <provenance> <image-digest> <source-commit> <build-run-id>");
  }

  const [sbomOutput, provenanceOutput] = await Promise.all([
    fs.readFile(sbomPath, "utf8"),
    fs.readFile(provenancePath, "utf8")
  ]);

  if (!statements(sbomOutput).some((statement) => hasSubject(statement, imageDigest))) {
    throw new Error("sbom_subject_digest_mismatch");
  }

  const provenance = statements(provenanceOutput).find((statement) => {
    if (!hasSubject(statement, imageDigest)) return false;
    if (statement.predicate?.invocation?.configSource?.digest?.sha1 !== expectedSourceCommit) return false;
    const buildInvocationId = statement.predicate?.metadata?.buildInvocationID;
    return buildInvocationId === undefined || String(buildInvocationId) === expectedBuildRunId;
  });

  if (!provenance) {
    throw new Error("provenance_evidence_mismatch");
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
