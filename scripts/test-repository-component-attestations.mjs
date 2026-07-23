#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

function dsseLine(statement) {
  return JSON.stringify({
    payload: Buffer.from(JSON.stringify(statement), "utf8").toString("base64")
  });
}

async function main() {
  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "kcml-attestation-test-"));
  try {
    const imageDigest = "sha256:" + "b".repeat(64);
    const subjectDigest = imageDigest.replace(/^sha256:/, "");
    const sourceCommit = "a".repeat(40);
    const buildRunId = "30020802220";

    const sbomPath = path.join(tmp, "sbom.jsonl");
    const provenancePath = path.join(tmp, "provenance.jsonl");

    const sbomStatement = {
      subject: [{ digest: { sha256: subjectDigest } }],
      predicateType: "https://spdx.dev/Document"
    };
    const provenanceStatement = {
      subject: [{ digest: { sha256: subjectDigest } }],
      predicateType: "https://slsa.dev/provenance/v1",
      predicate: {
        invocation: {
          configSource: {
            digest: { sha1: sourceCommit }
          }
        },
        metadata: {
          buildInvocationID: buildRunId
        }
      }
    };

    await fs.writeFile(sbomPath, dsseLine(sbomStatement) + "\n", "utf8");
    await fs.writeFile(provenancePath, dsseLine(provenanceStatement) + "\n", "utf8");

    await execFileAsync("node", [
      path.resolve("scripts/verify-repository-component-attestations.mjs"),
      sbomPath,
      provenancePath,
      imageDigest,
      sourceCommit,
      buildRunId
    ], { cwd: path.resolve(".") });

    const mismatch = await execFileAsync("node", [
      path.resolve("scripts/verify-repository-component-attestations.mjs"),
      sbomPath,
      provenancePath,
      imageDigest,
      "c".repeat(40),
      buildRunId
    ], { cwd: path.resolve(".") }).then(
      () => null,
      (error) => error
    );

    assert(mismatch, "expected provenance mismatch to fail");
    assert.match(String(mismatch.stderr || mismatch.stdout || mismatch.message), /provenance_evidence_mismatch/);
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
}

await main();
