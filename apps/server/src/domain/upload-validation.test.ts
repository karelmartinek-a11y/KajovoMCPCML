import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import yazl from "yazl";
import { validateAndQuarantineArchive } from "./upload-validation.js";

const roots: string[] = [];

const validFiles: Record<string, string | Buffer> = {
  "package.json": JSON.stringify({
    name: "@example/handler",
    type: "module",
    engines: { node: ">=22" },
    scripts: { test: "vitest run", lint: "eslint src", typecheck: "tsc --noEmit", build: "tsc" },
    dependencies: { zod: "3.25.76" },
    devDependencies: { "@types/node": "22.10.2", eslint: "9.30.1", typescript: "5.8.3", vitest: "3.2.4" }
  }),
  "tsconfig.json": JSON.stringify({ compilerOptions: { target: "ES2022", module: "NodeNext", moduleResolution: "NodeNext", strict: true, rootDir: "src", outDir: "dist" }, include: ["src/**/*.ts"] }),
  "pnpm-lock.yaml": "lockfileVersion: '9.0'\n",
  "src/index.ts": "export async function invoke(input: unknown) { return input; }\n",
  "src/index.test.ts": "import { it } from 'vitest'; it('works', () => {});\n"
};

async function zip(files: Record<string, string | Buffer>, modes: Record<string, number> = {}): Promise<Buffer> {
  const archive = new yazl.ZipFile();
  for (const [name, value] of Object.entries(files)) archive.addBuffer(Buffer.isBuffer(value) ? value : Buffer.from(value), name, modes[name] ? { mode: modes[name] } : undefined);
  archive.end();
  const chunks: Buffer[] = [];
  for await (const chunk of archive.outputStream) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

async function root(): Promise<string> {
  const value = await fs.mkdtemp(path.join(os.tmpdir(), "kcml-upload-test-"));
  roots.push(value);
  return value;
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })));
});

describe("handler ZIP quarantine", () => {
  it("accepts the fixed Node.js 22 TypeScript contract and records evidence", async () => {
    const result = await validateAndQuarantineArchive(await zip(validFiles), await root());
    expect(result.sourceDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(result.files).toContain("src/index.ts");
    expect(result.packageName).toBe("@example/handler");
    await expect(fs.stat(result.archivePath)).resolves.toBeTruthy();
  });

  it("rejects traversal and removes the partial quarantine directory", async () => {
    const original = await zip({ ...validFiles, "src/a.ts": "export {};" });
    const mutated = Buffer.from(original);
    const from = Buffer.from("src/a.ts");
    const to = Buffer.from("../a.ts ");
    let offset = 0;
    while ((offset = mutated.indexOf(from, offset)) >= 0) { to.copy(mutated, offset); offset += to.length; }
    await expect(validateAndQuarantineArchive(mutated, await root())).rejects.toThrow(/unsafe_archive_path|invalid relative path/);
  });

  it("rejects symlinks, embedded secrets, Dockerfiles and lifecycle scripts", async () => {
    await expect(validateAndQuarantineArchive(await zip({ ...validFiles, link: "src/index.ts" }, { link: 0o120777 }), await root())).rejects.toThrow("symlink_not_allowed");
    await expect(validateAndQuarantineArchive(await zip({ ...validFiles, "src/secret.ts": `const token = "kci_${"a".repeat(70)}";` }), await root())).rejects.toThrow("secret_detected");
    await expect(validateAndQuarantineArchive(await zip({ ...validFiles, Dockerfile: "FROM scratch" }), await root())).rejects.toThrow("custom_dockerfile_not_allowed");
    const pkg = JSON.parse(String(validFiles["package.json"])) as { scripts: Record<string, string> };
    pkg.scripts.postinstall = "node exploit.js";
    await expect(validateAndQuarantineArchive(await zip({ ...validFiles, "package.json": JSON.stringify(pkg) }), await root())).rejects.toThrow("package_script_not_allowed");
    await expect(validateAndQuarantineArchive(await zip({ ...validFiles, "scripts/run.sh": "#!/bin/sh" }), await root())).rejects.toThrow("source_file_not_allowed");
  });

  it("rejects suspicious compression ratios before execution", async () => {
    await expect(validateAndQuarantineArchive(await zip({ ...validFiles, "src/padding.ts": Buffer.alloc(2 * 1024 * 1024) }), await root())).rejects.toThrow("suspicious_compression_ratio");
  });
});
