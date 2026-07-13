import { createHash, randomUUID } from "node:crypto";
import { createWriteStream } from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { pipeline } from "node:stream/promises";
import type { Readable } from "node:stream";
import yauzl, { type Entry, type ZipFile } from "yauzl";

export const MAX_ARCHIVE_BYTES = 10 * 1024 * 1024;
export const MAX_EXPANDED_BYTES = 50 * 1024 * 1024;
export const MAX_FILES = 1_000;

const RUNTIME_DEPENDENCIES = new Set(["@kcml/handler-sdk", "zod"]);
const DEVELOPMENT_DEPENDENCIES = new Set(["@types/node", "eslint", "typescript", "vitest"]);
const EXACT_VERSION = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/;
const TEXT_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".mjs", ".cjs", ".json", ".md", ".txt", ".yaml", ".yml"]);
const BINARY_EXTENSIONS = new Set([".node", ".so", ".dll", ".dylib", ".exe", ".bin", ".wasm", ".jar", ".class"]);
const ROOT_SOURCE_FILES = new Set(["package.json", "pnpm-lock.yaml", "tsconfig.json", "readme.md", "license", "license.txt", "license.md"]);
const SECRET_PATTERNS = [
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  /\b(?:ghp|github_pat|glpat)-?[A-Za-z0-9_]{20,}\b/,
  /\bsk-[A-Za-z0-9_-]{20,}\b/,
  /\bkci_[A-Za-z0-9_-]{40,}\b/,
  /\bKaja\d{4,}:[A-Za-z0-9_-]{20,}\b/,
  /(?:password|client_secret|api[_-]?key)\s*[:=]\s*["']?[A-Za-z0-9_+/=.-]{16,}/i
];

export type ArchiveValidation = {
  directory: string;
  archivePath: string;
  sourceDirectory: string;
  sourceDigest: string;
  fileCount: number;
  expandedBytes: number;
  files: string[];
  packageName: string;
  dependencyCount: number;
};

type PackageJson = {
  name?: unknown;
  type?: unknown;
  engines?: { node?: unknown };
  scripts?: Record<string, unknown>;
  dependencies?: Record<string, unknown>;
  devDependencies?: Record<string, unknown>;
};

function invalid(code: string): Error {
  return Object.assign(new Error(code), { statusCode: 400 });
}

function openZip(buffer: Buffer): Promise<ZipFile> {
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(buffer, { lazyEntries: true, decodeStrings: true, validateEntrySizes: true }, (error, zip) => {
      if (error || !zip) reject(invalid("invalid_zip"));
      else resolve(zip);
    });
  });
}

function openEntryStream(zip: ZipFile, entry: Entry): Promise<Readable> {
  return new Promise((resolve, reject) => {
    zip.openReadStream(entry, (error, stream) => {
      if (error || !stream) reject(invalid("invalid_zip_entry"));
      else resolve(stream);
    });
  });
}

function normalizedEntryName(entry: Entry): string {
  const value = entry.fileName;
  if (!value || value.includes("\\") || value.includes("\0") || value.startsWith("/") || /^[A-Za-z]:/.test(value)) throw invalid("unsafe_archive_path");
  const normalized = path.posix.normalize(value);
  if (normalized === ".." || normalized.startsWith("../") || normalized.includes("/../")) throw invalid("unsafe_archive_path");
  return normalized.replace(/^\.\//, "");
}

function assertEntryType(entry: Entry, name: string): void {
  const unixMode = (entry.externalFileAttributes >>> 16) & 0xffff;
  const fileType = unixMode & 0o170000;
  const directory = name.endsWith("/");
  if (fileType === 0o120000) throw invalid("symlink_not_allowed");
  if (fileType !== 0 && fileType !== 0o100000 && !(directory && fileType === 0o040000)) throw invalid("special_file_not_allowed");
}

function assertAllowedPath(name: string): void {
  const lower = name.toLowerCase();
  const segments = lower.split("/");
  if (segments.includes("node_modules") || segments.includes(".git") || segments.includes(".github")) throw invalid("reserved_path_not_allowed");
  if (segments.some((part) => part === ".env" || part.startsWith(".env.") || part === ".npmrc" || part === ".pnpmfile.cjs")) throw invalid("secret_configuration_not_allowed");
  if (segments.at(-1)?.startsWith("dockerfile")) throw invalid("custom_dockerfile_not_allowed");
  if (BINARY_EXTENSIONS.has(path.extname(lower))) throw invalid("binary_artifact_not_allowed");
  if (segments.length > 20 || name.length > 240) throw invalid("archive_path_too_deep");
  const sourceDirectory = lower === "src/" || (lower.startsWith("src/") && lower.endsWith("/"));
  const typescriptSource = lower.startsWith("src/") && lower.endsWith(".ts");
  if (!ROOT_SOURCE_FILES.has(lower) && !sourceDirectory && !typescriptSource) throw invalid("source_file_not_allowed");
}

function assertNoSecrets(content: Buffer, name: string): void {
  const extension = path.extname(name).toLowerCase();
  if (!TEXT_EXTENSIONS.has(extension) && path.basename(name) !== "package.json") {
    if (content.includes(0)) throw invalid("binary_content_not_allowed");
    return;
  }
  if (content.includes(0)) throw invalid("binary_content_not_allowed");
  const text = content.toString("utf8");
  if (SECRET_PATTERNS.some((pattern) => pattern.test(text))) throw invalid("secret_detected");
}

function assertDependencies(dependencies: Record<string, unknown> | undefined, allowlist: ReadonlySet<string>, kind: string): number {
  let count = 0;
  for (const [name, version] of Object.entries(dependencies ?? {})) {
    count += 1;
    if (!allowlist.has(name)) throw invalid(`${kind}_dependency_not_allowed`);
    if (typeof version !== "string" || !EXACT_VERSION.test(version)) throw invalid("dependency_version_must_be_exact");
  }
  return count;
}

function validatePackageJson(content: Buffer): { packageName: string; dependencyCount: number } {
  let parsed: PackageJson;
  try {
    parsed = JSON.parse(content.toString("utf8")) as PackageJson;
  } catch {
    throw invalid("invalid_package_json");
  }
  if (typeof parsed.name !== "string" || !/^@[a-z0-9-]+\/[a-z0-9-]+$/.test(parsed.name)) throw invalid("invalid_package_name");
  if (parsed.type !== "module") throw invalid("package_must_use_esm");
  if (!parsed.engines || typeof parsed.engines.node !== "string" || !parsed.engines.node.includes("22")) throw invalid("node22_engine_required");
  const scriptNames = Object.keys(parsed.scripts ?? {});
  if (!scriptNames.includes("test")) throw invalid("test_script_required");
  if (scriptNames.some((name) => !["test", "lint", "typecheck", "build"].includes(name))) throw invalid("package_script_not_allowed");
  if (Object.values(parsed.scripts ?? {}).some((value) => typeof value !== "string" || value.length > 300)) throw invalid("invalid_package_script");
  const dependencyCount = assertDependencies(parsed.dependencies, RUNTIME_DEPENDENCIES, "runtime")
    + assertDependencies(parsed.devDependencies, DEVELOPMENT_DEPENDENCIES, "development");
  return { packageName: parsed.name, dependencyCount };
}

export async function validateAndQuarantineArchive(archive: Buffer, quarantineRoot: string): Promise<ArchiveValidation> {
  if (archive.length < 22) throw invalid("empty_or_invalid_zip");
  if (archive.length > MAX_ARCHIVE_BYTES) throw invalid("archive_too_large");
  const uploadDirectory = path.join(quarantineRoot, `upload-${randomUUID()}`);
  const sourceDirectory = path.join(uploadDirectory, "source");
  const archivePath = path.join(uploadDirectory, "source.zip");
  await fs.mkdir(sourceDirectory, { recursive: true, mode: 0o700 });
  await fs.writeFile(archivePath, archive, { mode: 0o600, flag: "wx" });
  const sourceDigest = `sha256:${createHash("sha256").update(archive).digest("hex")}`;
  const files: string[] = [];
  const seen = new Set<string>();
  let expandedBytes = 0;
  let packageJson: Buffer | null = null;
  let tsconfigJson: Buffer | null = null;
  try {
    const zip = await openZip(archive);
    await new Promise<void>((resolve, reject) => {
      let processing = false;
      const fail = (error: unknown) => {
        zip.close();
        reject(error instanceof Error ? error : new Error("invalid_zip"));
      };
      zip.on("error", fail);
      zip.on("end", () => {
        if (!processing) resolve();
      });
      zip.on("entry", (entry: Entry) => {
        processing = true;
        void (async () => {
          const name = normalizedEntryName(entry);
          assertEntryType(entry, name);
          assertAllowedPath(name);
          if (seen.has(name)) throw invalid("duplicate_archive_path");
          seen.add(name);
          if (seen.size > MAX_FILES) throw invalid("too_many_files");
          expandedBytes += entry.uncompressedSize;
          if (expandedBytes > MAX_EXPANDED_BYTES) throw invalid("expanded_archive_too_large");
          if (entry.uncompressedSize > 1024 * 1024 && entry.compressedSize > 0 && entry.uncompressedSize / entry.compressedSize > 100) throw invalid("suspicious_compression_ratio");
          if (name.endsWith("/")) {
            await fs.mkdir(path.join(sourceDirectory, name), { recursive: true, mode: 0o700 });
          } else {
            const destination = path.join(sourceDirectory, name);
            if (!destination.startsWith(`${sourceDirectory}${path.sep}`)) throw invalid("unsafe_archive_path");
            await fs.mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
            const stream = await openEntryStream(zip, entry);
            const chunks: Buffer[] = [];
            let actualSize = 0;
            stream.on("data", (chunk: Buffer) => {
              actualSize += chunk.length;
              if (actualSize > entry.uncompressedSize || actualSize > MAX_EXPANDED_BYTES) stream.destroy(invalid("invalid_zip_entry_size"));
              chunks.push(Buffer.from(chunk));
            });
            const writer = createWriteStream(destination, { flags: "wx", mode: 0o600 });
            await pipeline(stream, writer);
            const content = Buffer.concat(chunks);
            if (content.length !== entry.uncompressedSize) throw invalid("invalid_zip_entry_size");
            assertNoSecrets(content, name);
            if (name === "package.json") packageJson = content;
            if (name === "tsconfig.json") tsconfigJson = content;
            files.push(name);
          }
          processing = false;
          zip.readEntry();
        })().catch(fail);
      });
      zip.readEntry();
    });
    if (!files.includes("src/index.ts")) throw invalid("entrypoint_missing");
    if (!files.includes("tsconfig.json")) throw invalid("tsconfig_missing");
    if (!files.includes("pnpm-lock.yaml")) throw invalid("lockfile_missing");
    if (!files.some((file) => /(?:^|\/)[^/]+\.(?:test|spec)\.ts$/.test(file))) throw invalid("automated_tests_missing");
    if (!packageJson) throw invalid("package_json_missing");
    if (!tsconfigJson) throw invalid("tsconfig_missing");
    const packageInfo = validatePackageJson(packageJson);
    validateTsconfig(tsconfigJson);
    return {
      directory: uploadDirectory,
      archivePath,
      sourceDirectory,
      sourceDigest,
      fileCount: files.length,
      expandedBytes,
      files: [...files].sort(),
      ...packageInfo
    };
  } catch (error) {
    await fs.rm(uploadDirectory, { recursive: true, force: true });
    throw error;
  }
}

function validateTsconfig(content: Buffer): void {
  let parsed: { extends?: unknown; references?: unknown; compilerOptions?: Record<string, unknown>; include?: unknown };
  try {
    parsed = JSON.parse(content.toString("utf8")) as typeof parsed;
  } catch {
    throw invalid("invalid_tsconfig_json");
  }
  if (parsed.extends !== undefined || parsed.references !== undefined) throw invalid("tsconfig_inheritance_not_allowed");
  const options = parsed.compilerOptions ?? {};
  const required: Record<string, unknown> = {
    target: "ES2022",
    module: "NodeNext",
    moduleResolution: "NodeNext",
    strict: true,
    rootDir: "src",
    outDir: "dist"
  };
  for (const [key, value] of Object.entries(required)) if (options[key] !== value) throw invalid("tsconfig_policy_failed");
  if (options.plugins !== undefined || options.paths !== undefined || options.baseUrl !== undefined) throw invalid("tsconfig_extension_not_allowed");
  if (!Array.isArray(parsed.include) || parsed.include.length !== 1 || parsed.include[0] !== "src/**/*.ts") throw invalid("tsconfig_include_policy_failed");
}
