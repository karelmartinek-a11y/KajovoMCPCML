import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { Ajv2020 } from "ajv/dist/2020.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const componentsRoot = path.join(root, "components");
const catalog = JSON.parse(fs.readFileSync(path.join(root, "docs/onboarding-catalogs/repository-component-1.0.json"), "utf8"));
const validate = new Ajv2020({ strict: true, allErrors: true }).compile(catalog.componentDescriptor.schema);
const keyPattern = /^[a-z0-9][a-z0-9-]{2,62}$/;
const exactVersion = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/;
const secretPattern = /BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|github_pat_|ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,}|kci_[A-Za-z0-9_-]{40,}|(?:password|client_secret|api[_-]?key)\s*[:=]\s*["']?[A-Za-z0-9_+/=.-]{16,}/i;
const required = catalog.requiredFiles;
const dirs = fs.existsSync(componentsRoot) ? fs.readdirSync(componentsRoot, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name).sort() : [];
const failures = [];
for (const key of dirs) {
  if (!keyPattern.test(key)) failures.push(`${key}: invalid repository key`);
  const dir = path.join(componentsRoot, key);
  const mustExist = required.filter((item) => !item.includes("**"));
  for (const relative of mustExist) if (!fs.existsSync(path.join(dir, relative))) failures.push(`${key}: missing ${relative}`);
  const tests = fs.existsSync(path.join(dir, "src")) ? fs.readdirSync(path.join(dir, "src")).filter((name) => /\.(?:test|spec)\.ts$/.test(name)) : [];
  if (!tests.length) failures.push(`${key}: missing src test`);
  let descriptor;
  try { descriptor = JSON.parse(fs.readFileSync(path.join(dir, "component.kcml.json"), "utf8")); } catch { failures.push(`${key}: invalid component.kcml.json`); continue; }
  if (!validate(descriptor)) failures.push(`${key}: descriptor schema failed ${JSON.stringify(validate.errors)}`);
  if (descriptor.repositoryKey !== key) failures.push(`${key}: repositoryKey mismatch`);
  let pkg;
  try { pkg = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8")); } catch { failures.push(`${key}: invalid package.json`); continue; }
  if (pkg.type !== "module" || !String(pkg.engines?.node ?? "").includes("24")) failures.push(`${key}: Node.js 24 ESM required`);
  for (const script of catalog.packagePolicy.requiredScripts) if (typeof pkg.scripts?.[script] !== "string") failures.push(`${key}: missing script ${script}`);
  for (const script of catalog.packagePolicy.forbiddenLifecycleScripts) if (pkg.scripts?.[script]) failures.push(`${key}: forbidden script ${script}`);
  for (const [name, version] of Object.entries({ ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) })) if (typeof version !== "string" || !exactVersion.test(version)) failures.push(`${key}: ${name} must use exact version`);
  const stack = [dir];
  while (stack.length) {
    const current = stack.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const absolute = path.join(current, entry.name);
      if (entry.isSymbolicLink()) failures.push(`${key}: symlink forbidden ${path.relative(dir, absolute)}`);
      else if (entry.isDirectory()) stack.push(absolute);
      else if (entry.isFile() && !/pnpm-lock\.yaml$/.test(absolute)) {
        const content = fs.readFileSync(absolute);
        if (!content.includes(0) && secretPattern.test(content.toString("utf8"))) failures.push(`${key}: secret-like material in ${path.relative(dir, absolute)}`);
      }
    }
  }
}
if (failures.length) { console.error(failures.join("\n")); process.exitCode = 1; }
else console.log(`validated ${dirs.length} repository component(s)`);
