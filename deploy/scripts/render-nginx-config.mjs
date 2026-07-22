import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const HOSTNAME_PATTERN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const SAFE_PATH_PATTERN = /^\/[A-Za-z0-9._/-]+$/;

export function renderNginxConfig(template, values) {
  const { domain, componentHostSuffix, adminHost, authHost, registerHost, certPath, keyPath } = values;
  if (![domain, componentHostSuffix, adminHost, authHost, registerHost].every((value) => HOSTNAME_PATTERN.test(value))) {
    throw new Error("invalid_nginx_hostname");
  }
  if (![adminHost, authHost, registerHost].every((value) => value.endsWith(`.${domain}`))) {
    throw new Error("nginx_host_domain_mismatch");
  }
  if (componentHostSuffix !== domain && !componentHostSuffix.endsWith(`.${domain}`)) {
    throw new Error("nginx_component_host_domain_mismatch");
  }
  const secretApiHost = `secrets.${domain}`;
  const routedHosts = [adminHost, authHost, registerHost, secretApiHost];
  if (new Set(routedHosts).size !== routedHosts.length) {
    throw new Error("nginx_host_collision");
  }
  if (![certPath, keyPath].every((value) => SAFE_PATH_PATTERN.test(value))) {
    throw new Error("invalid_nginx_tls_path");
  }
  const replacements = {
    PUBLIC_BASE_DOMAIN: domain,
    COMPONENT_HOST_SUFFIX_REGEX: componentHostSuffix.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
    ADMIN_HOST: adminHost,
    AUTH_HOST: authHost,
    REGISTER_HOST: registerHost,
    TLS_CERT_PATH: certPath,
    TLS_KEY_PATH: keyPath
  };
  let output = template;
  for (const [key, value] of Object.entries(replacements)) output = output.replaceAll(`@${key}@`, value);
  if (/@[A-Z_]+@/.test(output)) throw new Error("unresolved_nginx_template_value");
  return output;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [templatePath, targetPath, domain, componentHostSuffix, adminHost, authHost, registerHost, certPath, keyPath] = process.argv.slice(2);
  if (!templatePath || !targetPath || !domain || !componentHostSuffix || !adminHost || !authHost || !registerHost || !certPath || !keyPath) {
    throw new Error("nginx_renderer_arguments_required");
  }
  const output = renderNginxConfig(readFileSync(templatePath, "utf8"), {
    domain,
    componentHostSuffix,
    adminHost,
    authHost,
    registerHost,
    certPath,
    keyPath
  });
  writeFileSync(targetPath, output, { mode: 0o644 });
}
