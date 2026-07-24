#!/usr/bin/env bash
set -euo pipefail
umask 022

destination="${1:?release destination required}"
build_id="${BUILD_ID:-$(git rev-parse HEAD)}"
source_commit="${GITHUB_SHA:-$(git rev-parse HEAD)}"
catalog_version="$(node --input-type=module -e "import('./apps/server/dist/domain/release.js').then(({KCML_RELEASE}) => process.stdout.write(KCML_RELEASE.catalogVersion))")"
workspace_restore_required=false

restore_workspace_dependencies() {
  if [ "$workspace_restore_required" = "true" ]; then
    CI=true pnpm install --frozen-lockfile
    find node_modules -type f -name '._*' -delete
  fi
}
trap restore_workspace_dependencies EXIT

rm -rf "$destination"
install -d -m 0755 "$destination/apps" "$destination/deploy" "$destination/docs" "$destination/docs/onboarding-catalogs" "$destination/scripts"
pnpm_major="$(pnpm --version | cut -d. -f1)"
workspace_restore_required=true
if [ "$pnpm_major" -ge 10 ]; then
  pnpm --filter @kcml/server deploy --prod --legacy "$destination/apps/server"
else
  pnpm --filter @kcml/server deploy --prod "$destination/apps/server"
fi
restore_workspace_dependencies
workspace_restore_required=false
trap - EXIT
install -d -m 0755 "$destination/apps/admin-ui"
cp -R apps/admin-ui/dist "$destination/apps/admin-ui/dist"
install -d -m 0755 "$destination/apps/server/dist/migrations"
cp apps/server/src/migrations/*.sql "$destination/apps/server/dist/migrations/"
cp -R deploy/alert-sink deploy/nginx deploy/scripts deploy/systemd "$destination/deploy/"
cp scripts/verify-repository-component-attestations.mjs "$destination/scripts/"
cp "docs/onboarding-catalogs/onboarding-1.1.json" "$destination/docs/"
cp "docs/onboarding-manifest-${catalog_version}.example.json" "$destination/docs/"
cp "apps/server/src/contracts/component-manifest-${catalog_version}.schema.json" "$destination/docs/"
cp docs/service-manifest-external-api-v1.0.example.json "$destination/docs/"
cp docs/onboarding-catalogs/*.json "$destination/docs/onboarding-catalogs/"
cp -R docs/releases "$destination/docs/releases"
find "$destination" -type f -name '._*' -delete

jq -n \
  --arg buildId "$build_id" \
  --arg sourceCommit "$source_commit" \
  --arg repository "${GITHUB_REPOSITORY:-local}" \
  --arg workflow "${GITHUB_WORKFLOW_REF:-local}" \
  --arg createdAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{schemaVersion:1,buildId:$buildId,sourceCommit:$sourceCommit,repository:$repository,workflow:$workflow,createdAt:$createdAt,nodeVersion:env.NODE_VERSION,pnpmVersion:env.PNPM_VERSION}' \
  > "$destination/release-manifest.json"

find "$destination" -type d -exec chmod 0755 {} +
find "$destination" -type f -exec chmod 0644 {} +
find "$destination/deploy/scripts" -type f -name '*.sh' -exec chmod 0755 {} +
