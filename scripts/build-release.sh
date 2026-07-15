#!/usr/bin/env bash
set -euo pipefail
umask 022

destination="${1:?release destination required}"
build_id="${BUILD_ID:-$(git rev-parse HEAD)}"
source_commit="${GITHUB_SHA:-$(git rev-parse HEAD)}"

rm -rf "$destination"
install -d -m 0755 "$destination/apps" "$destination/deploy" "$destination/docs" "$destination/docs/onboarding-catalogs"
pnpm_major="$(pnpm --version | cut -d. -f1)"
if [ "$pnpm_major" -ge 10 ]; then
  pnpm --filter @kcml/server deploy --prod --legacy "$destination/apps/server"
else
  pnpm --filter @kcml/server deploy --prod "$destination/apps/server"
fi
install -d -m 0755 "$destination/apps/admin-ui"
cp -R apps/admin-ui/dist "$destination/apps/admin-ui/dist"
install -d -m 0755 "$destination/apps/server/dist/migrations"
cp apps/server/src/migrations/*.sql "$destination/apps/server/dist/migrations/"
cp -R deploy/alert-sink deploy/nginx deploy/scripts deploy/systemd "$destination/deploy/"
cp Connect_in_Catalog_KajovoMCPCML_v1.5.docx "$destination/"
cp docs/onboarding-manifest-v1.5.example.json "$destination/docs/"
cp docs/service-manifest-external-api-v1.0.example.json "$destination/docs/"
cp docs/onboarding-catalogs/*.json "$destination/docs/onboarding-catalogs/"
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
