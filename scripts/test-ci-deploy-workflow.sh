#!/usr/bin/env bash
set -euo pipefail

workflow=".github/workflows/ci-deploy.yml"
test -f "$workflow"

# Every branch push must enter the test pipeline. Release/deploy are guarded
# below so only main can touch production, but direct branch pushes still get CI.
grep -A3 '^  push:' "$workflow" | grep -Fq 'branches: ["**"]'
if grep -A5 '^  push:' "$workflow" | grep -Eq 'paths(-ignore)?:'; then
  echo "main push trigger must not filter paths" >&2
  exit 1
fi
grep -Fq '  pull_request:' "$workflow"
grep -Fq '  workflow_dispatch:' "$workflow"
grep -Fq 'perform_factory_reset:' "$workflow"
grep -Fq 'factory_reset_confirmation:' "$workflow"

# Production release and deployment must remain main-only and run both
# automatically on pushes and explicitly on manual dispatches.
grep -Fq "if: github.ref == 'refs/heads/main' && (github.event_name == 'workflow_dispatch' || github.event_name == 'push')" "$workflow"
test "$(grep -Fc "if: github.ref == 'refs/heads/main' && (github.event_name == 'workflow_dispatch' || github.event_name == 'push')" "$workflow")" = "2"

# The release must be signed and the exact downloaded blob must be verified
# against the GitHub Actions workflow identity before privileged deployment.
grep -Fq 'cosign sign-blob --yes --bundle /tmp/kcml-release.tar.zst.sigstore.json /tmp/kcml-release.tar.zst' "$workflow"
grep -Fq 'cosign verify-blob kcml-release.tar.zst' "$workflow"
grep -Fq -- '--bundle kcml-release.tar.zst.sigstore.json' "$workflow"
grep -Fq -- '--certificate-identity=https://github.com/${{ github.repository }}/.github/workflows/ci-deploy.yml@refs/heads/main' "$workflow"
grep -Fq -- '--certificate-oidc-issuer=https://token.actions.githubusercontent.com' "$workflow"

# The deploy job must consume the release job artifact and cannot bypass CI/security.
grep -Fq 'needs: [ci, security, release]' "$workflow"
grep -Fq 'name: kcml-release-${{ github.sha }}' "$workflow"
grep -Fq 'sha256sum --check kcml-release.tar.zst.sha256' "$workflow"
grep -Fq '/usr/local/sbin/kcml-deploy-wrapper' "$workflow"
grep -Fq '"${{ github.event_name }}"' "$workflow"
grep -Fq 'KCML_FACTORY_RESET_CONFIRM:' "$workflow"
grep -Fq 'sudo --preserve-env=PASS,GHCR_TOKEN,GHCR_ACTOR,KCML_FACTORY_RESET_CONFIRM /usr/local/sbin/kcml-deploy-wrapper' "$workflow"

# Avoid indefinite production jobs on a wedged self-hosted runner.
grep -A8 '^  deploy:' "$workflow" | grep -Fq 'timeout-minutes:'

# Production deploys must be serialized without interrupting an in-flight
# privileged install. A queued stale revision must not touch the server.
grep -A12 '^  deploy:' "$workflow" | grep -Fq 'group: production-deploy'
grep -A12 '^  deploy:' "$workflow" | grep -Fq 'cancel-in-progress: false'
grep -Fq 'id: freshness' "$workflow"
grep -Fq '"$GITHUB_API_URL/repos/$GITHUB_REPOSITORY/git/ref/heads/main"' "$workflow"
test "$(grep -Fc "if: steps.freshness.outputs.should_deploy == 'true'" "$workflow")" = "4"
