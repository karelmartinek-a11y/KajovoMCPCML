#!/usr/bin/env bash
set -euo pipefail

workflow=".github/workflows/ci-deploy.yml"
test -f "$workflow"

# Production release and deployment must remain manual and main-only.
grep -Fq "if: github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch'" "$workflow"
test "$(grep -Fc "if: github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch'" "$workflow")" = "2"

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

# Avoid indefinite production jobs on a wedged self-hosted runner.
grep -A8 '^  deploy:' "$workflow" | grep -Fq 'timeout-minutes:'
