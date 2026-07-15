# KCML Managed Services release forensics, 2026-07-15

Scope: forensic review of the KCML0002 production release failure, release invariants, runtime ownership boundaries, and source-code occurrences directly able to affect this deployment path.

## Deviations and Remediation

### D01: Release invariant used an internal admin test path

- Occurrences: `deploy/scripts/install-release.sh` previously called `POST /api/mcp-servers/$kcml0002_server_id/test`; `apps/server/src/http/admin-routes.ts` still exposes `POST /api/mcp-servers/:id/test`; `apps/admin-ui/src/main.tsx` still uses the endpoint for manual admin diagnostics.
- Expected: production release validation proves OAuth token issuance, managed-service authorization, MCP gateway routing, handler invocation, runtime logs, and audit evidence.
- Root cause: the release script reused an admin diagnostic endpoint that invokes the registered handler from the web process instead of exercising the public gateway path.
- Remediation: the release script now runs `apps/server/src/cli/release-kcml0002-smoke.ts`, which creates a temporary Kaja credential, grants permission, obtains an OAuth client-credentials token, calls MCP JSON-RPC through the gateway, verifies result evidence, and records audit evidence.
- Guardrail: `scripts/test-build-release.sh` now fails if the release bundle references `/api/mcp-servers/$kcml0002_server_id/test`.
- Status: fixed for release gating. The admin endpoint remains intentionally available for human diagnostics only.

### D02: Web/admin process attempted runtime redeploy and Podman egress self-heal

- Occurrences: removed from `apps/server/src/http/admin-routes.ts`; valid runtime owners remain `apps/server/src/onboarding/worker.ts`, `apps/server/src/onboarding/monitoring.ts`, and `apps/server/src/onboarding/oci.ts`.
- Expected: only worker/monitor services with the rootless Podman user-bus environment may invoke `OciRuntime`.
- Root cause: admin enable/test self-heal introduced `OciRuntime.deploy` in the web process; production `kcml.service` does not expose the Podman DBus/user runtime environment.
- Remediation: admin enable and admin test no longer refresh or redeploy runtime egress capability. Runtime lifecycle remains owned by onboarding worker and monitor.
- Guardrail: `apps/server/src/http/admin-server-actions.test.ts` now asserts enabling a disabled server does not insert egress capability rows or invoke a Podman path.
- Status: fixed.

### D03: Release fallback proved upstream availability instead of KCML correctness

- Occurrences: `deploy/scripts/install-release.sh` previously probed `https://ha-inventory.hcasc.cz/v1/catalog` directly.
- Expected: production release must prove KCML-owned auth, gateway, authorizer, handler, audit, and log paths, not only external upstream availability.
- Root cause: the script used a direct inventory fallback after admin test failures, which could pass while KCML gateway behavior was still broken.
- Remediation: direct upstream fallback was removed. The new release smoke fails closed unless the complete gateway path and evidence pass.
- Status: fixed.

### D04: Legacy `mcp_server` and canonical `managed_service` state could drift

- Occurrences: `apps/server/src/domain/auth.ts` issues managed-service tokens from `managed_service`; final release invariant checks legacy `mcp_server`; lifecycle changes live in both `apps/server/src/domain/server-state.ts` and `apps/server/src/domain/managed-service.ts`.
- Expected: release promotion should leave both models aligned for KCML0002.
- Root cause: migration/backfill introduced the canonical managed-service model while some MCP lifecycle operations still target the legacy table.
- Remediation: `release-kcml0002-smoke.ts` uses `setManagedServiceApiState` when enabling from `REGISTERED_DISABLED`, and after a passing gateway smoke synchronizes the MCP managed-service row to `ACTIVE/HEALTHY/ENABLED` with audit and policy-event evidence.
- Status: fixed for release promotion. A wider domain refactor should later centralize MCP lifecycle transitions in one abstraction.

### D05: Virtual-host smoke through Node `fetch` hid Host-header behavior

- Occurrences: release smoke now uses `node:http.request`; generic `fetch` usage remains in browser/UI scripts, GitHub client, alert webhooks, onboarding probes with `redirect: "manual"`, and the soak script.
- Expected: production local smoke must route through `127.0.0.1` while sending the exact public Host header used by KCML routing.
- Root cause: Node `fetch` was not a reliable fit for this virtual-host smoke; SSH testing showed local curl with `Host` worked while the fetch-based script received KCML 404.
- Remediation: the release CLI uses `http.request` and explicit headers for `/oauth/token` and `/mcp`.
- Status: fixed.

### D06: Runtime port from DB config can be stale for release-local smoke

- Occurrences: fixed in `apps/server/src/cli/release-kcml0002-smoke.ts`.
- Expected: release smoke should target the just-started production service on local `PORT`, defaulting to `3010`, unless explicitly overridden.
- Root cause: `loadConfigFromDb` can reflect operational host config that is not the local release-loopback port.
- Remediation: `KCML_RELEASE_BASE_URL` is supported, with a default of `http://127.0.0.1:${PORT || "3010"}`.
- Status: fixed.

### D07: Release artifact test did not assert the KCML0002 smoke CLI

- Occurrences: fixed in `scripts/test-build-release.sh`.
- Expected: release packaging test should fail before deployment if a required CLI is not present in `dist` or the installer regresses to the admin diagnostic endpoint.
- Root cause: packaging checks only covered docs/catalog artifacts.
- Remediation: release packaging test now checks for `apps/server/dist/cli/release-kcml0002-smoke.js`, installer reference to that CLI, and absence of the admin test endpoint in the release script.
- Status: fixed.

### D08: Local Node runtime drift reduced confidence in pre-commit testing

- Occurrences: `package.json` requires Node `>=24.0.0`; production reports Node `v24.17.0`; the local shell default was Node 20 until the bundled Node 24 runtime was used.
- Expected: local validation should use a runtime compatible with production and package engines.
- Root cause: developer shell PATH selected a Homebrew Node 20 before the Codex bundled Node 24 runtime.
- Remediation: validation commands in this forensic pass use `/Users/karelmartinek/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin`.
- Status: mitigated for this release. A future repo script could enforce `engine-strict=true` or provide a checked-in wrapper.

### D09: HTTP error reporting in release smoke could obscure the original failure

- Occurrences: fixed in `apps/server/src/cli/release-kcml0002-smoke.ts`.
- Expected: deploy logs should show stable, actionable failure codes and response snippets.
- Root cause: JSON parsing happened before success-status validation, so non-JSON error pages could surface as parser failures instead of HTTP status failures.
- Remediation: the helper now checks status first and reports `http_status:<code>:<body>`.
- Status: fixed.

### D10: Admin UI still presents a diagnostic test as if it were operational proof

- Occurrences: `apps/admin-ui/src/main.tsx` calls `/api/mcp-servers/${server.id}/test`; `apps/server/src/http/admin-routes.ts` records `mcp_server.test.passed` or `mcp_server.test.failed`.
- Expected: UI labels and operator docs should distinguish "registered safe test contract" from production gateway proof.
- Root cause: the same admin action had been reused conceptually by release automation.
- Remediation: release automation no longer depends on it. Remaining UI copy should be renamed in a later UI-only change to avoid operator confusion.
- Status: release blocker removed; follow-up improvement recorded.

### D11: Generated document artifacts remain in the repository surface

- Occurrences: `doc/SSOT_extracted.md` and document generation scripts are present; the prompt explicitly called out not committing generated `.docx` artifacts or helper render directories.
- Expected: release commits should include source docs and machine-readable catalogs, not generated binary/render artifacts.
- Root cause: documentation generation outputs are adjacent to source-controlled docs and can be accidentally staged.
- Remediation: no generated `.docx` or render directory is included in this fix scope. Staging must be explicit and limited to source/runtime changes and this forensic source document.
- Status: controlled for this commit; a future cleanup should audit ignore rules and generated artifact locations.

### D12: Dirty worktree contained unrelated changes before this forensic pass

- Occurrences: `.github/workflows/*`, `Dockerfile`, domain upload/registration files, docs, handler package files, root package files, and lockfiles were already modified before this fix scope.
- Expected: release fix commits should be narrow and reviewable.
- Root cause: prior implementation work is still uncommitted in the same working tree.
- Remediation: this fix will stage only the KCML0002 release-gate files, admin runtime-boundary test, and this forensic document.
- Status: controlled for this commit; unrelated changes remain untouched.

### D13: Private handler image preload released GHCR credentials before runtime readiness

- Occurrences: `deploy/scripts/kcml-handler-preload-wrapper.sh`; installed production copy at `/usr/local/sbin/kcml-handler-preload-wrapper`; GitHub workflow `.github/workflows/onboarding-private-preload.yml`.
- Expected: the temporary GHCR credential remains available until the onboarding worker has pulled, verified, run, and exposed the handler runtime socket.
- Root cause: the wrapper treated `DEPLOYING` as success, but the worker performs `podman run` and socket readiness while still in `DEPLOYING`. The cleanup trap then removed `/var/lib/kcml/podman/auth.json` too early, leaving later pulls to fail with `invalid username/password`.
- Remediation: the wrapper now waits for `REGISTERED_DISABLED`, `TRIAL_TESTING`, or `ACTIVE` plus an existing runtime socket before removing the credential. The release installer also updates `/usr/local/sbin/kcml-handler-preload-wrapper` and `/usr/local/sbin/kcml-deploy-wrapper` from the verified release.
- Guardrail: `scripts/test-build-release.sh` now asserts the preload wrapper is packaged and installed by the release script.
- Status: fixed in source; production runtime must be refreshed with a valid GHCR credential before final deploy smoke can pass.

### D14: Missing runtime socket had no release-owned recovery path in the correct process context

- Occurrences: production runtime log for correlation `48bbc180-613f-4490-9d29-f4d78ba733c1` showed `connect ENOENT /var/lib/kcml/runtime/kcml0002/worker.sock`; previous admin self-heal was removed from `apps/server/src/http/admin-routes.ts` because it ran in the wrong process.
- Expected: if a release invariant depends on KCML0002, release should restore or fail from the worker/Podman context before proving the gateway.
- Root cause: after the GHCR credential-window failure, the onboarding job was already `ACTIVE`, so the worker would not re-lease it and recreate the socket automatically.
- Remediation: `apps/server/src/cli/release-kcml0002-runtime-refresh.ts` refreshes KCML0002 runtime using `OciRuntime` under the `kcml` user with worker credentials and rootless Podman env. `deploy/scripts/install-release.sh` stages GHCR auth, runs this refresh, then runs the gateway smoke and always cleans up registry credentials.
- Guardrail: `scripts/test-build-release.sh` now asserts the runtime refresh CLI is present and referenced by the release installer.
- Status: fixed in source; will be validated by production deploy with `packages: read` GitHub token passed to the deploy wrapper.

## Verification Plan

- Local targeted validation: `pnpm exec tsc -p apps/server/tsconfig.json --noEmit`; `pnpm exec vitest run apps/server/src/http/admin-server-actions.test.ts apps/server/src/onboarding/activation.test.ts --no-file-parallelism`.
- Local release validation: `pnpm lint`; `pnpm typecheck`; `pnpm test`; `pnpm build`; `bash scripts/test-build-release.sh`.
- Production-shaped validation before GitHub deploy: SSH to production, run the gateway smoke against `http://127.0.0.1:3010` with production web credentials and Host headers, verify audit chain and KCML0002 state alignment.
- GitHub validation: push to `main`, wait for push CI, manually dispatch `CI and production deploy`, then verify release job, deploy job, post-deploy invariants, service status, audit chain, and KCML0002 MCP smoke.
