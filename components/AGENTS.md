# AGENTS.md

## Scope

These rules apply to every path below `components/` and strengthen the repository root contract.

## Directory boundary

- Create one logical component only in `components/<repository-key>/` where the key matches `^[a-z0-9][a-z0-9-]{2,62}$`.
- Do not place generated components in `apps/`, `packages/` or the retired `handlers/` source pipeline.
- Do not use a KCML code or hostname as the repository key. KCML assigns identity during registration.
- Do not import source code from another component directory or from private `apps/` implementation paths.

## Required contract

- Follow `docs/onboarding-catalogs/repository-component-1.0.json` and the current companion component catalog without reducing either contract.
- Keep `component.kcml.json`, `manifest.kcml.json`, package metadata, tests and evidence synchronized with executable behavior.
- Use Node.js 24, ESM, pnpm 11.7.0, an isolated lockfile and exact dependency versions.
- Export asynchronous `invoke(input, context)` from `src/index.ts` and provide complete lint, typecheck, test and build scripts.
- Include real architecture, threat-model and runbook evidence. Placeholders, samples represented as completion and fake digests are forbidden.

## Security and lifecycle

- Never commit integration tokens, access tokens, secrets, credentials, `.env` files or runtime-generated secret material.
- Use only KCML-authorized secret grants and the KCML egress path; direct database access and uncontrolled outbound networking are forbidden.
- A green source PR or signed image is not registration. Deploy the immutable runtime, finalize real manifest digests, register through `/v2/component-onboardings`, resolve all gates and preserve only a nonsecret receipt.
- The integration token does not authorize GitHub writes, merge, deployment or administrative activation.

## Verification

Run from the repository root:

```bash
corepack pnpm repository-catalog:check
corepack pnpm repository-components:check
corepack pnpm run ci
```

Also execute the component package's lint, typecheck, test and build commands in isolated-workspace mode. Never claim successful registration, readiness or activation without inspecting the corresponding KCML job and gate evidence.
