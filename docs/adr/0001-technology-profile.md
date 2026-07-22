# ADR 0001: KCML technology profile

## Decision

KCML uses a modular control-plane application with separate public host roles:
`admin.hcasc.cz`, `auth.hcasc.cz`, `register.hcasc.cz`, and
`kcmlNNNN.hcasc.cz`. Uploaded handlers are not part of the trusted web process;
each runs in a separately constrained rootless OCI worker.

The production stack is:

- Node.js 24 LTS, Fastify, TypeScript.
- React 19 + Vite for the admin UI.
- PostgreSQL 16+ as the only authoritative state store.
- SQL migrations committed in `apps/server/src/migrations`.
- Nginx reverse proxy with exact host routing, restricted KCML regex routing
  and DNS-01 wildcard coverage for both `*.hcasc.cz` and the canonical component namespace `*.kajovocml.hcasc.cz`.
- GitHub API PR automation (existing repository authorization or preferred least-privilege GitHub App), least-privilege PR CI, trusted main image build,
  GHCR, SBOM/provenance and cosign verification.
- Rootless Podman workers with private Unix sockets, network deny-all and a
  separate allowlisted egress proxy.
- GitHub Actions CI and deployment through hardened systemd services.

## Rationale

The SSOT requires React 19 + TypeScript, PostgreSQL 16+, host based routing,
strict token handling, migrations, CI gates, rollback, and shared Ubuntu
production operation. The trusted control plane keeps transaction boundaries
and fail-closed catalog decisions in one authoritative process. The OCI worker
boundary prevents uploaded source from sharing a process, filesystem, network
or secrets with the catalog, authorization authority and database.

## Security invariants

- Hostname is a security boundary and is resolved before any MCP metadata or
handler dispatch.
- No wildcard permissions exist. Kaja permissions are row scoped to one MCP
server.
- Client secrets and access tokens use 64 CSPRNG bytes before Base64URL
encoding.
- Full token values are never stored; client secrets use Argon2id, access
tokens use HMAC-SHA-256 lookup digests with a server-side key.
- Integration tokens contain 512 bits of entropy, are displayed once, use a
  purpose-separated HMAC lookup digest and bind one job to one KCML identity.
- An integration token authorizes the audited state machine; it never bypasses
  PR/CI, signature, runtime, public HTTPS, OAuth/MCP or monitoring gates.
- Only the onboarding state machine may set `ACTIVE/enabled=true`, and only
  after every persistent gate is `PASS`.
- Admin password comes only from deployment secret `PASS`; MFA must also be
configured before login can succeed.
- Audit is append-only from the application perspective.
