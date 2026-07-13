# Incident Response Runbook

## Critical triggers

- Audit write failure.
- Database unavailable.
- Cross-host routing invariant failure.
- Token accepted for the wrong audience.
- Contract or artifact digest drift.
- Repeated backup restore failure.
- Invalid OCI signature/provenance or source/image digest drift.
- Integration, Kaja, access or egress capability token found in logs, audit,
  artifacts, PR output or an uploaded archive.
- Onboarding handler reaches a non-allowlisted, private, loopback, link-local or
  metadata address.

## Immediate action

1. Quarantine the affected KCML server.
2. Revoke resource tokens by changing the server revocation epoch.
3. Preserve audit, logs, traces, and build ID.
4. Notify primary and backup operational channels.
5. Require a new registration revision before returning to `ACTIVE`.
6. Revoke the integration token, ephemeral Kaja/access tokens and egress
   capability; cancel the job lease and stop the OCI worker.
7. Preserve the quarantine source digest, PR/check run, source commit, build ID,
   image digest, signature, SBOM, provenance and correlation IDs.

Automatic return from `QUARANTINED` is forbidden.
