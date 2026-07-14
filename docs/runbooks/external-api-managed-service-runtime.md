# EXTERNAL_API Managed Service Runtime

## Scope

This runbook describes the production runtime for `managed_service` records with `service_kind = EXTERNAL_API`.

## Onboarding

1. Create an integration intent through `POST /api/integration-intents` with `serviceKind = EXTERNAL_API`.
2. Submit the manifest through `POST /v1/service-onboardings`.
3. Intake validates the published JSON schema, ownership binding, reference evidence, upstream TLS, health, readiness, operational state and acceptance contract through the egress proxy.
4. Successful registration always ends in `REGISTERED_DISABLED` with `apiState = DISABLED`.

## Runtime Authorizer

The request-time authorizer is the only source of truth for a live `EXTERNAL_API` call.

It denies the request when any of these drift:

- token audience
- environment
- principal token epoch
- service token epoch
- permission epoch snapshot
- active revision epoch snapshot
- operation policy (`operationId`, HTTP method, templated path, required scopes)
- monitoring freshness (`health`, `readiness`, `tls`, `acceptance`)
- latest monitor internal error still inside the stale window

This means disable/enable, permission churn and revision updates all invalidate old tokens without waiting for expiry.

## Egress

All onboarding probes, runtime upstream calls and monitor probes for `EXTERNAL_API` go through the unix-socket egress proxy.

The proxy enforces:

- HTTPS only
- exact host:port allowlist from the manifest
- DNS / IP private-range blocking
- no redirects
- bounded request and response sizes
- fail-closed behavior on invalid or expired egress capability tokens

`web` and `monitor` issue short-lived internal capability tokens. Legacy onboarding jobs still use the persisted capability flow.

## Monitoring And Alerts

The monitor probes `health`, `readiness`, `tls` and `acceptance` for active `EXTERNAL_API` managed services.

- The latest probe evidence is stored in `managed_service_probe_result`.
- Repeated failures open an `operational_alert` keyed by `managed_service_id`.
- Repeated failures do not create duplicates.
- A passing probe closes the matching alert.
- A monitor internal error creates `managed_service.monitoring.internal_error` and runtime requests fail closed until fresh probe evidence replaces it.

## Release Smoke

`deploy/scripts/smoke-reference-external-api.sh` performs the production smoke flow:

1. find or update the in-repo reference `EXTERNAL_API` service
2. enable the service through the admin API
3. create a temporary Kaja credential
4. grant the reference scopes
5. issue a bearer token
6. call the managed-service gateway for read and write operations
7. confirm direct backend bypass returns `REFERENCE_DIRECT_BYPASS_BLOCKED`
8. confirm managed-service runtime logs contain the gateway request event

## Soak Harness

Use `scripts/external-api-soak.mjs` for the A22 soak run.

- Default duration is `72` hours.
- The summary file reports `PARTIALLY_IMPLEMENTED` until a full 72-hour run actually completes.
- When admin credentials and identifiers are supplied, the harness also exercises disable/enable and permission churn.

## Rollback

Use the normal deployment rollback path in `deploy/scripts/rollback.sh`.

Do not manually revert schema rows or clear monitor evidence in place. Fix forward on `main` is the default response unless the release runbook explicitly requires rollback.
