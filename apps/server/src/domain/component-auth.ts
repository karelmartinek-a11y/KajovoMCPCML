import { randomUUID } from "node:crypto";
import type { Db } from "../db.js";
import { tx } from "../db.js";
import { fingerprintSecret, hmacToken } from "../security/secrets.js";
import { appendAudit } from "./audit.js";

export type ComponentAuthorizationReason =
  | "allowed"
  | "invalid_token"
  | "expired_token"
  | "revoked_token"
  | "insufficient_scope"
  | "invalid_audience"
  | "component_disabled"
  | "component_quarantined"
  | "route_denied"
  | "catalog_incompatible";

export type ComponentAuthorizationDecision = {
  allow: boolean;
  reasonCode: ComponentAuthorizationReason;
  decisionId: string;
  correlationId: string;
  sourceComponentId: string | null;
  targetComponentId: string | null;
  sourceClientId: string | null;
  sourceComponentCode: string | null;
  targetComponentCode: string | null;
  audience: string | null;
  scopes: string[];
  policyEpoch: number | null;
  tokenFingerprint: string | null;
};

export function componentSourceIdentityMatches(
  decision: ComponentAuthorizationDecision,
  declared: { clientId: string; componentCode: string }
): boolean {
  return decision.allow
    && declared.clientId === decision.sourceClientId
    && declared.componentCode === decision.sourceComponentCode;
}

function denied(reasonCode: ComponentAuthorizationReason, correlationId: string, values: Partial<ComponentAuthorizationDecision> = {}): ComponentAuthorizationDecision {
  return {
    allow: false,
    reasonCode,
    decisionId: randomUUID(),
    correlationId,
    sourceComponentId: null,
    targetComponentId: null,
    sourceClientId: null,
    sourceComponentCode: null,
    targetComponentCode: null,
    audience: null,
    scopes: [],
    policyEpoch: null,
    tokenFingerprint: null,
    ...values
  };
}

export async function authorizeComponentCall(db: Db, params: {
  token: string;
  audience: string;
  host: string;
  scope: string;
  route: string;
  hmacKey: Buffer;
  correlationId: string;
  allowOnboardingProbe?: boolean;
}): Promise<ComponentAuthorizationDecision> {
  return tx(db, async (client) => {
    const tokenDigest = hmacToken(params.token, params.hmacKey);
    const principalToken = await client.query(`
      select token.*,principal.public_id source_client_id,principal.kind source_principal_kind,principal.status source_principal_status,
        principal.revocation_epoch current_source_revocation_epoch,
        token.source_principal_id,source.id source_component_id,source.code source_component_code,source.enabled source_enabled,
        source.lifecycle_state source_lifecycle_state,source.activation_state source_activation_state,
        target.id target_component_id,target.code target_component_code,target.hostname target_hostname,
        target.enabled target_enabled,target.ingress_enabled target_ingress_enabled,target.activation_state target_activation_state,
        target.lifecycle_state target_lifecycle_state,target.operational_state target_operational_state,
        target.policy_epoch,target.release_version,
        token.expires_at <= now() token_expired
      from principal_access_token token
      join principal on principal.id=token.source_principal_id
      left join component source on source.principal_id=principal.id
      join component target on lower(target.hostname::text)=lower($2)
      where token.lookup_digest=$1
        and (token.target_component_id is null or token.target_component_id=target.id)
      for update of token`, [tokenDigest, params.host]);
    if (principalToken.rowCount) {
      const row = principalToken.rows[0];
      const issuedScopes = row.scope_names as unknown;
      const onboardingProbe = params.allowOnboardingProbe === true
        && row.source_component_id
        && String(row.source_component_id) === String(row.target_component_id)
        && Boolean((await client.query(
          `select 1 from component_onboarding_job
            where component_id=$1 and principal_access_token_digest=$2
              and principal_access_token_handed_off_at is null and state not in ('CANCELLED','FAILED') limit 1`,
          [row.target_component_id, tokenDigest]
        )).rowCount);
      const controlCallback = (["component.control.ack", "component.state.query", "component.heartbeat"].includes(params.scope)
        && ["ENABLE_REQUESTED", "DISABLE_REQUESTED", "DISABLE_UNCONFIRMED"].includes(String(row.target_activation_state)))
        || (row.source_principal_kind === "PLATFORM"
          && (params.scope.startsWith("platform.control.") || params.scope === "platform.e2e.execute"));
      const base = {
        sourceComponentId: row.source_component_id ? String(row.source_component_id) : null,
        targetComponentId: String(row.target_component_id),
        sourceClientId: String(row.source_client_id),
        sourceComponentCode: row.source_component_code ? String(row.source_component_code) : String(row.source_client_id),
        targetComponentCode: String(row.target_component_code),
        audience: params.audience,
        scopes: row.scope_names as string[],
        policyEpoch: Number(row.policy_epoch),
        tokenFingerprint: String(row.fingerprint)
      };
      let principalDecision: ComponentAuthorizationDecision;
      if (row.revoked_at || Number(row.issued_revocation_epoch) !== Number(row.current_source_revocation_epoch)) {
        principalDecision = denied("revoked_token", params.correlationId, base);
      } else if (row.token_expired) {
        principalDecision = denied("expired_token", params.correlationId, base);
      } else if (row.source_principal_status !== "ACTIVE") {
        principalDecision = denied(row.source_principal_status === "QUARANTINED" ? "component_quarantined" : "component_disabled", params.correlationId, base);
      } else if (String(row.target_hostname).toLowerCase() !== params.host.toLowerCase()
        || params.audience.toLowerCase() !== `https://${String(row.target_hostname).toLowerCase()}`
        || (String(row.audience) !== "*" && String(row.audience).toLowerCase() !== params.audience.toLowerCase())) {
        principalDecision = denied("invalid_audience", params.correlationId, base);
      } else if (row.target_lifecycle_state === "QUARANTINED" || row.target_operational_state === "QUARANTINED" || row.source_lifecycle_state === "QUARANTINED") {
        principalDecision = denied("component_quarantined", params.correlationId, base);
      } else if ((!row.target_enabled || !row.target_ingress_enabled || (row.source_component_id && !row.source_enabled)) && !controlCallback && !onboardingProbe) {
        principalDecision = denied("component_disabled", params.correlationId, base);
      } else if (!Array.isArray(issuedScopes) || !(issuedScopes as unknown[]).some((scope) => scope === "*" || scope === params.scope)) {
        principalDecision = denied("insufficient_scope", params.correlationId, base);
      } else {
        const scopedPermission = row.source_component_id ? await client.query(
          `select route_pattern from component_permission
            where source_component_id=$1 and target_component_id=$2 and scope_name=$3 and revoked_at is null`,
          [row.source_component_id, row.target_component_id, params.scope]
        ) : await client.query(
          `select route_pattern from principal_component_permission
            where source_principal_id=$1 and target_component_id=$2 and scope_name=$3 and revoked_at is null`,
          [row.source_principal_id, row.target_component_id, params.scope]
        );
        const permission = row.source_component_id ? await client.query(
          `select 1 from component_permission
            where source_component_id=$1 and target_component_id=$2 and scope_name=$3 and revoked_at is null
              and ($4 = route_pattern or (right(route_pattern,2)='/*' and $4 like left(route_pattern,length(route_pattern)-1)||'%'))`,
          [row.source_component_id, row.target_component_id, params.scope, params.route]
        ) : await client.query(
          `select 1 from principal_component_permission
            where source_principal_id=$1 and target_component_id=$2 and scope_name=$3 and revoked_at is null
              and ($4=route_pattern or (right(route_pattern,2)='/*' and $4 like left(route_pattern,length(route_pattern)-1)||'%'))`,
          [row.source_principal_id, row.target_component_id, params.scope, params.route]
        );
        principalDecision = !scopedPermission.rowCount
          ? denied("insufficient_scope", params.correlationId, base)
          : permission.rowCount
          ? { allow: true, reasonCode: "allowed", decisionId: randomUUID(), correlationId: params.correlationId, ...base }
          : denied("route_denied", params.correlationId, base);
      }
      if (principalDecision.allow) {
        await client.query("update principal_access_token set last_used_at=now() where lookup_digest=$1", [tokenDigest]);
      }
      await appendAudit(client, {
        eventType: principalDecision.allow ? "component_authorization.allowed" : "component_authorization.denied",
        actorType: "component", actorId: principalDecision.sourceComponentId ?? principalDecision.sourceClientId,
        objectType: "component", objectId: principalDecision.targetComponentId,
        after: { decisionId: principalDecision.decisionId, reasonCode: principalDecision.reasonCode, scope: params.scope, route: params.route, audience: params.audience, tokenFingerprint: principalDecision.tokenFingerprint },
        correlationId: params.correlationId
      });
      return principalDecision;
    }
    const decision = denied("invalid_token", params.correlationId);
    await appendAudit(client, {
      eventType: decision.allow ? "component_authorization.allowed" : "component_authorization.denied",
      actorType: "component", actorId: decision.sourceComponentId ?? fingerprintSecret(params.token),
      objectType: "component", objectId: decision.targetComponentId,
      after: { decisionId: decision.decisionId, reasonCode: decision.reasonCode, scope: params.scope, route: params.route, audience: params.audience },
      correlationId: params.correlationId
    });
    return decision;
  });
}
