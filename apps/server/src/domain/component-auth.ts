import { randomUUID } from "node:crypto";
import type { Db } from "../db.js";
import { tx } from "../db.js";
import { fingerprintSecret, hmacToken, issueOpaqueSecret } from "../security/secrets.js";
import { appendAudit } from "./audit.js";
import { KCML_RELEASE } from "./release.js";

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

export async function issueComponentAccessToken(db: Db, params: {
  clientId: string;
  clientSecret: string;
  resource: string;
  hmacKey: Buffer;
  keyId: string;
  correlationId: string;
}): Promise<{ access_token: string; token_type: "Bearer"; expires_in: number; scope: string }> {
  return tx(db, async (client) => {
    const credentialResult = await client.query(
      `select credential.*,source.enabled source_enabled,source.lifecycle_state source_lifecycle_state
         from component_credential credential join component source on source.id=credential.component_id
        where credential.public_id=$1 for update of credential`,
      [params.clientId]
    );
    if (!credentialResult.rowCount) throw Object.assign(new Error("invalid_client"), { statusCode: 401 });
    const credential = credentialResult.rows[0];
    const digest = hmacToken(params.clientSecret, params.hmacKey);
    if (!Buffer.from(credential.secret_digest).equals(digest)
      || credential.status !== "ACTIVE" || credential.revoked_at
      || (credential.expires_at && new Date(credential.expires_at).getTime() <= Date.now())) {
      throw Object.assign(new Error("invalid_client"), { statusCode: 401 });
    }
    if (!credential.source_enabled) throw Object.assign(new Error("component_disabled"), { statusCode: 403 });
    if (credential.source_lifecycle_state === "QUARANTINED") throw Object.assign(new Error("component_quarantined"), { statusCode: 403 });
    const targetResult = await client.query(
      `select * from component where ('https://' || hostname::text)=$1 for update`,
      [params.resource]
    );
    if (!targetResult.rowCount) throw Object.assign(new Error("invalid_resource"), { statusCode: 400 });
    const target = targetResult.rows[0];
    if (!target.enabled || !target.ingress_enabled) throw Object.assign(new Error("component_disabled"), { statusCode: 403 });
    if (target.lifecycle_state === "QUARANTINED" || target.operational_state === "QUARANTINED") throw Object.assign(new Error("component_quarantined"), { statusCode: 403 });
    if (target.release_version !== KCML_RELEASE.catalogVersion) throw Object.assign(new Error("catalog_incompatible"), { statusCode: 409 });
    const permissions = await client.query(
      `select distinct scope_name from component_permission
        where source_component_id=$1 and target_component_id=$2 and revoked_at is null order by scope_name`,
      [credential.component_id, target.id]
    );
    const scopes = permissions.rows.map((row) => String(row.scope_name));
    if (!scopes.length) throw Object.assign(new Error("insufficient_scope"), { statusCode: 403 });
    const secret = issueOpaqueSecret();
    const ttlSeconds = 15 * 60;
    await client.query(
      `insert into component_access_token(
        lookup_digest,key_id,fingerprint,credential_id,source_component_id,target_component_id,audience,scope_names,expires_at,
        credential_revocation_epoch,target_revocation_epoch,policy_epoch_at_issue
      ) values ($1,$2,$3,$4,$5,$6,$7,$8::text[],now()+($9||' seconds')::interval,$10,$11,$12)`,
      [hmacToken(secret.value, params.hmacKey), params.keyId, secret.fingerprint, credential.id, credential.component_id,
        target.id, params.resource, scopes, ttlSeconds, credential.revocation_epoch, target.revocation_epoch, target.policy_epoch]
    );
    await appendAudit(client, {
      eventType: "component_access_token.issued", actorType: "component", actorId: String(credential.component_id),
      objectType: "component", objectId: String(target.id),
      after: { audience: params.resource, scopes, fingerprint: secret.fingerprint, expiresIn: ttlSeconds }, correlationId: params.correlationId
    });
    return { access_token: secret.value, token_type: "Bearer", expires_in: ttlSeconds, scope: scopes.join(" ") };
  });
}

export async function authorizeComponentCall(db: Db, params: {
  token: string;
  audience: string;
  host: string;
  scope: string;
  route: string;
  hmacKey: Buffer;
  correlationId: string;
}): Promise<ComponentAuthorizationDecision> {
  return tx(db, async (client) => {
    const tokenDigest = hmacToken(params.token, params.hmacKey);
    const principalToken = await client.query(`
      select token.*,principal.public_id source_client_id,principal.status source_principal_status,
        principal.revocation_epoch current_source_revocation_epoch,
        source.id source_component_id,source.code source_component_code,source.enabled source_enabled,
        source.lifecycle_state source_lifecycle_state,
        target.id target_component_id,target.code target_component_code,target.hostname target_hostname,
        target.enabled target_enabled,target.ingress_enabled target_ingress_enabled,
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
      } else if (String(row.target_hostname).toLowerCase() !== params.host.toLowerCase()) {
        principalDecision = denied("invalid_audience", params.correlationId, base);
      } else if (row.target_lifecycle_state === "QUARANTINED" || row.target_operational_state === "QUARANTINED" || row.source_lifecycle_state === "QUARANTINED") {
        principalDecision = denied("component_quarantined", params.correlationId, base);
      } else if (!row.target_enabled || !row.target_ingress_enabled || (row.source_component_id && !row.source_enabled)) {
        principalDecision = denied("component_disabled", params.correlationId, base);
      } else {
        const permission = row.source_component_id ? await client.query(
          `select 1 from component_permission
            where source_component_id=$1 and target_component_id=$2 and scope_name=$3 and revoked_at is null
              and ($4 = route_pattern or (right(route_pattern,2)='/*' and $4 like left(route_pattern,length(route_pattern)-1)||'%'))`,
          [row.source_component_id, row.target_component_id, params.scope, params.route]
        ) : { rowCount: 0 };
        principalDecision = permission.rowCount
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
    const result = await client.query(`
      select token.*,credential.status credential_status,credential.revoked_at credential_revoked_at,
        credential.public_id as source_client_id,
        credential.expires_at credential_expires_at,credential.revocation_epoch current_credential_epoch,
        source.enabled source_enabled,source.lifecycle_state source_lifecycle_state,source.code as source_component_code,
        target.enabled target_enabled,target.ingress_enabled as target_ingress_enabled,target.lifecycle_state target_lifecycle_state,
        target.operational_state target_operational_state,target.hostname target_hostname,target.code as target_component_code,target.release_version,target.policy_epoch,
        target.revocation_epoch current_target_epoch
      from component_access_token token
      join component_credential credential on credential.id=token.credential_id
      join component source on source.id=token.source_component_id
      join component target on target.id=token.target_component_id
      where token.lookup_digest=$1
      for update of token`, [tokenDigest]);
    let decision: ComponentAuthorizationDecision;
    if (!result.rowCount) {
      decision = denied("invalid_token", params.correlationId);
    } else {
      const row = result.rows[0];
      const base = {
        sourceComponentId: String(row.source_component_id),
        targetComponentId: String(row.target_component_id),
        sourceClientId: String(row.source_client_id),
        sourceComponentCode: String(row.source_component_code),
        targetComponentCode: String(row.target_component_code),
        audience: String(row.audience),
        scopes: row.scope_names as string[],
        policyEpoch: Number(row.policy_epoch),
        tokenFingerprint: String(row.fingerprint)
      };
      if (row.revoked_at || row.credential_status === "REVOKED" || row.credential_revoked_at
        || String(row.credential_revocation_epoch) !== String(row.current_credential_epoch)
        || String(row.target_revocation_epoch) !== String(row.current_target_epoch)) {
        decision = denied("revoked_token", params.correlationId, base);
      } else if (new Date(row.expires_at).getTime() <= Date.now() || (row.credential_expires_at && new Date(row.credential_expires_at).getTime() <= Date.now())) {
        decision = denied("expired_token", params.correlationId, base);
      } else if (String(row.audience) !== params.audience || String(row.target_hostname).toLowerCase() !== params.host.toLowerCase()) {
        decision = denied("invalid_audience", params.correlationId, base);
      } else if (row.target_lifecycle_state === "QUARANTINED" || row.target_operational_state === "QUARANTINED" || row.source_lifecycle_state === "QUARANTINED") {
        decision = denied("component_quarantined", params.correlationId, base);
      } else if (!row.target_enabled || !row.target_ingress_enabled || !row.source_enabled) {
        decision = denied("component_disabled", params.correlationId, base);
      } else if (row.release_version !== KCML_RELEASE.catalogVersion) {
        decision = denied("catalog_incompatible", params.correlationId, base);
      } else {
        const permission = await client.query(
          `select 1 from component_permission
            where source_component_id=$1 and target_component_id=$2 and scope_name=$3 and revoked_at is null
              and ($4 = route_pattern or (right(route_pattern,2)='/*' and $4 like left(route_pattern,length(route_pattern)-1)||'%'))`,
          [row.source_component_id, row.target_component_id, params.scope, params.route]
        );
        if (!(row.scope_names as string[]).includes(params.scope)) decision = denied("insufficient_scope", params.correlationId, base);
        else if (!permission.rowCount) decision = denied("route_denied", params.correlationId, base);
        else decision = { allow: true, reasonCode: "allowed", decisionId: randomUUID(), correlationId: params.correlationId, ...base };
      }
      if (decision.allow) await client.query("update component_access_token set last_used_at=now() where lookup_digest=$1", [tokenDigest]);
    }
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
