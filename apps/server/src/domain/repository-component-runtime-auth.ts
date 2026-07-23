import { randomUUID } from "node:crypto";
import type { Db } from "../db.js";
import { tx } from "../db.js";
import { hmacToken, issueOpaqueSecret } from "../security/secrets.js";
import { appendAudit } from "./audit.js";

export async function issueRepositoryComponentRuntimeSecretToken(db: Db, params: {
  repositoryKey: string;
  accessTokenHmacKey: Buffer;
  accessTokenHmacKeyId: string;
}): Promise<{ token: string; fingerprint: string; componentId: string; principalId: string }> {
  return tx(db, async (client) => {
    const component = await client.query(
      `select c.id,p.id as principal_id,p.public_id,p.policy_epoch,p.revocation_epoch
         from component c
         join principal p on p.id=c.principal_id
        where c.code=$1
        for update of c,p`,
      [params.repositoryKey]
    );
    if (!component.rowCount) throw new Error("repository_component_not_registered");
    const row = component.rows[0];
    await client.query(
      `update principal_access_token
          set revoked_at=coalesce(revoked_at,now()),
              rotated_at=now(),
              rotation_reason='RUNTIME_DEPLOY_SUPERSEDED'
        where source_principal_id=$1
          and target_component_id=$2
          and audience='kcml-runtime-secret-broker'
          and revoked_at is null`,
      [row.principal_id, row.id]
    );
    const issued = issueOpaqueSecret();
    await client.query(
      `insert into principal_access_token(
         lookup_digest,key_id,fingerprint,source_principal_id,target_component_id,audience,scope_names,
         issued_policy_epoch,issued_revocation_epoch,expires_at,handed_off_at
       ) values ($1,$2,$3,$4,$5,'kcml-runtime-secret-broker',array['secret.resolve'],$6,$7,'infinity',now())`,
      [
        hmacToken(issued.value, params.accessTokenHmacKey),
        params.accessTokenHmacKeyId,
        issued.fingerprint,
        row.principal_id,
        row.id,
        row.policy_epoch,
        row.revocation_epoch
      ]
    );
    await appendAudit(client, {
      eventType: "principal_access_token.rotated",
      actorType: "system",
      actorId: null,
      objectType: "component",
      objectId: String(row.id),
      after: {
        reason: "RUNTIME_DEPLOY_SECRET_BROKER",
        fingerprint: issued.fingerprint,
        principalPublicId: String(row.public_id)
      },
      correlationId: randomUUID()
    });
    return {
      token: issued.value,
      fingerprint: issued.fingerprint,
      componentId: String(row.id),
      principalId: String(row.principal_id)
    };
  });
}
