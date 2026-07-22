import type pg from "pg";
import { KCML_RELEASE } from "./release.js";

export const DEPLOYMENT_MANAGED_OWNER_USERNAME = "karmar78";
export const PLATFORM_WORKER_PRINCIPAL_PUBLIC_ID = "KCML-PLATFORM-WORKER";

export async function initializePreProductionBaselineState(client: pg.PoolClient): Promise<void> {
  await client.query(
    `insert into admin_bootstrap_state(singleton,completed,completed_at,completed_by,updated_at)
     values (true,false,null,null,now())
     on conflict (singleton) do nothing`
  );

  const platformPrincipal = await client.query(
    `insert into principal(kind,public_id,status,policy_epoch,revocation_epoch,metadata)
     values ('PLATFORM',$1,'ACTIVE',1,1,'{"managedBy":"KCML","purpose":"control-and-e2e-workers"}'::jsonb)
     on conflict (public_id) do update
       set kind='PLATFORM',
           status='ACTIVE',
           updated_at=now()
     returning id`,
    [PLATFORM_WORKER_PRINCIPAL_PUBLIC_ID]
  );

  await client.query(
    `insert into platform_worker_access_identity(singleton,principal_id,updated_at)
     values (true,$1,now())
     on conflict (singleton) do update
       set principal_id=excluded.principal_id,
           updated_at=now()`,
    [platformPrincipal.rows[0]?.id]
  );

  await client.query(
    `insert into release_epoch(
       release_version,
       blueprint_version,
       catalog_version,
       manifest_schema_version,
       pulse_envelope_version,
       policy_baseline,
       mcp_protocol_version,
       sealed_previous_epoch_hash
     )
     values ($1,$1,$1,$1,$1,$2::date,$3,'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
     on conflict (release_version) do update
       set blueprint_version=excluded.blueprint_version,
           catalog_version=excluded.catalog_version,
           manifest_schema_version=excluded.manifest_schema_version,
           pulse_envelope_version=excluded.pulse_envelope_version,
           policy_baseline=excluded.policy_baseline,
           mcp_protocol_version=excluded.mcp_protocol_version`,
    [KCML_RELEASE.catalogVersion, KCML_RELEASE.policyBaseline, KCML_RELEASE.mcpProtocolVersion]
  );
}
