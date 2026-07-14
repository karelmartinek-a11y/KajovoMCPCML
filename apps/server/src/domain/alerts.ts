import { createHash, createHmac, randomUUID } from "node:crypto";
import type pg from "pg";
import type { AppConfig } from "../config.js";
import type { Db } from "../db.js";
import { tx } from "../db.js";
import { appendAudit } from "./audit.js";

export type AlertSeverity = "WARNING" | "HIGH" | "CRITICAL";

type RaiseAlert = {
  serverId?: string | null;
  managedServiceId?: string | null;
  severity: AlertSeverity;
  alertType: string;
  title: string;
  detail: Record<string, unknown>;
  correlationId: string;
};

export async function raiseAlert(client: pg.PoolClient, alert: RaiseAlert): Promise<{ id: string; created: boolean }> {
  const serverId = alert.serverId ?? null;
  const managedServiceId = alert.managedServiceId ?? null;
  const lockKey = `${serverId ?? "system"}:${managedServiceId ?? "system"}:${alert.alertType}`;
  await client.query("select pg_advisory_xact_lock(hashtextextended($1,0))", [lockKey]);
  const existing = await client.query(
    `select id from operational_alert
      where server_id is not distinct from $1
        and managed_service_id is not distinct from $2
        and alert_type=$3
        and status in ('OPEN','ACKNOWLEDGED','SUPPRESSED')
      for update`,
    [serverId, managedServiceId, alert.alertType]
  );
  if (existing.rowCount) {
    const id = String(existing.rows[0].id);
    await client.query(
      `update operational_alert
          set severity=$2,title=$3,detail=$4,last_seen_at=now(),correlation_id=$5
        where id=$1`,
      [id, alert.severity, alert.title, JSON.stringify(alert.detail), alert.correlationId]
    );
    return { id, created: false };
  }
  const inserted = await client.query(
    `insert into operational_alert(server_id,managed_service_id,severity,alert_type,title,detail,correlation_id)
     values ($1,$2,$3,$4,$5,$6,$7) returning id`,
    [serverId, managedServiceId, alert.severity, alert.alertType, alert.title, JSON.stringify(alert.detail), alert.correlationId]
  );
  const id = String(inserted.rows[0].id);
  for (const channel of ["PRIMARY", "BACKUP"] as const) {
    await client.query(
      `insert into alert_webhook_delivery(alert_id,channel,idempotency_key)
       values ($1,$2,$3)`,
      [id, channel, randomUUID()]
    );
  }
  await appendAudit(client, {
    eventType: "alert.opened",
    actorType: "system",
    objectType: "operational_alert",
    objectId: id,
    after: {
      serverId,
      managedServiceId,
      severity: alert.severity,
      alertType: alert.alertType,
      title: alert.title,
      detail: alert.detail
    },
    correlationId: alert.correlationId
  });
  return { id, created: true };
}

export async function raiseAlertWithDb(db: Db, alert: RaiseAlert): Promise<{ id: string; created: boolean }> {
  return tx(db, async (client) => raiseAlert(client, alert));
}

export async function closeAlert(client: pg.PoolClient, params: {
  serverId?: string | null;
  managedServiceId?: string | null;
  alertType: string;
  reason: string;
  correlationId: string;
}): Promise<void> {
  const serverId = params.serverId ?? null;
  const managedServiceId = params.managedServiceId ?? null;
  const result = await client.query(
    `update operational_alert
        set status='CLOSED',closed_at=now(),last_seen_at=now()
      where server_id is not distinct from $1
        and managed_service_id is not distinct from $2
        and alert_type=$3
        and status in ('OPEN','ACKNOWLEDGED','SUPPRESSED')
      returning id`,
    [serverId, managedServiceId, params.alertType]
  );
  for (const row of result.rows) {
    await appendAudit(client, {
      eventType: "alert.closed",
      actorType: "system",
      objectType: "operational_alert",
      objectId: String(row.id),
      after: { reason: params.reason, serverId, managedServiceId },
      correlationId: params.correlationId
    });
  }
}

export async function expireAlertSuppressions(db: Db): Promise<number> {
  return tx(db, async (client) => {
    const correlationId = randomUUID();
    const result = await client.query(
      `update operational_alert
          set status='OPEN',suppression_reason=null,suppression_owner=null,suppressed_until=null,last_seen_at=now()
        where status='SUPPRESSED' and suppressed_until<=now()
        returning id,server_id,managed_service_id,alert_type`,
    );
    for (const row of result.rows) {
      await appendAudit(client, {
        eventType: "alert.suppression.expired",
        actorType: "system",
        objectType: "operational_alert",
        objectId: String(row.id),
        after: { serverId: row.server_id, managedServiceId: row.managed_service_id, alertType: row.alert_type },
        correlationId
      });
    }
    return result.rowCount ?? 0;
  });
}

type DeliveryLease = {
  id: string;
  alertId: string;
  channel: "PRIMARY" | "BACKUP";
  idempotencyKey: string;
  attemptCount: number;
  payload: Record<string, unknown>;
};

async function leaseDelivery(db: Db): Promise<DeliveryLease | null> {
  return tx(db, async (client) => {
    const result = await client.query(
      `select delivery.id,delivery.alert_id,delivery.channel,delivery.idempotency_key,delivery.attempt_count,
              alert.severity,alert.alert_type,alert.title,alert.detail,alert.correlation_id,
              alert.first_seen_at,alert.last_seen_at,server.code,server.hostname,
              managed.code as managed_code,managed.public_hostname as managed_hostname,
              revision.manifest->'owners'->>'service' as service_owner,
              revision.manifest->'monitoringProfile'->>'runbookRef' as runbook_ref,
              managed_revision.manifest->'owners'->>'service' as managed_service_owner,
              managed_revision.manifest->'monitoringProfile'->>'runbookRef' as managed_runbook_ref
         from alert_webhook_delivery delivery
         join operational_alert alert on alert.id=delivery.alert_id
         left join mcp_server server on server.id=alert.server_id
         left join registration_revision revision on revision.id=server.active_revision_id
         left join managed_service managed on managed.id=alert.managed_service_id
         left join managed_service_revision managed_revision on managed_revision.id=managed.active_revision_id
        where delivery.state in ('PENDING','RETRY')
          and delivery.next_attempt_at<=now()
        order by case alert.severity when 'CRITICAL' then 1 when 'HIGH' then 2 else 3 end,
                 delivery.next_attempt_at
        for update of delivery skip locked
        limit 1`
    );
    if (!result.rowCount) return null;
    const row = result.rows[0];
    const attemptCount = Number(row.attempt_count) + 1;
    await client.query(
      `update alert_webhook_delivery
          set attempt_count=$2,next_attempt_at=now()+interval '2 minutes',updated_at=now()
        where id=$1`,
      [row.id, attemptCount]
    );
    return {
      id: String(row.id),
      alertId: String(row.alert_id),
      channel: String(row.channel) as DeliveryLease["channel"],
      idempotencyKey: String(row.idempotency_key),
      attemptCount,
      payload: {
        alertId: row.alert_id,
        severity: row.severity,
        type: row.alert_type,
        title: row.title,
        detail: row.detail,
        correlationId: row.correlation_id,
        firstSeenAt: row.first_seen_at,
        lastSeenAt: row.last_seen_at,
        server: row.code ? {
          code: row.code,
          hostname: row.hostname,
          serviceOwner: row.service_owner,
          runbookRef: row.runbook_ref
        } : null,
        managedService: row.managed_code ? {
          code: row.managed_code,
          hostname: row.managed_hostname,
          serviceOwner: row.managed_service_owner,
          runbookRef: row.managed_runbook_ref
        } : null
      }
    };
  });
}

function webhookCredential(config: AppConfig, channel: DeliveryLease["channel"]): { url: string; key: Buffer } {
  const url = channel === "PRIMARY" ? config.ALERT_PRIMARY_WEBHOOK_URL : config.ALERT_BACKUP_WEBHOOK_URL;
  const key = channel === "PRIMARY" ? config.ALERT_PRIMARY_HMAC_KEY_BASE64 : config.ALERT_BACKUP_HMAC_KEY_BASE64;
  if (!url || !key) throw new Error(`alert_webhook_credential_missing:${channel.toLowerCase()}`);
  return { url, key };
}

export function signAlertWebhookBody(body: string, timestamp: string, key: Buffer): string {
  return `v1=${createHmac("sha256", key).update(`${timestamp}.${body}`).digest("hex")}`;
}

export async function deliverNextAlert(db: Db, config: AppConfig): Promise<boolean> {
  const delivery = await leaseDelivery(db);
  if (!delivery) return false;
  const correlationId = randomUUID();
  let httpStatus: number | null = null;
  let responseDigest: string | null = null;
  let failure: string | null = null;
  try {
    const credential = webhookCredential(config, delivery.channel);
    const body = JSON.stringify(delivery.payload);
    const timestamp = Math.floor(Date.now() / 1_000).toString();
    const signature = signAlertWebhookBody(body, timestamp, credential.key);
    const response = await fetch(credential.url, {
      method: "POST",
      redirect: "manual",
      signal: AbortSignal.timeout(10_000),
      headers: {
        "content-type": "application/json",
        "x-kcml-delivery-id": delivery.idempotencyKey,
        "x-kcml-timestamp": timestamp,
        "x-kcml-signature": signature
      },
      body
    });
    httpStatus = response.status;
    const responseBody = await response.text();
    responseDigest = createHash("sha256").update(responseBody).digest("hex");
    if (!response.ok) failure = `webhook_http_${response.status}`;
  } catch (error) {
    failure = error instanceof Error ? error.message.slice(0, 500) : "webhook_delivery_failed";
  }

  await tx(db, async (client) => {
    const terminal = Boolean(failure && delivery.attemptCount >= 10);
    const nextDelaySeconds = Math.min(3_600, 30 * 2 ** Math.min(delivery.attemptCount, 7));
    await client.query(
      `update alert_webhook_delivery
          set state=$2,
              last_http_status=$3,
              last_error=$4,
              response_digest=$5,
              delivered_at=case when $2='DELIVERED' then now() else delivered_at end,
              next_attempt_at=case when $2='RETRY' then now()+($6 || ' seconds')::interval else next_attempt_at end,
              updated_at=now()
        where id=$1`,
      [delivery.id, failure ? (terminal ? "DEAD_LETTER" : "RETRY") : "DELIVERED", httpStatus, failure, responseDigest, nextDelaySeconds]
    );
    await appendAudit(client, {
      eventType: failure ? (terminal ? "alert.delivery.dead_letter" : "alert.delivery.retry") : "alert.delivery.succeeded",
      actorType: "system",
      objectType: "operational_alert",
      objectId: delivery.alertId,
      after: {
        channel: delivery.channel,
        idempotencyKey: delivery.idempotencyKey,
        attemptCount: delivery.attemptCount,
        httpStatus,
        responseDigest,
        error: failure
      },
      correlationId
    });
  });
  return true;
}
