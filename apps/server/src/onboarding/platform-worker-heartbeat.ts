import type { Db } from "../db.js";

export type PlatformWorkerKind = "COMPONENT_CONTROL" | "COMPONENT_E2E";

export async function recordPlatformWorkerHeartbeat(db: Db, input: {
  workerKind: PlatformWorkerKind;
  workerId: string;
  buildId: string;
  completed: boolean;
  error?: string | null;
}): Promise<void> {
  await db.query(
    `insert into platform_worker_heartbeat(
       worker_kind,worker_id,build_id,started_at,last_heartbeat_at,last_completed_at,last_error
     ) values ($1,$2,$3,now(),now(),case when $4 then now() end,$5)
     on conflict (worker_kind) do update set
       worker_id=excluded.worker_id,
       build_id=excluded.build_id,
       started_at=case when platform_worker_heartbeat.worker_id=excluded.worker_id then platform_worker_heartbeat.started_at else now() end,
       last_heartbeat_at=now(),
       last_completed_at=case when $4 then now() else platform_worker_heartbeat.last_completed_at end,
       last_error=$5,
       updated_at=now()`,
    [input.workerKind, input.workerId, input.buildId, input.completed, input.error?.slice(0, 500) ?? null]
  );
}
