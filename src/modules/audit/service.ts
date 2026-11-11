import type { AuthEvent } from '../../core/context.js';
import type { Pool } from '../../db/pool.js';

type Queryable = Pick<Pool, 'query'>;

export interface AuditEntry {
  id: string;
  type: string;
  actorId: string | null;
  subjectId: string | null;
  ip: string | null;
  userAgent: string | null;
  details: Record<string, unknown>;
  createdAt: Date;
}

export async function recordAudit(db: Queryable, event: AuthEvent): Promise<void> {
  await db.query(
    `INSERT INTO audit_log (type, actor_id, subject_id, ip, user_agent, details)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [
      event.type,
      event.actorId ?? null,
      event.subjectId ?? null,
      event.ip ?? null,
      event.userAgent?.slice(0, 500) ?? null,
      event.details ?? {},
    ],
  );
}

/** One page of the log, newest first. */
export async function listAudit(
  db: Queryable,
  filter: {
    limit: number;
    before?: bigint | undefined;
    type?: string | undefined;
    actorId?: string | undefined;
  },
): Promise<{ entries: AuditEntry[]; nextCursor: string | null }> {
  const result = await db.query<{
    id: bigint;
    type: string;
    actor_id: string | null;
    subject_id: string | null;
    ip: string | null;
    user_agent: string | null;
    details: Record<string, unknown>;
    created_at: Date;
  }>(
    `SELECT id, type, actor_id, subject_id, host(ip) AS ip, user_agent, details, created_at
     FROM audit_log
     WHERE ($1::bigint IS NULL OR id < $1)
       AND ($2::text IS NULL OR type = $2)
       AND ($3::uuid IS NULL OR actor_id = $3)
     ORDER BY id DESC
     LIMIT $4`,
    [
      filter.before?.toString() ?? null,
      filter.type ?? null,
      filter.actorId ?? null,
      filter.limit + 1,
    ],
  );
  const page = result.rows.slice(0, filter.limit);
  const last = page.at(-1);
  return {
    entries: page.map((row) => ({
      id: row.id.toString(),
      type: row.type,
      actorId: row.actor_id,
      subjectId: row.subject_id,
      ip: row.ip,
      userAgent: row.user_agent,
      details: row.details,
      createdAt: row.created_at,
    })),
    nextCursor: result.rows.length > filter.limit && last ? last.id.toString() : null,
  };
}
