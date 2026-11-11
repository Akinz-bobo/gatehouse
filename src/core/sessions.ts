import { hashToken, randomToken } from '../crypto/tokens.js';
import { withTransaction, type Pool } from '../db/pool.js';
import type { Context } from './context.js';
import { errors } from './errors.js';
import { findUserById, type User } from './users.js';

type Queryable = Pick<Pool, 'query'>;

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  tokenType: 'Bearer';
  /** Seconds until the access token expires. */
  expiresIn: number;
}

export interface Session {
  id: string;
  authMethod: string;
  ip: string | null;
  userAgent: string | null;
  createdAt: Date;
  lastUsedAt: Date;
}

export interface ClientInfo {
  ip?: string | undefined;
  userAgent?: string | undefined;
}

async function issueTokens(
  { keys, hooks, config }: Pick<Context, 'keys' | 'hooks' | 'config'>,
  db: Queryable,
  user: User,
  sessionId: string,
): Promise<TokenPair> {
  const claims = await hooks.claimsFor(db, user);
  const accessToken = await keys.sign(
    { ...claims, sid: sessionId, email: user.email },
    { subject: user.id, ttlSeconds: config.ACCESS_TOKEN_TTL_SECONDS },
  );

  const refreshToken = randomToken();
  await db.query(
    `INSERT INTO refresh_tokens (session_id, token_hash, expires_at)
     VALUES ($1, $2, now() + make_interval(secs => $3))`,
    [sessionId, hashToken(refreshToken), config.REFRESH_TOKEN_TTL_SECONDS],
  );
  return {
    accessToken,
    refreshToken,
    tokenType: 'Bearer',
    expiresIn: config.ACCESS_TOKEN_TTL_SECONDS,
  };
}

/** Starts a session for a user who has just proved who they are. */
export async function startSession(
  context: Context,
  user: User,
  authMethod: string,
  client: ClientInfo,
  db?: Queryable,
): Promise<TokenPair & { sessionId: string }> {
  const run = async (tx: Queryable) => {
    const created = await tx.query<{ id: string }>(
      `INSERT INTO sessions (user_id, auth_method, ip, user_agent)
       VALUES ($1, $2, $3, $4) RETURNING id`,
      [user.id, authMethod, client.ip ?? null, client.userAgent?.slice(0, 500) ?? null],
    );
    const sessionId = (created.rows[0] as { id: string }).id;
    return { ...(await issueTokens(context, tx, user, sessionId)), sessionId };
  };
  return db ? run(db) : withTransaction(context.pool, run);
}

/**
 * Exchanges a refresh token for a new pair.
 *
 * Refresh tokens are single-use. The row is locked while it is checked, so
 * two requests racing with the same token cannot both succeed. If a token
 * that was already used is presented again, either it was stolen or the real
 * client's copy was: the two cannot be told apart, so the whole session is
 * ended and both parties must sign in again.
 */
export async function refreshSession(
  context: Context,
  refreshToken: string,
  client: ClientInfo,
): Promise<TokenPair> {
  const outcome = await withTransaction(context.pool, async (tx) => {
    const found = await tx.query<{
      id: string;
      session_id: string;
      user_id: string;
      used_at: Date | null;
      expired: boolean;
      revoked_at: Date | null;
    }>(
      `SELECT rt.id, rt.session_id, s.user_id, rt.used_at, rt.expires_at <= now() AS expired,
              s.revoked_at
       FROM refresh_tokens rt
       JOIN sessions s ON s.id = rt.session_id
       WHERE rt.token_hash = $1
       FOR UPDATE OF rt, s`,
      [hashToken(refreshToken)],
    );
    const row = found.rows[0];
    if (!row || row.revoked_at || row.expired) return { kind: 'invalid' as const };

    if (row.used_at) {
      await revokeSession(tx, row.session_id, 'refresh_token_reuse');
      return { kind: 'reused' as const, userId: row.user_id, sessionId: row.session_id };
    }

    const user = await findUserById(tx, row.user_id);
    if (!user || user.disabled) return { kind: 'invalid' as const };

    await tx.query('UPDATE refresh_tokens SET used_at = now() WHERE id = $1', [row.id]);
    await tx.query('UPDATE sessions SET last_used_at = now() WHERE id = $1', [row.session_id]);
    return { kind: 'ok' as const, tokens: await issueTokens(context, tx, user, row.session_id) };
  });

  if (outcome.kind === 'ok') return outcome.tokens;
  if (outcome.kind === 'reused') {
    await context.hooks.emit({
      type: 'token.reuse_detected',
      actorId: outcome.userId,
      subjectId: outcome.sessionId,
      ...client,
    });
    throw errors.refreshTokenReused();
  }
  throw errors.invalidRefreshToken();
}

export async function revokeSession(db: Queryable, id: string, reason: string): Promise<boolean> {
  const result = await db.query(
    `UPDATE sessions SET revoked_at = now(), revoked_reason = $2
     WHERE id = $1 AND revoked_at IS NULL`,
    [id, reason],
  );
  return (result.rowCount ?? 0) > 0;
}

/** Ends all of a user's sessions, optionally keeping one (the one making the request). */
export async function revokeUserSessions(
  db: Queryable,
  userId: string,
  reason: string,
  exceptSessionId?: string,
): Promise<number> {
  const result = await db.query(
    `UPDATE sessions SET revoked_at = now(), revoked_reason = $2
     WHERE user_id = $1 AND revoked_at IS NULL AND ($3::uuid IS NULL OR id <> $3)`,
    [userId, reason, exceptSessionId ?? null],
  );
  return result.rowCount ?? 0;
}

export async function listSessions(db: Queryable, userId: string): Promise<Session[]> {
  const result = await db.query<{
    id: string;
    auth_method: string;
    ip: string | null;
    user_agent: string | null;
    created_at: Date;
    last_used_at: Date;
  }>(
    `SELECT id, auth_method, host(ip) AS ip, user_agent, created_at, last_used_at
     FROM sessions
     WHERE user_id = $1 AND revoked_at IS NULL
     ORDER BY last_used_at DESC`,
    [userId],
  );
  return result.rows.map((row) => ({
    id: row.id,
    authMethod: row.auth_method,
    ip: row.ip,
    userAgent: row.user_agent,
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at,
  }));
}

/** True when the session exists, belongs to the user and has not been ended. */
export async function isSessionActive(
  db: Queryable,
  sessionId: string,
  userId: string,
): Promise<boolean> {
  const result = await db.query(
    'SELECT 1 FROM sessions WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL',
    [sessionId, userId],
  );
  return (result.rowCount ?? 0) > 0;
}
