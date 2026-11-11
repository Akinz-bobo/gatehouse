import { hashToken, randomToken } from '../crypto/tokens.js';
import { withTransaction } from '../db/pool.js';
import type { Context } from './context.js';
import { errors } from './errors.js';
import { revokeUserSessions } from './sessions.js';
import { findUserByEmail, setPassword } from './users.js';

const RESET_TTL_SECONDS = 30 * 60;

/**
 * Starts a password reset. Returns nothing and behaves the same whether or
 * not the email has an account, so it cannot be used to find out who is
 * registered.
 */
export async function requestPasswordReset(context: Context, email: string): Promise<void> {
  const user = await findUserByEmail(context.pool, email);
  if (!user || user.disabled) return;

  const token = randomToken();
  await context.pool.query(
    `INSERT INTO password_resets (user_id, token_hash, expires_at)
     VALUES ($1, $2, now() + make_interval(secs => $3))`,
    [user.id, hashToken(token), RESET_TTL_SECONDS],
  );
  await context.notifier.passwordReset(user.email, token);
  await context.hooks.emit({ type: 'password.reset_requested', subjectId: user.id });
}

/**
 * Completes a reset: the token works once, and every session the account had
 * is ended, since whoever knew the old password may still be signed in.
 */
export async function resetPassword(
  context: Context,
  token: string,
  newPassword: string,
): Promise<void> {
  const userId = await withTransaction(context.pool, async (tx) => {
    const found = await tx.query<{ id: string; user_id: string; email: string }>(
      `SELECT pr.id, pr.user_id, u.email
       FROM password_resets pr
       JOIN users u ON u.id = pr.user_id
       WHERE pr.token_hash = $1 AND pr.used_at IS NULL AND pr.expires_at > now()
       FOR UPDATE OF pr`,
      [hashToken(token)],
    );
    const row = found.rows[0];
    if (!row) throw errors.invalidToken('reset token');

    await setPassword(context, tx, { id: row.user_id, email: row.email }, newPassword);
    // Spend this token and any other outstanding ones for the account.
    await tx.query(
      'UPDATE password_resets SET used_at = now() WHERE user_id = $1 AND used_at IS NULL',
      [row.user_id],
    );
    await revokeUserSessions(tx, row.user_id, 'password_reset');
    return row.user_id;
  });
  await context.hooks.emit({ type: 'password.reset', actorId: userId, subjectId: userId });
}
