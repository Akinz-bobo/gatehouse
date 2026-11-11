import type { Context } from '../../core/context.js';
import { errors } from '../../core/errors.js';
import { hashToken, randomToken } from '../../crypto/tokens.js';
import { generateSecret, provisioningUri, verifyCode } from '../../crypto/totp.js';
import { withTransaction, type Pool } from '../../db/pool.js';

type Queryable = Pick<Pool, 'query'>;

const RECOVERY_CODE_COUNT = 10;

interface TotpRow {
  secret_encrypted: string;
  confirmed_at: Date | null;
  last_used_step: bigint | null;
}

export async function isTotpEnabled(db: Queryable, userId: string): Promise<boolean> {
  const result = await db.query(
    'SELECT 1 FROM mfa_totp WHERE user_id = $1 AND confirmed_at IS NOT NULL',
    [userId],
  );
  return (result.rowCount ?? 0) > 0;
}

/**
 * Begins enrolment: creates a secret and returns it for the user's
 * authenticator app. Nothing is enforced until the user confirms a code,
 * so a failed setup cannot lock anyone out.
 */
export async function enrollTotp(
  { pool, secrets, config }: Pick<Context, 'pool' | 'secrets' | 'config'>,
  user: { id: string; email: string },
): Promise<{ secret: string; uri: string }> {
  if (await isTotpEnabled(pool, user.id)) {
    throw errors.conflict('mfa_already_enabled', 'Two-factor authentication is already enabled');
  }
  const secret = generateSecret();
  await pool.query(
    `INSERT INTO mfa_totp (user_id, secret_encrypted) VALUES ($1, $2)
     ON CONFLICT (user_id) DO UPDATE
       SET secret_encrypted = EXCLUDED.secret_encrypted, confirmed_at = NULL, last_used_step = NULL`,
    [user.id, secrets.encrypt(secret)],
  );
  return { secret, uri: provisioningUri(secret, user.email, new URL(config.ISSUER).host) };
}

/**
 * Checks a code and records the time step it was for. A code is accepted
 * once: seeing it again, even inside its 30 seconds, is treated as a replay.
 */
async function consumeCode(
  { secrets }: Pick<Context, 'secrets'>,
  tx: Queryable,
  userId: string,
  code: string,
  { requireConfirmed }: { requireConfirmed: boolean },
): Promise<boolean> {
  const found = await tx.query<TotpRow>('SELECT * FROM mfa_totp WHERE user_id = $1 FOR UPDATE', [
    userId,
  ]);
  const row = found.rows[0];
  if (!row || (requireConfirmed && !row.confirmed_at)) return false;

  const step = verifyCode(secrets.decrypt(row.secret_encrypted), code);
  if (step === null) return false;
  if (row.last_used_step !== null && step <= row.last_used_step) return false;

  await tx.query('UPDATE mfa_totp SET last_used_step = $2 WHERE user_id = $1', [
    userId,
    step.toString(),
  ]);
  return true;
}

/** Completes enrolment and returns one-time recovery codes, shown only this once. */
export async function confirmTotp(
  context: Context,
  userId: string,
  code: string,
): Promise<string[]> {
  return withTransaction(context.pool, async (tx) => {
    if (!(await consumeCode(context, tx, userId, code, { requireConfirmed: false }))) {
      throw errors.invalid('invalid_mfa_code', 'That code is not correct');
    }
    await tx.query('UPDATE mfa_totp SET confirmed_at = now() WHERE user_id = $1', [userId]);

    const codes = Array.from({ length: RECOVERY_CODE_COUNT }, () =>
      randomToken(10).slice(0, 12).toLowerCase(),
    );
    await tx.query('DELETE FROM mfa_recovery_codes WHERE user_id = $1', [userId]);
    await tx.query(
      `INSERT INTO mfa_recovery_codes (user_id, code_hash) SELECT $1, unnest($2::text[])`,
      [userId, codes.map(hashToken)],
    );
    return codes;
  });
}

/** Verifies a second factor at sign-in: a TOTP code, or a recovery code that is then spent. */
export async function verifySecondFactor(
  context: Context,
  userId: string,
  input: { code?: string | undefined; recoveryCode?: string | undefined },
): Promise<'totp' | 'recovery_code' | null> {
  return withTransaction(context.pool, async (tx) => {
    if (input.code !== undefined) {
      const ok = await consumeCode(context, tx, userId, input.code, { requireConfirmed: true });
      return ok ? 'totp' : null;
    }
    if (input.recoveryCode !== undefined) {
      const spent = await tx.query(
        `UPDATE mfa_recovery_codes SET used_at = now()
         WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL`,
        [userId, hashToken(input.recoveryCode.trim().toLowerCase())],
      );
      return spent.rowCount ? 'recovery_code' : null;
    }
    return null;
  });
}

export async function disableTotp(context: Context, userId: string, code: string): Promise<void> {
  await withTransaction(context.pool, async (tx) => {
    if (!(await consumeCode(context, tx, userId, code, { requireConfirmed: true }))) {
      throw errors.invalid('invalid_mfa_code', 'That code is not correct');
    }
    await tx.query('DELETE FROM mfa_totp WHERE user_id = $1', [userId]);
    await tx.query('DELETE FROM mfa_recovery_codes WHERE user_id = $1', [userId]);
  });
}
