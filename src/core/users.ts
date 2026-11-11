import { pgErrorCode, type Pool } from '../db/pool.js';
import type { Context } from './context.js';
import { errors } from './errors.js';
import { assertAcceptablePassword } from './password-policy.js';

type Queryable = Pick<Pool, 'query'>;

export interface User {
  id: string;
  email: string;
  isSuperuser: boolean;
  attributes: Record<string, unknown>;
  hasPassword: boolean;
  disabled: boolean;
  createdAt: Date;
}

interface UserRow {
  id: string;
  email: string;
  password_hash: string | null;
  is_superuser: boolean;
  attributes: Record<string, unknown>;
  failed_logins: number;
  locked_until: Date | null;
  disabled_at: Date | null;
  created_at: Date;
}

const UNIQUE_VIOLATION = '23505';

export const normalizeEmail = (email: string) => email.trim().toLowerCase();

function toUser(row: UserRow): User {
  return {
    id: row.id,
    email: row.email,
    isSuperuser: row.is_superuser,
    attributes: row.attributes,
    hasPassword: row.password_hash !== null,
    disabled: row.disabled_at !== null,
    createdAt: row.created_at,
  };
}

export async function createUser(
  { pool, hasher }: Pick<Context, 'pool' | 'hasher'>,
  input: { email: string; password?: string | undefined },
  db: Queryable = pool,
): Promise<User> {
  const email = normalizeEmail(input.email);
  if (input.password !== undefined) assertAcceptablePassword(input.password, email);
  const passwordHash = input.password === undefined ? null : await hasher.hash(input.password);
  try {
    const result = await db.query<UserRow>(
      `INSERT INTO users (email, password_hash, password_changed_at)
       VALUES ($1, $2, CASE WHEN $2::text IS NULL THEN NULL ELSE now() END)
       RETURNING *`,
      [email, passwordHash],
    );
    return toUser(result.rows[0] as UserRow);
  } catch (error) {
    if (pgErrorCode(error) === UNIQUE_VIOLATION) throw errors.emailTaken();
    throw error;
  }
}

export async function findUserById(db: Queryable, id: string): Promise<User | null> {
  const result = await db.query<UserRow>('SELECT * FROM users WHERE id = $1', [id]);
  return result.rows[0] ? toUser(result.rows[0]) : null;
}

export async function findUserByEmail(db: Queryable, email: string): Promise<User | null> {
  const result = await db.query<UserRow>('SELECT * FROM users WHERE email = $1', [
    normalizeEmail(email),
  ]);
  return result.rows[0] ? toUser(result.rows[0]) : null;
}

export type CredentialCheck =
  | { ok: true; user: User }
  | {
      ok: false;
      reason: 'unknown_user' | 'wrong_password' | 'locked' | 'disabled';
      userId?: string;
    };

/**
 * Checks an email and password.
 *
 * Every failure looks the same from outside and takes about the same time:
 * an unknown email still pays for a full Argon2 verification, so neither the
 * response nor its timing shows which accounts exist.
 *
 * Repeated failures lock the account, and each further failure doubles the
 * lock. That makes online guessing useless without a permanent lockout that
 * an attacker could use to shut a victim out for good.
 */
export async function checkCredentials(
  { pool, hasher, config }: Pick<Context, 'pool' | 'hasher' | 'config'>,
  email: string,
  password: string,
): Promise<CredentialCheck> {
  const found = await pool.query<UserRow & { is_locked: boolean }>(
    `SELECT *, (locked_until IS NOT NULL AND locked_until > now()) AS is_locked
     FROM users WHERE email = $1`,
    [normalizeEmail(email)],
  );
  const row = found.rows[0];

  if (!row?.password_hash) {
    await hasher.verifyDummy(password);
    return { ok: false, reason: 'unknown_user' };
  }
  if (row.is_locked || row.disabled_at) {
    await hasher.verifyDummy(password);
    return { ok: false, reason: row.disabled_at ? 'disabled' : 'locked', userId: row.id };
  }

  if (await hasher.verify(row.password_hash, password)) {
    if (row.failed_logins > 0) {
      await pool.query('UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = $1', [
        row.id,
      ]);
    }
    return { ok: true, user: toUser(row) };
  }

  // Count the failure in one statement, so concurrent guesses cannot undercount.
  await pool.query(
    `UPDATE users
     SET failed_logins = failed_logins + 1,
         locked_until = CASE
           WHEN failed_logins + 1 >= $2
           THEN now() + make_interval(secs => $3 * power(2, least(failed_logins + 1 - $2, 6)))
           ELSE locked_until
         END
     WHERE id = $1`,
    [row.id, config.MAX_FAILED_LOGINS, config.LOCKOUT_SECONDS],
  );
  return { ok: false, reason: 'wrong_password', userId: row.id };
}

/** Sets a new password. The caller decides which sessions to end. */
export async function setPassword(
  { hasher }: Pick<Context, 'hasher'>,
  db: Queryable,
  user: Pick<User, 'id' | 'email'>,
  password: string,
): Promise<void> {
  assertAcceptablePassword(password, user.email);
  await db.query(
    `UPDATE users
     SET password_hash = $2, password_changed_at = now(), failed_logins = 0, locked_until = NULL
     WHERE id = $1`,
    [user.id, await hasher.hash(password)],
  );
}

export async function verifyPassword(
  { pool, hasher }: Pick<Context, 'pool' | 'hasher'>,
  userId: string,
  password: string,
): Promise<boolean> {
  const result = await pool.query<{ password_hash: string | null }>(
    'SELECT password_hash FROM users WHERE id = $1',
    [userId],
  );
  const hash = result.rows[0]?.password_hash;
  return hash ? hasher.verify(hash, password) : false;
}

export async function setSuperuser(db: Queryable, email: string, value: boolean): Promise<User> {
  const result = await db.query<UserRow>(
    'UPDATE users SET is_superuser = $2 WHERE email = $1 RETURNING *',
    [normalizeEmail(email), value],
  );
  if (!result.rows[0]) throw errors.notFound('User');
  return toUser(result.rows[0]);
}
