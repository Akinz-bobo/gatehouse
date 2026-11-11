import type { FastifyInstance } from 'fastify';
import { loadConfig, type ModuleName } from '../../src/config.js';
import type { Context } from '../../src/core/context.js';
import { setSuperuser } from '../../src/core/users.js';
import { createPool, type Pool } from '../../src/db/pool.js';
import { buildApp } from '../../src/http/app.js';

export const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? 'postgres://gatehouse:gatehouse@localhost:5546/gatehouse_test';

export const PASSWORD = 'correct horse battery staple';
// Fixed, so every test file can read the signing keys an earlier file stored.
const KEY_ENCRYPTION_KEY = Buffer.alloc(32, 7).toString('base64');

export function createTestPool(): Pool {
  return createPool(TEST_DATABASE_URL, 20);
}

/** Empties every table except the signing keys, which the running apps have cached. */
export async function resetDatabase(pool: Pool): Promise<void> {
  await pool.query(
    `TRUNCATE users, sessions, refresh_tokens, password_resets, roles, role_permissions,
              user_roles, policies, oauth_identities, oauth_states, oauth_exchange_codes,
              mfa_totp, mfa_recovery_codes, audit_log
     RESTART IDENTITY CASCADE`,
  );
}

export interface TestApp {
  app: FastifyInstance;
  context: Context;
  /** Reset tokens the service "sent", by email address. */
  sentResets: Map<string, string>;
}

export async function createTestApp(
  pool: Pool,
  modules: ModuleName[] = [],
  env: Record<string, string> = {},
  configure?: (app: FastifyInstance) => void,
): Promise<TestApp> {
  const config = loadConfig({
    NODE_ENV: 'test',
    LOG_LEVEL: 'silent',
    DATABASE_URL: TEST_DATABASE_URL,
    ISSUER: 'http://localhost:4000',
    KEY_ENCRYPTION_KEY,
    MODULES: modules.join(','),
    RATE_LIMIT_MAX: '100000',
    AUTH_RATE_LIMIT_MAX: '100000',
    // The cheapest allowed Argon2 settings, so the suite stays fast.
    PASSWORD_HASH_MEMORY_KIB: '1024',
    PASSWORD_HASH_ITERATIONS: '1',
    ...env,
  });
  const sentResets = new Map<string, string>();
  const { app, context } = await buildApp({
    config,
    pool,
    configure,
    notifier: {
      passwordReset: (email, token) => {
        sentResets.set(email, token);
        return Promise.resolve();
      },
    },
  });
  return { app, context, sentResets };
}

export interface Tokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

/** A small client for driving the API in tests. */
export function client(app: FastifyInstance) {
  const post = (url: string, payload?: unknown, token?: string) =>
    app.inject({
      method: 'POST',
      url,
      ...(payload === undefined ? {} : { payload: payload as object }),
      headers: token ? { authorization: `Bearer ${token}` } : {},
    });
  const request = (
    method: 'GET' | 'PUT' | 'DELETE',
    url: string,
    token?: string,
    payload?: unknown,
  ) =>
    app.inject({
      method,
      url,
      ...(payload === undefined ? {} : { payload: payload as object }),
      headers: token ? { authorization: `Bearer ${token}` } : {},
    });

  const register = (email: string, password = PASSWORD) =>
    post('/v1/auth/register', { email, password });
  const login = (email: string, password = PASSWORD) => post('/v1/auth/login', { email, password });

  /** Registers an account and signs in, returning its id and tokens. */
  const signUp = async (email: string): Promise<Tokens & { userId: string }> => {
    const created = await register(email);
    const userId = created.json<{ user: { id: string } }>().user.id;
    return { userId, ...(await login(email)).json<Tokens>() };
  };

  return {
    post,
    get: (url: string, token?: string) => request('GET', url, token),
    put: (url: string, token?: string, payload?: unknown) => request('PUT', url, token, payload),
    delete: (url: string, token?: string) => request('DELETE', url, token),
    register,
    login,
    signUp,
    /** Signs up an account and makes it a superuser. */
    signUpAdmin: async (pool: Pool, email = 'admin@example.com') => {
      const account = await signUp(email);
      await setSuperuser(pool, email, true);
      return account;
    },
  };
}

export const errorCode = (response: { body: string }): string | undefined =>
  (JSON.parse(response.body) as { error?: { code?: string } }).error?.code;
