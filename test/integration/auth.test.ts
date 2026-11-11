import {
  decodeJwt,
  decodeProtectedHeader,
  createLocalJWKSet,
  jwtVerify,
  SignJWT,
  generateKeyPair,
} from 'jose';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  PASSWORD,
  client,
  createTestApp,
  createTestPool,
  errorCode,
  resetDatabase,
  type TestApp,
  type Tokens,
} from './helpers.js';

const pool = createTestPool();
let test: TestApp;
let api: ReturnType<typeof client>;

beforeAll(async () => {
  test = await createTestApp(pool, [], { MAX_FAILED_LOGINS: '3', LOCKOUT_SECONDS: '60' });
  api = client(test.app);
});
beforeEach(() => resetDatabase(pool));
afterAll(async () => {
  await test.app.close();
  await pool.end();
});

describe('registration', () => {
  it('creates an account and never returns the password', async () => {
    const response = await api.register('Ada@Example.com');
    expect(response.statusCode).toBe(201);
    expect(response.json()).toMatchObject({
      user: { email: 'ada@example.com', isSuperuser: false },
    });
    expect(response.body).not.toContain('password');
  });

  it('stores an Argon2id hash, not the password', async () => {
    await api.register('ada@example.com');
    const stored = await pool.query<{ password_hash: string }>('SELECT password_hash FROM users');
    expect(stored.rows[0]?.password_hash).toMatch(/^\$argon2id\$/);
    expect(stored.rows[0]?.password_hash).not.toContain(PASSWORD);
  });

  it('treats emails as case-insensitive', async () => {
    await api.register('ada@example.com');
    const duplicate = await api.register('ADA@example.com');
    expect(duplicate.statusCode).toBe(409);
    expect(errorCode(duplicate)).toBe('email_taken');
  });

  it('rejects a weak password', async () => {
    const response = await api.register('ada@example.com', 'short');
    expect(response.statusCode).toBe(422);
    expect(errorCode(response)).toBe('weak_password');
  });

  it('rejects unknown fields, so nobody can register as a superuser', async () => {
    const response = await api.post('/v1/auth/register', {
      email: 'ada@example.com',
      password: PASSWORD,
      isSuperuser: true,
    });
    expect(response.statusCode).toBe(400);
  });
});

describe('sign-in', () => {
  beforeEach(() => api.register('ada@example.com'));

  it('returns an access token and a refresh token', async () => {
    const response = await api.login('ada@example.com');
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      mfaRequired: false,
      tokenType: 'Bearer',
      expiresIn: 900,
    });
    expect(response.headers['cache-control']).toBe('no-store');
  });

  it('gives the same answer for a wrong password and an unknown email', async () => {
    const wrong = await api.login('ada@example.com', 'not the password at all');
    const unknown = await api.login('nobody@example.com');
    expect(wrong.statusCode).toBe(401);
    expect(unknown.statusCode).toBe(401);
    expect(wrong.body).toBe(unknown.body);
  });

  it('locks the account after repeated failures, even for the right password', async () => {
    for (let attempt = 0; attempt < 3; attempt++)
      await api.login('ada@example.com', 'wrong password here');

    const locked = await api.login('ada@example.com');
    expect(locked.statusCode).toBe(401);
    expect(errorCode(locked)).toBe('invalid_credentials');
  });

  it('unlocks once the lock expires and clears the failure count', async () => {
    for (let attempt = 0; attempt < 3; attempt++)
      await api.login('ada@example.com', 'wrong password here');
    await pool.query(`UPDATE users SET locked_until = now() - interval '1 second'`);

    expect((await api.login('ada@example.com')).statusCode).toBe(200);
    const row = await pool.query<{ failed_logins: number }>('SELECT failed_logins FROM users');
    expect(row.rows[0]?.failed_logins).toBe(0);
  });

  it('refuses a disabled account', async () => {
    await pool.query('UPDATE users SET disabled_at = now()');
    expect((await api.login('ada@example.com')).statusCode).toBe(401);
  });
});

describe('access tokens', () => {
  it('are signed with ES256 and verifiable from the public JWKS alone', async () => {
    const { accessToken, userId } = await api.signUp('ada@example.com');
    const jwks = (await api.get('/.well-known/jwks.json')).json<{
      keys: Record<string, unknown>[];
    }>();

    expect(decodeProtectedHeader(accessToken).alg).toBe('ES256');
    // The published keys must contain no private material.
    for (const key of jwks.keys) expect(key).not.toHaveProperty('d');

    const { payload } = await jwtVerify(accessToken, createLocalJWKSet(jwks as never), {
      issuer: 'http://localhost:4000',
      audience: 'gatehouse',
    });
    expect(payload.sub).toBe(userId);
    expect(payload.sid).toEqual(expect.any(String));
  });

  it('rejects a token signed by someone else, even with a matching key id', async () => {
    const { accessToken } = await api.signUp('ada@example.com');
    const { privateKey } = await generateKeyPair('ES256');
    const forged = await new SignJWT({ ...decodeJwt(accessToken), email: 'admin@example.com' })
      .setProtectedHeader({ alg: 'ES256', kid: decodeProtectedHeader(accessToken).kid ?? '' })
      .sign(privateKey);

    expect((await api.get('/v1/auth/me', forged)).statusCode).toBe(401);
  });

  it('rejects an unsigned token', async () => {
    const { accessToken } = await api.signUp('ada@example.com');
    const [, body] = accessToken.split('.');
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');

    expect((await api.get('/v1/auth/me', `${header}.${body}.`)).statusCode).toBe(401);
  });

  it('rejects requests with no token', async () => {
    const response = await api.get('/v1/auth/me');
    expect(response.statusCode).toBe(401);
    expect(errorCode(response)).toBe('unauthenticated');
  });

  it('stop working the moment the session is signed out', async () => {
    const { accessToken } = await api.signUp('ada@example.com');
    expect((await api.get('/v1/auth/me', accessToken)).statusCode).toBe(200);

    expect((await api.post('/v1/auth/logout', undefined, accessToken)).statusCode).toBe(204);
    expect((await api.get('/v1/auth/me', accessToken)).statusCode).toBe(401);
  });
});

describe('refresh token rotation', () => {
  it('issues a new pair and retires the old refresh token', async () => {
    const first = await api.signUp('ada@example.com');
    const second = (
      await api.post('/v1/auth/refresh', { refreshToken: first.refreshToken })
    ).json<Tokens>();

    expect(second.refreshToken).not.toBe(first.refreshToken);
    expect((await api.get('/v1/auth/me', second.accessToken)).statusCode).toBe(200);
  });

  it('ends the whole session when a used refresh token is presented again', async () => {
    const stolen = await api.signUp('ada@example.com');
    // The real client refreshes; the thief then replays the token it copied.
    const legitimate = (
      await api.post('/v1/auth/refresh', { refreshToken: stolen.refreshToken })
    ).json<Tokens>();
    const replay = await api.post('/v1/auth/refresh', { refreshToken: stolen.refreshToken });

    expect(replay.statusCode).toBe(401);
    expect(errorCode(replay)).toBe('refresh_token_reused');
    // Neither party keeps access: the newer tokens die too.
    expect((await api.get('/v1/auth/me', legitimate.accessToken)).statusCode).toBe(401);
    expect(
      (await api.post('/v1/auth/refresh', { refreshToken: legitimate.refreshToken })).statusCode,
    ).toBe(401);
  });

  it('lets only one of two racing refreshes succeed', async () => {
    const { refreshToken } = await api.signUp('ada@example.com');
    const results = await Promise.all([
      api.post('/v1/auth/refresh', { refreshToken }),
      api.post('/v1/auth/refresh', { refreshToken }),
    ]);
    expect(results.filter((result) => result.statusCode === 200)).toHaveLength(1);
  });

  it('stores only a hash of the refresh token', async () => {
    const { refreshToken } = await api.signUp('ada@example.com');
    const stored = await pool.query<{ token_hash: string }>(
      'SELECT token_hash FROM refresh_tokens',
    );
    expect(stored.rows.map((row) => row.token_hash)).not.toContain(refreshToken);
  });

  it('rejects an expired or made-up refresh token', async () => {
    const { refreshToken } = await api.signUp('ada@example.com');
    await pool.query(`UPDATE refresh_tokens SET expires_at = now() - interval '1 second'`);

    expect(errorCode(await api.post('/v1/auth/refresh', { refreshToken }))).toBe(
      'invalid_refresh_token',
    );
    expect((await api.post('/v1/auth/refresh', { refreshToken: 'made-up' })).statusCode).toBe(401);
  });
});

describe('sessions', () => {
  it("lists a user's sessions and marks the current one", async () => {
    const first = await api.signUp('ada@example.com');
    await api.login('ada@example.com');

    const { sessions } = (await api.get('/v1/auth/sessions', first.accessToken)).json<{
      sessions: { current: boolean; authMethod: string }[];
    }>();
    expect(sessions).toHaveLength(2);
    expect(sessions.filter((session) => session.current)).toHaveLength(1);
    expect(sessions[0]?.authMethod).toBe('password');
  });

  it('lets a user end one of their own sessions', async () => {
    const first = await api.signUp('ada@example.com');
    const second = (await api.login('ada@example.com')).json<Tokens>();
    const sid = decodeJwt(second.accessToken).sid as string;

    expect((await api.delete(`/v1/auth/sessions/${sid}`, first.accessToken)).statusCode).toBe(204);
    expect((await api.get('/v1/auth/me', second.accessToken)).statusCode).toBe(401);
    expect((await api.get('/v1/auth/me', first.accessToken)).statusCode).toBe(200);
  });

  it("does not let a user end someone else's session", async () => {
    const ada = await api.signUp('ada@example.com');
    const eve = await api.signUp('eve@example.com');
    const adaSession = decodeJwt(ada.accessToken).sid as string;

    expect((await api.delete(`/v1/auth/sessions/${adaSession}`, eve.accessToken)).statusCode).toBe(
      404,
    );
    expect((await api.get('/v1/auth/me', ada.accessToken)).statusCode).toBe(200);
  });
});

describe('passwords', () => {
  const NEW_PASSWORD = 'an entirely different passphrase';

  it('changes the password and signs out every other session', async () => {
    const current = await api.signUp('ada@example.com');
    const other = (await api.login('ada@example.com')).json<Tokens>();

    const changed = await api.post(
      '/v1/auth/password/change',
      { currentPassword: PASSWORD, newPassword: NEW_PASSWORD },
      current.accessToken,
    );
    expect(changed.statusCode).toBe(204);
    expect((await api.get('/v1/auth/me', current.accessToken)).statusCode).toBe(200);
    expect((await api.get('/v1/auth/me', other.accessToken)).statusCode).toBe(401);
    expect((await api.login('ada@example.com')).statusCode).toBe(401);
    expect((await api.login('ada@example.com', NEW_PASSWORD)).statusCode).toBe(200);
  });

  it('requires the current password to change it', async () => {
    const { accessToken } = await api.signUp('ada@example.com');
    const response = await api.post(
      '/v1/auth/password/change',
      { currentPassword: 'a wrong current password', newPassword: NEW_PASSWORD },
      accessToken,
    );
    expect(response.statusCode).toBe(401);
  });

  it('answers a reset request identically for known and unknown emails', async () => {
    await api.register('ada@example.com');
    const known = await api.post('/v1/auth/password/reset-request', { email: 'ada@example.com' });
    const unknown = await api.post('/v1/auth/password/reset-request', {
      email: 'nobody@example.com',
    });

    expect(known.statusCode).toBe(202);
    expect(unknown.body).toBe(known.body);
    expect(test.sentResets.has('nobody@example.com')).toBe(false);
  });

  it('resets the password with a one-time token and ends every session', async () => {
    const { accessToken } = await api.signUp('ada@example.com');
    await api.post('/v1/auth/password/reset-request', { email: 'ada@example.com' });
    const token = test.sentResets.get('ada@example.com') ?? '';

    expect(
      (await api.post('/v1/auth/password/reset', { token, newPassword: NEW_PASSWORD })).statusCode,
    ).toBe(204);
    expect((await api.get('/v1/auth/me', accessToken)).statusCode).toBe(401);
    expect((await api.login('ada@example.com', NEW_PASSWORD)).statusCode).toBe(200);

    const again = await api.post('/v1/auth/password/reset', {
      token,
      newPassword: 'yet another passphrase 9',
    });
    expect(again.statusCode).toBe(400);
    expect(errorCode(again)).toBe('invalid_token');
  });

  it('rejects an expired reset token', async () => {
    await api.register('ada@example.com');
    await api.post('/v1/auth/password/reset-request', { email: 'ada@example.com' });
    await pool.query(`UPDATE password_resets SET expires_at = now() - interval '1 second'`);

    const response = await api.post('/v1/auth/password/reset', {
      token: test.sentResets.get('ada@example.com'),
      newPassword: NEW_PASSWORD,
    });
    expect(response.statusCode).toBe(400);
  });
});

describe('signing key rotation', () => {
  it('keeps old tokens valid, signs new ones with the new key, and needs a superuser', async () => {
    const user = await api.signUp('ada@example.com');
    expect((await api.post('/v1/admin/keys/rotate', undefined, user.accessToken)).statusCode).toBe(
      403,
    );

    const admin = await api.signUpAdmin(pool);
    const rotated = await api.post('/v1/admin/keys/rotate', undefined, admin.accessToken);
    expect(rotated.statusCode).toBe(200);
    const { kid } = rotated.json<{ kid: string }>();

    // A token signed before the rotation still verifies.
    expect((await api.get('/v1/auth/me', user.accessToken)).statusCode).toBe(200);
    // New tokens carry the new key id, and both keys are published.
    const fresh = (await api.login('ada@example.com')).json<Tokens>();
    expect(decodeProtectedHeader(fresh.accessToken).kid).toBe(kid);
    const jwks = (await api.get('/.well-known/jwks.json')).json<{ keys: { kid: string }[] }>();
    expect(jwks.keys.map((key) => key.kid)).toEqual(
      expect.arrayContaining([kid, decodeProtectedHeader(user.accessToken).kid]),
    );
  });

  it('stores private keys encrypted', async () => {
    await api.signUp('ada@example.com');
    const rows = await pool.query<{ private_jwk_encrypted: string }>(
      'SELECT private_jwk_encrypted FROM signing_keys',
    );
    for (const row of rows.rows) {
      expect(row.private_jwk_encrypted).toMatch(/^v1\./);
      expect(row.private_jwk_encrypted).not.toContain('"d"');
    }
  });
});

describe('with no modules enabled', () => {
  it('does not expose module routes', async () => {
    const { accessToken } = await api.signUpAdmin(pool);
    for (const url of [
      '/v1/roles',
      '/v1/policies',
      '/v1/audit',
      '/v1/mfa',
      '/v1/oauth/providers',
    ]) {
      expect((await api.get(url, accessToken)).statusCode).toBe(404);
    }
  });

  it('puts no role claims in the token', async () => {
    const { accessToken } = await api.signUp('ada@example.com');
    expect(decodeJwt(accessToken)).not.toHaveProperty('roles');
  });
});
