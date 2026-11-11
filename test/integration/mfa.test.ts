import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { codeForStep, stepAt } from '../../src/crypto/totp.js';
import {
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
let user: Tokens & { userId: string };

interface Challenge {
  mfaRequired: boolean;
  mfaToken: string;
  methods: string[];
}

beforeAll(async () => {
  test = await createTestApp(pool, ['mfa']);
  api = client(test.app);
});
beforeEach(async () => {
  await resetDatabase(pool);
  user = await api.signUp('ada@example.com');
});
afterAll(async () => {
  await test.app.close();
  await pool.end();
});

/** The code an authenticator app would show now, or `offset` steps from now. */
const codeNow = (secret: string, offset = 0n) => codeForStep(secret, stepAt(new Date()) + offset);

/** Turns two-factor on and returns the secret and recovery codes. */
async function enable(): Promise<{ secret: string; recoveryCodes: string[] }> {
  const { secret } = (await api.post('/v1/mfa/totp/enroll', undefined, user.accessToken)).json<{
    secret: string;
  }>();
  const confirmed = await api.post(
    '/v1/mfa/totp/confirm',
    { code: codeNow(secret) },
    user.accessToken,
  );
  return { secret, recoveryCodes: confirmed.json<{ recoveryCodes: string[] }>().recoveryCodes };
}

describe('enrolment', () => {
  it('returns a secret and an otpauth URI, and enforces nothing until confirmed', async () => {
    const enrolled = (await api.post('/v1/mfa/totp/enroll', undefined, user.accessToken)).json<{
      secret: string;
      uri: string;
    }>();
    expect(enrolled.uri).toMatch(/^otpauth:\/\/totp\//);

    expect((await api.get('/v1/mfa', user.accessToken)).json()).toEqual({ totp: false });
    expect((await api.login('ada@example.com')).json()).toMatchObject({ mfaRequired: false });
  });

  it('rejects a wrong confirmation code', async () => {
    await api.post('/v1/mfa/totp/enroll', undefined, user.accessToken);
    const response = await api.post('/v1/mfa/totp/confirm', { code: '000000' }, user.accessToken);
    expect(response.statusCode).toBe(422);
    expect(errorCode(response)).toBe('invalid_mfa_code');
  });

  it('issues ten recovery codes on confirmation and stores the secret encrypted', async () => {
    const { secret, recoveryCodes } = await enable();
    expect(new Set(recoveryCodes).size).toBe(10);

    const stored = await pool.query<{ secret_encrypted: string }>(
      'SELECT secret_encrypted FROM mfa_totp',
    );
    expect(stored.rows[0]?.secret_encrypted).toMatch(/^v1\./);
    expect(stored.rows[0]?.secret_encrypted).not.toContain(secret);
    const codes = await pool.query<{ code_hash: string }>(
      'SELECT code_hash FROM mfa_recovery_codes',
    );
    expect(codes.rows.map((row) => row.code_hash)).not.toContain(recoveryCodes[0]);
  });

  it('refuses a second enrolment while enabled', async () => {
    await enable();
    const again = await api.post('/v1/mfa/totp/enroll', undefined, user.accessToken);
    expect(again.statusCode).toBe(409);
  });
});

describe('sign-in with two-factor enabled', () => {
  let secret: string;
  let recoveryCodes: string[];
  let challenge: Challenge;

  beforeEach(async () => {
    ({ secret, recoveryCodes } = await enable());
    challenge = (await api.login('ada@example.com')).json<Challenge>();
  });

  it('issues no session after the password alone', () => {
    expect(challenge).toMatchObject({ mfaRequired: true, methods: ['totp'] });
    expect(challenge).not.toHaveProperty('accessToken');
    expect(challenge).not.toHaveProperty('refreshToken');
  });

  it('does not accept the MFA token as an access token', async () => {
    expect((await api.get('/v1/auth/me', challenge.mfaToken)).statusCode).toBe(401);
  });

  it('does not accept an access token as an MFA token', async () => {
    const response = await api.post('/v1/auth/mfa/verify', {
      mfaToken: user.accessToken,
      code: codeNow(secret, 1n),
    });
    expect(response.statusCode).toBe(400);
    expect(errorCode(response)).toBe('invalid_token');
  });

  it('completes sign-in with a valid code', async () => {
    const response = await api.post('/v1/auth/mfa/verify', {
      mfaToken: challenge.mfaToken,
      code: codeNow(secret, 1n),
    });
    expect(response.statusCode).toBe(200);
    const tokens = response.json<Tokens>();
    expect((await api.get('/v1/auth/me', tokens.accessToken)).statusCode).toBe(200);

    const { sessions } = (await api.get('/v1/auth/sessions', tokens.accessToken)).json<{
      sessions: { current: boolean; authMethod: string }[];
    }>();
    expect(sessions.find((session) => session.current)?.authMethod).toBe('password+totp');
  });

  it('rejects a wrong code', async () => {
    const response = await api.post('/v1/auth/mfa/verify', {
      mfaToken: challenge.mfaToken,
      code: '000000',
    });
    expect(response.statusCode).toBe(422);
    expect(errorCode(response)).toBe('invalid_mfa_code');
  });

  it('accepts each code once, so a code seen over the shoulder cannot be replayed', async () => {
    const code = codeNow(secret, 1n);
    const body = { mfaToken: challenge.mfaToken, code };
    expect((await api.post('/v1/auth/mfa/verify', body)).statusCode).toBe(200);
    expect((await api.post('/v1/auth/mfa/verify', body)).statusCode).toBe(422);
  });

  it('accepts a recovery code once', async () => {
    const body = { mfaToken: challenge.mfaToken, recoveryCode: recoveryCodes[0] };
    const first = await api.post('/v1/auth/mfa/verify', body);
    expect(first.statusCode).toBe(200);
    expect((await api.post('/v1/auth/mfa/verify', body)).statusCode).toBe(422);
  });

  it('requires exactly one of code and recovery code', async () => {
    const both = await api.post('/v1/auth/mfa/verify', {
      mfaToken: challenge.mfaToken,
      code: codeNow(secret, 1n),
      recoveryCode: recoveryCodes[0],
    });
    const neither = await api.post('/v1/auth/mfa/verify', { mfaToken: challenge.mfaToken });
    expect(both.statusCode).toBe(400);
    expect(neither.statusCode).toBe(400);
  });

  it('can be turned off with a valid code, after which the password is enough', async () => {
    const wrong = await api.post('/v1/mfa/totp/disable', { code: '000000' }, user.accessToken);
    expect(wrong.statusCode).toBe(422);

    const disabled = await api.post(
      '/v1/mfa/totp/disable',
      { code: codeNow(secret, 1n) },
      user.accessToken,
    );
    expect(disabled.statusCode).toBe(204);
    expect((await api.login('ada@example.com')).json()).toMatchObject({ mfaRequired: false });
  });
});
