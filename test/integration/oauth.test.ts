import { createHash } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  client,
  createTestApp,
  createTestPool,
  errorCode,
  resetDatabase,
  type TestApp,
  type Tokens,
} from './helpers.js';

const REDIRECT = 'https://app.example.com/auth/callback';
const pool = createTestPool();
let test: TestApp;
let api: ReturnType<typeof client>;
let provider: Server;

/** What the fake provider will say about whoever signs in next. */
let profile: Record<string, unknown>;
/** The PKCE challenge the provider was shown, to check the verifier against. */
let challenge: string | null;
let tokenRequests: URLSearchParams[];

/**
 * A stand-in identity provider with a token and a userinfo endpoint. Like a
 * real one, it refuses a code whose PKCE verifier does not match the
 * challenge from the authorization request.
 */
function startProvider(): Promise<Server> {
  const server = createServer((request, response) => {
    const send = (status: number, body: unknown) => {
      response.writeHead(status, { 'content-type': 'application/json' });
      response.end(JSON.stringify(body));
    };
    if (request.url === '/token') {
      let raw = '';
      request.on('data', (chunk: Buffer) => (raw += chunk.toString()));
      request.on('end', () => {
        const form = new URLSearchParams(raw);
        tokenRequests.push(form);
        const verifier = form.get('code_verifier') ?? '';
        const matches = createHash('sha256').update(verifier).digest('base64url') === challenge;
        if (form.get('code') !== 'good-code' || !matches) {
          send(400, { error: 'invalid_grant' });
          return;
        }
        send(200, { access_token: 'provider-access-token', token_type: 'Bearer' });
      });
      return;
    }
    if (request.url === '/userinfo') {
      if (request.headers.authorization !== 'Bearer provider-access-token') {
        send(401, {});
        return;
      }
      send(200, profile);
      return;
    }
    send(404, {});
  });
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () => {
      resolve(server);
    }),
  );
}

beforeAll(async () => {
  provider = await startProvider();
  const base = `http://127.0.0.1:${(provider.address() as AddressInfo).port}`;
  test = await createTestApp(pool, ['oauth'], {
    OAUTH_REDIRECT_ALLOWLIST: REDIRECT,
    OAUTH_PROVIDERS: JSON.stringify([
      {
        id: 'acme',
        clientId: 'client-id',
        clientSecret: 'client-secret',
        authorizationUrl: `${base}/authorize`,
        tokenUrl: `${base}/token`,
        userInfoUrl: `${base}/userinfo`,
      },
    ]),
  });
  api = client(test.app);
});
beforeEach(async () => {
  await resetDatabase(pool);
  profile = { sub: 'acme-user-1', email: 'Ada@Example.com', email_verified: true };
  challenge = null;
  tokenRequests = [];
});
afterAll(async () => {
  await test.app.close();
  await new Promise((resolve) => provider.close(resolve));
  await pool.end();
});

/** Starts a sign-in and returns the state the provider would hand back. */
async function start(): Promise<string> {
  const response = await api.get(
    `/v1/oauth/acme/start?redirect_uri=${encodeURIComponent(REDIRECT)}`,
  );
  expect(response.statusCode).toBe(302);
  const url = new URL(response.headers.location as string);
  challenge = url.searchParams.get('code_challenge');
  return url.searchParams.get('state') ?? '';
}

/** Plays the provider redirecting the browser back, and returns where the service sends it next. */
async function callback(state: string, query = 'code=good-code'): Promise<URL> {
  const response = await api.get(`/v1/oauth/acme/callback?${query}&state=${state}`);
  expect(response.statusCode).toBe(302);
  return new URL(response.headers.location as string);
}

const exchange = (code: string | null) => api.post('/v1/oauth/exchange', { code: code ?? '' });

/** The whole flow: returns the final redirect. */
const signIn = async () => callback(await start());

describe('starting a sign-in', () => {
  it('lists the configured providers without their secrets', async () => {
    const response = await api.get('/v1/oauth/providers');
    expect(response.json()).toEqual({ providers: ['acme'] });
    expect(response.body).not.toContain('client-secret');
  });

  it('redirects to the provider with state and a PKCE challenge, and no secret', async () => {
    const response = await api.get(
      `/v1/oauth/acme/start?redirect_uri=${encodeURIComponent(REDIRECT)}`,
    );
    const url = new URL(response.headers.location as string);

    expect(url.pathname).toBe('/authorize');
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('state')?.length).toBeGreaterThan(20);
    expect(url.searchParams.get('redirect_uri')).toBe(
      'http://localhost:4000/v1/oauth/acme/callback',
    );
    expect(url.search).not.toContain('client-secret');
  });

  it('refuses a redirect_uri that is not on the allow-list', async () => {
    const evil = encodeURIComponent('https://evil.example.com/steal');
    const response = await api.get(`/v1/oauth/acme/start?redirect_uri=${evil}`);
    expect(response.statusCode).toBe(422);
    expect(errorCode(response)).toBe('redirect_not_allowed');
  });

  it('answers 404 for an unknown provider', async () => {
    const response = await api.get(
      `/v1/oauth/nope/start?redirect_uri=${encodeURIComponent(REDIRECT)}`,
    );
    expect(response.statusCode).toBe(404);
  });
});

describe('completing a sign-in', () => {
  it('creates an account, and hands tokens over only through a one-time code', async () => {
    const redirect = await signIn();
    expect(redirect.origin + redirect.pathname).toBe(REDIRECT);
    // Tokens never travel in a URL.
    expect(redirect.search).not.toContain('eyJ');

    const response = await exchange(redirect.searchParams.get('code'));
    expect(response.statusCode).toBe(200);
    const tokens = response.json<Tokens>();
    const me = (await api.get('/v1/auth/me', tokens.accessToken)).json<{
      user: { email: string };
    }>();
    expect(me.user.email).toBe('ada@example.com');

    expect((await exchange(redirect.searchParams.get('code'))).statusCode).toBe(400);
  });

  it('sends the PKCE verifier and client secret to the token endpoint only', async () => {
    await signIn();
    expect(tokenRequests).toHaveLength(1);
    expect(tokenRequests[0]?.get('client_secret')).toBe('client-secret');
    expect(tokenRequests[0]?.get('code_verifier')?.length).toBeGreaterThan(40);
  });

  it('signs the same person into the same account next time', async () => {
    const first = (await exchange((await signIn()).searchParams.get('code'))).json<Tokens>();
    const second = (await exchange((await signIn()).searchParams.get('code'))).json<Tokens>();
    const idOf = async (tokens: Tokens) =>
      (await api.get('/v1/auth/me', tokens.accessToken)).json<{ user: { id: string } }>().user.id;

    expect(await idOf(second)).toBe(await idOf(first));
    const users = await pool.query('SELECT 1 FROM users');
    expect(users.rowCount).toBe(1);
  });

  it('accepts a state once only', async () => {
    const state = await start();
    await callback(state);
    const replay = await api.get(`/v1/oauth/acme/callback?code=good-code&state=${state}`);
    expect(replay.statusCode).toBe(400);
  });

  it('rejects a callback whose state it did not issue', async () => {
    await start();
    const forged = await api.get('/v1/oauth/acme/callback?code=good-code&state=made-up');
    expect(forged.statusCode).toBe(400);
    expect(errorCode(forged)).toBe('invalid_token');
  });

  it('rejects an expired state', async () => {
    const state = await start();
    await pool.query(`UPDATE oauth_states SET expires_at = now() - interval '1 second'`);
    const late = await api.get(`/v1/oauth/acme/callback?code=good-code&state=${state}`);
    expect(late.statusCode).toBe(400);
  });

  it('reports a refusal at the provider back to the client', async () => {
    const redirect = await callback(await start(), 'error=access_denied');
    expect(redirect.searchParams.get('error')).toBe('access_denied');
    expect(redirect.searchParams.has('code')).toBe(false);
  });

  it('reports a provider that rejects the code', async () => {
    const redirect = await callback(await start(), 'code=bad-code');
    expect(redirect.searchParams.get('error')).toBe('provider_error');
  });

  it('does not create an account from an unverified email', async () => {
    profile = { sub: 'acme-user-2', email: 'victim@example.com', email_verified: false };
    const redirect = await signIn();
    expect(redirect.searchParams.get('error')).toBe('email_not_verified');
    expect((await pool.query('SELECT 1 FROM users')).rowCount).toBe(0);
  });
});

describe('existing accounts', () => {
  it('never takes over a local account that has the same email', async () => {
    await api.register('ada@example.com');
    const redirect = await signIn();

    expect(redirect.searchParams.get('error')).toBe('account_exists');
    expect(redirect.searchParams.has('code')).toBe(false);
    expect((await pool.query('SELECT 1 FROM oauth_identities')).rowCount).toBe(0);
  });

  it('links a provider when the signed-in user asks, then signs in through it', async () => {
    const local = await api.signUp('ada@example.com');
    const link = await api.post(
      '/v1/oauth/acme/link',
      { redirect_uri: REDIRECT },
      local.accessToken,
    );
    expect(link.statusCode).toBe(200);
    const url = new URL(link.json<{ url: string }>().url);
    challenge = url.searchParams.get('code_challenge');
    await callback(url.searchParams.get('state') ?? '');

    const tokens = (await exchange((await signIn()).searchParams.get('code'))).json<Tokens>();
    const me = (await api.get('/v1/auth/me', tokens.accessToken)).json<{ user: { id: string } }>();
    expect(me.user.id).toBe(local.userId);
  });

  it('requires a signed-in user to link', async () => {
    const response = await api.post('/v1/oauth/acme/link', { redirect_uri: REDIRECT });
    expect(response.statusCode).toBe(401);
  });

  it('does not let a second user claim an identity that is already linked', async () => {
    await signIn();
    const other = await api.signUp('eve@example.com');
    const link = await api.post(
      '/v1/oauth/acme/link',
      { redirect_uri: REDIRECT },
      other.accessToken,
    );
    const url = new URL(link.json<{ url: string }>().url);
    challenge = url.searchParams.get('code_challenge');

    const redirect = await callback(url.searchParams.get('state') ?? '');
    expect(redirect.searchParams.get('error')).toBe('identity_in_use');
  });

  it('refuses a disabled account', async () => {
    await signIn();
    await pool.query('UPDATE users SET disabled_at = now()');
    const redirect = await signIn();
    expect(redirect.searchParams.has('code')).toBe(false);
  });
});
