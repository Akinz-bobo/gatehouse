import { createHash } from 'node:crypto';
import type { OAuthProviderConfig } from '../../config.js';
import type { Context } from '../../core/context.js';
import { errors } from '../../core/errors.js';
import {
  createUser,
  findUserByEmail,
  findUserById,
  normalizeEmail,
  type User,
} from '../../core/users.js';
import { hashToken, randomToken } from '../../crypto/tokens.js';
import { withTransaction } from '../../db/pool.js';

const STATE_TTL_SECONDS = 10 * 60;
const EXCHANGE_CODE_TTL_SECONDS = 60;
const PROVIDER_TIMEOUT_MS = 10_000;

function providerOf(context: Context, id: string): OAuthProviderConfig {
  const provider = context.config.OAUTH_PROVIDERS.find((candidate) => candidate.id === id);
  if (!provider) throw errors.notFound('OAuth provider');
  return provider;
}

const callbackUrl = (context: Context, providerId: string) =>
  `${context.config.ISSUER.replace(/\/$/, '')}/v1/oauth/${providerId}/callback`;

/**
 * Starts a sign-in with an external provider and returns the URL to send the
 * browser to.
 *
 *  - `state` ties the callback to this attempt, which stops an attacker from
 *    feeding a victim's browser a login the attacker started (login CSRF).
 *  - PKCE ties the authorization code to this service: a code intercepted on
 *    its way back is useless without the verifier kept here.
 *  - `redirectUri` must be on the allow-list, so the flow cannot be used to
 *    bounce a user, and their one-time code, to an attacker's site.
 */
export async function startOAuth(
  context: Context,
  providerId: string,
  redirectUri: string,
  linkUserId?: string,
): Promise<string> {
  const provider = providerOf(context, providerId);
  if (!context.config.OAUTH_REDIRECT_ALLOWLIST.includes(redirectUri)) {
    throw errors.invalid('redirect_not_allowed', 'That redirect_uri is not on the allow-list');
  }

  const state = randomToken();
  const verifier = randomToken(48);
  await context.pool.query(
    `INSERT INTO oauth_states (state_hash, provider, code_verifier, redirect_uri, link_user_id, expires_at)
     VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))`,
    [hashToken(state), provider.id, verifier, redirectUri, linkUserId ?? null, STATE_TTL_SECONDS],
  );

  const url = new URL(provider.authorizationUrl);
  url.search = new URLSearchParams({
    response_type: 'code',
    client_id: provider.clientId,
    redirect_uri: callbackUrl(context, provider.id),
    scope: provider.scopes.join(' '),
    state,
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
  }).toString();
  return url.toString();
}

interface ProviderProfile {
  subject: string;
  email: string | null;
  emailVerified: boolean;
}

async function fetchProfile(
  context: Context,
  provider: OAuthProviderConfig,
  code: string,
  verifier: string,
): Promise<ProviderProfile> {
  const signal = () => AbortSignal.timeout(PROVIDER_TIMEOUT_MS);
  const tokenResponse = await fetch(provider.tokenUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: callbackUrl(context, provider.id),
      client_id: provider.clientId,
      client_secret: provider.clientSecret,
      code_verifier: verifier,
    }),
    signal: signal(),
  });
  if (!tokenResponse.ok) throw new Error(`token endpoint answered ${tokenResponse.status}`);
  const token = (await tokenResponse.json()) as { access_token?: unknown };
  if (typeof token.access_token !== 'string') throw new Error('no access token in response');

  const profileResponse = await fetch(provider.userInfoUrl, {
    headers: { authorization: `Bearer ${token.access_token}`, accept: 'application/json' },
    signal: signal(),
  });
  if (!profileResponse.ok) throw new Error(`userinfo endpoint answered ${profileResponse.status}`);
  const profile = (await profileResponse.json()) as Record<string, unknown>;

  // OpenID Connect providers use `sub`; some older OAuth providers use `id`.
  const subject = profile.sub ?? profile.id;
  if (typeof subject !== 'string' && typeof subject !== 'number') {
    throw new Error('no subject in profile');
  }
  return {
    subject: String(subject),
    email: typeof profile.email === 'string' ? normalizeEmail(profile.email) : null,
    emailVerified: profile.email_verified === true,
  };
}

/**
 * Finds or creates the local account for a provider profile.
 *
 * An existing local account is never taken over just because a provider
 * reports the same email. Auto-linking on email would let an attacker who
 * registered someone's address first gain access to that person's later
 * provider sign-in, and the reverse. Linking only happens when a signed-in
 * user asks for it.
 */
async function resolveUser(
  context: Context,
  providerId: string,
  profile: ProviderProfile,
  linkUserId: string | null,
): Promise<User> {
  return withTransaction(context.pool, async (tx) => {
    const known = await tx.query<{ user_id: string }>(
      'SELECT user_id FROM oauth_identities WHERE provider = $1 AND subject = $2',
      [providerId, profile.subject],
    );
    const knownUserId = known.rows[0]?.user_id;
    const link = (userId: string) =>
      tx.query(
        `INSERT INTO oauth_identities (provider, subject, user_id, email) VALUES ($1, $2, $3, $4)`,
        [providerId, profile.subject, userId, profile.email],
      );

    if (linkUserId) {
      if (knownUserId && knownUserId !== linkUserId) {
        throw errors.conflict('identity_in_use', 'That account is linked to a different user');
      }
      if (!knownUserId) await link(linkUserId);
      const user = await findUserById(tx, linkUserId);
      if (!user) throw errors.notFound('User');
      return user;
    }

    if (knownUserId) {
      const user = await findUserById(tx, knownUserId);
      if (!user || user.disabled) throw errors.invalidCredentials();
      return user;
    }

    if (!profile.email || !profile.emailVerified) {
      throw errors.invalid('email_not_verified', 'The provider did not confirm an email address');
    }
    if (await findUserByEmail(tx, profile.email)) {
      throw errors.conflict(
        'account_exists',
        'An account with this email exists. Sign in to it and link this provider',
      );
    }
    const user = await createUser(context, { email: profile.email }, tx);
    await link(user.id);
    return user;
  });
}

/**
 * Handles the provider's callback and returns where to send the browser:
 * back to the client with a one-time code, or with an error. Tokens are not
 * put in the URL, where they would land in history and server logs.
 */
export async function completeOAuth(
  context: Context,
  providerId: string,
  query: { code?: string | undefined; state?: string | undefined; error?: string | undefined },
): Promise<string> {
  const provider = providerOf(context, providerId);

  // Deleting the state makes it single-use, even under a race.
  const claimed = await context.pool.query<{
    code_verifier: string;
    redirect_uri: string;
    link_user_id: string | null;
  }>(
    `DELETE FROM oauth_states
     WHERE state_hash = $1 AND provider = $2 AND expires_at > now()
     RETURNING code_verifier, redirect_uri, link_user_id`,
    [hashToken(query.state ?? ''), provider.id],
  );
  const state = claimed.rows[0];
  if (!state) throw errors.invalidToken('OAuth state');

  const redirect = new URL(state.redirect_uri);
  const fail = (code: string) => {
    redirect.searchParams.set('error', code);
    return redirect.toString();
  };
  if (query.error || !query.code) return fail('access_denied');

  let profile: ProviderProfile;
  try {
    profile = await fetchProfile(context, provider, query.code, state.code_verifier);
  } catch {
    return fail('provider_error');
  }

  let user: User;
  try {
    user = await resolveUser(context, provider.id, profile, state.link_user_id);
  } catch (error) {
    return fail((error as { code?: string }).code ?? 'sign_in_failed');
  }

  const code = randomToken();
  await context.pool.query(
    `INSERT INTO oauth_exchange_codes (code_hash, user_id, provider, expires_at)
     VALUES ($1, $2, $3, now() + make_interval(secs => $4))`,
    [hashToken(code), user.id, provider.id, EXCHANGE_CODE_TTL_SECONDS],
  );
  redirect.searchParams.set('code', code);
  return redirect.toString();
}

/** Spends a one-time code from the callback and returns the user it was issued for. */
export async function redeemExchangeCode(
  context: Context,
  code: string,
): Promise<{ user: User; provider: string }> {
  const spent = await context.pool.query<{ user_id: string; provider: string }>(
    `DELETE FROM oauth_exchange_codes
     WHERE code_hash = $1 AND expires_at > now()
     RETURNING user_id, provider`,
    [hashToken(code)],
  );
  const row = spent.rows[0];
  const user = row ? await findUserById(context.pool, row.user_id) : null;
  if (!row || !user || user.disabled) throw errors.invalidToken('code');
  return { user, provider: row.provider };
}
