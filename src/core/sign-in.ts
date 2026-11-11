import type { Context } from './context.js';
import { errors } from './errors.js';
import { startSession, type ClientInfo, type TokenPair } from './sessions.js';
import { findUserById, type User } from './users.js';

const MFA_TOKEN_TTL_SECONDS = 5 * 60;

export type SignInResult =
  ({ mfaRequired: false } & TokenPair) | { mfaRequired: true; mfaToken: string; methods: string[] };

const mfaAudience = (context: Context) => `${context.config.AUDIENCE}:mfa`;

/**
 * The last step of every sign-in, whatever proved the user's identity. If a
 * module demands a second factor, no session is created yet: the caller gets
 * a short-lived token that is good for one thing only, finishing the
 * challenge. Otherwise the session starts.
 */
export async function completeSignIn(
  context: Context,
  user: User,
  method: string,
  client: ClientInfo,
): Promise<SignInResult> {
  const challenges = await context.hooks.challengesFor(context.pool, user);
  if (challenges.length > 0) {
    const mfaToken = await context.keys.sign(
      { method },
      { subject: user.id, audience: mfaAudience(context), ttlSeconds: MFA_TOKEN_TTL_SECONDS },
    );
    return {
      mfaRequired: true,
      mfaToken,
      methods: challenges.map((challenge) => challenge.method),
    };
  }

  const { sessionId, ...tokens } = await startSession(context, user, method, client);
  await context.hooks.emit({
    type: 'login.succeeded',
    actorId: user.id,
    subjectId: sessionId,
    ...client,
    details: { method },
  });
  return { mfaRequired: false, ...tokens };
}

/**
 * Reads an MFA token. Its audience differs from an access token's, so it is
 * rejected everywhere else, and an access token is rejected here.
 */
export async function readMfaToken(
  context: Context,
  token: string,
): Promise<{ user: User; method: string }> {
  try {
    const payload = await context.keys.verify(token, mfaAudience(context));
    const user = payload.sub ? await findUserById(context.pool, payload.sub) : null;
    if (!user || user.disabled || typeof payload.method !== 'string') throw new Error('unusable');
    return { user, method: payload.method };
  } catch {
    throw errors.invalidToken('MFA token');
  }
}
