import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Context } from '../../core/context.js';
import { errors } from '../../core/errors.js';
import { requestPasswordReset, resetPassword } from '../../core/password-reset.js';
import {
  listSessions,
  refreshSession,
  revokeSession,
  revokeUserSessions,
} from '../../core/sessions.js';
import { completeSignIn } from '../../core/sign-in.js';
import {
  checkCredentials,
  createUser,
  setPassword,
  verifyPassword,
  type User,
} from '../../core/users.js';
import { authOf, authenticate, clientOf } from '../authenticate.js';

const email = z.email().max(254);
// Length limits are enforced by the password policy, which gives a clearer error.
const password = z.string().min(1).max(1024);

const credentials = z.strictObject({ email, password });
const refreshBody = z.strictObject({ refreshToken: z.string().min(1).max(512) });
const changeBody = z.strictObject({ currentPassword: password, newPassword: password });
const resetRequestBody = z.strictObject({ email });
const resetBody = z.strictObject({ token: z.string().min(1).max(512), newPassword: password });
const sessionParams = z.strictObject({ id: z.uuid() });

export const serializeUser = (user: User) => ({
  id: user.id,
  email: user.email,
  isSuperuser: user.isSuperuser,
  attributes: user.attributes,
  createdAt: user.createdAt.toISOString(),
});

export function authRoutes(app: FastifyInstance, context: Context): void {
  const { pool, hooks, config } = context;
  const requireAuth = { preHandler: authenticate(context) };
  // Sign-in, registration and reset are the endpoints worth attacking, so
  // they get a much tighter per-IP limit than the rest of the API.
  const strict = {
    config: { rateLimit: { max: config.AUTH_RATE_LIMIT_MAX, timeWindow: '1 minute' } },
  };

  app.post('/auth/register', strict, async (request, reply) => {
    const body = credentials.parse(request.body);
    const user = await createUser(context, body);
    await hooks.emit({
      type: 'user.registered',
      actorId: user.id,
      subjectId: user.id,
      ...clientOf(request),
    });
    return reply.status(201).send({ user: serializeUser(user) });
  });

  app.post('/auth/login', strict, async (request) => {
    const body = credentials.parse(request.body);
    const result = await checkCredentials(context, body.email, body.password);
    if (!result.ok) {
      await hooks.emit({
        type: 'login.failed',
        subjectId: result.userId,
        ...clientOf(request),
        details: { reason: result.reason },
      });
      throw errors.invalidCredentials();
    }
    return completeSignIn(context, result.user, 'password', clientOf(request));
  });

  app.post('/auth/refresh', strict, async (request) => {
    const body = refreshBody.parse(request.body);
    return refreshSession(context, body.refreshToken, clientOf(request));
  });

  app.post('/auth/logout', requireAuth, async (request, reply) => {
    const { user, sessionId } = authOf(request);
    await revokeSession(pool, sessionId, 'logout');
    await hooks.emit({
      type: 'session.revoked',
      actorId: user.id,
      subjectId: sessionId,
      details: { reason: 'logout' },
    });
    return reply.status(204).send();
  });

  app.get('/auth/me', requireAuth, async (request) => {
    const { user } = authOf(request);
    return { user: serializeUser(user), claims: await hooks.claimsFor(pool, user) };
  });

  app.get('/auth/sessions', requireAuth, async (request) => {
    const { user, sessionId } = authOf(request);
    const sessions = await listSessions(pool, user.id);
    return {
      sessions: sessions.map((session) => ({
        id: session.id,
        authMethod: session.authMethod,
        ip: session.ip,
        userAgent: session.userAgent,
        createdAt: session.createdAt.toISOString(),
        lastUsedAt: session.lastUsedAt.toISOString(),
        current: session.id === sessionId,
      })),
    };
  });

  app.delete('/auth/sessions/:id', requireAuth, async (request, reply) => {
    const { user } = authOf(request);
    const { id } = sessionParams.parse(request.params);
    // Scope the lookup to the caller, so one user cannot end another's session.
    const owned = (await listSessions(pool, user.id)).some((session) => session.id === id);
    if (!owned) throw errors.notFound('Session');
    await revokeSession(pool, id, 'revoked_by_user');
    await hooks.emit({
      type: 'session.revoked',
      actorId: user.id,
      subjectId: id,
      details: { reason: 'revoked_by_user' },
    });
    return reply.status(204).send();
  });

  app.post('/auth/password/change', { ...requireAuth, ...strict }, async (request, reply) => {
    const { user, sessionId } = authOf(request);
    const body = changeBody.parse(request.body);
    if (!(await verifyPassword(context, user.id, body.currentPassword))) {
      throw errors.invalidCredentials();
    }
    await setPassword(context, pool, user, body.newPassword);
    // Anyone else signed in with the old password is signed out.
    await revokeUserSessions(pool, user.id, 'password_changed', sessionId);
    await hooks.emit({
      type: 'password.changed',
      actorId: user.id,
      subjectId: user.id,
      ...clientOf(request),
    });
    return reply.status(204).send();
  });

  app.post('/auth/password/reset-request', strict, async (request, reply) => {
    const body = resetRequestBody.parse(request.body);
    await requestPasswordReset(context, body.email);
    // The same answer whether or not the address has an account.
    return reply.status(202).send({ status: 'accepted' });
  });

  app.post('/auth/password/reset', strict, async (request, reply) => {
    const body = resetBody.parse(request.body);
    await resetPassword(context, body.token, body.newPassword);
    return reply.status(204).send();
  });
}
