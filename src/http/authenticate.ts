import type { FastifyRequest } from 'fastify';
import type { Context } from '../core/context.js';
import { errors } from '../core/errors.js';
import { isSessionActive, type ClientInfo } from '../core/sessions.js';
import { findUserById, type User } from '../core/users.js';
import { hasPermission } from '../modules/rbac/permissions.js';
import { accessOf } from '../modules/rbac/service.js';

export interface AuthInfo {
  user: User;
  sessionId: string;
}

declare module 'fastify' {
  interface FastifyRequest {
    auth?: AuthInfo;
  }
}

export function clientOf(request: FastifyRequest): ClientInfo {
  return { ip: request.ip, userAgent: request.headers['user-agent'] };
}

/** The signed-in user, for handlers behind `authenticate`. */
export function authOf(request: FastifyRequest): AuthInfo {
  if (!request.auth) throw errors.unauthenticated();
  return request.auth;
}

/**
 * Requires a valid access token. Beyond the signature and expiry, this checks
 * that the session behind the token is still alive, so signing out, a
 * password change or a detected token theft takes effect here at once
 * instead of when the token expires.
 */
export function authenticate(context: Context) {
  return async (request: FastifyRequest): Promise<void> => {
    const header = request.headers.authorization;
    const token = header?.startsWith('Bearer ') ? header.slice(7) : undefined;
    if (!token) throw errors.unauthenticated();

    let subject: string | undefined;
    let sessionId: unknown;
    try {
      const payload = await context.keys.verify(token);
      subject = payload.sub;
      sessionId = payload.sid;
    } catch {
      throw errors.unauthenticated();
    }
    if (!subject || typeof sessionId !== 'string') throw errors.unauthenticated();
    if (!(await isSessionActive(context.pool, sessionId, subject))) throw errors.unauthenticated();

    const user = await findUserById(context.pool, subject);
    if (!user || user.disabled) throw errors.unauthenticated();
    request.auth = { user, sessionId };
  };
}

/**
 * Requires an administrative permission. Superusers always pass. With the
 * rbac module on, so does anyone whose roles grant the permission, read
 * fresh from the database and not from the token, so a revoked role stops
 * working immediately.
 */
export function requirePermission(context: Context, permission: string) {
  return async (request: FastifyRequest): Promise<void> => {
    const { user } = authOf(request);
    if (user.isSuperuser) return;
    if (context.enabled.has('rbac')) {
      const { permissions } = await accessOf(context.pool, user.id);
      if (hasPermission(permissions, permission)) return;
    }
    throw errors.forbidden(permission);
  };
}
