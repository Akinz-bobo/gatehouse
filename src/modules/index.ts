import type { FastifyInstance } from 'fastify';
import type { ModuleName } from '../config.js';
import type { Context } from '../core/context.js';
import { abacRoutes } from './abac/routes.js';
import { auditRoutes } from './audit/routes.js';
import { recordAudit } from './audit/service.js';
import { mfaRoutes } from './mfa/routes.js';
import { isTotpEnabled } from './mfa/service.js';
import { oauthRoutes } from './oauth/routes.js';
import { rbacRoutes } from './rbac/routes.js';
import { accessOf } from './rbac/service.js';

/**
 * An optional capability. `setup` wires the module into the core's extension
 * points; `routes` adds its endpoints. A module that is not enabled does
 * neither, so its endpoints do not exist and it adds nothing to sign-in.
 */
export interface Module {
  name: ModuleName;
  setup?(context: Context): void;
  routes(app: FastifyInstance, context: Context): void;
}

export const MODULE_REGISTRY: Record<ModuleName, Module> = {
  rbac: {
    name: 'rbac',
    // Roles and permissions travel inside every access token, so resource
    // servers can authorize without calling back.
    setup: (context) => {
      context.hooks.addClaims((db, user) => accessOf(db, user.id));
    },
    routes: rbacRoutes,
  },
  abac: { name: 'abac', routes: abacRoutes },
  oauth: { name: 'oauth', routes: oauthRoutes },
  mfa: {
    name: 'mfa',
    setup: (context) => {
      context.hooks.addChallenge(async (db, user) =>
        (await isTotpEnabled(db, user.id)) ? { method: 'totp' } : null,
      );
    },
    routes: mfaRoutes,
  },
  audit: {
    name: 'audit',
    setup: (context) => {
      context.hooks.onEvent((event) => recordAudit(context.pool, event));
    },
    routes: auditRoutes,
  },
};
