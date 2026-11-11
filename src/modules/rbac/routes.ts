import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Context } from '../../core/context.js';
import { authOf, authenticate, requirePermission } from '../../http/authenticate.js';
import { PERMISSION_PATTERN, hasPermission } from './permissions.js';
import { accessOf, assignRole, deleteRole, listRoles, putRole, removeRole } from './service.js';

const roleName = z
  .string()
  .regex(/^[a-z][a-z0-9_-]*$/)
  .max(64);
const permission = z.string().max(128).regex(PERMISSION_PATTERN, 'use a form like invoices:read');
const roleBody = z.strictObject({
  description: z.string().max(500).nullable().default(null),
  permissions: z.array(permission).max(200),
});
const roleParams = z.strictObject({ name: roleName });
const userRoleParams = z.strictObject({ userId: z.uuid(), name: roleName });
const userParams = z.strictObject({ userId: z.uuid() });
const checkBody = z.strictObject({ permission: permission });

export function rbacRoutes(app: FastifyInstance, context: Context): void {
  const { pool, hooks } = context;
  const requireAuth = { preHandler: authenticate(context) };
  const manage = {
    preHandler: [authenticate(context), requirePermission(context, 'auth:roles:manage')],
  };

  app.get('/roles', manage, async () => ({ roles: await listRoles(pool) }));

  app.put('/roles/:name', manage, async (request) => {
    const { name } = roleParams.parse(request.params);
    const body = roleBody.parse(request.body);
    const role = await putRole(pool, { name, ...body });
    await hooks.emit({
      type: 'role.saved',
      actorId: authOf(request).user.id,
      subjectId: name,
      details: { permissions: role.permissions },
    });
    return role;
  });

  app.delete('/roles/:name', manage, async (request, reply) => {
    const { name } = roleParams.parse(request.params);
    await deleteRole(pool, name);
    await hooks.emit({ type: 'role.deleted', actorId: authOf(request).user.id, subjectId: name });
    return reply.status(204).send();
  });

  app.get('/users/:userId/roles', manage, async (request) => {
    const { userId } = userParams.parse(request.params);
    return accessOf(pool, userId);
  });

  app.put('/users/:userId/roles/:name', manage, async (request, reply) => {
    const { userId, name } = userRoleParams.parse(request.params);
    await assignRole(pool, userId, name);
    await hooks.emit({
      type: 'role.assigned',
      actorId: authOf(request).user.id,
      subjectId: userId,
      details: { role: name },
    });
    return reply.status(204).send();
  });

  app.delete('/users/:userId/roles/:name', manage, async (request, reply) => {
    const { userId, name } = userRoleParams.parse(request.params);
    await removeRole(pool, userId, name);
    await hooks.emit({
      type: 'role.removed',
      actorId: authOf(request).user.id,
      subjectId: userId,
      details: { role: name },
    });
    return reply.status(204).send();
  });

  // For services that want a yes/no answer instead of reading the token's claims.
  app.post('/authz/check', requireAuth, async (request) => {
    const { user } = authOf(request);
    const body = checkBody.parse(request.body);
    const { permissions } = await accessOf(pool, user.id);
    return { allowed: user.isSuperuser || hasPermission(permissions, body.permission) };
  });
}
