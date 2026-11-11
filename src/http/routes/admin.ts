import type { FastifyInstance } from 'fastify';
import type { Context } from '../../core/context.js';
import { authOf, authenticate, requirePermission } from '../authenticate.js';

export function adminRoutes(app: FastifyInstance, context: Context): void {
  const guard = (permission: string) => ({
    preHandler: [authenticate(context), requirePermission(context, permission)],
  });

  app.post('/admin/keys/rotate', guard('auth:keys:rotate'), async (request) => {
    const kid = await context.keys.rotate();
    await context.hooks.emit({
      type: 'keys.rotated',
      actorId: authOf(request).user.id,
      details: { kid },
    });
    return { kid };
  });
}
