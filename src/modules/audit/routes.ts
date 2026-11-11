import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Context } from '../../core/context.js';
import { authenticate, requirePermission } from '../../http/authenticate.js';
import { listAudit } from './service.js';

const query = z.strictObject({
  limit: z.coerce.number().int().min(1).max(200).default(50),
  before: z
    .string()
    .regex(/^\d+$/)
    .transform((value) => BigInt(value))
    .optional(),
  type: z.string().max(100).optional(),
  actorId: z.uuid().optional(),
});

export function auditRoutes(app: FastifyInstance, context: Context): void {
  app.get(
    '/audit',
    { preHandler: [authenticate(context), requirePermission(context, 'auth:audit:read')] },
    async (request) => {
      const page = await listAudit(context.pool, query.parse(request.query));
      return {
        entries: page.entries.map((entry) => ({
          ...entry,
          createdAt: entry.createdAt.toISOString(),
        })),
        nextCursor: page.nextCursor,
      };
    },
  );
}
