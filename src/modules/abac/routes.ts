import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Context } from '../../core/context.js';
import { authOf, authenticate, requirePermission } from '../../http/authenticate.js';
import { accessOf } from '../rbac/service.js';
import { decide, type Condition, type Operand } from './engine.js';
import { createPolicy, deletePolicy, listPolicies } from './service.js';

const operand: z.ZodType<Operand> = z.lazy(() =>
  z.union([
    z.string().max(500),
    z.number(),
    z.boolean(),
    z.null(),
    z.array(operand).max(100),
    z.strictObject({ var: z.string().regex(/^(subject|resource|context)(\.[A-Za-z0-9_-]+)*$/) }),
  ]),
);
const pair = z.tuple([operand, operand]);
const condition: z.ZodType<Condition> = z.lazy(() =>
  z.union([
    z.strictObject({ all: z.array(condition).min(1).max(20) }),
    z.strictObject({ any: z.array(condition).min(1).max(20) }),
    z.strictObject({ not: condition }),
    z.strictObject({ eq: pair }),
    z.strictObject({ ne: pair }),
    z.strictObject({ gt: pair }),
    z.strictObject({ gte: pair }),
    z.strictObject({ lt: pair }),
    z.strictObject({ lte: pair }),
    z.strictObject({ in: pair }),
    z.strictObject({ contains: pair }),
    z.strictObject({ exists: operand }),
  ]),
);

const pattern = z
  .string()
  .max(128)
  .regex(/^(\*|[a-z0-9_-]+(:[a-z0-9_-]+)*(:\*)?)$/);
const policyBody = z.strictObject({
  name: z.string().min(1).max(100),
  description: z.string().max(500).optional(),
  effect: z.enum(['allow', 'deny']),
  actions: z.array(pattern).min(1).max(50),
  resources: z.array(pattern).min(1).max(50),
  condition: condition.nullable().optional(),
});
const policyParams = z.strictObject({ id: z.uuid() });
const evaluateBody = z.strictObject({
  action: z.string().min(1).max(128),
  resource: z.looseObject({ type: z.string().min(1).max(128) }),
  context: z.record(z.string(), z.unknown()).default({}),
});

export function abacRoutes(app: FastifyInstance, context: Context): void {
  const { pool, hooks } = context;
  const manage = {
    preHandler: [authenticate(context), requirePermission(context, 'auth:policies:manage')],
  };

  app.get('/policies', manage, async () => ({ policies: await listPolicies(pool) }));

  app.post('/policies', manage, async (request, reply) => {
    const body = policyBody.parse(request.body);
    const policy = await createPolicy(pool, body);
    await hooks.emit({
      type: 'policy.created',
      actorId: authOf(request).user.id,
      subjectId: policy.id,
      details: { name: policy.name, effect: policy.effect },
    });
    return reply.status(201).send(policy);
  });

  app.delete('/policies/:id', manage, async (request, reply) => {
    const { id } = policyParams.parse(request.params);
    await deletePolicy(pool, id);
    await hooks.emit({ type: 'policy.deleted', actorId: authOf(request).user.id, subjectId: id });
    return reply.status(204).send();
  });

  /**
   * Asks whether the signed-in user may do `action` to `resource`. The
   * subject is built here from the verified token, never taken from the
   * request body, so a caller cannot claim attributes they do not have.
   */
  app.post('/authz/evaluate', { preHandler: authenticate(context) }, async (request) => {
    const { user } = authOf(request);
    const body = evaluateBody.parse(request.body);
    const roles = context.enabled.has('rbac') ? (await accessOf(pool, user.id)).roles : [];
    return decide(await listPolicies(pool), {
      action: body.action,
      resource: body.resource,
      context: body.context,
      subject: { id: user.id, email: user.email, roles, attributes: user.attributes },
    });
  });
}
