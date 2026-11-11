import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Context } from '../../core/context.js';
import { errors } from '../../core/errors.js';
import { startSession } from '../../core/sessions.js';
import { readMfaToken } from '../../core/sign-in.js';
import { authOf, authenticate, clientOf } from '../../http/authenticate.js';
import {
  confirmTotp,
  disableTotp,
  enrollTotp,
  isTotpEnabled,
  verifySecondFactor,
} from './service.js';

const totpCode = z.string().regex(/^\d{6}$/, 'must be six digits');
const codeBody = z.strictObject({ code: totpCode });
const verifyBody = z
  .strictObject({
    mfaToken: z.string().min(1).max(2048),
    code: totpCode.optional(),
    recoveryCode: z.string().min(8).max(64).optional(),
  })
  .refine((body) => (body.code === undefined) !== (body.recoveryCode === undefined), {
    message: 'send either code or recoveryCode',
  });

export function mfaRoutes(app: FastifyInstance, context: Context): void {
  const { pool, hooks, config } = context;
  const requireAuth = { preHandler: authenticate(context) };
  const strict = {
    config: { rateLimit: { max: config.AUTH_RATE_LIMIT_MAX, timeWindow: '1 minute' } },
  };

  app.get('/mfa', requireAuth, async (request) => ({
    totp: await isTotpEnabled(pool, authOf(request).user.id),
  }));

  app.post('/mfa/totp/enroll', requireAuth, async (request) => {
    return enrollTotp(context, authOf(request).user);
  });

  app.post('/mfa/totp/confirm', requireAuth, async (request) => {
    const { user } = authOf(request);
    const { code } = codeBody.parse(request.body);
    const recoveryCodes = await confirmTotp(context, user.id, code);
    await hooks.emit({
      type: 'mfa.enabled',
      actorId: user.id,
      subjectId: user.id,
      ...clientOf(request),
    });
    return { recoveryCodes };
  });

  app.post('/mfa/totp/disable', requireAuth, async (request, reply) => {
    const { user } = authOf(request);
    const { code } = codeBody.parse(request.body);
    await disableTotp(context, user.id, code);
    await hooks.emit({
      type: 'mfa.disabled',
      actorId: user.id,
      subjectId: user.id,
      ...clientOf(request),
    });
    return reply.status(204).send();
  });

  /** The second step of sign-in: trades the MFA token and a code for a session. */
  app.post('/auth/mfa/verify', strict, async (request) => {
    const body = verifyBody.parse(request.body);
    const { user, method } = await readMfaToken(context, body.mfaToken);
    const factor = await verifySecondFactor(context, user.id, body);
    if (!factor) {
      await hooks.emit({ type: 'mfa.failed', subjectId: user.id, ...clientOf(request) });
      throw errors.invalid('invalid_mfa_code', 'That code is not correct');
    }
    const { sessionId, ...tokens } = await startSession(
      context,
      user,
      `${method}+${factor}`,
      clientOf(request),
    );
    await hooks.emit({
      type: 'login.succeeded',
      actorId: user.id,
      subjectId: sessionId,
      ...clientOf(request),
      details: { method: `${method}+${factor}` },
    });
    return { mfaRequired: false, ...tokens };
  });
}
