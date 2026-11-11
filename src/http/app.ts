import { randomUUID } from 'node:crypto';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import Fastify, { type FastifyInstance } from 'fastify';
import { ZodError } from 'zod';
import type { Config } from '../config.js';
import { Hooks, type Context, type Notifier } from '../core/context.js';
import { AuthError } from '../core/errors.js';
import { KeyStore } from '../core/keys.js';
import { PasswordHasher } from '../crypto/password.js';
import { SecretBox } from '../crypto/secretbox.js';
import type { Pool } from '../db/pool.js';
import { MODULE_REGISTRY } from '../modules/index.js';
import { registerApiDocs } from './openapi.js';
import { adminRoutes } from './routes/admin.js';
import { authRoutes } from './routes/auth.js';

export interface AppDependencies {
  config: Config;
  pool: Pool;
  /** Defaults to a notifier that logs. Replace it to send real email. */
  notifier?: Notifier | undefined;
  /** Runs on the new instance before any route is added. Used by tests to observe routes. */
  configure?: ((app: FastifyInstance) => void) | undefined;
}

const REQUEST_ID = /^[\w.-]{1,128}$/;
// Clock drift allowance when deciding how long a retired key must keep verifying.
const KEY_GRACE_MARGIN_SECONDS = 300;

export async function buildApp({
  config,
  pool,
  notifier,
  configure,
}: AppDependencies): Promise<{ app: FastifyInstance; context: Context }> {
  const app = Fastify({
    logger: {
      level: config.LOG_LEVEL,
      // Credentials never reach the logs, whichever header they arrive in.
      redact: ['req.headers.authorization', 'req.headers.cookie'],
    },
    bodyLimit: 64 * 1024,
    // Honour X-Forwarded-For only when deployed behind a proxy that sets it.
    trustProxy: config.NODE_ENV === 'production',
    genReqId: (request) => {
      const inbound = request.headers['x-request-id'];
      return typeof inbound === 'string' && REQUEST_ID.test(inbound) ? inbound : randomUUID();
    },
  });
  configure?.(app);

  const secrets = SecretBox.fromBase64(config.KEY_ENCRYPTION_KEY);
  const context: Context = {
    config,
    pool,
    secrets,
    keys: new KeyStore(pool, secrets, {
      issuer: config.ISSUER,
      audience: config.AUDIENCE,
      verifyGraceSeconds: config.ACCESS_TOKEN_TTL_SECONDS + KEY_GRACE_MARGIN_SECONDS,
    }),
    hasher: new PasswordHasher({
      memoryCost: config.PASSWORD_HASH_MEMORY_KIB,
      timeCost: config.PASSWORD_HASH_ITERATIONS,
    }),
    hooks: new Hooks(),
    enabled: new Set(config.MODULES),
    notifier: notifier ?? {
      // No mail transport is bundled. Outside development the token is not
      // logged: a reset link in a log file is a password in a log file.
      passwordReset: (email, token) => {
        app.log.info(
          config.NODE_ENV === 'development' ? { email, token } : { email },
          'password reset requested',
        );
        return Promise.resolve();
      },
    },
  };

  await app.register(helmet);
  if (config.CORS_ORIGINS.length > 0) {
    await app.register(cors, { origin: config.CORS_ORIGINS, credentials: false });
  }
  await app.register(rateLimit, { max: config.RATE_LIMIT_MAX, timeWindow: '1 minute' });

  app.addHook('onRequest', (request, reply, done) => {
    void reply.header('x-request-id', request.id);
    // Tokens and account data must never be stored by a browser or proxy.
    void reply.header('cache-control', 'no-store');
    done();
  });

  app.setErrorHandler((error: unknown, request, reply) => {
    if (error instanceof AuthError) {
      return reply.status(error.status).send({
        error: { code: error.code, message: error.message, details: error.details },
      });
    }
    if (error instanceof ZodError) {
      return reply.status(400).send({
        error: {
          code: 'validation_error',
          message: 'The request is not valid',
          details: {
            issues: error.issues.map((issue) => ({
              path: issue.path.join('.'),
              message: issue.message,
            })),
          },
        },
      });
    }
    const status = (error as { statusCode?: number }).statusCode;
    if (typeof status === 'number' && status >= 400 && status < 500) {
      const code = status === 429 ? 'rate_limited' : 'bad_request';
      return reply.status(status).send({ error: { code, message: (error as Error).message } });
    }
    request.log.error({ err: error }, 'unhandled error');
    return reply
      .status(500)
      .send({ error: { code: 'internal_error', message: 'Something went wrong' } });
  });

  app.get('/healthz', () => ({ status: 'ok' }));
  app.get('/readyz', async (_request, reply) => {
    try {
      await pool.query('SELECT 1');
      return { status: 'ready', modules: [...context.enabled] };
    } catch {
      return reply.status(503).send({ status: 'unavailable' });
    }
  });

  // The public keys resource servers verify tokens with. Safe to cache briefly.
  app.get('/.well-known/jwks.json', async (_request, reply) => {
    return reply.header('cache-control', 'public, max-age=60').send(await context.keys.jwks());
  });

  await registerApiDocs(app);

  const enabledModules = config.MODULES.map((name) => MODULE_REGISTRY[name]);
  for (const module of enabledModules) module.setup?.(context);

  await app.register(
    (v1, _options, done) => {
      authRoutes(v1, context);
      adminRoutes(v1, context);
      for (const module of enabledModules) module.routes(v1, context);
      done();
    },
    { prefix: '/v1' },
  );

  return { app, context };
}
