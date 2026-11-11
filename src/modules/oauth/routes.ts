import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Context } from '../../core/context.js';
import { completeSignIn } from '../../core/sign-in.js';
import { authOf, authenticate, clientOf } from '../../http/authenticate.js';
import { completeOAuth, redeemExchangeCode, startOAuth } from './service.js';

const providerParams = z.strictObject({ provider: z.string().regex(/^[a-z][a-z0-9_-]*$/) });
const startQuery = z.strictObject({ redirect_uri: z.url().max(2000) });
const callbackQuery = z.looseObject({
  code: z.string().max(4000).optional(),
  state: z.string().max(500).optional(),
  error: z.string().max(200).optional(),
});
const exchangeBody = z.strictObject({ code: z.string().min(1).max(500) });

export function oauthRoutes(app: FastifyInstance, context: Context): void {
  const strict = {
    config: { rateLimit: { max: context.config.AUTH_RATE_LIMIT_MAX, timeWindow: '1 minute' } },
  };

  app.get('/oauth/providers', () => ({
    providers: context.config.OAUTH_PROVIDERS.map((provider) => provider.id),
  }));

  app.get('/oauth/:provider/start', strict, async (request, reply) => {
    const { provider } = providerParams.parse(request.params);
    const query = startQuery.parse(request.query);
    return reply.redirect(await startOAuth(context, provider, query.redirect_uri));
  });

  // Links a provider to the signed-in user. Returns the URL instead of
  // redirecting, because the browser cannot attach a bearer token to a navigation.
  app.post('/oauth/:provider/link', { preHandler: authenticate(context) }, async (request) => {
    const { provider } = providerParams.parse(request.params);
    const query = startQuery.parse(request.body);
    return {
      url: await startOAuth(context, provider, query.redirect_uri, authOf(request).user.id),
    };
  });

  app.get('/oauth/:provider/callback', strict, async (request, reply) => {
    const { provider } = providerParams.parse(request.params);
    const query = callbackQuery.parse(request.query);
    return reply.redirect(await completeOAuth(context, provider, query));
  });

  app.post('/oauth/exchange', strict, async (request) => {
    const { code } = exchangeBody.parse(request.body);
    const { user, provider } = await redeemExchangeCode(context, code);
    return completeSignIn(context, user, `oauth:${provider}`, clientOf(request));
  });
}
