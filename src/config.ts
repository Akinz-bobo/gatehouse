import { z } from 'zod';

export const MODULES = ['rbac', 'abac', 'oauth', 'mfa', 'audit'] as const;
export type ModuleName = (typeof MODULES)[number];

const list = (value: string) =>
  value
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item.length > 0);

const oauthProvider = z.strictObject({
  id: z.string().regex(/^[a-z][a-z0-9_-]*$/),
  clientId: z.string().min(1),
  clientSecret: z.string().min(1),
  authorizationUrl: z.url(),
  tokenUrl: z.url(),
  userInfoUrl: z.url(),
  scopes: z.array(z.string()).default(['openid', 'email', 'profile']),
});
export type OAuthProviderConfig = z.infer<typeof oauthProvider>;

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  HOST: z.string().default('0.0.0.0'),
  PORT: z.coerce.number().int().min(1).max(65535).default(4000),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  DATABASE_URL: z.url(),
  DATABASE_POOL_MAX: z.coerce.number().int().positive().default(10),

  /** The `iss` claim, and the base URL other services fetch the JWKS from. */
  ISSUER: z.url(),
  /** The `aud` claim. Resource servers should require it. */
  AUDIENCE: z.string().min(1).default('gatehouse'),
  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).max(3600).default(900),
  REFRESH_TOKEN_TTL_SECONDS: z.coerce
    .number()
    .int()
    .min(3600)
    .default(30 * 24 * 3600),

  /** 32 random bytes, base64. Encrypts signing keys and TOTP secrets at rest. */
  KEY_ENCRYPTION_KEY: z
    .string()
    .refine((value) => Buffer.from(value, 'base64').length === 32, 'must be 32 bytes, base64'),

  /** Which optional modules to load. Empty means JWT authentication only. */
  MODULES: z
    .string()
    .default('')
    .transform(list)
    .pipe(z.array(z.enum(MODULES))),

  /** Browser origins allowed to call the API. Empty disables CORS. */
  CORS_ORIGINS: z.string().default('').transform(list),
  RATE_LIMIT_MAX: z.coerce.number().int().positive().default(300),
  /** Per-IP limit on sign-in, registration and reset endpoints, per minute. */
  AUTH_RATE_LIMIT_MAX: z.coerce.number().int().positive().default(20),
  MAX_FAILED_LOGINS: z.coerce.number().int().positive().default(5),
  LOCKOUT_SECONDS: z.coerce.number().int().positive().default(900),

  PASSWORD_HASH_MEMORY_KIB: z.coerce.number().int().min(1024).default(19_456),
  PASSWORD_HASH_ITERATIONS: z.coerce.number().int().min(1).default(2),

  /** JSON array of OAuth providers. Used only when the oauth module is on. */
  OAUTH_PROVIDERS: z
    .string()
    .default('[]')
    .transform((value, context) => {
      try {
        return JSON.parse(value) as unknown;
      } catch {
        context.addIssue({ code: 'custom', message: 'must be valid JSON' });
        return z.NEVER;
      }
    })
    .pipe(z.array(oauthProvider)),
  /** Where the service may send a browser after an OAuth sign-in. Exact matches only. */
  OAUTH_REDIRECT_ALLOWLIST: z.string().default('').transform(list),
});

export type Config = z.infer<typeof schema>;

/** Reads configuration from the environment and fails fast on anything invalid. */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    const problems = parsed.error.issues
      .map((issue) => `  ${issue.path.join('.')}: ${issue.message}`)
      .join('\n');
    throw new Error(`Invalid configuration:\n${problems}`);
  }
  return parsed.data;
}
