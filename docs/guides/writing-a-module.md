# Writing a module

A module is one object in a registry. This guide adds a small one: `terms`, which records that a user accepted the terms of service and puts the accepted version in their token.

## 1. Name it

In `src/config.ts`, add the name to the list of known modules. `MODULES=terms` now validates.

```ts
export const MODULES = ['rbac', 'abac', 'oauth', 'mfa', 'audit', 'terms'] as const;
```

## 2. Add its table

Migrations are numbered SQL files. Create `migrations/010_terms.sql`:

```sql
CREATE TABLE terms_acceptances (
  user_id      uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
  version      text NOT NULL,
  accepted_at  timestamptz NOT NULL DEFAULT now()
);
```

The table exists whether or not the module is enabled. That keeps one schema for every deployment.

## 3. Write the module

`src/modules/terms/index.ts`:

```ts
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { Context } from '../../core/context.js';
import { authOf, authenticate } from '../../http/authenticate.js';
import type { Module } from '../index.js';

const body = z.strictObject({ version: z.string().min(1).max(32) });

function routes(app: FastifyInstance, context: Context): void {
  app.post('/terms/accept', { preHandler: authenticate(context) }, async (request, reply) => {
    const { user } = authOf(request);
    const { version } = body.parse(request.body);
    await context.pool.query(
      `INSERT INTO terms_acceptances (user_id, version) VALUES ($1, $2)
       ON CONFLICT (user_id) DO UPDATE SET version = EXCLUDED.version, accepted_at = now()`,
      [user.id, version],
    );
    await context.hooks.emit({
      type: 'terms.accepted',
      actorId: user.id,
      subjectId: user.id,
      details: { version },
    });
    return reply.status(204).send();
  });
}

export const termsModule: Module = {
  name: 'terms',
  setup(context) {
    // Every access token now carries the version this user accepted.
    context.hooks.addClaims(async (db, user) => {
      const found = await db.query<{ version: string }>(
        'SELECT version FROM terms_acceptances WHERE user_id = $1',
        [user.id],
      );
      return { terms: found.rows[0]?.version ?? null };
    });
  },
  routes,
};
```

## 4. Register it

In `src/modules/index.ts`:

```ts
export const MODULE_REGISTRY: Record<ModuleName, Module> = {
  // ...
  terms: termsModule,
};
```

The type `Record<ModuleName, Module>` makes the compiler insist that every name in `MODULES` has an entry.

## 5. Describe and test it

- Add the route to `openapi/openapi.yaml`. The test in `test/integration/openapi.test.ts` fails until the spec and the routes agree.
- Add `terms_acceptances` to the `TRUNCATE` in `test/integration/helpers.ts`.
- Write `test/integration/terms.test.ts`. Start the app with only your module, `createTestApp(pool, ['terms'])`, and check both that it works and that its routes answer `404` when it is off.

## The extension points

| Hook                 | Signature                                   | Use it to                                                                                                                  |
| -------------------- | ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `hooks.addClaims`    | `(db, user) => Promise<object>`             | Add claims to every access token and to `GET /v1/auth/me`                                                                  |
| `hooks.addChallenge` | `(db, user) => Promise<{ method } \| null>` | Demand another step before a session starts. Finish it by calling `startSession` from your own verify route, as `mfa` does |
| `hooks.onEvent`      | `(event) => Promise<void>`                  | React to anything that happens: forward to a SIEM, send a "new sign-in" email                                              |
| `hooks.emit`         | `(event) => Promise<void>`                  | Announce your own events, so `audit` records them                                                                          |

And from `Context`: `pool` for the database, `config`, `keys` to sign and verify tokens, `secrets` to encrypt anything you must read back, `hasher` for passwords, and `enabled` to see which other modules are on.

## Rules of the road

- **Guard with `authenticate`**, and `requirePermission(context, 'yourmodule:thing:manage')` for administrative routes. Superusers pass automatically, and `rbac` roles can grant the permission.
- **Validate with `z.strictObject`**, so unknown fields are refused.
- **Hash what you only compare** (`hashToken`) and **encrypt what you must read back** (`context.secrets`). Store neither in the clear.
- **Fail closed.** If your module cannot decide, the answer is no.
- **Do not import another module's internals.** Check `context.enabled.has('rbac')` and use its public service functions, as `abac` does.
- **Claims run on every token.** Keep `addClaims` to one indexed query.
- **Listeners run inline.** An `onEvent` listener that throws fails the request that raised the event. That is deliberate for `audit`, where an action that cannot be recorded should not happen. Catch errors yourself if your listener is best-effort.
