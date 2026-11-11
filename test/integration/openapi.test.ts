import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { MODULES } from '../../src/config.js';
import { loadOpenApiDocument } from '../../src/http/openapi.js';
import { client, createTestApp, createTestPool, type TestApp } from './helpers.js';

const pool = createTestPool();
const served = new Set<string>();
let test: TestApp;

beforeAll(async () => {
  // Every module on, so every route the service can serve is registered.
  test = await createTestApp(pool, [...MODULES], {}, (app) => {
    app.addHook('onRoute', (route) => {
      if (route.url.startsWith('/docs')) return;
      const path = route.url.replace(/:(\w+)/g, '{$1}');
      for (const method of [route.method].flat()) {
        if (method !== 'HEAD') served.add(`${method} ${path}`);
      }
    });
  });
});
afterAll(async () => {
  await test.app.close();
  await pool.end();
});

describe('the OpenAPI description', () => {
  it('describes exactly the routes the service serves', async () => {
    const document = await loadOpenApiDocument();
    const described = new Set(
      Object.entries(document.paths).flatMap(([path, operations]) =>
        Object.keys(operations)
          .filter((key) => key !== 'parameters')
          .map((method) => `${method.toUpperCase()} ${path}`),
      ),
    );
    expect([...described].sort()).toEqual([...served].sort());
  });

  it('is served as JSON and through Swagger UI', async () => {
    const api = client(test.app);
    const json = await api.get('/docs/json');
    expect(json.statusCode).toBe(200);
    expect(json.json<{ info: { title: string } }>().info.title).toBe('Gatehouse');
    expect((await api.get('/docs')).statusCode).toBeLessThan(400);
  });

  it('reports the enabled modules on the readiness probe', async () => {
    const ready = (await client(test.app).get('/readyz')).json<{ modules: string[] }>();
    expect(ready.modules.sort()).toEqual([...MODULES].sort());
  });
});
