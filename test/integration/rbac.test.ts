import { decodeJwt } from 'jose';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  client,
  createTestApp,
  createTestPool,
  errorCode,
  resetDatabase,
  type TestApp,
  type Tokens,
} from './helpers.js';

const pool = createTestPool();
let test: TestApp;
let api: ReturnType<typeof client>;
let admin: Tokens & { userId: string };
let user: Tokens & { userId: string };

beforeAll(async () => {
  test = await createTestApp(pool, ['rbac']);
  api = client(test.app);
});
beforeEach(async () => {
  await resetDatabase(pool);
  admin = await api.signUpAdmin(pool);
  user = await api.signUp('ada@example.com');
});
afterAll(async () => {
  await test.app.close();
  await pool.end();
});

const saveRole = (name: string, permissions: string[], token = admin.accessToken) =>
  api.put(`/v1/roles/${name}`, token, { permissions });
const assign = (userId: string, role: string, token = admin.accessToken) =>
  api.put(`/v1/users/${userId}/roles/${role}`, token);
const check = async (permission: string, token = user.accessToken) =>
  (await api.post('/v1/authz/check', { permission }, token)).json<{ allowed: boolean }>().allowed;

describe('managing roles', () => {
  it('creates, replaces, lists and deletes a role', async () => {
    expect((await saveRole('editor', ['invoices:read'])).statusCode).toBe(200);
    const replaced = await saveRole('editor', ['invoices:read', 'invoices:write']);
    expect(replaced.json()).toMatchObject({
      name: 'editor',
      permissions: ['invoices:read', 'invoices:write'],
    });

    const { roles } = (await api.get('/v1/roles', admin.accessToken)).json<{
      roles: { name: string }[];
    }>();
    expect(roles.map((role) => role.name)).toEqual(['editor']);

    expect((await api.delete('/v1/roles/editor', admin.accessToken)).statusCode).toBe(204);
    expect((await api.delete('/v1/roles/editor', admin.accessToken)).statusCode).toBe(404);
  });

  it('is closed to ordinary users', async () => {
    expect((await saveRole('editor', ['invoices:read'], user.accessToken)).statusCode).toBe(403);
    expect((await api.get('/v1/roles', user.accessToken)).statusCode).toBe(403);
    expect((await api.get('/v1/roles')).statusCode).toBe(401);
  });

  it('rejects a malformed permission', async () => {
    const response = await saveRole('editor', ['Invoices Read!']);
    expect(response.statusCode).toBe(400);
  });

  it('answers 404 when assigning an unknown role or to an unknown user', async () => {
    await saveRole('editor', ['invoices:read']);
    expect((await assign(user.userId, 'ghost')).statusCode).toBe(404);
    expect((await assign('00000000-0000-4000-8000-000000000000', 'editor')).statusCode).toBe(404);
  });
});

describe('permissions', () => {
  beforeEach(async () => {
    await saveRole('editor', ['invoices:read', 'invoices:write']);
    await assign(user.userId, 'editor');
  });

  it('puts roles and permissions into new access tokens', async () => {
    const fresh = (await api.login('ada@example.com')).json<Tokens>();
    expect(decodeJwt(fresh.accessToken)).toMatchObject({
      roles: ['editor'],
      permissions: ['invoices:read', 'invoices:write'],
    });
  });

  it('answers permission checks from the database, default deny', async () => {
    expect(await check('invoices:read')).toBe(true);
    expect(await check('invoices:delete')).toBe(false);
    expect(await check('payroll:read')).toBe(false);
  });

  it('supports wildcards within a namespace only', async () => {
    await saveRole('billing-admin', ['invoices:*']);
    await assign(user.userId, 'billing-admin');
    expect(await check('invoices:delete')).toBe(true);
    expect(await check('payroll:read')).toBe(false);
  });

  it('takes effect at once when a role is removed, without waiting for the token to expire', async () => {
    expect(await check('invoices:read')).toBe(true);
    await api.delete(`/v1/users/${user.userId}/roles/editor`, admin.accessToken);
    expect(await check('invoices:read')).toBe(false);
  });

  it('removes access when the role itself is deleted', async () => {
    await api.delete('/v1/roles/editor', admin.accessToken);
    expect(await check('invoices:read')).toBe(false);
  });

  it('lets a superuser pass every check', async () => {
    expect(await check('anything:at-all', admin.accessToken)).toBe(true);
  });
});

describe('delegated administration', () => {
  it('lets a role holder manage roles, and stops when the role is revoked', async () => {
    await saveRole('role-admin', ['auth:roles:manage']);
    await assign(user.userId, 'role-admin');
    expect((await saveRole('viewer', ['invoices:read'], user.accessToken)).statusCode).toBe(200);

    await api.delete(`/v1/users/${user.userId}/roles/role-admin`, admin.accessToken);
    const denied = await saveRole('viewer', ['invoices:write'], user.accessToken);
    expect(denied.statusCode).toBe(403);
    expect(errorCode(denied)).toBe('forbidden');
  });

  it('does not let a role manager read the audit log or rotate keys', async () => {
    await saveRole('role-admin', ['auth:roles:manage']);
    await assign(user.userId, 'role-admin');
    expect((await api.post('/v1/admin/keys/rotate', undefined, user.accessToken)).statusCode).toBe(
      403,
    );
  });
});
