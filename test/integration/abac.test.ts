import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  client,
  createTestApp,
  createTestPool,
  resetDatabase,
  type TestApp,
  type Tokens,
} from './helpers.js';

const pool = createTestPool();
let test: TestApp;
let api: ReturnType<typeof client>;
let admin: Tokens & { userId: string };
let user: Tokens & { userId: string };

interface Decision {
  allowed: boolean;
  reason: string;
  policies: string[];
}

beforeAll(async () => {
  test = await createTestApp(pool, ['rbac', 'abac']);
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

const addPolicy = (policy: Record<string, unknown>, token = admin.accessToken) =>
  api.post('/v1/policies', policy, token);
const evaluate = async (body: Record<string, unknown>, token = user.accessToken) =>
  (await api.post('/v1/authz/evaluate', body, token)).json<Decision>();

const OWNER_CAN_EDIT = {
  name: 'owners edit their documents',
  effect: 'allow',
  actions: ['documents:update'],
  resources: ['document'],
  condition: { eq: [{ var: 'resource.ownerId' }, { var: 'subject.id' }] },
};

describe('policies', () => {
  it('denies by default when nothing matches', async () => {
    const decision = await evaluate({ action: 'documents:update', resource: { type: 'document' } });
    expect(decision).toEqual({ allowed: false, reason: 'no_matching_policy', policies: [] });
  });

  it('allows when a condition on resource and subject attributes holds', async () => {
    expect((await addPolicy(OWNER_CAN_EDIT)).statusCode).toBe(201);

    const own = await evaluate({
      action: 'documents:update',
      resource: { type: 'document', ownerId: user.userId },
    });
    expect(own).toMatchObject({ allowed: true, policies: ['owners edit their documents'] });

    const someoneElses = await evaluate({
      action: 'documents:update',
      resource: { type: 'document', ownerId: admin.userId },
    });
    expect(someoneElses.allowed).toBe(false);
  });

  it('lets an explicit deny override any allow', async () => {
    await addPolicy(OWNER_CAN_EDIT);
    await addPolicy({
      name: 'archived documents are frozen',
      effect: 'deny',
      actions: ['documents:*'],
      resources: ['document'],
      condition: { eq: [{ var: 'resource.archived' }, true] },
    });

    const decision = await evaluate({
      action: 'documents:update',
      resource: { type: 'document', ownerId: user.userId, archived: true },
    });
    expect(decision).toEqual({
      allowed: false,
      reason: 'denied_by_policy',
      policies: ['archived documents are frozen'],
    });
  });

  it('reads subject attributes and roles from the server, not the request', async () => {
    await addPolicy({
      name: 'finance reads payroll',
      effect: 'allow',
      actions: ['payroll:read'],
      resources: ['payroll'],
      condition: { eq: [{ var: 'subject.attributes.department' }, 'finance'] },
    });
    const request = { action: 'payroll:read', resource: { type: 'payroll' } };
    expect((await evaluate(request)).allowed).toBe(false);

    // A caller cannot name their own attributes.
    const spoofed = await api.post(
      '/v1/authz/evaluate',
      { ...request, subject: { attributes: { department: 'finance' } } },
      user.accessToken,
    );
    expect(spoofed.statusCode).toBe(400);

    await pool.query(`UPDATE users SET attributes = '{"department":"finance"}' WHERE id = $1`, [
      user.userId,
    ]);
    expect((await evaluate(request)).allowed).toBe(true);
  });

  it("combines with rbac: conditions can test the subject's roles", async () => {
    await api.put('/v1/roles/auditor', admin.accessToken, { permissions: ['reports:read'] });
    await api.put(`/v1/users/${user.userId}/roles/auditor`, admin.accessToken);
    await addPolicy({
      name: 'auditors read reports in office hours',
      effect: 'allow',
      actions: ['reports:read'],
      resources: ['report'],
      condition: {
        all: [
          { contains: [{ var: 'subject.roles' }, 'auditor'] },
          { gte: [{ var: 'context.hour' }, 9] },
          { lt: [{ var: 'context.hour' }, 17] },
        ],
      },
    });
    const at = (hour: number) =>
      evaluate({ action: 'reports:read', resource: { type: 'report' }, context: { hour } });

    expect((await at(10)).allowed).toBe(true);
    expect((await at(22)).allowed).toBe(false);
  });

  it('fails closed when a condition refers to an attribute that is missing', async () => {
    await addPolicy(OWNER_CAN_EDIT);
    const decision = await evaluate({ action: 'documents:update', resource: { type: 'document' } });
    expect(decision.allowed).toBe(false);
  });
});

describe('managing policies', () => {
  it('is closed to ordinary users', async () => {
    expect((await addPolicy(OWNER_CAN_EDIT, user.accessToken)).statusCode).toBe(403);
    expect((await api.get('/v1/policies', user.accessToken)).statusCode).toBe(403);
  });

  it('rejects conditions with unknown operators or variable roots', async () => {
    const unknownOperator = await addPolicy({
      ...OWNER_CAN_EDIT,
      condition: { regex: ['a', 'b'] },
    });
    const badRoot = await addPolicy({
      ...OWNER_CAN_EDIT,
      condition: { eq: [{ var: 'process.env.SECRET' }, 'x'] },
    });
    expect(unknownOperator.statusCode).toBe(400);
    expect(badRoot.statusCode).toBe(400);
  });

  it('lists and deletes policies, and a deleted policy stops applying', async () => {
    const created = (await addPolicy(OWNER_CAN_EDIT)).json<{ id: string }>();
    const listed = (await api.get('/v1/policies', admin.accessToken)).json<{
      policies: { id: string }[];
    }>();
    expect(listed.policies.map((policy) => policy.id)).toEqual([created.id]);

    expect((await api.delete(`/v1/policies/${created.id}`, admin.accessToken)).statusCode).toBe(
      204,
    );
    const decision = await evaluate({
      action: 'documents:update',
      resource: { type: 'document', ownerId: user.userId },
    });
    expect(decision.allowed).toBe(false);
  });
});
