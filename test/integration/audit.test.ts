import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  PASSWORD,
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

interface Entry {
  id: string;
  type: string;
  actorId: string | null;
  subjectId: string | null;
  details: Record<string, unknown>;
}
interface Page {
  entries: Entry[];
  nextCursor: string | null;
}

beforeAll(async () => {
  test = await createTestApp(pool, ['audit', 'rbac']);
  api = client(test.app);
});
beforeEach(async () => {
  await resetDatabase(pool);
  admin = await api.signUpAdmin(pool);
});
afterAll(async () => {
  await test.app.close();
  await pool.end();
});

const audit = async (query = '') =>
  (await api.get(`/v1/audit${query}`, admin.accessToken)).json<Page>();

describe('the audit log', () => {
  it('records sign-ins, failures and administrative changes, newest first', async () => {
    await api.login('admin@example.com', 'the wrong password here');
    await api.put('/v1/roles/editor', admin.accessToken, { permissions: ['invoices:read'] });

    const { entries } = await audit();
    expect(entries.map((entry) => entry.type)).toEqual([
      'role.saved',
      'login.failed',
      'login.succeeded',
      'user.registered',
    ]);
    expect(entries[0]).toMatchObject({ actorId: admin.userId, subjectId: 'editor' });
    expect(entries[1]).toMatchObject({ subjectId: admin.userId });
  });

  it('never records a password, token or code', async () => {
    await api.login('admin@example.com', 'the wrong password here');
    await api.post('/v1/auth/refresh', { refreshToken: admin.refreshToken });

    const rows = await pool.query<{ row: string }>('SELECT audit_log::text AS row FROM audit_log');
    const everything = rows.rows.map((entry) => entry.row).join('\n');
    expect(everything).not.toContain(PASSWORD);
    expect(everything).not.toContain('the wrong password here');
    expect(everything).not.toContain(admin.refreshToken);
    expect(everything).not.toContain(admin.accessToken);
  });

  it('filters by type and by actor', async () => {
    const other = await api.signUp('ada@example.com');
    await api.post('/v1/auth/logout', undefined, other.accessToken);

    const failures = await audit('?type=session.revoked');
    expect(failures.entries).toHaveLength(1);
    const byActor = await audit(`?actorId=${other.userId}`);
    expect(byActor.entries.every((entry) => entry.actorId === other.userId)).toBe(true);
    expect(byActor.entries.length).toBeGreaterThan(0);
  });

  it('pages with a cursor', async () => {
    for (let attempt = 0; attempt < 3; attempt++) await api.login('admin@example.com');

    const first = await audit('?limit=2');
    expect(first.entries).toHaveLength(2);
    expect(first.nextCursor).not.toBeNull();
    const second = await audit(`?limit=2&before=${first.nextCursor ?? ''}`);
    const ids = [...first.entries, ...second.entries].map((entry) => BigInt(entry.id));
    expect(ids).toEqual([...ids].sort((a, b) => (a > b ? -1 : 1)));
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('is readable only with the audit permission', async () => {
    const user = await api.signUp('ada@example.com');
    expect((await api.get('/v1/audit', user.accessToken)).statusCode).toBe(403);

    await api.put('/v1/roles/auditor', admin.accessToken, { permissions: ['auth:audit:read'] });
    await api.put(`/v1/users/${user.userId}/roles/auditor`, admin.accessToken);
    expect((await api.get('/v1/audit', user.accessToken)).statusCode).toBe(200);
  });

  it('cannot be edited or deleted, even with direct database access', async () => {
    await expect(pool.query(`UPDATE audit_log SET type = 'tampered'`)).rejects.toThrow(
      /append-only/,
    );
    await expect(pool.query('DELETE FROM audit_log')).rejects.toThrow(/append-only/);
  });

  it('records a detected refresh token replay', async () => {
    const victim = await api.signUp('ada@example.com');
    await api.post('/v1/auth/refresh', { refreshToken: victim.refreshToken });
    await api.post('/v1/auth/refresh', { refreshToken: victim.refreshToken });

    const { entries } = await audit('?type=token.reuse_detected');
    expect(entries).toHaveLength(1);
    expect(entries[0]?.subjectId).toEqual(expect.any(String));
  });
});
