import { errors } from '../../core/errors.js';
import { pgErrorCode, withTransaction, type Pool } from '../../db/pool.js';

type Queryable = Pick<Pool, 'query'>;

export interface Role {
  name: string;
  description: string | null;
  permissions: string[];
}

const UNIQUE_VIOLATION = '23505';

export async function listRoles(db: Queryable): Promise<Role[]> {
  const result = await db.query<Role>(
    `SELECT r.name, r.description,
            coalesce(array_agg(rp.permission ORDER BY rp.permission)
                     FILTER (WHERE rp.permission IS NOT NULL), '{}') AS permissions
     FROM roles r
     LEFT JOIN role_permissions rp ON rp.role_id = r.id
     GROUP BY r.id
     ORDER BY r.name`,
  );
  return result.rows;
}

/** Creates a role, or replaces the permissions of an existing one. */
export async function putRole(pool: Pool, role: Role): Promise<Role> {
  await withTransaction(pool, async (tx) => {
    const upserted = await tx.query<{ id: string }>(
      `INSERT INTO roles (name, description) VALUES ($1, $2)
       ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description
       RETURNING id`,
      [role.name, role.description],
    );
    const roleId = (upserted.rows[0] as { id: string }).id;
    await tx.query('DELETE FROM role_permissions WHERE role_id = $1', [roleId]);
    await tx.query(
      `INSERT INTO role_permissions (role_id, permission)
       SELECT $1, unnest($2::text[])`,
      [roleId, [...new Set(role.permissions)]],
    );
  });
  return { ...role, permissions: [...new Set(role.permissions)].sort() };
}

export async function deleteRole(db: Queryable, name: string): Promise<void> {
  const result = await db.query('DELETE FROM roles WHERE name = $1', [name]);
  if (!result.rowCount) throw errors.notFound('Role');
}

export async function assignRole(db: Queryable, userId: string, roleName: string): Promise<void> {
  try {
    const result = await db.query(
      `INSERT INTO user_roles (user_id, role_id)
       SELECT $1, id FROM roles WHERE name = $2
       ON CONFLICT DO NOTHING
       RETURNING role_id`,
      [userId, roleName],
    );
    if (result.rowCount) return;
  } catch (error) {
    // Foreign key violation: the user does not exist.
    if (pgErrorCode(error) === '23503') throw errors.notFound('User');
    if (pgErrorCode(error) === UNIQUE_VIOLATION) return;
    throw error;
  }
  // Nothing inserted: either the role is unknown or the user already has it.
  const role = await db.query('SELECT 1 FROM roles WHERE name = $1', [roleName]);
  if (!role.rowCount) throw errors.notFound('Role');
}

export async function removeRole(db: Queryable, userId: string, roleName: string): Promise<void> {
  await db.query(
    `DELETE FROM user_roles
     WHERE user_id = $1 AND role_id = (SELECT id FROM roles WHERE name = $2)`,
    [userId, roleName],
  );
}

/** A user's roles and the union of the permissions those roles grant. */
export async function accessOf(
  db: Queryable,
  userId: string,
): Promise<{ roles: string[]; permissions: string[] }> {
  const result = await db.query<{ roles: string[]; permissions: string[] }>(
    `SELECT coalesce(array_agg(DISTINCT r.name ORDER BY r.name), '{}') AS roles,
            coalesce(array_agg(DISTINCT rp.permission ORDER BY rp.permission)
                     FILTER (WHERE rp.permission IS NOT NULL), '{}') AS permissions
     FROM user_roles ur
     JOIN roles r ON r.id = ur.role_id
     LEFT JOIN role_permissions rp ON rp.role_id = r.id
     WHERE ur.user_id = $1`,
    [userId],
  );
  return result.rows[0] ?? { roles: [], permissions: [] };
}
