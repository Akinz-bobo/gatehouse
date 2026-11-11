import { errors } from '../../core/errors.js';
import { pgErrorCode, type Pool } from '../../db/pool.js';
import type { Condition, Policy } from './engine.js';

type Queryable = Pick<Pool, 'query'>;

export interface PolicyInput {
  name: string;
  description?: string | undefined;
  effect: 'allow' | 'deny';
  actions: string[];
  resources: string[];
  condition?: Condition | null | undefined;
}

export async function listPolicies(db: Queryable): Promise<Policy[]> {
  const result = await db.query<Policy>(
    `SELECT id, name, effect, actions, resources, condition FROM policies ORDER BY name`,
  );
  return result.rows;
}

export async function createPolicy(db: Queryable, input: PolicyInput): Promise<Policy> {
  try {
    const result = await db.query<Policy>(
      `INSERT INTO policies (name, description, effect, actions, resources, condition)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, name, effect, actions, resources, condition`,
      [
        input.name,
        input.description ?? null,
        input.effect,
        input.actions,
        input.resources,
        input.condition ? JSON.stringify(input.condition) : null,
      ],
    );
    return result.rows[0] as Policy;
  } catch (error) {
    if (pgErrorCode(error) === '23505') {
      throw errors.conflict('policy_exists', `A policy named ${input.name} already exists`);
    }
    throw error;
  }
}

export async function deletePolicy(db: Queryable, id: string): Promise<void> {
  const result = await db.query('DELETE FROM policies WHERE id = $1', [id]);
  if (!result.rowCount) throw errors.notFound('Policy');
}
