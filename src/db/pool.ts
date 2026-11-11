import pg from 'pg';

// Postgres returns bigint (int8) as a string by default. Money is bigint
// everywhere in this service, so parse it into a native BigInt.
pg.types.setTypeParser(pg.types.builtins.INT8, (value) => BigInt(value));

export type Pool = pg.Pool;
export type Client = pg.PoolClient;

export function createPool(connectionString: string, max = 10): Pool {
  return new pg.Pool({ connectionString, max });
}

const SERIALIZATION_FAILURE = '40001';
const DEADLOCK_DETECTED = '40P01';

export function pgErrorCode(error: unknown): string | undefined {
  if (typeof error === 'object' && error !== null && 'code' in error) {
    return typeof error.code === 'string' ? error.code : undefined;
  }
  return undefined;
}

function isRetryable(error: unknown): boolean {
  const code = pgErrorCode(error);
  return code === SERIALIZATION_FAILURE || code === DEADLOCK_DETECTED;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Runs `work` inside a database transaction, committing on success and rolling
 * back on any error. Serialization failures and deadlocks are retried with
 * jittered backoff, because they mean "try again", not "something is wrong".
 */
export async function withTransaction<T>(
  pool: Pool,
  work: (client: Client) => Promise<T>,
  { maxAttempts = 4 }: { maxAttempts?: number } = {},
): Promise<T> {
  for (let attempt = 1; ; attempt++) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const result = await work(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      if (!isRetryable(error) || attempt >= maxAttempts) throw error;
      await sleep(Math.random() * 20 * 2 ** attempt);
    } finally {
      client.release();
    }
  }
}
