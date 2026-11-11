import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createPool, type Pool } from './pool.js';

const MIGRATIONS_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../migrations',
);

// Any constant works; it only has to be the same for every migrator.
const MIGRATION_LOCK_ID = 727_002;

/**
 * Applies every migration in `migrations/` that has not run yet, in filename
 * order. An advisory lock makes it safe for several instances to start at once.
 */
export async function migrate(pool: Pool, dir = MIGRATIONS_DIR): Promise<string[]> {
  const client = await pool.connect();
  const applied: string[] = [];
  try {
    await client.query('SELECT pg_advisory_lock($1)', [MIGRATION_LOCK_ID]);
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        name        text PRIMARY KEY,
        applied_at  timestamptz NOT NULL DEFAULT now()
      )`);
    const done = await client.query<{ name: string }>('SELECT name FROM schema_migrations');
    const alreadyApplied = new Set(done.rows.map((row) => row.name));

    const files = (await readdir(dir)).filter((file) => file.endsWith('.sql')).sort();
    for (const file of files) {
      if (alreadyApplied.has(file)) continue;
      const sql = await readFile(path.join(dir, file), 'utf8');
      try {
        await client.query('BEGIN');
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations (name) VALUES ($1)', [file]);
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK');
        throw new Error(`Migration ${file} failed`, { cause: error });
      }
      applied.push(file);
    }
    return applied;
  } finally {
    await client.query('SELECT pg_advisory_unlock($1)', [MIGRATION_LOCK_ID]).catch(() => undefined);
    client.release();
  }
}

const runDirectly = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (runDirectly) {
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error('DATABASE_URL is required');
  const pool = createPool(url, 1);
  try {
    const applied = await migrate(pool);
    console.log(applied.length ? `Applied: ${applied.join(', ')}` : 'Nothing to apply');
  } finally {
    await pool.end();
  }
}
