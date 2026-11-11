import { randomBytes } from 'node:crypto';
import { setSuperuser } from './core/users.js';
import { createPool } from './db/pool.js';

const USAGE = `Usage: pnpm cli <command>

  generate-key              Print a new KEY_ENCRYPTION_KEY
  grant-superuser <email>   Give an account full administrative access
  revoke-superuser <email>  Take it away again
`;

const [command, argument] = process.argv.slice(2);

async function withPool<T>(work: (pool: ReturnType<typeof createPool>) => Promise<T>): Promise<T> {
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error('DATABASE_URL is required');
  const pool = createPool(url, 1);
  try {
    return await work(pool);
  } finally {
    await pool.end();
  }
}

switch (command) {
  case 'generate-key':
    console.log(randomBytes(32).toString('base64'));
    break;
  case 'grant-superuser':
  case 'revoke-superuser': {
    if (!argument) throw new Error('An email address is required');
    const grant = command === 'grant-superuser';
    const user = await withPool((pool) => setSuperuser(pool, argument, grant));
    console.log(`${user.email} is ${grant ? 'now' : 'no longer'} a superuser`);
    break;
  }
  default:
    console.log(USAGE);
    process.exitCode = command ? 1 : 0;
}
