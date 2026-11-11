import { loadConfig } from './config.js';
import { createPool } from './db/pool.js';
import { buildApp } from './http/app.js';

const config = loadConfig();
const pool = createPool(config.DATABASE_URL, config.DATABASE_POOL_MAX);
const { app } = await buildApp({ config, pool });

let shuttingDown = false;
const shutdown = async (signal: string) => {
  if (shuttingDown) return;
  shuttingDown = true;
  app.log.info({ signal }, 'shutting down');
  try {
    await app.close();
    await pool.end();
    process.exit(0);
  } catch (error) {
    app.log.error({ err: error }, 'shutdown failed');
    process.exit(1);
  }
};
process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));

await app.listen({ host: config.HOST, port: config.PORT });
app.log.info({ modules: config.MODULES }, 'gatehouse is ready');
