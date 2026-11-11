import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    coverage: { include: ['src/**'], exclude: ['src/server.ts'] },
    projects: [
      {
        // Pure logic. Needs no database, so it runs anywhere.
        test: { name: 'unit', include: ['test/unit/**/*.test.ts'] },
      },
      {
        test: {
          name: 'integration',
          include: ['test/integration/**/*.test.ts'],
          // These tests share one database, so files run one at a time.
          fileParallelism: false,
          globalSetup: ['test/integration/global-setup.ts'],
        },
      },
    ],
  },
});
