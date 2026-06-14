import { defineConfig } from 'vitest/config'

/**
 * Vitest config for the live-server integration tier (`test/integration/`).
 * Kept separate from the default config (`vite.config.ts`, which runs the
 * server-free `test/node/` unit suite) so `pnpm test:node` never reaches for a
 * server. These tests require `TEST_SERVER_URL` and skip when it is unset.
 */
export default defineConfig({
  test: {
    include: ['test/integration/**/*.test.ts']
  }
})
