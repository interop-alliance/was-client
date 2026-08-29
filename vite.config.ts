import { defineConfig } from 'vitest/config'

/**
 * Vitest configuration, plus the dev server that Playwright drives for the
 * browser tests. The port is pinned (and `strictPort` set) so a dev server from
 * another project cannot silently answer the browser suite's requests.
 */
export default defineConfig({
  server: {
    port: 5183,
    strictPort: true
  },
  test: {
    include: ['test/node/**/*.test.ts', 'src/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['src/**/*.ts']
    }
  }
})
