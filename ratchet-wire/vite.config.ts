/// <reference types="vitest/config" />
import { defineConfig } from 'vitest/config'

export default defineConfig({
  base: '/crypto-lab-ratchet-wire/',
  server: {
    port: 5173,
    strictPort: true
  },
  build: {
    outDir: 'dist',
    minify: true,
    sourcemap: true
  },
  test: {
    // Unit/integration tests only. Playwright specs live in e2e/ and are run by
    // `npm run test:e2e`, not Vitest.
    include: ['src/**/*.test.ts']
  }
})
