import { defineConfig } from 'vite'

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
  }
})
