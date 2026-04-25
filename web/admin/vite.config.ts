import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Vite config for the Akashic admin FE.
//
// In production builds, the output `dist/` directory is embedded into
// the Go BFF binary via embed.FS and served by the BFF directly.
// In dev (`npm run dev`), Vite hosts on port 5173 and proxies any
// `/api` request to the BFF on `:8082` so HMR works without CORS.
//
// The `base: ''` setting makes Vite emit relative asset URLs in
// index.html. That matters because the BFF serves the same index.html
// at any path under "/" (SPA fallback), and absolute paths would
// break when the FE is served from a subdirectory.
export default defineConfig({
  plugins: [react()],
  base: '',
  build: {
    // Output directly into cmd/admin-bff/dist/ so the Go binary's
    // //go:embed directive can pick it up. Co-locating the embed
    // source with the main package that embeds it (rather than
    // symlinking from web/admin/dist/) keeps both `go build` and
    // `npm run build` simple and order-independent.
    outDir: '../../cmd/admin-bff/dist',
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8082',
        changeOrigin: false,
      },
    },
  },
});
