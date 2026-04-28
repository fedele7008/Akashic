import { defineConfig } from "vite";
import { resolve } from "node:path";

/**
 * Library-mode build: emits a single ESM bundle plus the default
 * stylesheet. Output is hosted at `api.<tenant>/widgets/akashic.js`
 * and `api.<tenant>/widgets/akashic-default.css`.
 *
 * Bundle is self-contained — Lit is bundled in, not externalised.
 * Tenants embed it via a single <script src="..."> tag with no
 * import-map plumbing.
 */
export default defineConfig({
  build: {
    target: "es2022",
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: true,
    cssCodeSplit: false,
    lib: {
      entry: resolve(__dirname, "src/index.ts"),
      formats: ["es"],
      fileName: () => "akashic.js",
    },
    rollupOptions: {
      output: {
        // Single CSS file regardless of how many components contribute styles.
        assetFileNames: (asset) => {
          if (asset.name?.endsWith(".css")) return "akashic-default.css";
          return asset.name ?? "[name]";
        },
      },
    },
  },
});
