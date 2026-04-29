/**
 * Akashic widgets — entry point.
 *
 * Importing this module registers all `<akashic-*>` custom elements
 * on the global `customElements` registry. Tenants embed via:
 *
 *   <script src="https://api.<tenant>/widgets/akashic.js"></script>
 *   <akashic-signup></akashic-signup>
 *
 * Side-effect: also exposes `window.Akashic` for the rare case where
 * a tenant prefers programmatic mounting (e.g., conditional rendering
 * based on framework state). Auto-registration is the expected path.
 */

// Note: akashic-default.css is shipped as a separate, optional asset
// (public/akashic-default.css → dist/akashic-default.css). Tenants
// who want our baseline styling load it via:
//   <link rel="stylesheet" href="https://api.<tenant>/widgets/akashic-default.css">
// Tenants who supply their own CSS skip the link tag entirely. The
// JS bundle does NOT auto-inject styles.

import { configure, getConfig, type AkashicConfig } from "./lib/config";
import { mount } from "./lib/mount";

// Side-effect imports register the elements.
import "./components/akashic-signup";
import "./components/akashic-signin";
import "./components/akashic-forgot-help";
import "./components/akashic-profile";
import "./components/akashic-change-password";
import "./components/akashic-clients";

declare global {
  interface Window {
    Akashic?: {
      configure: (cfg: Partial<AkashicConfig>) => void;
      getConfig: () => AkashicConfig;
      mount: typeof mount;
    };
  }
}

window.Akashic = { configure, getConfig, mount };

export { configure, getConfig, mount };
export type { AkashicConfig };
