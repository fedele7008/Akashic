import type { Config } from "tailwindcss";

// Phase 8: minimal Tailwind setup. Component library (shadcn/ui or
// Radix) and an actual design system land in chapters 4-6 when the
// real UI gets built. For Chapter 2's scaffold, we just want
// utility classes available so a placeholder landing page can render
// without inline styles.
const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      // Reserve space for theme tokens that operator-rebranding will
      // populate (chapter 4's landing page will use AKASHIC_PORTAL_*
      // env vars). Keeping the extend block here so a future-me knows
      // where to put them.
      colors: {},
      fontFamily: {},
    },
  },
  plugins: [],
};

export default config;
