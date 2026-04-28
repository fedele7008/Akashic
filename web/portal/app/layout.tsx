import type { Metadata } from "next";

import { env } from "../lib/env";
import "./globals.css";

// Phase 8b: the sample portal is a widget consumer. It loads the
// Akashic widget bundle from `api.<tenant>/widgets/akashic.js` once
// at the document level — every page that drops in <akashic-*> tags
// gets the registered custom elements automatically.
//
// Tenants integrating Akashic into their own product do exactly this
// (the sample portal serves as the worked example). The optional
// default stylesheet provides a baseline look that respects the
// `--akashic-*` CSS custom properties; tenants who want their own
// design system skip the stylesheet and write their own
// `::part(...)` rules instead.

export const metadata: Metadata = {
  title: process.env.AKASHIC_PORTAL_BRAND_NAME ?? "Akashic",
  description:
    process.env.AKASHIC_PORTAL_TAGLINE ??
    "Identity provider built on Akashic.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const widgetsBaseUrl = env.api.baseUrl;
  return (
    <html lang="en">
      <head>
        <link
          rel="stylesheet"
          href={`${widgetsBaseUrl}/widgets/akashic-default.css`}
        />
      </head>
      <body>
        {children}
        {/*
          Plain module <script> rather than next/script. next/script's
          beforeInteractive strategy preloads the bundle, but Next's
          preload `<link>` uses a different `crossorigin` mode than
          the actual script tag, which Chrome rejects as a credentials
          mismatch and re-fetches anyway. ESM modules are deferred by
          default — the bundle loads asynchronously, registers all
          `<akashic-*>` custom elements, and the elements upgrade in
          place even though they're already in the DOM. No preload
          dance needed.
        */}
        <script
          src={`${widgetsBaseUrl}/widgets/akashic.js`}
          type="module"
          async
        />
      </body>
    </html>
  );
}
