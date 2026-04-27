import type { NextConfig } from "next";

// Standalone output bundles the app into a self-contained Node.js
// directory we can drop into a slim runtime container. This is the
// recommended pattern for Docker deployments — see
// https://nextjs.org/docs/app/api-reference/next-config-js/output#automatically-copying-traced-files
//
// The result lives at `.next/standalone/` after `next build` and
// contains a minimal node_modules + a server.js entry point. The
// runtime stage of the Dockerfile copies this directory and runs
// `node server.js`.
const nextConfig: NextConfig = {
  output: "standalone",

  // Phase 8: trust X-Forwarded-* headers from the docker proxy in
  // front of us. The proxy sets X-Forwarded-Proto (http vs https),
  // X-Forwarded-For (real client IP), Host. Without this, Next would
  // see the proxy's IP and HTTP scheme and produce wrong redirects.
  // Mirrors the admin-bff's `isHTTPS()` trick in pkg/admin_bff/csrf.go.
  experimental: {
    serverActions: {
      // Allow forms posted from the operator-configured deployment
      // domains. The default would only allow same-origin which is
      // fine in production but can trip up dev environments where
      // the host TLS terminator and the docker proxy talk via
      // different hostnames.
      allowedOrigins: ["*"],
    },
  },
};

export default nextConfig;
