# ──────────────────────────────────────────────────────────────────────
# Akashic sample-static — minimal HTML demonstration
#
# Pure static HTML + the Akashic widget bundle. Demonstrates that
# widgets work with zero framework, zero backend, zero JS toolchain.
# Counterpart to services/portal (the Next.js sample).
#
# nginx serves the docs from /usr/share/nginx/html on port 3000 (the
# port the proxy expects from the sample-portal upstream alias).
# ──────────────────────────────────────────────────────────────────────
FROM nginx:alpine

COPY services/sample-static/nginx.conf /etc/nginx/conf.d/default.conf
COPY services/sample-static/html /usr/share/nginx/html

# Run envsubst over the HTML at container start so the api base URL
# can be operator-configured via env without rebuilding the image.
COPY services/sample-static/docker-entrypoint.d/ /docker-entrypoint.d/
RUN chmod +x /docker-entrypoint.d/*.sh

EXPOSE 3000

# Inherits nginx's default CMD (`nginx -g 'daemon off;'`) — and the
# stock nginx:alpine entrypoint runs everything in /docker-entrypoint.d/
# before launching nginx itself, so our envsubst script fires
# automatically.
