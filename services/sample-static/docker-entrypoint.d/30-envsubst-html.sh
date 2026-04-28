#!/bin/sh
# Substitute `${AKASHIC_PORTAL_API_BASE_URL}` into the HTML pages
# AND into _oauth.js (which the OAuth helper reads as its API base
# URL — see the file for why it can't infer this at runtime). nginx:
# alpine's entrypoint runs scripts from /docker-entrypoint.d/ in
# order — this drops in at 30-, after the image's own template-
# processing scripts and before nginx itself.
#
# Idempotent in normal use: containers are stopped + recreated, so
# the templated files always start from the image's pristine copy
# each run. (Restart-without-recreate preserves the post-substitution
# file from the previous run, which is harmless because the
# substitution would produce the same output anyway as long as the
# env hasn't changed.)
#
# We pass the explicit `'${AKASHIC_PORTAL_API_BASE_URL}'` whitelist
# to envsubst so that any unrelated `${...}` patterns (e.g. JS
# template-string fragments) pass through untouched.

set -e

API_BASE_URL="${AKASHIC_PORTAL_API_BASE_URL:-https://api.akashic.example.com}"

# HTML pages — every page references the widget bundle via
# ${AKASHIC_PORTAL_API_BASE_URL}/widgets/akashic.js.
for f in /usr/share/nginx/html/*.html; do
    [ -f "$f" ] || continue
    AKASHIC_PORTAL_API_BASE_URL="$API_BASE_URL" \
        envsubst '${AKASHIC_PORTAL_API_BASE_URL}' < "$f" > "$f.subst"
    mv "$f.subst" "$f"
done

# _oauth.js — the OAuth helper sources its `apiBase` constant from
# the same env. (Other .js files, if any, are NOT templated; the
# allowlist below is intentional.)
for f in /usr/share/nginx/html/_oauth.js; do
    [ -f "$f" ] || continue
    AKASHIC_PORTAL_API_BASE_URL="$API_BASE_URL" \
        envsubst '${AKASHIC_PORTAL_API_BASE_URL}' < "$f" > "$f.subst"
    mv "$f.subst" "$f"
done

echo "[sample-static] templated HTML + _oauth.js with AKASHIC_PORTAL_API_BASE_URL=$API_BASE_URL"
