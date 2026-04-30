#!/bin/sh
set -e

# Generate adminer auth config (included by nginx.conf)
if [ -n "$ADMINER_AUTH_USER" ] && [ -n "$ADMINER_AUTH_PASSWORD" ]; then
    HASH=$(openssl passwd -apr1 "$ADMINER_AUTH_PASSWORD")
    echo "$ADMINER_AUTH_USER:$HASH" > /etc/nginx/adminer.htpasswd
    cat > /etc/nginx/adminer-auth.conf <<'EOF'
auth_basic           "Adminer";
auth_basic_user_file /etc/nginx/adminer.htpasswd;
EOF
    echo "[proxy] Basic auth configured for adminer (user: $ADMINER_AUTH_USER)"
else
    cat > /etc/nginx/adminer-auth.conf <<'EOF'
auth_basic off;
EOF
    echo "[proxy] No adminer credentials set -- basic auth disabled"
fi

# Generate redisinsight auth config (included by nginx.conf)
if [ -n "$REDISINSIGHT_AUTH_USER" ] && [ -n "$REDISINSIGHT_AUTH_PASSWORD" ]; then
    HASH=$(openssl passwd -apr1 "$REDISINSIGHT_AUTH_PASSWORD")
    echo "$REDISINSIGHT_AUTH_USER:$HASH" > /etc/nginx/redisinsight.htpasswd
    cat > /etc/nginx/redisinsight-auth.conf <<'EOF'
auth_basic           "RedisInsight";
auth_basic_user_file /etc/nginx/redisinsight.htpasswd;
EOF
    echo "[proxy] Basic auth configured for redisinsight (user: $REDISINSIGHT_AUTH_USER)"
else
    cat > /etc/nginx/redisinsight-auth.conf <<'EOF'
auth_basic off;
EOF
    echo "[proxy] No redisinsight credentials set -- basic auth disabled"
fi

# Generate phpldapadmin auth config (included by nginx.conf)
if [ -n "$PHPLDAPADMIN_AUTH_USER" ] && [ -n "$PHPLDAPADMIN_AUTH_PASSWORD" ]; then
    HASH=$(openssl passwd -apr1 "$PHPLDAPADMIN_AUTH_PASSWORD")
    echo "$PHPLDAPADMIN_AUTH_USER:$HASH" > /etc/nginx/phpldapadmin.htpasswd
    cat > /etc/nginx/phpldapadmin-auth.conf <<'EOF'
auth_basic           "phpLDAPadmin";
auth_basic_user_file /etc/nginx/phpldapadmin.htpasswd;
EOF
    echo "[proxy] Basic auth configured for phpldapadmin (user: $PHPLDAPADMIN_AUTH_USER)"
else
    cat > /etc/nginx/phpldapadmin-auth.conf <<'EOF'
auth_basic off;
EOF
    echo "[proxy] No phpldapadmin credentials set -- basic auth disabled"
fi

# ─── /etc/hosts IPv4-only pinning for host-gateway aliases ────────────
#
# On Docker Desktop for Mac with IPv6 enabled, `extra_hosts` entries
# using `host-gateway` get BOTH an IPv4 and an IPv6 line in /etc/hosts.
# nginx's static `proxy_pass https://akashic:8082` resolves via libc,
# which (per RFC 3484) prefers IPv6, but the IPv6 host-gateway alias
# `fdc4:f303:9324::254` isn't reachable from container userspace —
# every upstream connect() fails with "Network unreachable" and nginx
# returns 404 from its temporarily-disabled-upstream backoff.
#
# Fix: drop IPv6 entries for the akashic-* aliases so libc returns
# only the IPv4 form. Deletes lines whose first token contains a `:`
# (IPv6 syntax) AND whose subsequent tokens include any akashic alias.
# Idempotent — runs once at proxy startup.
HOSTS_TMP="$(mktemp)"
awk '
  # Pass through any line that does not have ":" in the first column —
  # i.e., everything that is not an IPv6 entry. This includes blank
  # lines, comments, and IPv4 entries.
  $1 !~ /:/ { print; next }

  # For IPv6 entries, drop the line if any subsequent token names one
  # of our host-gateway aliases. Keep all other IPv6 lines intact
  # (loopback, link-local, etc.).
  {
    drop = 0
    for (i = 2; i <= NF; i++) {
      if ($i == "akashic" \
          || $i == "akashic.akashic.local" \
          || $i == "auth.akashic.local" \
          || $i == "ctrl.akashic.local" \
          || $i == "api.akashic.local" \
          || $i == "host.docker.internal") {
        drop = 1
        break
      }
    }
    if (!drop) print
  }
' /etc/hosts > "$HOSTS_TMP"
cat "$HOSTS_TMP" > /etc/hosts
rm -f "$HOSTS_TMP"
echo "[proxy] /etc/hosts IPv6 entries for host-gateway aliases removed"

exec nginx -g "daemon off;"
