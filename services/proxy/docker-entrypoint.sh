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

exec nginx -g "daemon off;"
