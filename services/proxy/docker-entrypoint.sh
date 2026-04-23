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

exec nginx -g "daemon off;"
