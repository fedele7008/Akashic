#!/bin/sh
# Redis healthcheck that adapts to TLS on/off
if [ "$REDIS_TLS" = "on" ]; then
    redis-cli --tls --cacert /certs/ca.crt -a "$REDIS_PASSWORD" ping 2>/dev/null | grep -q PONG
else
    redis-cli -a "$REDIS_PASSWORD" ping 2>/dev/null | grep -q PONG
fi
