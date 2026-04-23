#!/bin/sh
# Loki healthcheck that adapts to TLS on/off
if [ "$LOKI_TLS_MODE" = "on" ]; then
    wget -q --no-check-certificate -O - "https://127.0.0.1:3100/ready" 2>/dev/null | grep -q "ready"
else
    wget -q -O - "http://127.0.0.1:3100/ready" 2>/dev/null | grep -q "ready"
fi
