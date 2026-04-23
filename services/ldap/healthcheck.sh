#!/bin/sh
# LDAP healthcheck that adapts to TLS on/off
if [ "$LDAP_TLS_MODE" = "on" ]; then
    # LDAPS on port 636 with CA verification
    LDAPTLS_CACERT=/container/service/slapd/assets/certs/ca.crt \
        ldapsearch -x -H ldaps://localhost:636 -b "" -s base 2>/dev/null | grep -q "result:"
else
    ldapsearch -x -H ldap://localhost:389 -b "" -s base 2>/dev/null | grep -q "result:"
fi
