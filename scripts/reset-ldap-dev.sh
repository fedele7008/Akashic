#!/bin/bash
# Development utility: Reset LDAP directory
# WARNING: This will DELETE ALL LDAP DATA - only use in development!

set -e

echo "=================================================="
echo "  Akashic LDAP Reset (DEVELOPMENT ONLY)"
echo "=================================================="
echo ""
echo "WARNING: This will delete ALL data in LDAP!"
echo "  - All users (ou=users)"
echo "  - All groups (ou=groups)"
echo "  - All organizational units"
echo ""
read -p "Are you sure you want to continue? (type 'yes'): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Aborted."
    exit 0
fi

# Load environment variables
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

LDAP_ADMIN_PASSWORD="${AKASHIC_LDAP_ADMIN_PASSWORD:-admin}"
BASE_DN="${AKASHIC_LDAP_BASE_DN:-dc=akashic,dc=local}"

echo ""
echo "Checking if LDAP container is running..."
if ! docker ps | grep -q akashic-ldap; then
    echo "ERROR: LDAP container (akashic-ldap) is not running!"
    echo "Start it with: docker compose up -d openldap"
    exit 1
fi

echo ""
echo "Deleting LDAP directory structure..."
echo ""

# Function to delete an entry if it exists
delete_entry() {
    local dn="$1"
    echo "  → Deleting: $dn"
    docker exec akashic-ldap ldapdelete -x -H ldap://localhost \
        -D "cn=admin,$BASE_DN" \
        -w "$LDAP_ADMIN_PASSWORD" \
        -r "$dn" 2>/dev/null || echo "    (entry doesn't exist or already deleted)"
}

# Delete organizational units and their contents
# Note: -r flag recursively deletes child entries
delete_entry "ou=users,$BASE_DN"
delete_entry "ou=groups,$BASE_DN"

echo ""
echo "✓ LDAP directory reset successfully!"
echo ""
echo "The base DN ($BASE_DN) and admin user remain intact."
echo ""
echo "When you start Akashic, the LDAP structure will be recreated automatically:"
echo "  - ou=users,$BASE_DN"
echo "  - ou=groups,$BASE_DN"
echo ""
