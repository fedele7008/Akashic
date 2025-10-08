#!/bin/bash
# Development utility: Reset ALL data stores (PostgreSQL + LDAP + Redis)
# WARNING: This will DELETE ALL DATA - only use in development!

set -e

echo "=========================================================="
echo "  Akashic Complete Reset (DEVELOPMENT ONLY)"
echo "=========================================================="
echo ""
echo "This will reset ALL data stores:"
echo "  ✗ PostgreSQL database (all tables dropped)"
echo "  ✗ LDAP directory (all users/groups deleted)"
echo "  ✗ Redis cache (all sessions/cache cleared)"
echo "  ✗ Bootstrap status (will need new bootstrap)"
echo ""
echo "WARNING: This is IRREVERSIBLE!"
echo ""
read -p "Are you sure you want to continue? (type 'YES' in capitals): " confirm

if [ "$confirm" != "YES" ]; then
    echo "Aborted."
    exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo "=================================================="
echo "Step 1/3: Resetting PostgreSQL..."
echo "=================================================="
echo ""

# Run PostgreSQL reset (non-interactive)
if [ -f "$SCRIPT_DIR/reset-db-dev.sh" ]; then
    # Bypass the confirmation by piping "yes"
    echo "yes" | bash "$SCRIPT_DIR/reset-db-dev.sh"
else
    echo "ERROR: reset-db-dev.sh not found!"
    exit 1
fi

echo ""
echo "=================================================="
echo "Step 2/3: Resetting LDAP..."
echo "=================================================="
echo ""

# Run LDAP reset (non-interactive)
if [ -f "$SCRIPT_DIR/reset-ldap-dev.sh" ]; then
    # Bypass the confirmation by piping "yes"
    echo "yes" | bash "$SCRIPT_DIR/reset-ldap-dev.sh"
else
    echo "ERROR: reset-ldap-dev.sh not found!"
    exit 1
fi

echo ""
echo "=================================================="
echo "Step 3/3: Flushing Redis..."
echo "=================================================="
echo ""

# Load environment variables
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

if docker ps | grep -q akashic-redis; then
    echo "  → Flushing all Redis data..."
    docker exec akashic-redis redis-cli FLUSHALL
    echo "  ✓ Redis flushed"
else
    echo "  ⚠ Redis container not running (skipped)"
fi

echo ""
echo "=========================================================="
echo "  ✓ Complete Reset Successful!"
echo "=========================================================="
echo ""
echo "All data has been cleared. You can now:"
echo ""
echo "  1. Start Akashic server:"
echo "     ./build/akashic run --verbose"
echo ""
echo "  2. The server will automatically:"
echo "     - Run PostgreSQL migrations (create tables)"
echo "     - Initialize LDAP structure (create OUs)"
echo "     - Generate a new bootstrap token"
echo ""
echo "  3. Create root user via bootstrap API"
echo ""
echo "Environment is ready for fresh testing!"
echo ""
