#!/bin/bash
# Development utility: Reset PostgreSQL database
# WARNING: This will DELETE ALL DATA - only use in development!

set -e

echo "=================================================="
echo "  Akashic Database Reset (DEVELOPMENT ONLY)"
echo "=================================================="
echo ""
echo "WARNING: This will delete ALL data in the database!"
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

DB_NAME="${AKASHIC_DATABASE_POSTGRES_DB:-akashic}"
DB_USER="${AKASHIC_DATABASE_POSTGRES_USERNAME:-admin}"

echo ""
echo "Dropping and recreating database: $DB_NAME"
echo ""

# Drop and recreate database
docker exec -i akashic-postgres psql -U "$DB_USER" -d postgres <<EOF
DROP DATABASE IF EXISTS $DB_NAME;
CREATE DATABASE $DB_NAME;
EOF

echo ""
echo "✓ Database reset successfully!"
echo ""
echo "You can now start Akashic, and migrations will run automatically."
echo ""
