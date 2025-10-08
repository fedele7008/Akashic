# Development Scripts

Utility scripts for Akashic development.

**⚠️ WARNING: Reset scripts DELETE DATA and should ONLY be used in development!**

## Reset Scripts

### Complete System Reset

Resets ALL data stores: PostgreSQL, LDAP, and Redis in one command.

```bash
./scripts/reset-all-dev.sh
```

**What it does:**
1. PostgreSQL: Drops and recreates database
2. LDAP: Deletes all organizational units and users
3. Redis: Flushes all sessions and cache

**Requires:** Type `YES` (in capitals) to confirm

**Use when:** Starting completely fresh for testing

---

### Individual Reset Scripts

#### Reset PostgreSQL Database

Completely resets the PostgreSQL database, deleting all data and schema.

```bash
./scripts/reset-db-dev.sh
```

**Use when:** Testing database migrations only

#### Reset LDAP Directory

Deletes all organizational units and user entries from LDAP.

```bash
./scripts/reset-ldap-dev.sh
```

**What it deletes:**
- `ou=users,dc=akashic,dc=local` (and all user entries)
- `ou=groups,dc=akashic,dc=local` (and all group entries)

**What remains:**
- Base DN: `dc=akashic,dc=local`
- Admin user: `cn=admin,dc=akashic,dc=local`

**Use when:** Testing LDAP user creation or bootstrap flow

---

## Database Management

### Fix Dirty Migration State

If migrations fail partway through, the database can be in a "dirty" state. There are two ways to fix this:

#### Option 1: Environment Variable (Automatic Fix)

Set the `AKASHIC_FORCE_MIGRATION_VERSION` environment variable to force the migration version:

```bash
AKASHIC_FORCE_MIGRATION_VERSION=1 go run cmd/akashic/main.go run --verbose
```

#### Option 2: Manual Database Reset

Use the reset script (development only):

```bash
./scripts/reset-db-dev.sh
go run cmd/akashic/main.go run --verbose
```

## Migration Behavior

The migration system now:
- ✅ Only runs migrations when needed
- ✅ Skips if database is already up-to-date
- ✅ Detects dirty states with helpful error messages
- ✅ Provides automatic fix via environment variable

### Migration States

- **Clean, up-to-date**: No migrations run, server starts normally
- **Pending migrations**: Migrations run automatically on startup
- **Dirty state**: Server won't start, provides instructions for fix

## Quick Start After Fresh Clone

```bash
# 1. Start all services
docker compose up -d

# 2. Run Akashic (migrations and LDAP structure created automatically)
./build/akashic run --verbose

# 3. Bootstrap token will be displayed in console
```

## Usage Examples

### Testing Bootstrap Flow (Complete)

```bash
# 1. Reset everything to fresh state
./scripts/reset-all-dev.sh
# Type: YES

# 2. Start server (auto-creates LDAP structure and generates bootstrap token)
./build/akashic run --verbose

# 3. Get bootstrap status
curl http://localhost:8081/bootstrap/status | jq

# 4. Create root user
curl -X POST http://localhost:8081/bootstrap/user \
  -H "Content-Type: application/json" \
  -d '{
    "bootstrap_token": "YOUR_TOKEN_HERE",
    "username": "admin",
    "email": "admin@example.com",
    "password": "SecurePass123"
  }' | jq

# 5. Verify user created in LDAP
docker exec akashic-ldap ldapsearch -x -H ldap://localhost \
  -D "cn=admin,dc=akashic,dc=local" \
  -w "$AKASHIC_LDAP_ADMIN_PASSWORD" \
  -b "ou=users,dc=akashic,dc=local" "(uid=admin)"
```

### Testing LDAP Auto-Initialization

```bash
# 1. Reset only LDAP
./scripts/reset-ldap-dev.sh
# Type: yes

# 2. Verify LDAP structure deleted
docker exec akashic-ldap ldapsearch -x -H ldap://localhost \
  -D "cn=admin,dc=akashic,dc=local" \
  -w "$AKASHIC_LDAP_ADMIN_PASSWORD" \
  -b "dc=akashic,dc=local" "(objectClass=organizationalUnit)" dn

# 3. Start server (OUs auto-created)
./build/akashic run --verbose
# Look for: "organizational unit created successfully"

# 4. Verify structure exists
docker exec akashic-ldap ldapsearch -x -H ldap://localhost \
  -D "cn=admin,dc=akashic,dc=local" \
  -w "$AKASHIC_LDAP_ADMIN_PASSWORD" \
  -b "dc=akashic,dc=local" "(objectClass=organizationalUnit)" dn
```

## Troubleshooting

### "Dirty database" error

**Cause:** A previous migration was interrupted.

**Solution 1 (Quick):**
```bash
AKASHIC_FORCE_MIGRATION_VERSION=1 go run cmd/akashic/main.go run
```

**Solution 2 (Clean slate):**
```bash
./scripts/reset-db-dev.sh
go run cmd/akashic/main.go run
```

### Database connection refused

**Cause:** PostgreSQL container not running.

**Solution:**
```bash
docker-compose up -d postgres
```
