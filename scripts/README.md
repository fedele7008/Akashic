# Development Scripts

Utility scripts for Akashic development.

## Database Management

### Reset Database (Development Only)

Completely resets the PostgreSQL database, deleting all data and schema.

```bash
./scripts/reset-db-dev.sh
```

**Warning:** This is destructive and should only be used in development!

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
# 1. Start database services
docker-compose up -d postgres redis

# 2. Run Akashic (migrations run automatically on first start)
go run cmd/akashic/main.go run --verbose

# 3. Bootstrap will be displayed in console
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
