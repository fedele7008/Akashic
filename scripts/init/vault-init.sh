#!/bin/bash
# Vault Initialization Script
# Initializes and unseals HashiCorp Vault

set -e

# Configuration
VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
VAULT_CAPATH="${VAULT_CAPATH:-/vault/certs/vault/root-ca.crt}"
VAULT_DEV_MODE="${VAULT_DEV_MODE:-true}"
VAULT_INIT_FILE="${VAULT_INIT_FILE:-/vault/file/vault-init.json}"
VAULT_TOKEN_FILE="${VAULT_TOKEN_FILE:-/vault/file/.vault-token}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} ✓ $*"
}

log_error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} ✗ $*"
}

log_warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} ⚠ $*"
}

# Wait for Vault to be available
wait_for_vault() {
    log "Waiting for Vault to be available at ${VAULT_ADDR}..."
    local max_retries=30
    local retry=0

    while [ $retry -lt $max_retries ]; do
        if curl --cacert ${VAULT_CAPATH} -s "${VAULT_ADDR}/v1/sys/health" > /dev/null 2>&1 || \
           curl --cacert ${VAULT_CAPATH} -s "${VAULT_ADDR}/v1/sys/health" | grep -q "sealed\|initialized" 2>&1; then
            log_success "Vault is available"
            return 0
        fi

        retry=$((retry + 1))
        log "Attempt ${retry}/${max_retries} - Vault not ready yet..."
        sleep 2
    done

    log_error "Vault did not become available after ${max_retries} attempts"
    return 1
}

# Check if Vault is already initialized
is_vault_initialized() {
    local response
    response=$(curl --cacert ${VAULT_CAPATH} -s "${VAULT_ADDR}/v1/sys/health" || echo "{}")
    echo "$response" | grep -q '"initialized":true'
}

# Initialize Vault
initialize_vault() {
    log "Initializing Vault..."

    if [ "$VAULT_DEV_MODE" = "true" ]; then
        log_warning "Running in DEV MODE - using predefined root token"
        log_warning "This is INSECURE and should NEVER be used in production!"

        # In dev mode, initialize with 1 key share and 1 key threshold for simplicity
        local init_response
        init_response=$(curl --cacert ${VAULT_CAPATH} -s -X PUT "${VAULT_ADDR}/v1/sys/init" \
            -H "Content-Type: application/json" \
            -d '{
                "secret_shares": 1,
                "secret_threshold": 1
            }')

        # Save initialization data
        echo "$init_response" > "$VAULT_INIT_FILE"
        chmod 600 "$VAULT_INIT_FILE"

        # Extract root token and unseal key
        ROOT_TOKEN=$(echo "$init_response" | grep -o '"root_token":"[^"]*"' | cut -d'"' -f4)
        UNSEAL_KEY=$(echo "$init_response" | grep -o '"keys":\["[^"]*"\]' | sed 's/.*\["\(.*\)"\].*/\1/')

        # Save root token
        echo "$ROOT_TOKEN" > "$VAULT_TOKEN_FILE"
        chmod 600 "$VAULT_TOKEN_FILE"

        log_success "Vault initialized successfully"
        log "Root token saved to: $VAULT_TOKEN_FILE"
        log "Initialization data saved to: $VAULT_INIT_FILE"

        # Export for unsealing
        export VAULT_UNSEAL_KEY="$UNSEAL_KEY"
        export VAULT_TOKEN="$ROOT_TOKEN"

    else
        log "Running in PRODUCTION MODE"

        # In production, use more secure defaults
        local init_response
        init_response=$(curl --cacert ${VAULT_CAPATH} -s -X PUT "${VAULT_ADDR}/v1/sys/init" \
            -H "Content-Type: application/json" \
            -d '{
                "secret_shares": 5,
                "secret_threshold": 3
            }')

        # Save initialization data (IMPORTANT: Store this securely!)
        echo "$init_response" > "$VAULT_INIT_FILE"
        chmod 600 "$VAULT_INIT_FILE"

        log_success "Vault initialized successfully"
        log_warning "IMPORTANT: Initialization data saved to: $VAULT_INIT_FILE"
        log_warning "IMPORTANT: Backup this file securely and remove it from the server!"
        log_warning "IMPORTANT: You will need 3 out of 5 unseal keys to unseal Vault"

        # Extract root token
        ROOT_TOKEN=$(echo "$init_response" | grep -o '"root_token":"[^"]*"' | cut -d'"' -f4)
        echo "$ROOT_TOKEN" > "$VAULT_TOKEN_FILE"
        chmod 600 "$VAULT_TOKEN_FILE"

        export VAULT_TOKEN="$ROOT_TOKEN"
    fi
}

# Unseal Vault
unseal_vault() {
    log "Unsealing Vault..."

    if [ "$VAULT_DEV_MODE" = "true" ]; then
        # In dev mode, use the single unseal key
        if [ -z "$VAULT_UNSEAL_KEY" ]; then
            # Try to load from init file
            if [ -f "$VAULT_INIT_FILE" ]; then
                VAULT_UNSEAL_KEY=$(cat "$VAULT_INIT_FILE" | grep -o '"keys":\["[^"]*"\]' | sed 's/.*\["\(.*\)"\].*/\1/')
            else
                log_error "No unseal key available and init file not found"
                return 1
            fi
        fi

        curl --cacert ${VAULT_CAPATH} -s -X PUT "${VAULT_ADDR}/v1/sys/unseal" \
            -H "Content-Type: application/json" \
            -d "{\"key\": \"$VAULT_UNSEAL_KEY\"}" > /dev/null

        log_success "Vault unsealed successfully"

    else
        log_warning "Production mode requires manual unsealing with 3 out of 5 keys"
        log "Use the keys from: $VAULT_INIT_FILE"
        log "Run: vault operator unseal <key>"

        # TODO: In production, implement auto-unseal with cloud KMS
        # For now, we'll assume manual unsealing or cloud auto-unseal is configured
    fi
}

# Load existing root token
load_existing_token() {
    if [ -f "$VAULT_TOKEN_FILE" ]; then
        VAULT_TOKEN=$(cat "$VAULT_TOKEN_FILE")
        export VAULT_TOKEN
        log "Loaded existing root token from: $VAULT_TOKEN_FILE"
    else
        log_error "Vault is initialized but no root token found!"
        log_error "Check: $VAULT_TOKEN_FILE"
        return 1
    fi
}

# Main execution
main() {
    log "=== Vault Initialization ==="
    log "Vault Address: ${VAULT_ADDR}"
    log "Dev Mode: ${VAULT_DEV_MODE}"

    # Wait for Vault to be ready
    if ! wait_for_vault; then
        log_error "Failed to connect to Vault"
        exit 1
    fi

    # Check if already initialized
    if is_vault_initialized; then
        log_warning "Vault is already initialized"

        # Check if sealed
        local health_response
        health_response=$(curl --cacert ${VAULT_CAPATH} -s "${VAULT_ADDR}/v1/sys/health" || echo "{}")

        if echo "$health_response" | grep -q '"sealed":true'; then
            log "Vault is sealed, attempting to unseal..."
            load_existing_token
            unseal_vault
        else
            log_success "Vault is already unsealed"
            load_existing_token
        fi
    else
        log "Vault is not initialized, initializing now..."
        initialize_vault
        unseal_vault
    fi

    # Verify Vault is ready
    if curl --cacert ${VAULT_CAPATH} -s "${VAULT_ADDR}/v1/sys/health" | grep -q '"sealed":false'; then
        log_success "Vault is ready for use"
        log "Root token: ${VAULT_TOKEN}"
        return 0
    else
        log_error "Vault initialization completed but Vault is not ready"
        return 1
    fi
}

# Run main function
main "$@"
