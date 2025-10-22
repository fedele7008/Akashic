#!/bin/bash

set -u

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

AKASHIC_SECRET="${AKASHIC_SECRET:-}"
AKASHIC_VAULT_ADDRESS="${AKASHIC_VAULT_ADDRESS:-https://vault:8200}"
AKASHIC_VAULT_TLS_CACERT="${AKASHIC_VAULT_TLS_CACERT:-/certs/vault/root-ca.crt}"
CERTS_OUTPUT_DIR="${CERTS_OUTPUT_DIR:-/certs}"
VAULT_TOKEN_FILE="${VAULT_TOKEN_FILE:-/vault/token/vault/root-token.enc}"
VAULT_KEY_DIR="${VAULT_KEY_DIR:-/vault/token/vault/keys}"

# PKI Configuration
ROOT_CA_TTL="87600h"           # 10 years
INTERMEDIATE_CA_TTL="43800h"   # 5 years
MTLS_CA_TTL="43800h"           # 5 years
SERVER_CERT_TTL="8760h"        # 1 year
CLIENT_CERT_TTL="8760h"        # 1 year

# Organization details
ORG_NAME="Akashic"
ORG_UNIT="Security"
COUNTRY="US"

source "${SCRIPT_DIR}/util.sh"

main() {
    log_header "Akashic Infrastructure PKI Setup"
    log "Script directory: ${SCRIPT_DIR}"

    # Wait for Vault to be available
    if ! wait_for_vault; then
        log_error "Failed to connect to Vault"
        return 1
    fi

    # Run vault initialization
    log_section "Step 1: Vault initialization"

    # Check if vault is already initialized
    local status_response
    status_response=$(akashic-cli pki vault status || echo "{}") > /dev/null 2>&1
    echo "$status_response" | grep -q 'initialized: true'
    if [[ $? -eq 0 ]]; then
        # CASE: Vault is already initialized
        log "Vault is already initialized"
    else
        # CASE: Vault is not initialized
        log "Vault is not initialized. Initializing..."
        print_log_output_header
        akashic-cli pki vault init --keys 5 --thresholds 3 --key-out-dir "${VAULT_KEY_DIR}" --key-out-format "vault-key.enc" --root-out "${VAULT_TOKEN_FILE}" --override
        init_response=$?
        print_log_output_footer
        if [[ ${init_response} -eq 0 ]]; then
            log_success "Vault initialization successful"
        else
            log_error "Vault initialization failed"
            return 1
        fi

        log "Inspecting tokens..."
        print_log_output_header
        akashic-cli pki token inspect -i "${VAULT_TOKEN_FILE}" -i "${VAULT_KEY_DIR}/*.enc"
        print_log_output_footer
    fi

    # Check if vault is already unsealed
    status_response=$(akashic-cli pki vault status || echo "{}") > /dev/null 2>&1
    echo "$status_response" | grep -q 'sealed: false'
    if [[ $? -eq 0 ]]; then
        # CASE: Vault is already unsealed
        log "Vault is already unsealed"
    else
        # CASE: Vault is not unsealed
        log "Vault is sealed. Unsealing..."
        print_log_output_header
        akashic-cli pki vault unseal -i "${VAULT_KEY_DIR}/*.enc"
        unseal_response=$?
        print_log_output_footer
        if [[ ${unseal_response} -eq 0 ]]; then
            log_success "Vault unseal successful"
        else
            log_error "Vault unseal failed"
            return 1
        fi
    fi

    log "Vault status..."
    print_log_output_header
    akashic-cli pki vault status
    print_log_output_footer

    log_success "Vault initialization successful"
}

main
log_success "Akashic Infrastructure PKI setup complete"
