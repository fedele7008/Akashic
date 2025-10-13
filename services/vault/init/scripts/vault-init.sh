#!/bin/bash

set -u

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

VAULT_ADDR="${VAULT_ADDR:-https://vault:8200}"
VAULT_TOKEN_FILE="${VAULT_TOKEN_FILE:-/vault/file/.vault-token}"
VAULT_CAPATH="${VAULT_CAPATH:-/vault/certs/vault/root-ca.crt}"
CERTS_OUTPUT_DIR="${CERTS_OUTPUT_DIR:-/vault/certs}"

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

    if ! command_exists curl; then
        log_error "curl is not installed"
        return 1
    fi

    # Wait for Vault to be available
    if ! wait_for_vault; then
        log_error "Failed to connect to Vault"
        return 1
    fi
}

main
echo "Akashic Infrastructure PKI setup complete"

# tail -f /dev/null