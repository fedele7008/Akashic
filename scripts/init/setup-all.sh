#!/bin/bash
set -eu

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Configuration
VAULT_CAPATH="${VAULT_CAPATH:-/vault/certs/vault/root-ca.crt}"
VAULT_ADDR="${VAULT_ADDR:-https://vault:8200}"
VAULT_TOKEN_FILE="${VAULT_TOKEN_FILE:-/vault/file/.vault-token}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
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

log_header() {
    echo ""
    echo -e "${MAGENTA}╔═══════════════════════════════════════════════════════════════════╗${NC}"
    printf "${MAGENTA}║${NC} %-78s ${MAGENTA}║${NC}\n" "$*"
    echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

log_section() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN} $*${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
}

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Wait for Vault to be available
wait_for_vault() {
    log "Waiting for Vault to be available at ${VAULT_ADDR}..."
    local max_retries=30
    local retry=0

    while [ $retry -lt $max_retries ]; do
        if curl --cacert ${VAULT_CAPATH} -s "${VAULT_ADDR}/v1/sys/health" > /dev/null 2>&1 || \
           curl --cacert ${VAULT_CAPATH} -s "${VAULT_ADDR}/v1/sys/health" | grep -q "sealed\|initialized" 2>&1; then
            log_success "Vault is reachable"
            return 0
        fi

        retry=$((retry + 1))
        log "Attempt ${retry}/${max_retries} - Vault not ready yet..."
        sleep 2
    done

    log_error "Vault did not become available after ${max_retries} attempts"
    return 1
}

# Run Vault initialization
run_vault_init() {
    log_section "Step 1: Vault Initialization"

    if [ ! -f "${SCRIPT_DIR}/vault-init.sh" ]; then
        log_error "vault-init.sh not found in ${SCRIPT_DIR}"
        return 1
    fi

    log "Running Vault initialization script..."
    bash "${SCRIPT_DIR}/vault-init.sh"

    if [ $? -eq 0 ]; then
        log_success "Vault initialization completed successfully"
        return 0
    else
        log_error "Vault initialization failed"
        return 1
    fi
}

# Run PKI setup
run_pki_setup() {
    log_section "Step 2: PKI Infrastructure Setup"

    if [ ! -f "${SCRIPT_DIR}/vault-pki-setup.sh" ]; then
        log_error "vault-pki-setup.sh not found in ${SCRIPT_DIR}"
        return 1
    fi

    # Load Vault token
    if [ -f "$VAULT_TOKEN_FILE" ]; then
        export VAULT_TOKEN=$(cat "$VAULT_TOKEN_FILE")
        log "Loaded Vault token from: $VAULT_TOKEN_FILE"
    else
        log_error "Vault token file not found: $VAULT_TOKEN_FILE"
        return 1
    fi

    log "Running PKI setup script..."
    bash "${SCRIPT_DIR}/vault-pki-setup.sh"

    if [ $? -eq 0 ]; then
        log_success "PKI setup completed successfully"
        return 0
    else
        log_error "PKI setup failed"
        return 1
    fi
}

# Verify setup
verify_setup() {
    log_section "Step 3: Verification"

    local errors=0

    # Check Vault status
    log "Checking Vault status..."
    if curl --cacert ${VAULT_CAPATH} -s "${VAULT_ADDR}/v1/sys/health" | grep -q '"sealed":false'; then
        log_success "Vault is unsealed and ready"
    else
        log_error "Vault is not in ready state"
        errors=$((errors + 1))
    fi

    # Check if PKI engines are mounted
    log "Checking PKI secrets engines..."
    local token=$(cat "$VAULT_TOKEN_FILE" 2>/dev/null || echo "")

    if [ -n "$token" ]; then
        local mounts=$(curl --cacert ${VAULT_CAPATH} -s -H "X-Vault-Token: ${token}" "${VAULT_ADDR}/v1/sys/mounts")

        if echo "$mounts" | grep -q '"pki/"'; then
            log_success "Root CA engine (pki/) is mounted"
        else
            log_error "Root CA engine not found"
            errors=$((errors + 1))
        fi

        if echo "$mounts" | grep -q '"pki_int/"'; then
            log_success "Intermediate CA engine (pki_int/) is mounted"
        else
            log_error "Intermediate CA engine not found"
            errors=$((errors + 1))
        fi

        if echo "$mounts" | grep -q '"pki_mtls_akashic_ctrl/"'; then
            log_success "mTLS CA for akashic-ctrl is mounted"
        else
            log_warning "mTLS CA for akashic-ctrl not found (may not be critical)"
        fi
    else
        log_warning "Could not verify PKI engines (no token available)"
    fi

    # Check if certificates were generated
    log "Checking generated certificates..."

    if [ -f "/vault/certs/ca/roots/root-ca.crt" ]; then
        log_success "Root CA certificate found"
    else
        log_error "Root CA certificate not found"
        errors=$((errors + 1))
    fi

    if [ -f "/vault/certs/ca/internal-ca.crt" ]; then
        log_success "Intermediate CA certificate found"
    else
        log_error "Intermediate CA certificate not found"
        errors=$((errors + 1))
    fi

    if [ -f "/vault/certs/ca/trust/trust-bundle.pem" ]; then
        log_success "Trust bundle found"
    else
        log_error "Trust bundle not found"
        errors=$((errors + 1))
    fi

    if [ $errors -eq 0 ]; then
        log_success "All verification checks passed"
        return 0
    else
        log_error "${errors} verification check(s) failed"
        return 1
    fi
}

# Print summary
print_summary() {
    log_section "Setup Summary"

    log "Vault Address: ${VAULT_ADDR}"

    if [ -f "$VAULT_TOKEN_FILE" ]; then
        local token=$(cat "$VAULT_TOKEN_FILE")
        log "Vault Root Token: ${token}"
        log ""
        log_warning "IMPORTANT: Save the root token securely!"
        log_warning "You can access the Vault UI at: ${VAULT_ADDR}/ui"
    fi

    log ""
    log "Generated Certificates:"
    log "  Root CA:          /vault/certs/ca/roots/root-ca.crt"
    log "  Intermediate CA:  /vault/certs/ca/internal-ca.crt"
    log "  Trust Bundle:     /vault/certs/ca/trust/trust-bundle.pem"
    log "  mTLS CAs:         /vault/certs/ca/mtls/"

    log ""
    log "PKI Secrets Engines:"
    log "  Root CA:          pki/"
    log "  Intermediate CA:  pki_int/"
    log "  mTLS CAs:         pki_mtls_akashic_ctrl/, pki_mtls_ldap/, pki_mtls_loki/"

    log ""
    log "Next Steps:"
    log "  1. Services can now request certificates from Vault"
    log "  2. Use Vault Agent for automatic certificate provisioning"
    log "  3. Configure services to trust the CA bundle"
    log "  4. Enable mTLS on services that require it"
}

# Cleanup on error
cleanup_on_error() {
    log_error "Setup failed, performing cleanup..."
    # Add any cleanup logic here if needed
}

# Main execution
main() {
    log_header "Akashic Infrastructure Setup"

    log "Starting infrastructure setup..."
    log "Script Directory: ${SCRIPT_DIR}"

    # Check prerequisites
    if ! command_exists curl; then
        log_error "curl is not installed"
        exit 1
    fi

    # Wait for Vault to be available
    if ! wait_for_vault; then
        log_error "Failed to connect to Vault"
        exit 1
    fi

    # Run initialization steps
    local failed=0

    # Step 1: Initialize Vault
    if ! run_vault_init; then
        log_error "Vault initialization failed"
        failed=1
    fi

    # Step 2: Setup PKI
    if [ $failed -eq 0 ]; then
        if ! run_pki_setup; then
            log_error "PKI setup failed"
            failed=1
        fi
    fi

    # Step 3: Verify setup
    if [ $failed -eq 0 ]; then
        if ! verify_setup; then
            log_warning "Setup verification found issues (setup may still be functional)"
        fi
    fi

    # Print results
    if [ $failed -eq 0 ]; then
        log_header "Setup Completed Successfully"
        print_summary
        exit 0
    else
        log_header "Setup Failed"
        cleanup_on_error
        exit 1
    fi
}

# Handle script interruption
trap 'log_error "Script interrupted"; cleanup_on_error; exit 130' INT TERM

# tail -f /dev/null
# Run main function
main "$@"