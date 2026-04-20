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
CONFIGS_DIR="${CONFIGS_DIR:-/configs}"

source "${SCRIPT_DIR}/util.sh"

main() {
    log_header "Akashic Infrastructure PKI Setup"
    log "Script directory: ${SCRIPT_DIR}"

    # Wait for Vault to be available
    if ! wait_for_vault; then
        log_error "Failed to connect to Vault"
        return 1
    fi

    # =========================================================================
    # Step 1: Vault initialization
    # =========================================================================
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

    # =========================================================================
    # Step 2: Vault unseal
    # =========================================================================
    log_section "Step 2: Vault unseal"

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

    # =========================================================================
    # Step 3: Mount PKI secret engines
    # =========================================================================
    log_section "Step 3: Mount PKI secret engines"

    mount_engine() {
        local path=$1
        local description=$2
        local config_file="${CONFIGS_DIR}/mount/${path}.json"

        log "Mounting PKI engine: ${path}"

        local mount_args=("-t" "${VAULT_TOKEN_FILE}" "-d" "${description}")
        if [[ -f "${config_file}" ]]; then
            mount_args+=("-f" "${config_file}")
            log "Using config: ${config_file}"
        else
            log_warning "Config file not found: ${config_file}, using defaults"
        fi

        print_log_output_header
        akashic-cli pki vault engine mount "${path}" "${mount_args[@]}"
        local mount_result=$?
        print_log_output_footer

        if [[ ${mount_result} -eq 0 ]]; then
            log_success "PKI engine mounted: ${path}"
        else
            log_error "Failed to mount PKI engine: ${path}"
            return 1
        fi
    }

    # Root CA — offline anchor, 10-year TTL
    mount_engine "pki-root" "Akashic Root CA" || return 1

    # Internal CA — subordinate CA for non-public services, 5-year TTL
    mount_engine "pki-internal" "Akashic Internal CA" || return 1

    # Public CA — dev CA for browser-facing certs, 5-year TTL
    mount_engine "pki-public" "Akashic Public CA (Development)" || return 1

    # mTLS CAs — per-service isolation, 5-year TTL
    mount_engine "pki-mtls-akashic-ctrl" "Akashic Control Plane mTLS CA" || return 1
    mount_engine "pki-mtls-ldap" "LDAP mTLS CA" || return 1
    mount_engine "pki-mtls-loki" "Loki mTLS CA" || return 1

    log_success "All PKI engines mounted successfully"

    # =========================================================================
    # Step 4: Generate Root CA
    # =========================================================================
    log_section "Step 4: Generate Root CA"

    generate_root() {
        local engine=$1
        local output=$2
        local config_file="${CONFIGS_DIR}/root/${engine}.json"

        log "Generating root CA: ${engine}"

        local gen_args=("-e" "${engine}" "-o" "${output}" "-t" "${VAULT_TOKEN_FILE}")
        if [[ -f "${config_file}" ]]; then
            gen_args+=("-f" "${config_file}")
            log "Using config: ${config_file}"
        else
            log_warning "Config file not found: ${config_file}, using defaults"
        fi

        print_log_output_header
        akashic-cli pki vault engine generate root internal "${gen_args[@]}"
        local gen_result=$?
        print_log_output_footer

        if [[ ${gen_result} -eq 0 ]]; then
            log_success "Root CA generated: ${output}"
        else
            log_error "Failed to generate root CA: ${engine}"
            return 1
        fi
    }

    generate_root "pki-root" "${CERTS_OUTPUT_DIR}/ca/roots/root-ca.crt" || return 1

    log_success "Root CA generated successfully"

    # =========================================================================
    # Step 5: Generate Intermediate CA CSRs
    # =========================================================================
    log_section "Step 5: Generate Intermediate CA CSRs"

    generate_csr() {
        local engine=$1
        local output=$2
        local config_file="${CONFIGS_DIR}/csr/${engine}.json"

        log "Generating CSR: ${engine}"

        local gen_args=("-e" "${engine}" "-o" "${output}" "-t" "${VAULT_TOKEN_FILE}")
        if [[ -f "${config_file}" ]]; then
            gen_args+=("-f" "${config_file}")
            log "Using config: ${config_file}"
        else
            log_warning "Config file not found: ${config_file}, using defaults"
        fi

        print_log_output_header
        akashic-cli pki vault engine generate csr internal "${gen_args[@]}"
        local gen_result=$?
        print_log_output_footer

        if [[ ${gen_result} -eq 0 ]]; then
            log_success "CSR generated: ${output}"
        else
            log_error "Failed to generate CSR: ${engine}"
            return 1
        fi
    }

    generate_csr "pki-internal" "${CERTS_OUTPUT_DIR}/ca/internal-ca.csr" || return 1
    generate_csr "pki-public" "${CERTS_OUTPUT_DIR}/ca/public-ca.csr" || return 1
    generate_csr "pki-mtls-akashic-ctrl" "${CERTS_OUTPUT_DIR}/ca/mtls/akashic-ctrl/akashic-ctrl-ca.csr" || return 1
    generate_csr "pki-mtls-ldap" "${CERTS_OUTPUT_DIR}/ca/mtls/ldap/ldap-ca.csr" || return 1
    generate_csr "pki-mtls-loki" "${CERTS_OUTPUT_DIR}/ca/mtls/loki/loki-ca.csr" || return 1

    log_success "All intermediate CA CSRs generated successfully"
}

main
log_success "Akashic Infrastructure PKI setup complete"
