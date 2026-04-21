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
            log "- Using config: ${config_file}"
        else
            log_warning "- Config file not found: ${config_file}, using defaults"
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
            log "- Using config: ${config_file}"
        else
            log_warning "- Config file not found: ${config_file}, using defaults"
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
            log "- Using config: ${config_file}"
        else
            log_warning "- Config file not found: ${config_file}, using defaults"
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

    # =========================================================================
    # Step 6: Sign Intermediate CA CSRs
    # =========================================================================
    log_section "Step 6: Sign Intermediate CA CSRs"

    sign_intermediate() {
        local signer_engine=$1
        local csr_file=$2
        local output=$3
        local config_name=$4
        local config_file="${CONFIGS_DIR}/sign/${config_name}.json"

        log "Signing CSR: ${csr_file}"
        log "- Signer: ${signer_engine} → Output: ${output}"

        local sign_args=("-e" "${signer_engine}" "--csr" "${csr_file}" "-o" "${output}" "-t" "${VAULT_TOKEN_FILE}")
        if [[ -f "${config_file}" ]]; then
            sign_args+=("-f" "${config_file}")
            log "- Using config: ${config_file}"
        else
            log_warning "- Config file not found: ${config_file}, using defaults"
        fi

        print_log_output_header
        akashic-cli pki vault engine sign intermediate "${sign_args[@]}"
        local sign_result=$?
        print_log_output_footer

        if [[ ${sign_result} -eq 0 ]]; then
            log_success "Certificate signed: ${output}"
        else
            log_error "Failed to sign intermediate: ${csr_file}"
            return 1
        fi
    }

    # Sign pki-internal and pki-public with pki-root
    sign_intermediate "pki-root" \
        "${CERTS_OUTPUT_DIR}/ca/internal-ca.csr" \
        "${CERTS_OUTPUT_DIR}/ca/internal-ca.crt" \
        "pki-internal" || return 1

    sign_intermediate "pki-root" \
        "${CERTS_OUTPUT_DIR}/ca/public-ca.csr" \
        "${CERTS_OUTPUT_DIR}/ca/public-ca.crt" \
        "pki-public" || return 1

    log_success "Internal and Public CA certificates signed by Root"

    # =========================================================================
    # Step 7: Register signed certificates into their engines
    # =========================================================================
    log_section "Step 7: Register signed certificates"

    register_cert() {
        local engine=$1
        local cert_file=$2

        log "Registering certificate into engine: ${engine}"
        log "- Certificate: ${cert_file}"

        print_log_output_header
        akashic-cli pki vault engine register -e "${engine}" --cert "${cert_file}" -t "${VAULT_TOKEN_FILE}"
        local reg_result=$?
        print_log_output_footer

        if [[ ${reg_result} -eq 0 ]]; then
            log_success "Certificate registered: ${engine}"
        else
            log_error "Failed to register certificate: ${engine}"
            return 1
        fi
    }

    # Register Internal CA and Public CA (activates them as signing CAs)
    register_cert "pki-internal" "${CERTS_OUTPUT_DIR}/ca/internal-ca.crt" || return 1
    register_cert "pki-public" "${CERTS_OUTPUT_DIR}/ca/public-ca.crt" || return 1

    log_success "Internal and Public CA engines activated"

    # =========================================================================
    # Step 8: Sign mTLS CA CSRs with Internal CA
    # =========================================================================
    log_section "Step 8: Sign mTLS CA CSRs with Internal CA"

    # Now that pki-internal is active, use it to sign the mTLS CAs
    sign_intermediate "pki-internal" \
        "${CERTS_OUTPUT_DIR}/ca/mtls/akashic-ctrl/akashic-ctrl-ca.csr" \
        "${CERTS_OUTPUT_DIR}/ca/mtls/akashic-ctrl/akashic-ctrl-ca.crt" \
        "pki-mtls-akashic-ctrl" || return 1

    sign_intermediate "pki-internal" \
        "${CERTS_OUTPUT_DIR}/ca/mtls/ldap/ldap-ca.csr" \
        "${CERTS_OUTPUT_DIR}/ca/mtls/ldap/ldap-ca.crt" \
        "pki-mtls-ldap" || return 1

    sign_intermediate "pki-internal" \
        "${CERTS_OUTPUT_DIR}/ca/mtls/loki/loki-ca.csr" \
        "${CERTS_OUTPUT_DIR}/ca/mtls/loki/loki-ca.crt" \
        "pki-mtls-loki" || return 1

    log_success "All mTLS CA certificates signed by Internal CA"

    # =========================================================================
    # Step 9: Register mTLS CA certificates
    # =========================================================================
    log_section "Step 9: Register mTLS CA certificates"

    register_cert "pki-mtls-akashic-ctrl" "${CERTS_OUTPUT_DIR}/ca/mtls/akashic-ctrl/akashic-ctrl-ca.crt" || return 1
    register_cert "pki-mtls-ldap" "${CERTS_OUTPUT_DIR}/ca/mtls/ldap/ldap-ca.crt" || return 1
    register_cert "pki-mtls-loki" "${CERTS_OUTPUT_DIR}/ca/mtls/loki/loki-ca.crt" || return 1

    log_success "All mTLS CA engines activated"

    # =========================================================================
    # Step 10: Configure CRL/CA URLs
    # =========================================================================
    log_section "Step 10: Configure CRL/CA URLs"

    configure_urls() {
        local engine=$1

        log "Configuring URLs: ${engine}"

        print_log_output_header
        akashic-cli pki vault engine config urls -e "${engine}" -t "${VAULT_TOKEN_FILE}"
        local url_result=$?
        print_log_output_footer

        if [[ ${url_result} -eq 0 ]]; then
            log_success "URLs configured: ${engine}"
        else
            log_error "Failed to configure URLs: ${engine}"
            return 1
        fi
    }

    configure_urls "pki-root" || return 1
    configure_urls "pki-internal" || return 1
    configure_urls "pki-public" || return 1
    configure_urls "pki-mtls-akashic-ctrl" || return 1
    configure_urls "pki-mtls-ldap" || return 1
    configure_urls "pki-mtls-loki" || return 1

    log_success "All CRL/CA URLs configured"

    # =========================================================================
    # Step 11: Create PKI Roles
    # =========================================================================
    log_section "Step 11: Create PKI Roles"

    create_role() {
        local engine=$1
        local role_name=$2
        local config_file="${CONFIGS_DIR}/roles/${engine}-${role_name}.json"

        log "Creating role: ${engine}/${role_name}"

        local role_args=("-e" "${engine}" "-t" "${VAULT_TOKEN_FILE}")
        if [[ -f "${config_file}" ]]; then
            role_args+=("-f" "${config_file}")
            log "- Using config: ${config_file}"
        else
            log_error "- Config file not found: ${config_file}"
            return 1
        fi

        print_log_output_header
        akashic-cli pki vault engine role create "${role_name}" "${role_args[@]}"
        local role_result=$?
        print_log_output_footer

        if [[ ${role_result} -eq 0 ]]; then
            log_success "Role created: ${engine}/${role_name}"
        else
            log_error "Failed to create role: ${engine}/${role_name}"
            return 1
        fi
    }

    # Internal CA roles
    create_role "pki-internal" "server" || return 1

    # Public CA roles
    create_role "pki-public" "server" || return 1

    # mTLS CA roles (server + client for each)
    create_role "pki-mtls-akashic-ctrl" "server" || return 1
    create_role "pki-mtls-akashic-ctrl" "client" || return 1
    create_role "pki-mtls-ldap" "server" || return 1
    create_role "pki-mtls-ldap" "client" || return 1
    create_role "pki-mtls-loki" "server" || return 1
    create_role "pki-mtls-loki" "client" || return 1

    log_success "All PKI roles created"

    # =========================================================================
    # Step 12: Issue Leaf Certificates
    # =========================================================================
    log_section "Step 12: Issue Leaf Certificates"

    issue_cert() {
        local engine=$1
        local role=$2
        local config_name=$3
        local cert_out=$4
        local key_out=$5
        local config_file="${CONFIGS_DIR}/issue/${config_name}.json"

        log "Issuing: ${config_name}"
        log "- Engine: ${engine}, Role: ${role}"

        local issue_args=("-e" "${engine}" "-r" "${role}" "-o" "${cert_out}" "--key-out" "${key_out}" "-t" "${VAULT_TOKEN_FILE}")
        if [[ -f "${config_file}" ]]; then
            issue_args+=("-f" "${config_file}")
            log "- Config: ${config_file}"
        else
            log_error "- Config file not found: ${config_file}"
            return 1
        fi

        print_log_output_header
        akashic-cli pki vault engine issue "${issue_args[@]}"
        local issue_result=$?
        print_log_output_footer

        if [[ ${issue_result} -eq 0 ]]; then
            log_success "Certificate issued: ${cert_out}"
        else
            log_error "Failed to issue certificate: ${config_name}"
            return 1
        fi
    }

    # --- Internal server certificates (pki-internal/server) ---
    issue_cert "pki-internal" "server" "akashic-ctrl" \
        "${CERTS_OUTPUT_DIR}/akashic/ctrl.crt" \
        "${CERTS_OUTPUT_DIR}/akashic/ctrl.key" || return 1

    issue_cert "pki-internal" "server" "akashic-auth" \
        "${CERTS_OUTPUT_DIR}/akashic/auth.crt" \
        "${CERTS_OUTPUT_DIR}/akashic/auth.key" || return 1

    issue_cert "pki-internal" "server" "postgres" \
        "${CERTS_OUTPUT_DIR}/postgres/postgres.crt" \
        "${CERTS_OUTPUT_DIR}/postgres/postgres.key" || return 1

    issue_cert "pki-internal" "server" "redis" \
        "${CERTS_OUTPUT_DIR}/redis/redis.crt" \
        "${CERTS_OUTPUT_DIR}/redis/redis.key" || return 1

    issue_cert "pki-internal" "server" "ldap-server" \
        "${CERTS_OUTPUT_DIR}/ldap/ldap.crt" \
        "${CERTS_OUTPUT_DIR}/ldap/ldap.key" || return 1

    issue_cert "pki-internal" "server" "loki-server" \
        "${CERTS_OUTPUT_DIR}/loki/loki.crt" \
        "${CERTS_OUTPUT_DIR}/loki/loki.key" || return 1

    # --- mTLS: Control Plane (pki-mtls-akashic-ctrl) ---
    issue_cert "pki-mtls-akashic-ctrl" "server" "mtls-ctrl-server" \
        "${CERTS_OUTPUT_DIR}/akashic/mtls-ctrl.crt" \
        "${CERTS_OUTPUT_DIR}/akashic/mtls-ctrl.key" || return 1

    issue_cert "pki-mtls-akashic-ctrl" "client" "mtls-ctrl-client-cli" \
        "${CERTS_OUTPUT_DIR}/akashic-cli/akashic-ctrl-client.crt" \
        "${CERTS_OUTPUT_DIR}/akashic-cli/akashic-ctrl-client.key" || return 1

    issue_cert "pki-mtls-akashic-ctrl" "client" "mtls-ctrl-client-bff" \
        "${CERTS_OUTPUT_DIR}/bff/akashic-ctrl-client.crt" \
        "${CERTS_OUTPUT_DIR}/bff/akashic-ctrl-client.key" || return 1

    # --- mTLS: LDAP (pki-mtls-ldap) ---
    issue_cert "pki-mtls-ldap" "server" "mtls-ldap-server" \
        "${CERTS_OUTPUT_DIR}/ldap/mtls-ldap.crt" \
        "${CERTS_OUTPUT_DIR}/ldap/mtls-ldap.key" || return 1

    issue_cert "pki-mtls-ldap" "client" "mtls-ldap-client-akashic" \
        "${CERTS_OUTPUT_DIR}/akashic/ldap-client.crt" \
        "${CERTS_OUTPUT_DIR}/akashic/ldap-client.key" || return 1

    issue_cert "pki-mtls-ldap" "client" "mtls-ldap-client-phpldapadmin" \
        "${CERTS_OUTPUT_DIR}/phpldapadmin/ldap-client.crt" \
        "${CERTS_OUTPUT_DIR}/phpldapadmin/ldap-client.key" || return 1

    # --- mTLS: Loki (pki-mtls-loki) ---
    issue_cert "pki-mtls-loki" "server" "mtls-loki-server" \
        "${CERTS_OUTPUT_DIR}/loki/mtls-loki.crt" \
        "${CERTS_OUTPUT_DIR}/loki/mtls-loki.key" || return 1

    issue_cert "pki-mtls-loki" "client" "mtls-loki-client-akashic" \
        "${CERTS_OUTPUT_DIR}/akashic/loki-client.crt" \
        "${CERTS_OUTPUT_DIR}/akashic/loki-client.key" || return 1

    issue_cert "pki-mtls-loki" "client" "mtls-loki-client-grafana" \
        "${CERTS_OUTPUT_DIR}/grafana/loki-client.crt" \
        "${CERTS_OUTPUT_DIR}/grafana/loki-client.key" || return 1

    log_success "All leaf certificates issued"
}

main
log_success "Akashic Infrastructure PKI setup complete"
