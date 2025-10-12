#!/bin/bash
# Vault PKI Setup Script
# Configures HashiCorp Vault PKI secrets engines and generates certificate hierarchy

set -e

# Configuration
VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-}"
VAULT_CAPATH="${VAULT_CAPATH:-/vault/certs/vault/root-ca.crt}"
VAULT_TOKEN_FILE="${VAULT_TOKEN_FILE:-/vault/file/.vault-token}"
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

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
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

log_section() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN} $*${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
}

# Load Vault token
load_vault_token() {
    if [ -z "$VAULT_TOKEN" ]; then
        if [ -f "$VAULT_TOKEN_FILE" ]; then
            VAULT_TOKEN=$(cat "$VAULT_TOKEN_FILE")
            export VAULT_TOKEN
            log "Loaded Vault token from: $VAULT_TOKEN_FILE"
        else
            log_error "No Vault token provided and token file not found: $VAULT_TOKEN_FILE"
            exit 1
        fi
    fi
}

# Check if PKI engine is already enabled
is_pki_enabled() {
    local mount_path=$1
    curl --cacert ${VAULT_CAPATH} -s -H "X-Vault-Token: ${VAULT_TOKEN}" \
        "${VAULT_ADDR}/v1/sys/mounts" | grep -q "\"${mount_path}/\""
}

# Enable PKI secrets engine
enable_pki_engine() {
    local mount_path=$1
    local description=$2
    local max_ttl=$3

    log "Enabling PKI secrets engine at: ${mount_path}"

    if is_pki_enabled "$mount_path"; then
        log_warning "PKI engine already enabled at: ${mount_path}"
        return 0
    fi

    curl --cacert ${VAULT_CAPATH} -s -X POST \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{
            \"type\": \"pki\",
            \"description\": \"${description}\",
            \"config\": {
                \"max_lease_ttl\": \"${max_ttl}\"
            }
        }" \
        "${VAULT_ADDR}/v1/sys/mounts/${mount_path}"

    log_success "PKI engine enabled at: ${mount_path}"
}

# Generate Root CA
generate_root_ca() {
    log_section "Generating Root CA"

    enable_pki_engine "pki" "Root CA" "$ROOT_CA_TTL"

    # Generate root CA
    log "Generating root CA certificate..."

    local response
    response=$(curl --cacert ${VAULT_CAPATH} -s -X POST \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{
            \"common_name\": \"${ORG_NAME} Root CA\",
            \"issuer_name\": \"root-ca\",
            \"ttl\": \"${ROOT_CA_TTL}\",
            \"key_type\": \"rsa\",
            \"key_bits\": 4096,
            \"organization\": \"${ORG_NAME}\",
            \"ou\": \"${ORG_UNIT}\",
            \"country\": \"${COUNTRY}\"
        }" \
        "${VAULT_ADDR}/v1/pki/root/generate/internal")

    # Save root CA certificate
    mkdir -p "${CERTS_OUTPUT_DIR}/ca/roots"
    echo "$response" | grep -o '"certificate":"[^"]*"' | cut -d'"' -f4 | sed 's/\\n/\n/g' \
        > "${CERTS_OUTPUT_DIR}/ca/roots/root-ca.crt"

    # Configure CA URLs
    curl --cacert ${VAULT_CAPATH} -s -X POST \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{
            \"issuing_certificates\": [\"${VAULT_ADDR}/v1/pki/ca\"],
            \"crl_distribution_points\": [\"${VAULT_ADDR}/v1/pki/crl\"]
        }" \
        "${VAULT_ADDR}/v1/pki/config/urls" > /dev/null

    log_success "Root CA generated and saved to: ${CERTS_OUTPUT_DIR}/ca/roots/root-ca.crt"
}

# Generate Intermediate CA
generate_intermediate_ca() {
    log_section "Generating Intermediate CA"

    enable_pki_engine "pki_int" "Intermediate CA" "$INTERMEDIATE_CA_TTL"

    # Generate CSR for intermediate CA
    log "Generating intermediate CA CSR..."

    local csr_response
    csr_response=$(curl --cacert ${VAULT_CAPATH} -s -X POST \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{
            \"common_name\": \"${ORG_NAME} Intermediate CA\",
            \"issuer_name\": \"intermediate-ca\",
            \"key_type\": \"rsa\",
            \"key_bits\": 4096,
            \"organization\": \"${ORG_NAME}\",
            \"ou\": \"${ORG_UNIT}\",
            \"country\": \"${COUNTRY}\"
        }" \
        "${VAULT_ADDR}/v1/pki_int/intermediate/generate/internal")

    local csr
    csr=$(echo "$csr_response" | grep -o '"csr":"[^"]*"' | cut -d'"' -f4)

    # Sign intermediate CA with root CA
    log "Signing intermediate CA with root CA..."

    local signed_cert
    signed_cert=$(curl --cacert ${VAULT_CAPATH} -s -X POST \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{
            \"csr\": \"${csr}\",
            \"format\": \"pem_bundle\",
            \"ttl\": \"${INTERMEDIATE_CA_TTL}\"
        }" \
        "${VAULT_ADDR}/v1/pki/root/sign-intermediate" | grep -o '"certificate":"[^"]*"' | cut -d'"' -f4)

    # Set signed certificate as intermediate CA
    curl --cacert ${VAULT_CAPATH} -s -X POST \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{
            \"certificate\": \"${signed_cert}\"
        }" \
        "${VAULT_ADDR}/v1/pki_int/intermediate/set-signed" > /dev/null

    # Save intermediate CA certificate
    mkdir -p "${CERTS_OUTPUT_DIR}/ca"
    echo "$signed_cert" | sed 's/\\n/\n/g' > "${CERTS_OUTPUT_DIR}/ca/internal-ca.crt"

    # Configure intermediate CA URLs
    curl --cacert ${VAULT_CAPATH} -s -X POST \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{
            \"issuing_certificates\": [\"${VAULT_ADDR}/v1/pki_int/ca\"],
            \"crl_distribution_points\": [\"${VAULT_ADDR}/v1/pki_int/crl\"]
        }" \
        "${VAULT_ADDR}/v1/pki_int/config/urls" > /dev/null

    log_success "Intermediate CA generated and saved to: ${CERTS_OUTPUT_DIR}/ca/internal-ca.crt"
}

# Generate mTLS CA
generate_mtls_ca() {
    local service_name=$1
    local description=$2

    log_section "Generating mTLS CA for: ${service_name}"

    local mount_path="pki_mtls_${service_name}"
    enable_pki_engine "$mount_path" "$description" "$MTLS_CA_TTL"

    # Generate CSR for mTLS CA
    log "Generating mTLS CA CSR for ${service_name}..."

    local csr_response
    csr_response=$(curl --cacert ${VAULT_CAPATH} -s -X POST \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{
            \"common_name\": \"${ORG_NAME} ${description}\",
            \"issuer_name\": \"${service_name}-mtls-ca\",
            \"key_type\": \"rsa\",
            \"key_bits\": 2048,
            \"organization\": \"${ORG_NAME}\",
            \"ou\": \"mTLS - ${description}\",
            \"country\": \"${COUNTRY}\"
        }" \
        "${VAULT_ADDR}/v1/${mount_path}/intermediate/generate/internal")

    local csr
    csr=$(echo "$csr_response" | grep -o '"csr":"[^"]*"' | cut -d'"' -f4)

    # Sign mTLS CA with intermediate CA
    log "Signing ${service_name} mTLS CA with intermediate CA..."

    local signed_cert
    signed_cert=$(curl --cacert ${VAULT_CAPATH} -s -X POST \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{
            \"csr\": \"${csr}\",
            \"format\": \"pem_bundle\",
            \"ttl\": \"${MTLS_CA_TTL}\"
        }" \
        "${VAULT_ADDR}/v1/pki_int/root/sign-intermediate" | grep -o '"certificate":"[^"]*"' | cut -d'"' -f4)

    # Set signed certificate as mTLS CA
    curl --cacert ${VAULT_CAPATH} -s -X POST \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{
            \"certificate\": \"${signed_cert}\"
        }" \
        "${VAULT_ADDR}/v1/${mount_path}/intermediate/set-signed" > /dev/null

    # Save mTLS CA certificate
    mkdir -p "${CERTS_OUTPUT_DIR}/ca/mtls/${service_name}"
    echo "$signed_cert" | sed 's/\\n/\n/g' > "${CERTS_OUTPUT_DIR}/ca/mtls/${service_name}/${service_name}-ca.crt"

    # Configure mTLS CA URLs
    curl --cacert ${VAULT_CAPATH} -s -X POST \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{
            \"issuing_certificates\": [\"${VAULT_ADDR}/v1/${mount_path}/ca\"],
            \"crl_distribution_points\": [\"${VAULT_ADDR}/v1/${mount_path}/crl\"]
        }" \
        "${VAULT_ADDR}/v1/${mount_path}/config/urls" > /dev/null

    log_success "mTLS CA for ${service_name} generated and saved"
}

# Create PKI role
create_pki_role() {
    local mount_path=$1
    local role_name=$2
    local allowed_domains=$3
    local allow_subdomains=$4
    local allow_bare_domains=$5
    local allow_localhost=$6
    local ttl=$7
    local server_flag=$8
    local client_flag=$9

    log "Creating PKI role: ${role_name} in ${mount_path}"

    curl --cacert ${VAULT_CAPATH} -s -X POST \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{
            \"allowed_domains\": ${allowed_domains},
            \"allow_subdomains\": ${allow_subdomains},
            \"allow_bare_domains\": ${allow_bare_domains},
            \"allow_localhost\": ${allow_localhost},
            \"allow_ip_sans\": true,
            \"server_flag\": ${server_flag},
            \"client_flag\": ${client_flag},
            \"key_type\": \"rsa\",
            \"key_bits\": 2048,
            \"ttl\": \"${ttl}\",
            \"max_ttl\": \"${ttl}\",
            \"organization\": [\"${ORG_NAME}\"],
            \"ou\": [\"${ORG_UNIT}\"],
            \"country\": [\"${COUNTRY}\"]
        }" \
        "${VAULT_ADDR}/v1/${mount_path}/roles/${role_name}" > /dev/null

    log_success "PKI role created: ${role_name}"
}

# Setup server certificate roles
setup_server_roles() {
    log_section "Setting up Server Certificate Roles"

    # General server role (for akashic, bff, web, etc.)
    create_pki_role "pki_int" "server-general" \
        '["akashic.local","localhost","*.akashic.local"]' \
        true true true "$SERVER_CERT_TTL" true false

    # Database server role
    create_pki_role "pki_int" "server-database" \
        '["postgres","redis","localhost"]' \
        false true true "$SERVER_CERT_TTL" true false

    # LDAP server role
    create_pki_role "pki_int" "server-ldap" \
        '["ldap","ldap.akashic.local","localhost"]' \
        false true true "$SERVER_CERT_TTL" true false

    # Observability server role (Loki, Grafana)
    create_pki_role "pki_int" "server-observability" \
        '["loki","grafana","localhost"]' \
        false true true "$SERVER_CERT_TTL" true false
}

# Setup client certificate roles
setup_client_roles() {
    log_section "Setting up Client Certificate Roles"

    # General client role
    create_pki_role "pki_int" "client-general" \
        '["*.akashic.local"]' \
        false false false "$CLIENT_CERT_TTL" false true
}

# Setup mTLS roles for specific services
setup_mtls_roles() {
    log_section "Setting up mTLS Certificate Roles"

    # Akashic Control Plane mTLS role
    create_pki_role "pki_mtls_akashic_ctrl" "akashic-ctrl-client" \
        '["akashic-cli","akashic-bff"]' \
        false true false "$CLIENT_CERT_TTL" false true

    create_pki_role "pki_mtls_akashic_ctrl" "akashic-ctrl-server" \
        '["akashic-ctrl","localhost","127.0.0.1"]' \
        false true true "$SERVER_CERT_TTL" true false

    # LDAP mTLS role
    create_pki_role "pki_mtls_ldap" "ldap-client" \
        '["akashic","phpldapadmin"]' \
        false true false "$CLIENT_CERT_TTL" false true

    create_pki_role "pki_mtls_ldap" "ldap-server" \
        '["ldap","localhost"]' \
        false true true "$SERVER_CERT_TTL" true false

    # Loki mTLS role
    create_pki_role "pki_mtls_loki" "loki-client" \
        '["akashic","grafana"]' \
        false true false "$CLIENT_CERT_TTL" false true

    create_pki_role "pki_mtls_loki" "loki-server" \
        '["loki","localhost"]' \
        false true true "$SERVER_CERT_TTL" true false
}

# Create trust bundle
create_trust_bundle() {
    log_section "Creating Trust Bundle"

    mkdir -p "${CERTS_OUTPUT_DIR}/ca/trust"

    # Combine root CA and intermediate CA into trust bundle
    cat "${CERTS_OUTPUT_DIR}/ca/roots/root-ca.crt" \
        "${CERTS_OUTPUT_DIR}/ca/internal-ca.crt" \
        > "${CERTS_OUTPUT_DIR}/ca/trust/trust-bundle.pem"

    log_success "Trust bundle created: ${CERTS_OUTPUT_DIR}/ca/trust/trust-bundle.pem"
}

# Set proper permissions
set_permissions() {
    log_section "Setting File Permissions"

    # Make certificates readable by all services
    find "${CERTS_OUTPUT_DIR}" -type f -name "*.crt" -exec chmod 644 {} \;
    find "${CERTS_OUTPUT_DIR}" -type f -name "*.pem" -exec chmod 644 {} \;

    log_success "Permissions set correctly"
}

# Main execution
main() {
    log_section "Vault PKI Setup"
    log "Vault Address: ${VAULT_ADDR}"
    log "Certificate Output Directory: ${CERTS_OUTPUT_DIR}"

    # Load Vault token
    load_vault_token

    # Generate CA hierarchy
    generate_root_ca
    generate_intermediate_ca

    # Generate mTLS CAs
    generate_mtls_ca "akashic-ctrl" "Akashic Control Plane mTLS CA"
    generate_mtls_ca "ldap" "LDAP mTLS CA"
    generate_mtls_ca "loki" "Loki mTLS CA"

    # Setup PKI roles
    setup_server_roles
    setup_client_roles
    setup_mtls_roles

    # Create trust bundle
    create_trust_bundle

    # Set permissions
    set_permissions

    log_section "PKI Setup Complete"
    log_success "All PKI engines configured successfully"
    log_success "Certificates available in: ${CERTS_OUTPUT_DIR}"
    log ""
    log "Next steps:"
    log "  1. Services can now request certificates from Vault"
    log "  2. Use Vault Agent for automatic certificate renewal"
    log "  3. Configure services to use certificates from: ${CERTS_OUTPUT_DIR}"
}

# Run main function
main "$@"
