#!/usr/bin/env bash

# ============================================================================
# Akashic Init Container Setup Script
# ============================================================================
# This script runs as an init container in Docker Compose to:
# 1. Check for existing certificates
# 2. Build Akashic binary if needed
# 3. Generate PKI certificates if missing
# 4. Create certificate compatibility layer for 3rd party apps
# 5. Validate all components are ready
#
# This enables "clone and run" deployment with zero manual configuration.
# ============================================================================

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CERTS_DIR="${PROJECT_ROOT}/certs"
BUILD_DIR="${PROJECT_ROOT}/build"
AKASHIC_BIN="${BUILD_DIR}/akashic"
INIT_MARKER="${CERTS_DIR}/.initialized"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ============================================================================
# Utility Functions
# ============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# ============================================================================
# Check if initialization is needed
# ============================================================================

check_if_initialized() {
    if [[ -f "${INIT_MARKER}" ]]; then
        log_info "Initialization marker found: ${INIT_MARKER}"

        # Validate that certificates still exist
        if [[ -f "${CERTS_DIR}/ca/ca.crt" ]] && \
           [[ -f "${CERTS_DIR}/servers/control.crt" ]] && \
           [[ -f "${CERTS_DIR}/clients/cli.crt" ]]; then
            log_success "PKI certificates exist and are valid"
            return 0
        else
            log_warning "Initialization marker exists but certificates are missing"
            log_info "Re-initializing..."
            rm -f "${INIT_MARKER}"
            return 1
        fi
    else
        log_info "No initialization marker found - first time setup"
        return 1
    fi
}

# ============================================================================
# Build Akashic binary
# ============================================================================

build_akashic() {
    log_info "Building Akashic binary..."

    # Create build directory
    mkdir -p "${BUILD_DIR}"

    # Build the binary
    cd "${PROJECT_ROOT}"

    if command -v go &> /dev/null; then
        log_info "Go toolchain found, building binary..."
        go build -o "${AKASHIC_BIN}" ./cmd/akashic

        if [[ $? -eq 0 ]]; then
            log_success "Akashic binary built successfully: ${AKASHIC_BIN}"
            chmod +x "${AKASHIC_BIN}"
            return 0
        else
            log_error "Failed to build Akashic binary"
            return 1
        fi
    else
        log_warning "Go toolchain not found"
        log_info "Binary will be built inside Docker container"
        return 1
    fi
}

# ============================================================================
# Check if binary exists or build it
# ============================================================================

ensure_binary() {
    if [[ -f "${AKASHIC_BIN}" ]]; then
        log_success "Akashic binary found: ${AKASHIC_BIN}"
        return 0
    fi

    log_info "Akashic binary not found, building..."
    build_akashic
}

# ============================================================================
# Generate PKI certificates
# ============================================================================

generate_certificates() {
    log_info "Generating PKI certificates..."

    # Ensure binary exists
    if ! ensure_binary; then
        log_error "Cannot generate certificates without Akashic binary"
        log_error "Build the binary first or run this script inside Docker container"
        return 1
    fi

    # Create certs directory
    mkdir -p "${CERTS_DIR}"

    # Check if CA already exists
    if [[ -f "${CERTS_DIR}/ca/ca.crt" ]] && [[ -f "${CERTS_DIR}/ca/ca.key" ]]; then
        log_info "CA already exists, skipping initialization"
        log_success "Using existing CA: ${CERTS_DIR}/ca/ca.crt"
    else
        # Initialize CA
        log_info "Initializing Certificate Authority..."
        "${AKASHIC_BIN}" pki init --certs-dir "${CERTS_DIR}"

        if [[ $? -ne 0 ]]; then
            log_error "Failed to initialize CA"
            return 1
        fi

        log_success "CA initialized successfully"
    fi

    # Generate server certificates
    log_info "Generating server certificates..."

    # Control server certificate
    if [[ ! -f "${CERTS_DIR}/servers/control.crt" ]]; then
        "${AKASHIC_BIN}" pki generate-server \
            --certs-dir "${CERTS_DIR}" \
            --name control \
            --dns localhost,control,akashic-control \
            --ip 127.0.0.1
        log_info "Generated control server certificate"
    else
        log_info "Control server certificate already exists, skipping"
    fi

    # Auth server certificate
    if [[ ! -f "${CERTS_DIR}/servers/auth.crt" ]]; then
        "${AKASHIC_BIN}" pki generate-server \
            --certs-dir "${CERTS_DIR}" \
            --name auth \
            --dns localhost,auth,akashic-auth \
            --ip 127.0.0.1
        log_info "Generated auth server certificate"
    else
        log_info "Auth server certificate already exists, skipping"
    fi

    # LDAP server certificate (if using bundled LDAP)
    if [[ "${AKASHIC_USE_BUNDLED_LDAP:-true}" == "true" ]]; then
        if [[ ! -f "${CERTS_DIR}/servers/ldap.crt" ]]; then
            log_info "Generating LDAP server certificate..."
            "${AKASHIC_BIN}" pki generate-server \
                --certs-dir "${CERTS_DIR}" \
                --name ldap \
                --dns localhost,ldap,akashic-ldap,ldap.akashic.local \
                --ip 127.0.0.1
            log_info "Generated LDAP server certificate"
        else
            log_info "LDAP server certificate already exists, skipping"
        fi
    fi

    log_success "Server certificates ready"

    # Generate client certificates
    log_info "Generating client certificates..."

    # CLI client certificate
    if [[ ! -f "${CERTS_DIR}/clients/cli.crt" ]]; then
        "${AKASHIC_BIN}" pki generate-client \
            --certs-dir "${CERTS_DIR}" \
            --name cli \
            --dns localhost
        log_info "Generated CLI client certificate"
    else
        log_info "CLI client certificate already exists, skipping"
    fi

    # BFF client certificate (if using bundled BFF)
    if [[ "${AKASHIC_USE_BUNDLED_BFF:-true}" == "true" ]]; then
        if [[ ! -f "${CERTS_DIR}/clients/bff.crt" ]]; then
            log_info "Generating BFF client certificate..."
            "${AKASHIC_BIN}" pki generate-client \
                --certs-dir "${CERTS_DIR}" \
                --name bff \
                --dns localhost,bff,akashic-bff
            log_info "Generated BFF client certificate"
        else
            log_info "BFF client certificate already exists, skipping"
        fi
    fi

    log_success "Client certificates ready"

    # Verify certificates (optional - skip if fails)
    log_info "Verifying certificate chain..."
    if "${AKASHIC_BIN}" pki verify \
        --certs-dir "${CERTS_DIR}" \
        --cert servers/control.crt 2>/dev/null; then
        log_success "Certificate verification passed"
    else
        log_warning "Certificate verification skipped (optional)"
    fi

    return 0
}

# ============================================================================
# Create certificate compatibility layer
# ============================================================================

create_compatibility_layer() {
    log_info "Creating certificate compatibility layer for 3rd party apps..."

    local compat_dir="${CERTS_DIR}/compat"

    # LDAP compatibility directory
    if [[ "${AKASHIC_USE_BUNDLED_LDAP:-true}" == "true" ]]; then
        log_info "Setting up LDAP certificate compatibility..."

        local ldap_compat="${compat_dir}/ldap"
        mkdir -p "${ldap_compat}"

        # Create symlinks (for development) or copies (for production)
        # Using symlinks for easier updates during development
        ln -sf "../../servers/ldap.crt" "${ldap_compat}/ldap.crt"
        ln -sf "../../servers/ldap.key" "${ldap_compat}/ldap.key"
        ln -sf "../../ca/ca.crt" "${ldap_compat}/ca.crt"

        log_success "LDAP certificate compatibility layer created: ${ldap_compat}"
    fi

    # phpLDAPadmin compatibility directory
    if [[ "${AKASHIC_USE_BUNDLED_LDAP:-true}" == "true" ]]; then
        log_info "Setting up phpLDAPadmin certificate compatibility..."

        local phpldapadmin_compat="${compat_dir}/phpldapadmin"
        mkdir -p "${phpldapadmin_compat}"

        ln -sf "../../ca/ca.crt" "${phpldapadmin_compat}/ca.crt"

        log_success "phpLDAPadmin certificate compatibility layer created: ${phpldapadmin_compat}"
    fi

    # BFF compatibility directory (if using bundled BFF)
    if [[ "${AKASHIC_USE_BUNDLED_BFF:-true}" == "true" ]]; then
        log_info "Setting up BFF certificate compatibility..."

        local bff_compat="${compat_dir}/bff"
        mkdir -p "${bff_compat}"

        ln -sf "../../clients/bff.crt" "${bff_compat}/client.crt"
        ln -sf "../../clients/bff.key" "${bff_compat}/client.key"
        ln -sf "../../ca/ca.crt" "${bff_compat}/ca.crt"

        log_success "BFF certificate compatibility layer created: ${bff_compat}"
    fi

    log_success "Certificate compatibility layer setup complete"
}

# ============================================================================
# Set proper permissions
# ============================================================================

set_permissions() {
    log_info "Setting proper file permissions..."

    # Set permissions for CA private key (most sensitive)
    if [[ -f "${CERTS_DIR}/ca/ca.key" ]]; then
        chmod 400 "${CERTS_DIR}/ca/ca.key"
        log_info "CA private key: 400 (read-only for owner)"
    fi

    # Set permissions for server private keys
    find "${CERTS_DIR}/servers" -name "*.key" -exec chmod 400 {} \; 2>/dev/null || true
    log_info "Server private keys: 400 (read-only for owner)"

    # Set permissions for client private keys
    find "${CERTS_DIR}/clients" -name "*.key" -exec chmod 400 {} \; 2>/dev/null || true
    log_info "Client private keys: 400 (read-only for owner)"

    # Set permissions for certificates (public)
    find "${CERTS_DIR}" -name "*.crt" -exec chmod 644 {} \; 2>/dev/null || true
    log_info "Certificates: 644 (readable by all)"

    log_success "File permissions set successfully"
}

# ============================================================================
# Display certificate inventory
# ============================================================================

display_inventory() {
    log_info "Certificate Inventory:"
    echo ""
    echo "CA Certificate:"
    echo "  ${CERTS_DIR}/ca/ca.crt"
    echo ""

    echo "Server Certificates:"
    find "${CERTS_DIR}/servers" -name "*.crt" 2>/dev/null | while read -r cert; do
        echo "  ${cert}"
    done
    echo ""

    echo "Client Certificates:"
    find "${CERTS_DIR}/clients" -name "*.crt" 2>/dev/null | while read -r cert; do
        echo "  ${cert}"
    done
    echo ""

    echo "Compatibility Layer:"
    if [[ -d "${CERTS_DIR}/compat" ]]; then
        find "${CERTS_DIR}/compat" -type l 2>/dev/null | while read -r link; do
            echo "  ${link} -> $(readlink "${link}")"
        done
    fi
    echo ""
}

# ============================================================================
# Create initialization marker
# ============================================================================

create_marker() {
    log_info "Creating initialization marker..."

    cat > "${INIT_MARKER}" <<EOF
# Akashic PKI Initialization Marker
# This file indicates that PKI setup has been completed successfully.
# Delete this file to force re-initialization.

Initialized: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Version: 0.0.2

CA Certificate: ${CERTS_DIR}/ca/ca.crt
Server Certificates: ${CERTS_DIR}/servers/
Client Certificates: ${CERTS_DIR}/clients/
Compatibility Layer: ${CERTS_DIR}/compat/
EOF

    log_success "Initialization marker created: ${INIT_MARKER}"
}

# ============================================================================
# Main execution
# ============================================================================

main() {
    log_info "Akashic Init Container Setup - Starting..."
    log_info "Project root: ${PROJECT_ROOT}"
    log_info "Certificates directory: ${CERTS_DIR}"
    echo ""

    # Check if already initialized
    if check_if_initialized; then
        log_success "Akashic is already initialized - skipping setup"
        display_inventory
        exit 0
    fi

    # Step 1: Ensure Akashic binary exists
    log_info "Step 1/5: Checking for Akashic binary..."
    if ! ensure_binary; then
        log_error "Failed to build or find Akashic binary"
        exit 1
    fi
    echo ""

    # Step 2: Generate PKI certificates
    log_info "Step 2/5: Generating PKI certificates..."
    if ! generate_certificates; then
        log_error "Failed to generate certificates"
        exit 1
    fi
    echo ""

    # Step 3: Create compatibility layer
    log_info "Step 3/5: Creating certificate compatibility layer..."
    create_compatibility_layer
    echo ""

    # Step 4: Set proper permissions
    log_info "Step 4/5: Setting file permissions..."
    set_permissions
    echo ""

    # Step 5: Create initialization marker
    log_info "Step 5/5: Finalizing setup..."
    create_marker
    echo ""

    # Display inventory
    display_inventory

    # Success!
    log_success "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log_success "  Akashic initialization complete!"
    log_success "  PKI certificates generated and configured."
    log_success "  Ready to start Akashic services."
    log_success "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Run main function
main "$@"
