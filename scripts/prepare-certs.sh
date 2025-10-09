#!/usr/bin/env bash

# ============================================================================
# Akashic Certificate Preparation Script
# ============================================================================
# This script prepares certificates for 3rd party applications that expect
# flat directory structures or specific filenames.
#
# Creates compatibility layer in certs/compat/ with symlinks or copies
# to the organized certificate structure in certs/{ca,servers,clients}/
#
# Usage:
#   ./scripts/prepare-certs.sh [--copy|--symlink] [--app APP_NAME]
#
# Options:
#   --copy      Copy files instead of symlinking (recommended for production)
#   --symlink   Create symlinks (default, recommended for development)
#   --app NAME  Prepare certificates for specific app only (ldap, phpldapadmin, bff)
#   --clean     Remove compatibility layer
#   --verify    Verify compatibility layer
# ============================================================================

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CERTS_DIR="${PROJECT_ROOT}/certs"
COMPAT_DIR="${CERTS_DIR}/compat"

# Default mode
MODE="symlink"
APP_NAME=""
CLEAN=false
VERIFY=false

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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
# Parse arguments
# ============================================================================

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --copy)
                MODE="copy"
                shift
                ;;
            --symlink)
                MODE="symlink"
                shift
                ;;
            --app)
                APP_NAME="$2"
                shift 2
                ;;
            --clean)
                CLEAN=true
                shift
                ;;
            --verify)
                VERIFY=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

show_help() {
    cat << EOF
Akashic Certificate Preparation Script

Usage: $0 [OPTIONS]

Options:
  --copy              Copy files instead of symlinking (production)
  --symlink           Create symlinks (default, development)
  --app NAME          Prepare certs for specific app only
  --clean             Remove compatibility layer
  --verify            Verify compatibility layer
  -h, --help          Show this help message

Applications:
  ldap                OpenLDAP server
  phpldapadmin        phpLDAPadmin web interface
  bff                 Backend For Frontend

Examples:
  # Prepare all apps with symlinks (development)
  $0 --symlink

  # Prepare all apps with copies (production)
  $0 --copy

  # Prepare only LDAP certificates
  $0 --app ldap

  # Clean compatibility layer
  $0 --clean

  # Verify compatibility layer
  $0 --verify
EOF
}

# ============================================================================
# Create or verify links/copies
# ============================================================================

create_link_or_copy() {
    local source="$1"
    local target="$2"

    # Check if source exists
    if [[ ! -f "${source}" ]]; then
        log_error "Source file does not exist: ${source}"
        return 1
    fi

    # Create target directory if needed
    mkdir -p "$(dirname "${target}")"

    # Remove existing target if it exists
    if [[ -e "${target}" ]] || [[ -L "${target}" ]]; then
        rm -f "${target}"
    fi

    # Create link or copy based on mode
    if [[ "${MODE}" == "symlink" ]]; then
        # Calculate relative path from target to source
        local target_dir
        target_dir="$(dirname "${target}")"
        local rel_source
        rel_source="$(realpath --relative-to="${target_dir}" "${source}")"

        ln -s "${rel_source}" "${target}"
        log_info "Created symlink: ${target} -> ${rel_source}"
    else
        cp "${source}" "${target}"
        log_info "Copied file: ${source} -> ${target}"
    fi
}

# ============================================================================
# Prepare LDAP certificates
# ============================================================================

prepare_ldap() {
    log_info "Preparing LDAP certificate compatibility layer..."

    local ldap_dir="${COMPAT_DIR}/ldap"
    mkdir -p "${ldap_dir}"

    # LDAP server certificate
    if [[ -f "${CERTS_DIR}/servers/ldap.crt" ]]; then
        create_link_or_copy "${CERTS_DIR}/servers/ldap.crt" "${ldap_dir}/ldap.crt"
    else
        log_warning "LDAP server certificate not found: ${CERTS_DIR}/servers/ldap.crt"
        log_warning "Run './scripts/setup-pki.sh' to generate certificates"
        return 1
    fi

    # LDAP server private key
    if [[ -f "${CERTS_DIR}/servers/ldap.key" ]]; then
        create_link_or_copy "${CERTS_DIR}/servers/ldap.key" "${ldap_dir}/ldap.key"
        chmod 400 "${ldap_dir}/ldap.key"
    else
        log_warning "LDAP server key not found: ${CERTS_DIR}/servers/ldap.key"
        return 1
    fi

    # CA certificate
    if [[ -f "${CERTS_DIR}/ca/ca.crt" ]]; then
        create_link_or_copy "${CERTS_DIR}/ca/ca.crt" "${ldap_dir}/ca.crt"
    else
        log_error "CA certificate not found: ${CERTS_DIR}/ca/ca.crt"
        return 1
    fi

    log_success "LDAP certificates prepared in: ${ldap_dir}"
}

# ============================================================================
# Prepare phpLDAPadmin certificates
# ============================================================================

prepare_phpldapadmin() {
    log_info "Preparing phpLDAPadmin certificate compatibility layer..."

    local phpldapadmin_dir="${COMPAT_DIR}/phpldapadmin"
    mkdir -p "${phpldapadmin_dir}"

    # CA certificate (for LDAPS client connection)
    if [[ -f "${CERTS_DIR}/ca/ca.crt" ]]; then
        create_link_or_copy "${CERTS_DIR}/ca/ca.crt" "${phpldapadmin_dir}/ca.crt"
    else
        log_error "CA certificate not found: ${CERTS_DIR}/ca/ca.crt"
        return 1
    fi

    log_success "phpLDAPadmin certificates prepared in: ${phpldapadmin_dir}"
}

# ============================================================================
# Prepare BFF certificates
# ============================================================================

prepare_bff() {
    log_info "Preparing BFF certificate compatibility layer..."

    local bff_dir="${COMPAT_DIR}/bff"
    mkdir -p "${bff_dir}"

    # BFF client certificate
    if [[ -f "${CERTS_DIR}/clients/bff.crt" ]]; then
        create_link_or_copy "${CERTS_DIR}/clients/bff.crt" "${bff_dir}/client.crt"
    else
        log_warning "BFF client certificate not found: ${CERTS_DIR}/clients/bff.crt"
        log_warning "Run './scripts/setup-pki.sh' to generate certificates"
        return 1
    fi

    # BFF client private key
    if [[ -f "${CERTS_DIR}/clients/bff.key" ]]; then
        create_link_or_copy "${CERTS_DIR}/clients/bff.key" "${bff_dir}/client.key"
        chmod 400 "${bff_dir}/client.key"
    else
        log_warning "BFF client key not found: ${CERTS_DIR}/clients/bff.key"
        return 1
    fi

    # CA certificate
    if [[ -f "${CERTS_DIR}/ca/ca.crt" ]]; then
        create_link_or_copy "${CERTS_DIR}/ca/ca.crt" "${bff_dir}/ca.crt"
    else
        log_error "CA certificate not found: ${CERTS_DIR}/ca/ca.crt"
        return 1
    fi

    log_success "BFF certificates prepared in: ${bff_dir}"
}

# ============================================================================
# Clean compatibility layer
# ============================================================================

clean_compat() {
    log_info "Cleaning compatibility layer..."

    if [[ -d "${COMPAT_DIR}" ]]; then
        rm -rf "${COMPAT_DIR}"
        log_success "Compatibility layer removed: ${COMPAT_DIR}"
    else
        log_info "Compatibility layer does not exist"
    fi
}

# ============================================================================
# Verify compatibility layer
# ============================================================================

verify_compat() {
    log_info "Verifying compatibility layer..."

    local errors=0

    # Check LDAP
    if [[ -d "${COMPAT_DIR}/ldap" ]]; then
        log_info "Checking LDAP certificates..."
        for file in ldap.crt ldap.key ca.crt; do
            local path="${COMPAT_DIR}/ldap/${file}"
            if [[ -f "${path}" ]] || [[ -L "${path}" ]]; then
                if [[ -L "${path}" ]]; then
                    local target
                    target="$(readlink "${path}")"
                    log_success "  ${file}: symlink -> ${target}"
                else
                    log_success "  ${file}: file"
                fi
            else
                log_error "  ${file}: MISSING"
                ((errors++))
            fi
        done
    else
        log_warning "LDAP compatibility layer not found"
    fi

    # Check phpLDAPadmin
    if [[ -d "${COMPAT_DIR}/phpldapadmin" ]]; then
        log_info "Checking phpLDAPadmin certificates..."
        for file in ca.crt; do
            local path="${COMPAT_DIR}/phpldapadmin/${file}"
            if [[ -f "${path}" ]] || [[ -L "${path}" ]]; then
                if [[ -L "${path}" ]]; then
                    local target
                    target="$(readlink "${path}")"
                    log_success "  ${file}: symlink -> ${target}"
                else
                    log_success "  ${file}: file"
                fi
            else
                log_error "  ${file}: MISSING"
                ((errors++))
            fi
        done
    else
        log_warning "phpLDAPadmin compatibility layer not found"
    fi

    # Check BFF
    if [[ -d "${COMPAT_DIR}/bff" ]]; then
        log_info "Checking BFF certificates..."
        for file in client.crt client.key ca.crt; do
            local path="${COMPAT_DIR}/bff/${file}"
            if [[ -f "${path}" ]] || [[ -L "${path}" ]]; then
                if [[ -L "${path}" ]]; then
                    local target
                    target="$(readlink "${path}")"
                    log_success "  ${file}: symlink -> ${target}"
                else
                    log_success "  ${file}: file"
                fi
            else
                log_error "  ${file}: MISSING"
                ((errors++))
            fi
        done
    else
        log_warning "BFF compatibility layer not found"
    fi

    if [[ ${errors} -eq 0 ]]; then
        log_success "Verification passed - all certificates present"
        return 0
    else
        log_error "Verification failed - ${errors} files missing"
        return 1
    fi
}

# ============================================================================
# Main execution
# ============================================================================

main() {
    parse_args "$@"

    log_info "Akashic Certificate Preparation"
    log_info "Certificates directory: ${CERTS_DIR}"
    log_info "Compatibility directory: ${COMPAT_DIR}"
    log_info "Mode: ${MODE}"
    echo ""

    # Handle clean operation
    if [[ "${CLEAN}" == true ]]; then
        clean_compat
        exit 0
    fi

    # Handle verify operation
    if [[ "${VERIFY}" == true ]]; then
        verify_compat
        exit $?
    fi

    # Check if certificates exist
    if [[ ! -d "${CERTS_DIR}/ca" ]] || [[ ! -f "${CERTS_DIR}/ca/ca.crt" ]]; then
        log_error "PKI certificates not found"
        log_error "Run './scripts/setup-pki.sh' first to generate certificates"
        exit 1
    fi

    # Create compatibility layer directory
    mkdir -p "${COMPAT_DIR}"

    # Prepare certificates for specific app or all apps
    if [[ -n "${APP_NAME}" ]]; then
        case "${APP_NAME}" in
            ldap)
                prepare_ldap
                ;;
            phpldapadmin)
                prepare_phpldapadmin
                ;;
            bff)
                prepare_bff
                ;;
            *)
                log_error "Unknown app: ${APP_NAME}"
                log_error "Valid apps: ldap, phpldapadmin, bff"
                exit 1
                ;;
        esac
    else
        # Prepare all apps
        prepare_ldap || log_warning "LDAP preparation failed (skipping)"
        prepare_phpldapadmin || log_warning "phpLDAPadmin preparation failed (skipping)"
        prepare_bff || log_warning "BFF preparation failed (skipping)"
    fi

    echo ""
    log_success "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log_success "  Certificate compatibility layer ready"
    log_success "  Mode: ${MODE}"
    log_success "  Location: ${COMPAT_DIR}"
    log_success "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Run main function
main "$@"
