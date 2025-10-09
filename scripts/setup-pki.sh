#!/bin/bash

# PKI Setup Script for Akashic
# This script automates the setup of the Public Key Infrastructure (PKI)
# for secure communication between Akashic components

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
CERTS_DIR="./certs"
AKASHIC_BIN="./build/akashic"

# Print colored message
print_msg() {
    local color=$1
    shift
    echo -e "${color}$@${NC}"
}

print_success() { print_msg "$GREEN" "✓ $@"; }
print_error() { print_msg "$RED" "✗ $@"; }
print_info() { print_msg "$BLUE" "ℹ $@"; }
print_warning() { print_msg "$YELLOW" "⚠ $@"; }

# Check if akashic binary exists
check_binary() {
    if [ ! -f "$AKASHIC_BIN" ]; then
        print_error "Akashic binary not found at $AKASHIC_BIN"
        print_info "Please build the binary first: go build -o build/akashic ./cmd/akashic"
        exit 1
    fi
    print_success "Found Akashic binary"
}

# Initialize CA
init_ca() {
    print_info "Initializing Certificate Authority..."

    if [ -f "$CERTS_DIR/ca/ca.crt" ] && [ "$FORCE" != "true" ]; then
        print_warning "CA already exists. Use --force to regenerate."
        return 0
    fi

    $AKASHIC_BIN pki init \
        --certs-dir "$CERTS_DIR" \
        ${FORCE:+--force}

    print_success "Certificate Authority initialized"
}

# Generate server certificates
generate_server_certs() {
    print_info "Generating server certificates..."

    # Control Server Certificate
    print_info "  → Control server certificate"
    $AKASHIC_BIN pki generate-server \
        --certs-dir "$CERTS_DIR" \
        --name control \
        --dns localhost \
        --dns control.akashic.local \
        --ip 127.0.0.1 \
        ${FORCE:+--force}

    # Auth Server Certificate
    print_info "  → Auth server certificate"
    $AKASHIC_BIN pki generate-server \
        --certs-dir "$CERTS_DIR" \
        --name auth \
        --dns localhost \
        --dns auth.akashic.local \
        --ip 0.0.0.0 \
        ${FORCE:+--force}

    # LDAP Server Certificate (if using embedded LDAP with TLS)
    print_info "  → LDAP server certificate"
    $AKASHIC_BIN pki generate-server \
        --certs-dir "$CERTS_DIR" \
        --name ldap \
        --dns ldap \
        --dns ldap.akashic.local \
        ${FORCE:+--force}

    print_success "Server certificates generated"
}

# Generate client certificates
generate_client_certs() {
    print_info "Generating client certificates..."

    # CLI Client Certificate
    print_info "  → CLI client certificate"
    $AKASHIC_BIN pki generate-client \
        --certs-dir "$CERTS_DIR" \
        --name cli \
        --common-name "Akashic CLI Client" \
        ${FORCE:+--force}

    # BFF Client Certificate
    print_info "  → BFF client certificate"
    $AKASHIC_BIN pki generate-client \
        --certs-dir "$CERTS_DIR" \
        --name bff \
        --common-name "Akashic BFF Client" \
        ${FORCE:+--force}

    print_success "Client certificates generated"
}

# Display certificate inventory
show_inventory() {
    print_info "Certificate Inventory:"
    echo ""
    $AKASHIC_BIN pki list --certs-dir "$CERTS_DIR"
    echo ""
}

# Check for expiring certificates
check_expiry() {
    print_info "Checking certificate expiration..."
    echo ""
    $AKASHIC_BIN pki check-expiry --certs-dir "$CERTS_DIR" --warning-days 60 || true
    echo ""
}

# Verify certificate chain
verify_certs() {
    print_info "Verifying certificates..."

    # Verify control server certificate
    $AKASHIC_BIN pki verify \
        --certs-dir "$CERTS_DIR" \
        --cert "$CERTS_DIR/servers/control.crt" > /dev/null 2>&1
    print_success "Control server certificate verified"

    # Verify auth server certificate
    $AKASHIC_BIN pki verify \
        --certs-dir "$CERTS_DIR" \
        --cert "$CERTS_DIR/servers/auth.crt" > /dev/null 2>&1
    print_success "Auth server certificate verified"

    # Verify LDAP server certificate
    $AKASHIC_BIN pki verify \
        --certs-dir "$CERTS_DIR" \
        --cert "$CERTS_DIR/servers/ldap.crt" > /dev/null 2>&1
    print_success "LDAP server certificate verified"

    # Verify CLI client certificate
    $AKASHIC_BIN pki verify \
        --certs-dir "$CERTS_DIR" \
        --cert "$CERTS_DIR/clients/cli.crt" > /dev/null 2>&1
    print_success "CLI client certificate verified"

    # Verify BFF client certificate
    $AKASHIC_BIN pki verify \
        --certs-dir "$CERTS_DIR" \
        --cert "$CERTS_DIR/clients/bff.crt" > /dev/null 2>&1
    print_success "BFF client certificate verified"

    echo ""
}

# Print usage
usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Automate PKI setup for Akashic secure communication.

OPTIONS:
    -h, --help      Show this help message
    -f, --force     Force regeneration of existing certificates
    -d, --dir DIR   Certificate directory (default: ./certs)
    -b, --bin PATH  Path to akashic binary (default: ./build/akashic)
    -v, --verify    Only verify existing certificates
    -l, --list      Only list existing certificates
    -e, --expiry    Only check certificate expiration

EXAMPLES:
    # Full PKI setup (CA + all certificates)
    $0

    # Force regenerate all certificates
    $0 --force

    # Verify existing certificates
    $0 --verify

    # Check expiration status
    $0 --expiry

    # List all certificates
    $0 --list

    # Use custom paths
    $0 --dir /path/to/certs --bin /path/to/akashic

EOF
}

# Main function
main() {
    local VERIFY_ONLY=false
    local LIST_ONLY=false
    local EXPIRY_ONLY=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -f|--force)
                FORCE=true
                shift
                ;;
            -d|--dir)
                CERTS_DIR="$2"
                shift 2
                ;;
            -b|--bin)
                AKASHIC_BIN="$2"
                shift 2
                ;;
            -v|--verify)
                VERIFY_ONLY=true
                shift
                ;;
            -l|--list)
                LIST_ONLY=true
                shift
                ;;
            -e|--expiry)
                EXPIRY_ONLY=true
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    # Print header
    echo ""
    print_info "═══════════════════════════════════════════════"
    print_info "  Akashic PKI Setup Script"
    print_info "═══════════════════════════════════════════════"
    echo ""

    # Check binary
    check_binary

    # Handle special modes
    if [ "$VERIFY_ONLY" = true ]; then
        verify_certs
        exit 0
    fi

    if [ "$LIST_ONLY" = true ]; then
        show_inventory
        exit 0
    fi

    if [ "$EXPIRY_ONLY" = true ]; then
        check_expiry
        exit 0
    fi

    # Full setup
    init_ca
    echo ""

    generate_server_certs
    echo ""

    generate_client_certs
    echo ""

    verify_certs

    show_inventory

    check_expiry

    # Print summary
    print_success "═══════════════════════════════════════════════"
    print_success "  PKI setup complete!"
    print_success "═══════════════════════════════════════════════"
    echo ""
    print_info "Next steps:"
    print_info "  1. Update configs/config.yaml with TLS settings:"
    print_info "     server.control.tls.enabled: true"
    print_info "     ldap.use_tls: true (if using embedded LDAP)"
    print_info "  2. Start Akashic server: ./build/akashic run"
    print_info "  3. Test mTLS connection:"
    print_info "     curl --cert certs/clients/cli.crt \\"
    print_info "          --key certs/clients/cli.key \\"
    print_info "          --cacert certs/ca/ca.crt \\"
    print_info "          https://localhost:8081/status"
    echo ""
}

# Run main function
main "$@"
