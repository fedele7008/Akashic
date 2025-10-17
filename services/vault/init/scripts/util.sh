#!/bin/bash

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
    printf "${MAGENTA}║${NC} %-65s ${MAGENTA}║${NC}\n" "$*"
    echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

log_section() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE} $*${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
}

print_log_output_header() {
    echo -e "${CYAN}════════════════════════ OUTPUT ═══════════════════════${NC}"
}

print_log_output_footer() {
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
}

log_output() {
    print_log_output_header
    echo -e "$*"
    print_log_output_footer
}

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Wait for Vault to be available
wait_for_vault() {
    log "Waiting for Vault to be available at ${AKASHIC_VAULT_ADDRESS}..."
    local max_retries=30
    local retry=0

    while [ $retry -lt $max_retries ]; do
        akashic-cli pki vault status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
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
