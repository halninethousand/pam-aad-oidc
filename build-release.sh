#!/bin/bash

# Builds pam_aad_oidc.so for Azure AD JWT authentication

set -e

echo "=== PAM AAD OIDC Build Script ==="
echo

# go check
if ! command -v go &> /dev/null; then
    echo "ERROR: Go is not installed. Please install Go 1.18 or later."
    exit 1
fi

GO_VERSION=$(go version | cut -d' ' -f3 | sed 's/go//')
echo "Found Go version: $GO_VERSION"

echo "Checking system dependencies..."

MISSING_DEPS=()
if ! command -v gcc &> /dev/null; then
    MISSING_DEPS+=("gcc")
fi
if ! command -v make &> /dev/null; then
    MISSING_DEPS+=("make")
fi

# Check for required PAM development library
if [ ! -f "/usr/include/security/pam_appl.h" ] && [ ! -f "/usr/include/pam/pam_appl.h" ]; then
    MISSING_DEPS+=("libpam-dev or libpam0g-dev")
fi

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    echo "ERROR: Missing required dependencies:"
    printf '  %s\n' "${MISSING_DEPS[@]}"
    echo
    echo "Install them with:"
    echo "  sudo apt update"
    echo "  sudo apt install -y gcc make libpam-dev"
    exit 1
fi

echo "All dependencies found."
echo

echo "Cleaning previous build artifacts..."
make clean 2>/dev/null || true
echo

echo "Building pam_aad_oidc.so..."
make
if [ ! -f "pam_aad_oidc.so" ]; then
    echo "ERROR: Failed to build pam_aad_oidc.so"
    exit 1
fi
echo "✓ Successfully built pam_aad_oidc.so"

echo
echo "=== Build Complete ==="
echo "Generated artifacts:"
ls -la *.so
echo
echo "PAM module ready for installation:"
echo "  pam_aad_oidc.so  - Azure AD JWT authentication module"
echo
echo "Installation commands:"
echo "  sudo cp pam_aad_oidc.so /lib/security/"
echo "  # or: sudo cp pam_aad_oidc.so /usr/lib/x86_64-linux-gnu/security/"
