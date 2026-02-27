#!/bin/bash

# Identity Attestation Circuit Compilation Script
# Requires: circom 2.1.0+, node 18+

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
SRC_DIR="$ROOT_DIR/src"
BUILD_DIR="$ROOT_DIR/build"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_step() { echo -e "${BLUE}==>${NC} $1"; }
print_success() { echo -e "${GREEN}✓${NC} $1"; }
print_warning() { echo -e "${YELLOW}⚠${NC} $1"; }
print_error() { echo -e "${RED}✗${NC} $1"; }

echo ""
echo "=================================="
echo " Identity Attestation Circuit Compiler"
echo "=================================="
echo ""

# Check circom is installed
if ! command -v circom &> /dev/null; then
    print_error "circom not found!"
    echo ""
    echo "Install circom:"
    echo "  curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh"
    echo "  git clone https://github.com/iden3/circom.git"
    echo "  cd circom && cargo build --release"
    echo "  cargo install --path circom"
    echo ""
    exit 1
fi

# Check snarkjs is installed
if ! command -v snarkjs &> /dev/null; then
    print_warning "snarkjs not found globally, will use npx"
    SNARKJS="npx snarkjs"
else
    SNARKJS="snarkjs"
fi

# Create build directory
mkdir -p "$BUILD_DIR"

# Navigate to root for correct circomlib resolution
cd "$ROOT_DIR"

print_step "Compiling circuit..."
echo "  Source: $SRC_DIR/identity_attestation.circom"
echo "  Output: $BUILD_DIR/"
echo ""

# Compile the circuit
# --r1cs: Generate R1CS constraint system
# --wasm: Generate WASM for witness generation
# --sym: Generate symbol file for debugging
# -o: Output directory
circom "$SRC_DIR/identity_attestation.circom" \
    --r1cs \
    --wasm \
    --sym \
    -l node_modules \
    -o "$BUILD_DIR"

print_success "Circuit compiled successfully!"
echo ""

# Show circuit info
print_step "Circuit information:"
$SNARKJS r1cs info "$BUILD_DIR/identity_attestation.r1cs"
echo ""

# Print constraints (for debugging)
print_step "Exporting R1CS to JSON (for analysis)..."
$SNARKJS r1cs export json "$BUILD_DIR/identity_attestation.r1cs" "$BUILD_DIR/identity_attestation.r1cs.json"
print_success "R1CS exported to $BUILD_DIR/identity_attestation.r1cs.json"
echo ""

print_success "Compilation complete!"
echo ""
echo "Next steps:"
echo "  1. Run trusted setup:  ./scripts/trusted-setup.sh"
echo "  2. Generate test proof: npm run test:generate"
echo "  3. Verify test proof:   npm run test:verify"
echo ""
