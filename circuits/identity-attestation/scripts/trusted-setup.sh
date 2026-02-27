#!/bin/bash

# Trusted Setup Script for Identity Attestation Circuit
# This performs the Powers of Tau ceremony + circuit-specific setup

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$ROOT_DIR/build"
KEYS_DIR="$ROOT_DIR/keys"

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
echo " Trusted Setup Ceremony"
echo "=================================="
echo ""

# Check if R1CS exists
if [ ! -f "$BUILD_DIR/identity_attestation.r1cs" ]; then
    print_error "R1CS file not found! Run ./scripts/compile.sh first."
    exit 1
fi

# Check snarkjs
if ! command -v snarkjs &> /dev/null; then
    SNARKJS="npx snarkjs"
else
    SNARKJS="snarkjs"
fi

# Create keys directory
mkdir -p "$KEYS_DIR"

cd "$ROOT_DIR"

# ============================================
# Phase 1: Powers of Tau (Universal Setup)
# ============================================
# This can be reused across circuits of similar size
# Power 12 = 2^12 = 4096 constraints max
# Power 14 = 2^14 = 16384 constraints max
# Power 16 = 2^16 = 65536 constraints max

POWER=14  # Adjust based on circuit size

print_step "Phase 1: Powers of Tau ceremony"
echo "  Power: $POWER (supports up to 2^$POWER = $((2**POWER)) constraints)"
echo ""

# Check if we already have a ptau file
PTAU_FILE="$KEYS_DIR/pot${POWER}_final.ptau"

if [ -f "$PTAU_FILE" ]; then
    print_warning "Using existing Powers of Tau file: $PTAU_FILE"
else
    print_step "Starting new Powers of Tau ceremony..."

    # Step 1: Start ceremony
    $SNARKJS powersoftau new bn128 $POWER "$KEYS_DIR/pot${POWER}_0000.ptau" -v

    # Step 2: First contribution (use random entropy)
    print_step "Adding contribution 1 (random entropy)..."
    $SNARKJS powersoftau contribute "$KEYS_DIR/pot${POWER}_0000.ptau" "$KEYS_DIR/pot${POWER}_0001.ptau" \
        --name="Identity ZK Ceremony" -v -e="$(head -c 64 /dev/urandom | base64)"

    # Step 3: Verify the ceremony
    print_step "Verifying Powers of Tau..."
    $SNARKJS powersoftau verify "$KEYS_DIR/pot${POWER}_0001.ptau"

    # Step 4: Prepare for phase 2 (apply random beacon)
    print_step "Preparing for phase 2..."
    $SNARKJS powersoftau prepare phase2 "$KEYS_DIR/pot${POWER}_0001.ptau" "$PTAU_FILE" -v

    # Cleanup intermediate files
    rm -f "$KEYS_DIR/pot${POWER}_0000.ptau" "$KEYS_DIR/pot${POWER}_0001.ptau"

    print_success "Powers of Tau ceremony complete!"
fi

echo ""

# ============================================
# Phase 2: Circuit-Specific Setup
# ============================================

print_step "Phase 2: Circuit-specific setup"

# Step 1: Generate initial zkey
print_step "Generating initial proving key..."
$SNARKJS groth16 setup "$BUILD_DIR/identity_attestation.r1cs" "$PTAU_FILE" "$KEYS_DIR/identity_attestation_0000.zkey"

# Step 2: Contribute to the circuit setup
print_step "Adding circuit contribution..."
$SNARKJS zkey contribute "$KEYS_DIR/identity_attestation_0000.zkey" "$KEYS_DIR/identity_attestation_0001.zkey" \
    --name="Identity Circuit Ceremony" -v -e="$(head -c 64 /dev/urandom | base64)"

# Step 3: Apply random beacon (finalize)
print_step "Applying random beacon (finalizing)..."
BEACON=$(head -c 32 /dev/urandom | xxd -p -c 64)
$SNARKJS zkey beacon "$KEYS_DIR/identity_attestation_0001.zkey" "$KEYS_DIR/identity_attestation.zkey" \
    "$BEACON" 10 -n="Final Beacon"

# Step 4: Verify the final zkey
print_step "Verifying final proving key..."
$SNARKJS zkey verify "$BUILD_DIR/identity_attestation.r1cs" "$PTAU_FILE" "$KEYS_DIR/identity_attestation.zkey"

# Step 5: Export verification key
print_step "Exporting verification key..."
$SNARKJS zkey export verificationkey "$KEYS_DIR/identity_attestation.zkey" "$KEYS_DIR/verification_key.json"

# Cleanup intermediate files
rm -f "$KEYS_DIR/identity_attestation_0000.zkey" "$KEYS_DIR/identity_attestation_0001.zkey"

print_success "Trusted setup complete!"
echo ""

# Show key info
print_step "Generated files:"
echo "  Proving key:      $KEYS_DIR/identity_attestation.zkey"
echo "  Verification key: $KEYS_DIR/verification_key.json"
echo "  Powers of Tau:    $PTAU_FILE"
echo ""

# Show verification key preview
print_step "Verification key preview:"
head -20 "$KEYS_DIR/verification_key.json"
echo "  ..."
echo ""

print_success "Setup complete! Ready to generate proofs."
echo ""
echo "Next steps:"
echo "  1. Generate test proof: npm run test:generate"
echo "  2. Verify test proof:   npm run test:verify"
echo "  3. Export for Soroban:  node scripts/export-to-soroban.js"
echo ""
