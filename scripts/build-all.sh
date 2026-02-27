#!/usr/bin/env bash
#
# Build all Soroban contracts for on-chain ZK
#
# Prerequisites:
# - Rust toolchain with wasm32-unknown-unknown target
# - cargo-stellar (optional, for optimization)
#
# Usage:
#   ./scripts/build-all.sh
#

set -e  # Exit on error

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Building On-Chain ZK Contracts${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo ""

# Check for wasm32 target
if ! rustup target list | grep -q "wasm32-unknown-unknown (installed)"; then
    echo -e "${YELLOW}Installing wasm32-unknown-unknown target...${NC}"
    rustup target add wasm32-unknown-unknown
fi

# Build merkle-tree
echo -e "${GREEN}Building merkle-tree contract...${NC}"
cd contracts/merkle-tree
cargo build --target wasm32-unknown-unknown --release
echo -e "${GREEN}✓ merkle-tree built${NC}"
echo ""

# Build identity-auth
echo -e "${GREEN}Building identity-auth contract...${NC}"
cd ../identity-auth
cargo build --target wasm32-unknown-unknown --release
echo -e "${GREEN}✓ identity-auth built${NC}"
echo ""

# Build groth16-verifier (if present)
if [ -d "../groth16-verifier" ]; then
    echo -e "${GREEN}Building groth16-verifier contract...${NC}"
    cd ../groth16-verifier
    cargo build --target wasm32-unknown-unknown --release
    echo -e "${GREEN}✓ groth16-verifier built${NC}"
    echo ""
fi

cd ../..

# Summary
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Build Complete${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo ""
echo "Built contracts:"
ls -lh contracts/*/target/wasm32-unknown-unknown/release/*.wasm 2>/dev/null || echo "  (WASM files in contracts/*/target/wasm32-unknown-unknown/release/)"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Deploy to testnet: ./scripts/deploy-testnet.sh <your_secret_key>"
echo "2. Or optimize first: stellar contract optimize --wasm <path_to_wasm>"
echo ""
