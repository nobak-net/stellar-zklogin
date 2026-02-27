#!/usr/bin/env bash
#
# Deploy on-chain ZK contracts to Stellar testnet
#
# Prerequisites:
# - Stellar CLI installed (brew install stellar/tap/stellar-cli)
# - Testnet account with XLM
# - Contracts built (run build-all.sh first)
#
# Usage:
#   ./scripts/deploy-testnet.sh <your_secret_key>
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
NETWORK="testnet"
GROTH16_VERIFIER_ID="CCQR3AM..."  # Already deployed

echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  On-Chain ZK Contracts Deployment (Testnet)${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo ""

# Check for secret key argument
if [ -z "$1" ]; then
    echo -e "${RED}Error: Secret key required${NC}"
    echo "Usage: $0 <your_secret_key>"
    echo ""
    echo "Example:"
    echo "  $0 SXXX..."
    exit 1
fi

SOURCE_KEY="$1"

# Check Stellar CLI is installed
if ! command -v stellar &> /dev/null; then
    echo -e "${RED}Error: Stellar CLI not found${NC}"
    echo "Install with: brew install stellar/tap/stellar-cli"
    exit 1
fi

echo -e "${YELLOW}Network:${NC} $NETWORK"
echo -e "${YELLOW}Groth16 Verifier (existing):${NC} $GROTH16_VERIFIER_ID"
echo ""

# Step 1: Deploy Merkle Tree
echo -e "${GREEN}Step 1: Deploying Merkle Tree Contract${NC}"
echo "────────────────────────────────────────"

cd contracts/merkle-tree

if [ ! -f "target/wasm32-unknown-unknown/release/merkle_tree.wasm" ]; then
    echo -e "${RED}Error: merkle_tree.wasm not found${NC}"
    echo "Run: cargo build --target wasm32-unknown-unknown --release"
    exit 1
fi

echo "Deploying merkle-tree contract..."
MERKLE_TREE_ID=$(stellar contract deploy \
    --wasm target/wasm32-unknown-unknown/release/merkle_tree.wasm \
    --network $NETWORK \
    --source $SOURCE_KEY 2>&1 | tail -n 1)

if [ -z "$MERKLE_TREE_ID" ]; then
    echo -e "${RED}Error: Failed to deploy merkle-tree contract${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Merkle Tree deployed:${NC} $MERKLE_TREE_ID"
echo ""

# Step 2: Deploy Identity Auth
echo -e "${GREEN}Step 2: Deploying Identity Auth Contract${NC}"
echo "────────────────────────────────────────"

cd ../identity-auth

if [ ! -f "target/wasm32-unknown-unknown/release/identity_auth.wasm" ]; then
    echo -e "${RED}Error: identity_auth.wasm not found${NC}"
    echo "Run: cargo build --target wasm32-unknown-unknown --release"
    exit 1
fi

echo "Deploying identity-auth contract..."
IDENTITY_AUTH_ID=$(stellar contract deploy \
    --wasm target/wasm32-unknown-unknown/release/identity_auth.wasm \
    --network $NETWORK \
    --source $SOURCE_KEY 2>&1 | tail -n 1)

if [ -z "$IDENTITY_AUTH_ID" ]; then
    echo -e "${RED}Error: Failed to deploy identity-auth contract${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Identity Auth deployed:${NC} $IDENTITY_AUTH_ID"
echo ""

# Step 3: Load Verification Key
echo -e "${GREEN}Step 3: Loading Verification Key${NC}"
echo "────────────────────────────────────────"

cd ../../circuits/identity-attestation/keys

if [ ! -f "verification_key_soroban.json" ]; then
    echo -e "${RED}Error: verification_key_soroban.json not found${NC}"
    echo "Run: npm run build in circuits/identity-attestation/"
    exit 1
fi

echo "Loading VK into groth16-verifier..."
stellar contract invoke \
    --id $GROTH16_VERIFIER_ID \
    --network $NETWORK \
    --source $SOURCE_KEY \
    -- \
    set_verification_key \
    --vk "$(cat verification_key_soroban.json)" > /dev/null

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Verification key loaded${NC}"
else
    echo -e "${YELLOW}⚠ VK loading may have failed (check manually)${NC}"
fi

echo ""

# Step 4: Initialize Identity Auth Contract
echo -e "${GREEN}Step 4: Initializing Identity Auth Contract${NC}"
echo "────────────────────────────────────────"

echo -e "${YELLOW}Note: Manual initialization required${NC}"
echo ""
echo "Run the following command to initialize:"
echo ""
echo "stellar contract invoke \\"
echo "  --id $IDENTITY_AUTH_ID \\"
echo "  --network $NETWORK \\"
echo "  --source <YOUR_SECRET_KEY> \\"
echo "  -- \\"
echo "  initialize \\"
echo "  --config '{"
echo "    \"server_pub_key\": \"<64_byte_hex_pubkey>\","
echo "    \"verifier_id\": \"$GROTH16_VERIFIER_ID\","
echo "    \"merkle_tree_id\": \"$MERKLE_TREE_ID\","
echo "    \"vk_hash\": \"<vk_hash_from_circuit>\""
echo "  }'"
echo ""

# Summary
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Deployment Summary${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo ""
echo "Deployed Contracts:"
echo "  - Groth16 Verifier: $GROTH16_VERIFIER_ID (pre-existing)"
echo "  - Merkle Tree:      $MERKLE_TREE_ID"
echo "  - Identity Auth:    $IDENTITY_AUTH_ID"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "1. Initialize identity-auth contract (see command above)"
echo "2. Update your API config with the new contract IDs"
echo ""

# Save contract IDs to file
cd ../../..
cat > deployment_ids.env <<EOF
# Deployment IDs (Testnet) - $(date)
export GROTH16_VERIFIER_ID="$GROTH16_VERIFIER_ID"
export MERKLE_TREE_ID="$MERKLE_TREE_ID"
export IDENTITY_AUTH_ID="$IDENTITY_AUTH_ID"
EOF

echo -e "${GREEN}✓ Contract IDs saved to:${NC} deployment_ids.env"
echo ""
echo "To use these IDs in your shell:"
echo "  source deployment_ids.env"
echo ""
