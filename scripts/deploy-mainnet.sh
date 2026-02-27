#!/usr/bin/env bash
#
# Deploy on-chain ZK contracts to Stellar MAINNET
#
# Prerequisites:
# - Stellar CLI installed (brew install stellar/tap/stellar-cli)
# - Funded mainnet account (~100 XLM for 3 contract deployments + initialization)
# - Contracts built (run build-all.sh first)
#
# Usage:
#   ./scripts/deploy-mainnet.sh <identity_name>
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
NETWORK="mainnet"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${RED}  On-Chain ZK Contracts Deployment (MAINNET)${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${RED}  WARNING: This deploys to Stellar MAINNET (real XLM)${NC}"
echo ""

# Check for identity name argument
if [ -z "$1" ]; then
    echo -e "${RED}Error: Identity name required${NC}"
    echo "Usage: $0 <identity_name>"
    echo ""
    echo "Available identities:"
    stellar keys ls 2>/dev/null | sed 's/^/  /'
    exit 1
fi

SOURCE_IDENTITY="$1"

# Verify identity exists
if ! stellar keys address "$SOURCE_IDENTITY" > /dev/null 2>&1; then
    echo -e "${RED}Error: Identity '$SOURCE_IDENTITY' not found${NC}"
    echo "Create one with: stellar keys generate $SOURCE_IDENTITY"
    exit 1
fi

SOURCE_ADDRESS=$(stellar keys address "$SOURCE_IDENTITY")

# Check Stellar CLI is installed
if ! command -v stellar &> /dev/null; then
    echo -e "${RED}Error: Stellar CLI not found${NC}"
    echo "Install with: brew install stellar/tap/stellar-cli"
    exit 1
fi

echo -e "${YELLOW}Identity:${NC} $SOURCE_IDENTITY"
echo -e "${YELLOW}Address: ${NC} $SOURCE_ADDRESS"
echo ""

# Confirmation prompt
read -p "Deploy to MAINNET with this identity? (yes/no) " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    echo "Aborted."
    exit 0
fi

echo ""
echo -e "${YELLOW}Network:${NC} $NETWORK (mainnet)"
echo ""

# ─────────────────────────────────────────────────────
# Step 1: Deploy Groth16 Verifier
# ─────────────────────────────────────────────────────
echo -e "${GREEN}Step 1: Deploying Groth16 Verifier Contract${NC}"
echo "────────────────────────────────────────"

GROTH16_WASM="$ROOT_DIR/target/wasm32-unknown-unknown/release/groth16_verifier.wasm"

if [ ! -f "$GROTH16_WASM" ]; then
    echo -e "${RED}Error: groth16_verifier.wasm not found at $GROTH16_WASM${NC}"
    echo "Run: ./scripts/build-all.sh"
    exit 1
fi

echo "Deploying groth16-verifier contract..."
GROTH16_VERIFIER_ID=$(stellar contract deploy \
    --wasm "$GROTH16_WASM" \
    --network $NETWORK \
    --source $SOURCE_IDENTITY 2>&1 | tail -n 1)

if [ -z "$GROTH16_VERIFIER_ID" ]; then
    echo -e "${RED}Error: Failed to deploy groth16-verifier contract${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Groth16 Verifier deployed:${NC} $GROTH16_VERIFIER_ID"
echo ""

# ─────────────────────────────────────────────────────
# Step 2: Deploy Merkle Tree
# ─────────────────────────────────────────────────────
echo -e "${GREEN}Step 2: Deploying Merkle Tree Contract${NC}"
echo "────────────────────────────────────────"

MERKLE_WASM="$ROOT_DIR/target/wasm32-unknown-unknown/release/merkle_tree.wasm"

if [ ! -f "$MERKLE_WASM" ]; then
    echo -e "${RED}Error: merkle_tree.wasm not found at $MERKLE_WASM${NC}"
    echo "Run: ./scripts/build-all.sh"
    exit 1
fi

echo "Deploying merkle-tree contract..."
MERKLE_TREE_ID=$(stellar contract deploy \
    --wasm "$MERKLE_WASM" \
    --network $NETWORK \
    --source $SOURCE_IDENTITY 2>&1 | tail -n 1)

if [ -z "$MERKLE_TREE_ID" ]; then
    echo -e "${RED}Error: Failed to deploy merkle-tree contract${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Merkle Tree deployed:${NC} $MERKLE_TREE_ID"
echo ""

# ─────────────────────────────────────────────────────
# Step 3: Deploy Identity Auth
# ─────────────────────────────────────────────────────
echo -e "${GREEN}Step 3: Deploying Identity Auth Contract${NC}"
echo "────────────────────────────────────────"

IDENTITY_WASM="$ROOT_DIR/target/wasm32-unknown-unknown/release/identity_auth.wasm"

if [ ! -f "$IDENTITY_WASM" ]; then
    echo -e "${RED}Error: identity_auth.wasm not found at $IDENTITY_WASM${NC}"
    echo "Run: ./scripts/build-all.sh"
    exit 1
fi

echo "Deploying identity-auth contract..."
IDENTITY_AUTH_ID=$(stellar contract deploy \
    --wasm "$IDENTITY_WASM" \
    --network $NETWORK \
    --source $SOURCE_IDENTITY 2>&1 | tail -n 1)

if [ -z "$IDENTITY_AUTH_ID" ]; then
    echo -e "${RED}Error: Failed to deploy identity-auth contract${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Identity Auth deployed:${NC} $IDENTITY_AUTH_ID"
echo ""

# ─────────────────────────────────────────────────────
# Step 4: Load Verification Key
# ─────────────────────────────────────────────────────
echo -e "${GREEN}Step 4: Loading Verification Key${NC}"
echo "────────────────────────────────────────"

VK_PATH="$ROOT_DIR/circuits/identity-attestation/keys/verification_key_soroban.json"

if [ ! -f "$VK_PATH" ]; then
    echo -e "${RED}Error: verification_key_soroban.json not found${NC}"
    echo "Run: npm run build in circuits/identity-attestation/"
    exit 1
fi

echo "Initializing groth16-verifier (setting admin)..."
stellar contract invoke \
    --id $GROTH16_VERIFIER_ID \
    --network $NETWORK \
    --source $SOURCE_IDENTITY \
    -- \
    initialize \
    --admin $SOURCE_ADDRESS 2>&1 && \
    echo -e "${GREEN}✓ Groth16 Verifier initialized (admin: $SOURCE_ADDRESS)${NC}" || \
    echo -e "${YELLOW}⚠ Groth16 init may have failed (already initialized?)${NC}"

echo ""
echo "Loading VK into groth16-verifier..."
stellar contract invoke \
    --id $GROTH16_VERIFIER_ID \
    --network $NETWORK \
    --source $SOURCE_IDENTITY \
    -- \
    set_verification_key \
    --admin $SOURCE_ADDRESS \
    --vk "$(cat "$VK_PATH")" 2>&1 && \
    echo -e "${GREEN}✓ Verification key loaded${NC}" || \
    echo -e "${YELLOW}⚠ VK loading may have failed (check manually)${NC}"

echo ""

# ─────────────────────────────────────────────────────
# Step 5: Initialize Merkle Tree Contract
# ─────────────────────────────────────────────────────
echo -e "${GREEN}Step 5: Initializing Merkle Tree Contract${NC}"
echo "────────────────────────────────────────"

echo "Initializing merkle-tree (setting admin)..."
stellar contract invoke \
    --id $MERKLE_TREE_ID \
    --network $NETWORK \
    --source $SOURCE_IDENTITY \
    -- \
    initialize \
    --admin $SOURCE_ADDRESS 2>&1 && \
    echo -e "${GREEN}✓ Merkle Tree initialized (admin: $SOURCE_ADDRESS)${NC}" || \
    echo -e "${YELLOW}⚠ Merkle Tree init may have failed (already initialized?)${NC}"

echo ""

# ─────────────────────────────────────────────────────
# Step 6: Initialize Identity Auth Contract
# ─────────────────────────────────────────────────────
echo -e "${GREEN}Step 6: Initializing Identity Auth Contract${NC}"
echo "────────────────────────────────────────"

echo -e "${YELLOW}Note: Manual initialization required${NC}"
echo ""
echo "The server_pub_key must be:"
echo "  Poseidon(stringToFieldElement('<your-attestation-server-secret>'), 1)"
echo ""
echo "Compute it using the API code or a helper, then run:"
echo ""
echo "stellar contract invoke \\"
echo "  --id $IDENTITY_AUTH_ID \\"
echo "  --network $NETWORK \\"
echo "  --source $SOURCE_IDENTITY \\"
echo "  -- \\"
echo "  initialize \\"
echo "  --admin $SOURCE_ADDRESS \\"
echo "  --config '{"
echo "    \"server_pub_key\": \"<poseidon_commitment_hex>\","
echo "    \"verifier_id\": \"$GROTH16_VERIFIER_ID\","
echo "    \"merkle_tree_id\": \"$MERKLE_TREE_ID\","
echo "    \"vk_hash\": \"<vk_hash_from_circuit>\""
echo "  }'"
echo ""

# ─────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  MAINNET Deployment Summary${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo ""
echo "Deployed Contracts:"
echo "  - Groth16 Verifier: $GROTH16_VERIFIER_ID"
echo "  - Merkle Tree:      $MERKLE_TREE_ID"
echo "  - Identity Auth:    $IDENTITY_AUTH_ID"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "1. Initialize identity-auth contract (see command above)"
echo "2. Update your API config with the new contract IDs"
echo "3. Set SPONSOR_SECRET_KEY in your API environment"
echo ""

# Save contract IDs to file
cat > "$ROOT_DIR/deployment_ids_mainnet.env" <<EOF
# Deployment IDs (Mainnet) - $(date)
export GROTH16_VERIFIER_ID="$GROTH16_VERIFIER_ID"
export MERKLE_TREE_ID="$MERKLE_TREE_ID"
export IDENTITY_AUTH_ID="$IDENTITY_AUTH_ID"
EOF

echo -e "${GREEN}✓ Contract IDs saved to:${NC} deployment_ids_mainnet.env"
echo ""
echo "To use these IDs in your shell:"
echo "  source deployment_ids_mainnet.env"
echo ""
