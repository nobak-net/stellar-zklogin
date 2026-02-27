#!/usr/bin/env bash
#
# Pre-deploy gate: build, test, and validate contracts before deployment.
#
# Run this BEFORE deploy-testnet.sh or deploy-mainnet.sh.
# If any step fails, deployment is NOT safe.
#
# Usage:
#   ./scripts/test-before-deploy.sh
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

FAILED=0
TOTAL=0
PASSED=0

check() {
    TOTAL=$((TOTAL + 1))
    local desc="$1"
    shift
    if "$@" > /dev/null 2>&1; then
        PASSED=$((PASSED + 1))
        echo -e "  ${GREEN}✓${NC} $desc"
    else
        FAILED=$((FAILED + 1))
        echo -e "  ${RED}✗${NC} $desc"
    fi
}

echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Pre-Deploy Contract Validation${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo ""

# ─────────────────────────────────────────────────────
# Step 1: Build
# ─────────────────────────────────────────────────────
echo -e "${YELLOW}Step 1: Build${NC}"
echo "────────────────────────────────────────"

if cargo build --target wasm32-unknown-unknown --release 2>&1; then
    echo -e "  ${GREEN}✓${NC} All contracts compile"
else
    echo -e "  ${RED}✗${NC} Build failed — aborting"
    exit 1
fi
echo ""

# ─────────────────────────────────────────────────────
# Step 2: Unit tests
# ─────────────────────────────────────────────────────
echo -e "${YELLOW}Step 2: Unit Tests${NC}"
echo "────────────────────────────────────────"

for contract in groth16-verifier merkle-tree identity-auth; do
    TOTAL=$((TOTAL + 1))
    OUTPUT=$(cargo test -p "$contract" 2>&1 || true)
    # Count passed/failed from test output
    RESULT_LINE=$(echo "$OUTPUT" | grep "^test result:" | tail -1)
    if echo "$RESULT_LINE" | grep -q "0 failed"; then
        PASSED=$((PASSED + 1))
        PASS_COUNT=$(echo "$RESULT_LINE" | grep -o '[0-9]* passed' | grep -o '[0-9]*')
        echo -e "  ${GREEN}✓${NC} $contract — $PASS_COUNT tests passed"
    else
        FAIL_COUNT=$(echo "$RESULT_LINE" | grep -o '[0-9]* failed' | grep -o '[0-9]*')
        PASS_COUNT=$(echo "$RESULT_LINE" | grep -o '[0-9]* passed' | grep -o '[0-9]*')
        # List which tests failed
        FAILED_TESTS=$(echo "$OUTPUT" | grep "^    test::" | sed 's/^    //')
        FAILED=$((FAILED + 1))
        echo -e "  ${RED}✗${NC} $contract — $FAIL_COUNT failed, $PASS_COUNT passed"
        echo "$OUTPUT" | grep "^failures:" -A 100 | grep "^    " | while read -r line; do
            echo -e "      ${RED}↳${NC} $line"
        done
    fi
done
echo ""

# ─────────────────────────────────────────────────────
# Step 3: WASM size check
# ─────────────────────────────────────────────────────
echo -e "${YELLOW}Step 3: WASM Size Validation${NC}"
echo "────────────────────────────────────────"

# Soroban max contract size is 256KB (262144 bytes)
MAX_SIZE=262144

for wasm in target/wasm32-unknown-unknown/release/{groth16_verifier,merkle_tree,identity_auth}.wasm; do
    TOTAL=$((TOTAL + 1))
    NAME=$(basename "$wasm" .wasm)
    SIZE=$(stat -f%z "$wasm" 2>/dev/null || stat -c%s "$wasm" 2>/dev/null)
    SIZE_KB=$((SIZE / 1024))

    if [ "$SIZE" -lt "$MAX_SIZE" ]; then
        PASSED=$((PASSED + 1))
        echo -e "  ${GREEN}✓${NC} $NAME — ${SIZE_KB}KB (limit: 256KB)"
    else
        FAILED=$((FAILED + 1))
        echo -e "  ${RED}✗${NC} $NAME — ${SIZE_KB}KB exceeds 256KB limit!"
    fi
done
echo ""

# ─────────────────────────────────────────────────────
# Step 4: Security invariants (static checks)
# ─────────────────────────────────────────────────────
echo -e "${YELLOW}Step 4: Security Invariants${NC}"
echo "────────────────────────────────────────"

# Check that upgrade() exists in all 3 deployment contracts
for contract in identity-auth groth16-verifier merkle-tree; do
    TOTAL=$((TOTAL + 1))
    if grep -q "fn upgrade" "contracts/$contract/src/lib.rs"; then
        PASSED=$((PASSED + 1))
        echo -e "  ${GREEN}✓${NC} $contract has upgrade() function"
    else
        FAILED=$((FAILED + 1))
        echo -e "  ${RED}✗${NC} $contract MISSING upgrade() — cannot patch after deploy!"
    fi
done

# Check that admin is stored (not hardcoded to contract address)
TOTAL=$((TOTAL + 1))
if grep -q "current_contract_address" "contracts/identity-auth/src/lib.rs"; then
    FAILED=$((FAILED + 1))
    echo -e "  ${RED}✗${NC} identity-auth still uses current_contract_address() for admin (bug)"
else
    PASSED=$((PASSED + 1))
    echo -e "  ${GREEN}✓${NC} identity-auth admin is externally set"
fi

# Check that set_verification_key requires admin
TOTAL=$((TOTAL + 1))
if grep -A3 "fn set_verification_key" "contracts/groth16-verifier/src/lib.rs" | grep -q "require_admin\|admin.*require_auth"; then
    PASSED=$((PASSED + 1))
    echo -e "  ${GREEN}✓${NC} groth16-verifier set_verification_key is admin-gated"
else
    FAILED=$((FAILED + 1))
    echo -e "  ${RED}✗${NC} groth16-verifier set_verification_key is NOT admin-gated!"
fi

# Check that nullifier tracking exists
TOTAL=$((TOTAL + 1))
if grep -q "NullifierAlreadyUsed" "contracts/identity-auth/src/lib.rs"; then
    PASSED=$((PASSED + 1))
    echo -e "  ${GREEN}✓${NC} identity-auth has nullifier replay protection"
else
    FAILED=$((FAILED + 1))
    echo -e "  ${RED}✗${NC} identity-auth MISSING nullifier replay protection!"
fi

echo ""

# ─────────────────────────────────────────────────────
# Step 5: Circuit artifacts check
# ─────────────────────────────────────────────────────
echo -e "${YELLOW}Step 5: Circuit Artifacts${NC}"
echo "────────────────────────────────────────"

check "verification_key_soroban.json exists" test -f "circuits/identity-attestation/keys/verification_key_soroban.json"
check "identity_attestation.wasm (circom) exists" test -f "circuits/identity-attestation/build/identity_attestation_js/identity_attestation.wasm"

echo ""

# ─────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}  ALL $TOTAL CHECKS PASSED — safe to deploy${NC}"
else
    echo -e "${RED}  $FAILED/$TOTAL CHECKS FAILED — DO NOT DEPLOY${NC}"
fi
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo ""

exit $FAILED
