# Quick Start — stellar-zkLogin Deployment & Testing

Deploy and test the on-chain ZK social identity authentication system on Stellar testnet.

## Prerequisites

```bash
# Install Stellar CLI
brew install stellar/tap/stellar-cli

# Verify installation
stellar --version  # Should be 23.4+

# Create testnet account
stellar keys generate --network testnet deployer
stellar keys address deployer
```

**Fund your testnet account:**
Visit https://laboratory.stellar.org/#account-creator and fund the address.

## Step 1: Build Contracts (~5 minutes)

```bash
cd stellar-zkLogin

# Build all contracts
stellar contract build

# Verify WASM files
ls target/wasm32-unknown-unknown/release/*.wasm
```

## Step 2: Deploy Contracts (~10 minutes)

```bash
# Deploy to testnet
./scripts/deploy-testnet.sh $(stellar keys show deployer)

# The script deploys in dependency order:
#   1. groth16-verifier → loads VK
#   2. poseidon-hash, commitment-scheme, bn254-basics
#   3. merkle-tree → admin set to identity-auth address
#   4. identity-auth → configured with verifier + merkle refs
#   5. zk-wallet, zk-key-escrow

# Save the contract IDs
source deployment_ids.env
```

## Step 3: Initialize Identity Auth

```bash
# Get VK hash from circuit
VK_HASH=$(jq -r '.vk_hash' circuits/identity-attestation/keys/verification_key_soroban.json)

# Initialize identity-auth with server pubkey and contract references
stellar contract invoke \
  --id $IDENTITY_AUTH_ID \
  --network testnet \
  --source $(stellar keys show deployer) \
  -- \
  initialize \
  --config "{
    \"server_pub_key\": \"<YOUR_SERVER_PUBKEY>\",
    \"verifier_id\": \"$GROTH16_VERIFIER_ID\",
    \"merkle_tree_id\": \"$MERKLE_TREE_ID\",
    \"vk_hash\": \"$VK_HASH\"
  }"

# Verify initialization
stellar contract invoke \
  --id $IDENTITY_AUTH_ID \
  --network testnet \
  -- \
  is_initialized
# Expected: true
```

## Step 4: Verify Deployment

```bash
# Check contract state
stellar contract invoke \
  --id $IDENTITY_AUTH_ID \
  --network testnet \
  -- \
  get_config

# Check authorization count (should be 0)
stellar contract invoke \
  --id $IDENTITY_AUTH_ID \
  --network testnet \
  -- \
  get_auth_count

# Check merkle tree root
stellar contract invoke \
  --id $MERKLE_TREE_ID \
  --network testnet \
  -- \
  get_root
```

## Step 5: Generate & Submit a Test Proof

```bash
# Build circuit (if not already compiled)
cd circuits/identity-attestation
npm install
./scripts/compile.sh
./scripts/trusted-setup.sh

# Generate a test proof
npm run test:generate

# The proof + public inputs can now be submitted to identity-auth.authorize()
```

## Troubleshooting

### "Contract not found"

```bash
# Verify contract exists
stellar contract info \
  --id $IDENTITY_AUTH_ID \
  --network testnet
```

### "Verification key not set"

```bash
# Check VK in verifier
stellar contract invoke \
  --id $GROTH16_VERIFIER_ID \
  --network testnet \
  -- \
  get_verification_key

# If empty, use the VK loading script
./scripts/load-vk.sh $GROTH16_VERIFIER_ID $(stellar keys show deployer)
```

### "Nullifier already used"

The proof has already been submitted. Generate a new proof with a different `nullifierSecret`.

### "Assert Failed" in circuit

Input values must be valid BN254 field elements (< field modulus `21888242871839275222246405745257275088548364400416034343698204186575808495617`).

## Architecture Reference

See [README.md](README.md) for full architecture and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for Sui zkLogin comparison.

## Deploy Sequence Diagram

```
groth16-verifier  ←──  Load VK (locked after first set)
       │
poseidon-hash, commitment-scheme, bn254-basics  (independent)
       │
merkle-tree  ←──  initialize(admin = identity-auth address)
       │
identity-auth  ←──  initialize(verifier_id, merkle_tree_id, server_pubkey)
       │
zk-wallet  ←──  initialize(admin, verifier_id, token_id)
zk-key-escrow  ←──  initialize(admin, verifier_id)
```

## Resources

- Contract source: `contracts/*/src/lib.rs`
- Circuit source: `circuits/identity-attestation/src/identity_attestation.circom`
- Security model: [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md)
- Stellar Testnet Explorer: https://stellar.expert/explorer/testnet
- Stellar Laboratory: https://laboratory.stellar.org
