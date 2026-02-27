# Identity Attestation ZK Circuit

**Zero-Knowledge Social Identity Proof for Soroban**

This circuit enables users to prove they own a social account (Google, Apple, etc.) without revealing their email address. It uses a semi-trusted model where a server validates OAuth and provides attestations — similar in purpose to [Sui zkLogin](https://docs.sui.io/concepts/cryptography/zklogin), but with a smaller circuit optimized for mobile proving.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                 ZK SOCIAL IDENTITY FLOW                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. User → OAuth Sign-In (Google/Apple) → idToken                │
│  2. Server validates idToken, computes identityHash              │
│  3. Server creates attestation:                                  │
│       attestationHash = Poseidon(identityHash, timestamp, nonce) │
│  4. User receives attestation data                               │
│  5. User runs snarkjs locally → Groth16 proof (~2-5 seconds)    │
│  6. Proof submitted to groth16-verifier contract (on-chain)      │
│  7. identity-auth contract tracks nullifiers & commitments       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## What the Circuit Proves

The prover demonstrates (in zero-knowledge) that:

1. **Server Attestation**: They know an identityHash that was attested by the trusted server
2. **Freshness**: The attestation is recent (within configurable time window)
3. **Commitment**: The output commitment uniquely binds to their identityHash
4. **Non-replay**: The nullifier prevents reusing the same proof

## Comparison with Sui zkLogin Circuit

| Aspect | This circuit | Sui zkLogin circuit |
|--------|-------------|---------------------|
| JWT verification | Off-chain (server) | In-circuit (RSA in BN254) |
| Constraints | ~2,300 | ~100,000+ |
| Proving time | ~2-5s (mobile, snarkjs) | ~2-5s (centralized prover) |
| Trust trade-off | Requires trusted attestation server | Trustless (JWK oracle) |
| Mobile-friendly | Yes (lightweight circuit) | Typically uses centralized prover |

The key trade-off: Sui verifies the JWT signature *inside* the circuit (trustless but expensive), while stellar-zkLogin delegates JWT validation to the server (semi-trusted but 40x fewer constraints).

## Circuit Inputs/Outputs

### Private Inputs (Hidden from Verifier)

| Input | Description |
|-------|-------------|
| `identityHash` | SHA256("{provider}:{email}:{userId}:verified:{flag}") as field element |
| `attestationTimestamp` | Unix timestamp when server created attestation |
| `serverNonce` | Random nonce from server |
| `attestationHash` | Poseidon(identityHash, timestamp, nonce) from server |
| `blinding` | Random value for commitment (user-generated) |
| `nullifierSecret` | Secret for nullifier (user must keep secret) |

### Public Inputs (Visible On-Chain)

| Input | Description |
|-------|-------------|
| `currentTimestamp` | Current blockchain time |
| `maxAttestationAge` | Max age of attestation in seconds (e.g., 86400 = 24h) |
| `serverPubCommitment` | Server's public key commitment (known constant) |

### Public Outputs

| Output | Description |
|--------|-------------|
| `commitment` | Poseidon(identityHash, blinding) — hides identityHash |
| `nullifierHash` | Poseidon(identityHash, nullifierSecret) — prevents replay |

## Identity Hash Formula

```
identityHash = SHA256("{provider}:{email}:{userId}:verified:{emailVerified}")
```

| Provider | Prefix | Example |
|----------|--------|---------|
| Google | `gmail` | `SHA256("gmail:user@gmail.com:1234567890:verified:true")` |
| Apple | `apple` | `SHA256("apple:user@icloud.com:001234.abc:verified:true")` |

The `gmail` prefix is maintained for backward compatibility with existing deployments.

## Quick Start

### Prerequisites

1. **Install Circom** (2.1.0+):
   ```bash
   curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh
   git clone https://github.com/iden3/circom.git
   cd circom && cargo build --release && cargo install --path circom
   ```

2. **Install Node.js** (18+)

3. **Install dependencies**:
   ```bash
   cd circuits/identity-attestation
   npm install
   ```

### Build & Test

```bash
# 1. Compile the circuit
./scripts/compile.sh

# 2. Run trusted setup (one-time)
./scripts/trusted-setup.sh

# 3. Generate a test proof
npm run test:generate

# 4. Verify the proof
npm run test:verify
```

## Circuit Statistics

| Metric | Value |
|--------|-------|
| Constraints | ~2,300 |
| Curve | BN254 |
| Proof system | Groth16 |
| WASM size | ~2.1 MB |
| zkey size | ~1.1 MB |
| Proving time | ~2-5 seconds (mobile) |
| Verification time | ~50 ms (off-chain) |

## File Structure

```
circuits/identity-attestation/
├── src/
│   └── identity_attestation.circom  # Main circuit
├── scripts/
│   ├── compile.sh                   # Compilation script
│   └── trusted-setup.sh            # Trusted setup ceremony
├── test/
│   ├── generate-proof.js           # Proof generation test
│   └── verify-proof.js            # Verification test
├── build/                          # Compiled artifacts (generated)
│   ├── identity_attestation.r1cs
│   ├── identity_attestation_js/
│   ├── proof.json
│   └── public.json
├── keys/                           # Cryptographic keys (generated)
│   ├── identity_attestation.zkey  # Proving key
│   └── verification_key.json     # Verification key
├── package.json
└── README.md
```

## Integration with Soroban

### Using groth16-verifier (Direct)

```rust
let proof = Groth16Proof { a, b, c };
let valid = verifier.verify(&proof, &public_inputs);
```

### Using identity-auth (Orchestrator)

```rust
// identity-auth handles verification + nullifier tracking + merkle insertion
identity_auth.authorize(&proof, &commitment, &nullifier_hash);

// Check if user is authorized
let is_auth = identity_auth.is_authorized(&commitment);
```

## Security Model

### What's Trusted

- **Attestation server**: Validates OAuth tokens, produces attestations
- **Server key**: The server's signing key must remain secret
- **Trusted setup**: The Powers of Tau ceremony participants (≥1 must be honest)

### What's Zero-Knowledge

- The user's email address
- The user's OAuth user ID
- The attestation timestamp and server nonce
- The blinding factor and nullifier secret

### What's Public (On-Chain)

- The commitment (binds to identityHash but doesn't reveal it)
- The nullifier hash (prevents replay but doesn't identify user)
- Current timestamp and max age (freshness parameters)
- Server's public commitment (identifies trusted server)

See [docs/SECURITY_MODEL.md](../../docs/SECURITY_MODEL.md) for full threat analysis.

## References

- [Sui zkLogin](https://docs.sui.io/concepts/cryptography/zklogin) — reference architecture
- [Circom Documentation](https://docs.circom.io/)
- [snarkjs](https://github.com/iden3/snarkjs)
- [circomlib](https://github.com/iden3/circomlib)
- [BN254 Curve (EIP-196)](https://eips.ethereum.org/EIPS/eip-196)
- [Groth16 Paper](https://eprint.iacr.org/2016/260)

## License

Apache-2.0
