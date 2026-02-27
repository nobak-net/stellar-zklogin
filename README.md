# stellar-zkLogin

**Zero-Knowledge Social Login for Stellar Soroban**

ZK-based identity authentication for Stellar — prove you own a social account (Google, Apple) without revealing your email address. Groth16 proofs verified on-chain via Soroban smart contracts.

> Inspired by [Sui zkLogin](https://docs.sui.io/concepts/cryptography/zklogin), adapted for the Stellar ecosystem using Soroban's native BN254 host functions.

## How It Works

```
  Mobile App                  Attestation Server              Soroban (On-Chain)
  ──────────                  ──────────────────              ──────────────────
  1. Google/Apple OAuth
     → idToken
                    ───────►  2. Validate OAuth token
                              3. Compute identityHash
                              4. Create attestation:
                                 Poseidon(identityHash,
                                          timestamp, nonce)
                    ◄───────  5. Return attestation data

  6. Generate Groth16 proof
     (snarkjs, ~2-5 seconds)
                                                    ───────►  7. identity-auth.authorize()
                                                              8. groth16-verifier.verify(proof)
                                                              9. Store nullifier (replay protection)
                                                             10. Insert commitment into merkle tree
```

**What's proven in zero-knowledge:**
- The user knows an `identityHash` that was attested by the trusted server
- The attestation is recent (configurable freshness window)
- The commitment uniquely binds to their identity without revealing it
- The nullifier prevents proof reuse

**What's never revealed on-chain:**
- Email address, OAuth tokens, provider user ID, attestation details

## Architecture

```
stellar-zkLogin/
├── contracts/
│   ├── identity-auth/        # Orchestrator — verifies proofs, tracks identities
│   ├── groth16-verifier/     # On-chain Groth16 proof verification (BN254)
│   ├── merkle-tree/          # Poseidon merkle tree for identity membership
│   ├── poseidon-hash/        # ZK-friendly hash (BN254/BLS12-381)
│   ├── commitment-scheme/    # Hiding/binding Poseidon + Pedersen commitments
│   ├── bn254-basics/         # BN254 elliptic curve operations
│   ├── zk-wallet/            # ZK-gated token wallet
│   └── zk-key-escrow/        # ZK-gated key recovery escrow
├── circuits/
│   └── identity-attestation/ # Circom circuit (~2,300 constraints)
└── scripts/
    ├── build-all.sh
    └── deploy-testnet.sh
```

### Contract Dependency Graph

```
                     ┌──────────────────┐
                     │  identity-auth   │ ← Orchestrator
                     │  (entry point)   │
                     └────────┬─────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
     ┌────────────────┐ ┌──────────┐ ┌───────────────┐
     │groth16-verifier│ │merkle-tree│ │  (nullifier   │
     │  verify(proof) │ │insert_leaf│ │   storage)    │
     └────────────────┘ └──────────┘ └───────────────┘
              │               │
              ▼               ▼
     ┌────────────────┐ ┌──────────────┐
     │  bn254-basics  │ │poseidon-hash │
     │ (EC operations)│ │ (tree nodes) │
     └────────────────┘ └──────────────┘
```

## Trust Model: Semi-Trusted

stellar-zkLogin uses a **semi-trusted model** — the server validates OAuth tokens and produces attestations, but identity verification happens trustlessly on-chain via Groth16 proofs.

| Layer | Trust Assumption | Mitigation |
|-------|-----------------|------------|
| OAuth Provider | Google/Apple validate identity | Industry standard, audited |
| Attestation Server | Correctly validates tokens, doesn't forge attestations | Server pubkey is committed on-chain; ZK proof binds to specific attestation |
| ZK Circuit | Correctly constrains the proof | Open-source, auditable, trusted setup ceremony |
| Soroban Contracts | On-chain verification is correct | Open-source, formal verification possible |
| Trusted Setup | Powers of Tau ceremony participants didn't collude | Multi-party ceremony with public contributions |

**What the server CANNOT do:**
- Identify which on-chain commitment belongs to which user (blinding factor)
- Replay a user's proof (nullifier protection)
- Create a valid proof without the user's private witness data

**What the server CAN do (trust assumption):**
- Refuse to issue attestations (denial of service, not identity theft)
- Issue attestations for invalid identities (mitigated by OAuth validation)

> See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for full threat analysis.
> See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for comparison with Sui zkLogin.

## Contracts

| Contract | Purpose | Lines | Tests |
|----------|---------|-------|-------|
| `identity-auth` | Orchestrator: verify ZK proofs, track authorized identities | ~1050 | 7+ |
| `groth16-verifier` | On-chain Groth16 verification (BN254 pairing) | ~570 | 4+ |
| `merkle-tree` | Poseidon merkle tree (depth 20, ~1M leaves) | ~610 | 5+ |
| `poseidon-hash` | ZK-friendly Poseidon hash (BN254 + BLS12-381) | ~150 | 2+ |
| `commitment-scheme` | Poseidon commitments + Pedersen (homomorphic) | ~350 | 3+ |
| `bn254-basics` | BN254 EC ops: G1 add/mul, pairing check | ~180 | 2+ |
| `zk-wallet` | ZK-gated token transfers (prove identity to spend) | ~840 | 7+ |
| `zk-key-escrow` | ZK-gated key recovery (prove identity to recover) | ~790 | 8+ |

## Circuit

**`circuits/identity-attestation/`** — Circom 2.1.0

| Metric | Value |
|--------|-------|
| Constraints | ~2,300 |
| Curve | BN254 |
| Proof system | Groth16 |
| WASM size | ~2.1 MB |
| zkey size | ~1.1 MB |
| Proving time | ~2-5s (mobile, snarkjs) |
| Verification time | ~50ms (off-chain) / 1 Soroban TX (on-chain) |

### Circuit I/O

**Private inputs** (witness — never revealed):
- `identityHash` — SHA256 of social identity, as BN254 field element
- `attestationTimestamp`, `serverNonce`, `attestationHash` — server attestation data
- `blinding` — random commitment factor (user-generated)
- `nullifierSecret` — secret for replay protection (user must keep)

**Public inputs** (visible on-chain):
- `currentTimestamp` — ledger timestamp for freshness
- `maxAttestationAge` — configurable validity window
- `serverPubCommitment` — identifies the trusted attestation server

**Public outputs:**
- `commitment = Poseidon(identityHash, blinding)` — hides identity
- `nullifierHash = Poseidon(identityHash, nullifierSecret)` — prevents replay

## Build & Test

### Prerequisites

- Rust 1.74+
- [Stellar CLI](https://developers.stellar.org/docs/tools/developer-tools/cli/install-cli) 23.4+
- Node.js 18+ (for circuit tooling)
- [Circom](https://docs.circom.io/getting-started/installation/) 2.1.0+ (for circuit compilation)

### Build Contracts

```bash
stellar contract build
```

### Run Tests

```bash
cargo test --workspace
```

### Build Circuit

```bash
cd circuits/identity-attestation
npm install
./scripts/compile.sh
./scripts/trusted-setup.sh
```

### Deploy to Testnet

```bash
./scripts/deploy-testnet.sh <SECRET_KEY>
```

## SDK Compatibility

| Dependency | Version |
|-----------|---------|
| `soroban-sdk` | 25.1.1 |
| `soroban-poseidon` | 25.0.0 |
| Circom | 2.1.0 |
| snarkjs | 0.7.x |

## Identity Hash Formula

The identity hash is provider-agnostic:

```
identityHash = SHA256("{provider}:{email}:{userId}:verified:{emailVerified}")
```

| Provider | Prefix | Example |
|----------|--------|---------|
| Google | `gmail` | `SHA256("gmail:user@gmail.com:1234567890:verified:true")` |
| Apple | `apple` | `SHA256("apple:user@icloud.com:001234.abc:verified:true")` |

The hash is truncated to 31 bytes (248 bits) to fit in the BN254 scalar field.

## Prior Art & Comparison

| Feature | stellar-zkLogin | [Sui zkLogin](https://docs.sui.io/concepts/cryptography/zklogin) |
|---------|-----------------|-------------|
| Integration level | Smart contract (Soroban) | Protocol-native (validator consensus) |
| Proof system | Groth16 (BN254) | Groth16 (BN254) |
| OAuth flow | Server attestation → ZK proof | JWK oracle → ZK proof |
| JWK management | Server validates tokens | Validators fetch JWKs via oracle |
| Address derivation | Commitment in merkle tree | `Hash(iss \|\| address_seed)` |
| Privacy mechanism | Poseidon commitment + blinding | `user_salt` separates address from identity |
| Replay protection | Nullifier hash (Tornado Cash model) | Ephemeral keypair + expiry |
| Key model | Direct proof submission | Ephemeral keys bound to OAuth by ZK proof |
| Multi-provider | Google, Apple (extensible) | Google, Apple, Facebook, Twitch, Kakao, Slack |
| Trusted setup | Required (Groth16) | Required (Groth16) |
| Open source | Apache 2.0 | Apache 2.0 |

> See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed architectural comparison.

## Roadmap

- [x] Core ZK primitives (BN254, Groth16, Poseidon, Merkle)
- [x] Identity attestation circuit (Circom)
- [x] Orchestrator contract (identity-auth)
- [x] ZK-gated wallet and key escrow
- [x] Testnet deployment
- [ ] Security audit fixes (14 findings)
- [ ] 47-test security matrix
- [ ] Circuit recompilation (identity rename)
- [ ] Off-chain verification SDK (TypeScript)
- [ ] Mainnet deployment
- [ ] Third-party audit

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for responsible disclosure policy.

For the full security model and threat analysis, see [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).

## License

Apache 2.0 — see [LICENSE](LICENSE).

## References

- [docs/DESIGN_RATIONALE.md](docs/DESIGN_RATIONALE.md) — why this architecture, lessons from Sui zkLogin
- [Sui zkLogin Documentation](https://docs.sui.io/concepts/cryptography/zklogin)
- [Groth16 Paper](https://eprint.iacr.org/2016/260) — Jens Groth, 2016
- [Poseidon Hash](https://eprint.iacr.org/2019/458) — Grassi et al., 2019
- [BN254 Curve (EIP-196)](https://eips.ethereum.org/EIPS/eip-196)
- [Circom Documentation](https://docs.circom.io/)
- [snarkjs](https://github.com/iden3/snarkjs)
- [Tornado Cash Circuit Audit](https://tornado.cash/audits/TornadoCash_circuit_audit_ABDK.pdf) — similar nullifier pattern
- [Soroban Documentation](https://soroban.stellar.org)
