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
├── circuits/
│   └── identity-attestation/   # Circom circuit (2,295 constraints, BN254)
├── contracts/                  # 8 Soroban smart contracts (Rust)
│   ├── identity-auth/          # Orchestrator — verifies proofs, tracks identities
│   ├── groth16-verifier/       # On-chain Groth16 proof verification (BN254)
│   ├── merkle-tree/            # Poseidon merkle tree for identity membership
│   ├── poseidon-hash/          # ZK-friendly hash (BN254/BLS12-381)
│   ├── commitment-scheme/      # Hiding/binding Poseidon + Pedersen commitments
│   ├── bn254-basics/           # BN254 elliptic curve operations
│   ├── zk-wallet/              # ZK-gated token wallet
│   └── zk-key-escrow/          # ZK-gated key recovery escrow
├── packages/
│   ├── sdk/                    # @nobak/stellar-zklogin — TypeScript SDK
│   ├── server/                 # @nobak/stellar-zklogin-server — Reference server (Hono/CF Workers)
│   └── circuits/               # Circuit artifact packaging
├── examples/
│   └── demo/                   # Educational demo site (Hono + vanilla JS, CF Pages)
├── docs/                       # Architecture, security model, trust evolution
├── scripts/
│   ├── build-all.sh
│   ├── deploy-testnet.sh
│   ├── deploy-mainnet.sh
│   └── test-before-deploy.sh
├── package.json                # Monorepo root (npm workspaces + Turborepo)
└── turbo.json                  # Turborepo task config
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

| Contract | Purpose | Lines | WASM | Tests | Status |
|----------|---------|-------|------|-------|--------|
| `identity-auth` | Orchestrator: verify ZK proofs, track authorized identities | ~1050 | 15 KB | 24 | 24 pass |
| `groth16-verifier` | On-chain Groth16 verification (BN254 pairing) | ~570 | 10 KB | 21 | 21 pass |
| `merkle-tree` | Poseidon merkle tree (depth 20, ~1M leaves) | ~610 | 43 KB | 18 | 17 pass, 1 ignored |
| `poseidon-hash` | ZK-friendly Poseidon hash (BN254 + BLS12-381) | ~150 | 127 KB | 5 | 5 pass |
| `commitment-scheme` | Poseidon commitments + Pedersen (homomorphic) | ~350 | 27 KB | 5 | 5 pass |
| `bn254-basics` | BN254 EC ops: G1 add/mul, pairing check | ~180 | 3 KB | 4 | 4 pass |
| `zk-wallet` | ZK-gated token transfers (prove identity to spend) | ~840 | 13 KB | 13 | 13 pass |
| `zk-key-escrow` | ZK-gated key recovery (prove identity to recover) | ~790 | 12 KB | 13 | 13 pass |

> **Test run:** 103 passed, 0 failed, 1 ignored (104 total) — `cargo test --workspace`
> **Circuit tests:** 8 tests (16 assertions) — `node test/circuit-security.test.js`
> The 1 ignored test is a merkle-tree performance benchmark (T-M2).

## Circuit

**`circuits/identity-attestation/`** — Circom 2.1.0

| Metric | Value |
|--------|-------|
| Constraints | 2,295 |
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

## Demo

**[stellar-zklogin-demo.pages.dev](https://stellar-zklogin-demo.pages.dev)** — Interactive educational site.

| Page | What |
|------|------|
| Home (`/`) | Architecture overview, feature status, comparison table |
| Learn (`/learn`) | 8-section deep dive with real code snippets |
| Try It (`/try`) | Guided 6-step tutorial: sign in → hash → attest → prove → verify → wallet |

Built with Hono on Cloudflare Pages, vanilla JS (no framework), Radix UI Themes (CSS-only).

```bash
cd examples/demo
npm install && npm run build    # Build
npm run dev                     # Dev server (localhost:8788)
npm run deploy                  # Deploy to CF Pages
npm test                        # 11 tests (flow + passkey)
```

See `examples/demo/` for source.

## SDK

**`@nobak/stellar-zklogin`** — TypeScript SDK for client-side proving and verification.

```bash
npm install @nobak/stellar-zklogin
```

Exports: identity hashing, Poseidon attestation, Groth16 proving/verification, Soroban encoding, end-to-end `StellarZKLogin` class.

See `packages/sdk/` for source.

## Build & Test

### Monorepo

This is an npm workspaces + Turborepo monorepo. From root:

```bash
npm install           # Install all packages
npm run build         # Build SDK + demo (via Turborepo)
npm test              # Run all TS tests
```

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
./scripts/deploy-testnet.sh $(stellar keys show deployer)
```

### Testnet Deployment (2026-02-27)

| Contract | Contract ID | Status |
|----------|-------------|--------|
| `bn254-basics` | `CCJZTOPNX7VJDW7GD5IZZNSG7T2ODZUCWCSRMEFJ23XSPOAF453BHHIR` | Deployed |
| `poseidon-hash` | `CA6I5VSREXRRSHUE4RJHMBJZSQBUEINO2FZYG2I7OF3XK5VRV7OOWG3K` | Deployed |
| `commitment-scheme` | `CDE236UO4UBL7O6EBYVQTVY25VUDQ5MJ7NK5ZZGBCBBBJIQJVKK5E5HF` | Deployed |
| `groth16-verifier` | `CCCVOVIW5VS4MBYPB77IX2H4IXVOFJCMBD2APMVWDJDYZFX6DYEB3WZ4` | Deployed + Initialized |
| `merkle-tree` | `CBPU2ABXSPEJ5T4KB2ON2KJ24L6BHWF24Z5NELIAJ42ULC5VILMSZOHQ` | Deployed + Initialized |
| `identity-auth` | `CABLST6SHB7F3LNQBFF3BSVNDAPCOMBU2PA5WDKQH4VSOTDA2VWWUVZB` | Deployed |
| `zk-wallet` | `CCFBZVXCOYC73YGLV7Y7JM3WNH5AGPWIYVRGVQSVIYSKARA5RJOHAFC3` | Deployed + Initialized |
| `zk-key-escrow` | `CB5C75XDKXEIZGKIEJ7VR66R56WVUZBVV2H4HA23QGG66EFLU4ZNWCM6` | Deployed + Initialized |

> Contract IDs saved to `deployment_ids.env`. Load with: `source deployment_ids.env`

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
- [ ] **Phase 0: Testnet Hardening** (17 findings, 12-16 engineering days)
  - [ ] Recompile circuit for `identityHash` rename (F4) — compare R1CS hash with v1
  - [ ] Resolve circuit dead signal `serverBindingCheck` — constrain or remove (F10)
  - [x] Add access control to `set_verification_key()` — lock after first set (F9) ✓
  - [ ] Load production VK into groth16-verifier on testnet (F8)
  - [x] Wire identity-auth cross-contract calls to verifier + merkle tree (F1) ✓
  - [x] Fix nullifier ordering — mark AFTER proof verification (F11) ✓
  - [x] Add access control to merkle-tree `insert_leaf()` (F13) ✓
  - [ ] Implement storage TTL for nullifiers + merkle nodes (F5)
  - [ ] Add contract-level timestamp freshness check (F12)
  - [ ] Optimize `is_known_root()` — map instead of linear scan (F14)
  - [ ] Add rate limiting on ZK API endpoints (F15)
  - [ ] Normalize `checkAccount` response timing (F16)
  - [x] Add BN254 field prime bounds check in `decimalToBytes` (F17) ✓
  - [ ] Design secret rotation mechanism (F6)
  - [ ] Decide cross-provider nullifier behavior (F7)
  - [ ] E2E test: iOS → API → Soroban → verify
  - [ ] E2E test: Android → API → Soroban → verify
  - [ ] E2E test: React Native → API → Soroban → verify
  - [x] 45/55 security tests passing (pre-audit target exceeded) — see [docs/SECURITY_TEST_MATRIX.md](docs/SECURITY_TEST_MATRIX.md) ✓
- [ ] **Phase 1: Security Audit** (3-4 weeks, overlapping with Phase 0)
  - [ ] Audit scope: circuit (138 lines) + verifier (341 lines) + orchestrator (721 lines)
  - [ ] Third-party audit engagement
  - [ ] Fix audit findings
- [ ] **Phase 2: Mainnet Deployment** (1-2 weeks post-audit)
  - [ ] Generate production secrets (never reuse testnet)
  - [ ] Deploy contracts to mainnet (verifier → merkle → identity-auth)
  - [ ] Staged rollout: internal → beta → production
- [ ] Off-chain verification SDK (TypeScript)
- [ ] **Phase 3: Hardening & Decentralization** (Q3-Q4 2026)
  - [ ] Key rotation mechanism (multi-commitment support)
  - [ ] Multi-attestor design (N-of-M threshold)
  - [ ] TEE evaluation (AWS Nitro Enclaves)
  - [ ] DKIM circuit research (trustless path)

> See [docs/TRUST_EVOLUTION.md](docs/TRUST_EVOLUTION.md) for the full decentralization spectrum and trust evolution roadmap.

## Current Limitations

> **These are pre-mainnet blockers.** See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for all 17 findings.

| Issue | Contract | Status |
|-------|----------|--------|
| ~~`verify_proof()` is stubbed~~ | zk-wallet, zk-key-escrow | ✅ **Fixed** — real cross-contract verification via groth16-verifier |
| ~~`insert_leaf()` has no caller access control~~ | merkle-tree | ✅ **Fixed** — admin + authorized inserter ACL (F13) |
| `insert_leaf()` panics with `UnreachableCodeReached` | merkle-tree (called by identity-auth) | Feature disabled — merkle tree insertion skipped during `authorize()`. Proof verification and nullifier tracking still functional. |
| Circuit artifacts not recompiled for identity rename | circuits/identity-attestation | `gmail_attestation.*` → `identity_attestation.*` pending (F4) |
| No contract-level timestamp freshness check | identity-auth | Design needed (F12) |

**Remaining pre-mainnet blockers:** Circuit recompile (F4), storage TTL (F5), timestamp freshness (F12), API rate limiting (F15).

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
