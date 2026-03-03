# Architecture: stellar-zkLogin

## Overview

stellar-zkLogin enables zero-knowledge social login on Stellar. Users prove ownership of a social account (Google, Apple) to Soroban smart contracts without revealing their email address or OAuth credentials.

This document covers the full protocol flow, contract architecture, and a detailed comparison with Sui's zkLogin — the most mature ZK social login implementation in production.

---

## Protocol Flow

### Registration (First-Time Login)

```
┌──────────────┐     ┌────────────────────┐     ┌──────────────────────────┐
│  Mobile App  │     │ Attestation Server │     │      Soroban Chain       │
│              │     │  (semi-trusted)    │     │                          │
└──────┬───────┘     └────────┬───────────┘     └────────────┬─────────────┘
       │                      │                              │
       │  1. OAuth Sign-In    │                              │
       │  (Google/Apple)      │                              │
       │  → receives idToken  │                              │
       │                      │                              │
       │  2. POST /get-       │                              │
       │     attestation      │                              │
       │  ──────────────────► │                              │
       │                      │ 3. Validate idToken with     │
       │                      │    provider (Google API)     │
       │                      │                              │
       │                      │ 4. Compute identityHash:     │
       │                      │    SHA256("gmail:email:      │
       │                      │     userId:verified:true")   │
       │                      │                              │
       │                      │ 5. Create attestation:       │
       │                      │    attestationHash =         │
       │                      │    Poseidon(identityHash,    │
       │                      │     timestamp, serverNonce)  │
       │                      │                              │
       │  ◄────────────────── │                              │
       │  6. Attestation data │                              │
       │     + identityHash   │                              │
       │                      │                              │
       │  7. Generate random: │                              │
       │     blinding,        │                              │
       │     nullifierSecret  │                              │
       │                      │                              │
       │  8. snarkjs.groth16. │                              │
       │     fullProve()      │                              │
       │     (~2-5 seconds)   │                              │
       │                      │                              │
       │  9. Submit TX with   │                              │
       │     proof + publics  │                              │
       │  ──────────────────────────────────────────────────►│
       │                      │                              │
       │                      │              10. identity-auth.authorize()
       │                      │                  │
       │                      │                  ├─ groth16-verifier.verify()
       │                      │                  │  (pairing check on BN254)
       │                      │                  │
       │                      │                  ├─ Check nullifier not used
       │                      │                  │
       │                      │                  ├─ Store nullifier
       │                      │                  │
       │                      │                  └─ merkle-tree.insert_leaf()
       │                      │                     (commitment added to tree)
       │                      │                              │
       │  ◄──────────────────────────────────────────────────│
       │  11. TX success                                     │
       │                      │                              │
```

### Recovery (Prove Identity Again)

```
Same flow as registration, but:
- Uses the SAME identityHash (deterministic from OAuth identity)
- Different blinding → different commitment (unlinkable to registration)
- Different nullifierSecret → different nullifier
- identity-auth.is_authorized() checks commitment exists in merkle tree
```

### Authorization Check (Is This User Registered?)

```
identity-auth.is_authorized(commitment, merkle_proof, index)
  └─ merkle-tree.verify_proof(commitment, index, proof, root)
     └─ Returns true if commitment exists in the tree
```

---

## Contract Architecture

### identity-auth (Orchestrator)

The central contract that coordinates proof verification, nullifier tracking, and identity registration.

**Storage layout:**

```
DataKey::Admin           → Address           (contract admin)
DataKey::Config          → IdentityAuthConfig (server pubkey, contract refs, VK hash)
DataKey::VerifierId      → Address           (groth16-verifier contract)
DataKey::MerkleTreeId    → Address           (merkle-tree contract)
DataKey::Nullifier(hash) → bool              (used nullifiers)
DataKey::AuthCount       → u64               (total authorizations)
```

**Key functions:**

| Function | Description |
|----------|-------------|
| `initialize(admin, config)` | Set up contract with server pubkey and references |
| `authorize(proof, request)` | Verify Groth16 proof → store nullifier → insert commitment |
| `is_authorized(commitment, proof, index)` | Verify commitment exists in merkle tree |
| `is_nullifier_used(hash)` | Check replay protection |
| `get_auth_count()` | Total successful authorizations |

**Cross-contract calls:**

```rust
// Proof verification (identity-auth → groth16-verifier)
env.invoke_contract::<bool>(
    &verifier_id,
    &Symbol::new(&env, "verify"),
    vec![&env, proof.into_val(&env), public_inputs.into_val(&env)]
)

// Merkle insertion (identity-auth → merkle-tree)
env.invoke_contract::<U256>(
    &merkle_tree_id,
    &Symbol::new(&env, "insert_leaf"),
    vec![&env, commitment.into_val(&env)]
)
```

### groth16-verifier

On-chain Groth16 verification using Soroban's native BN254 host functions.

**Verification equation:**

```
e(A, B) = e(α, β) · e(L, γ) · e(C, δ)

where L = IC[0] + Σ(public_inputs[i] · IC[i+1])
```

This is the same equation used by Ethereum's precompiles (EIP-196/197) and Sui's zkLogin verifier.

**Storage:**
- `DataKey::Admin` → contract admin
- `DataKey::VerificationKey` → `{ alpha_g1, beta_g2, gamma_g2, delta_g2, ic: Vec<G1> }`

### merkle-tree

Poseidon-based merkle tree for tracking authorized identity commitments.

- **Depth:** 20 (supports ~1,048,576 leaves)
- **Hash:** Poseidon over BN254 scalar field (circuit-compatible)
- **Root history:** Stores historical roots for concurrent authorization checks

### Supporting Contracts

| Contract | Role |
|----------|------|
| `poseidon-hash` | ZK-friendly hash via `soroban-poseidon` crate |
| `commitment-scheme` | Poseidon commitments + Pedersen (homomorphic) |
| `bn254-basics` | Low-level G1 add/mul, G2 ops, pairing check |
| `zk-wallet` | ZK-gated token transfers (prove identity → spend) |
| `zk-key-escrow` | ZK-gated key recovery (prove identity → recover secret) |

---

## Comparison with Sui zkLogin

### Overview

Sui shipped [zkLogin](https://docs.sui.io/concepts/cryptography/zklogin) in September 2023, making it the first L1 with native ZK social login. stellar-zkLogin achieves similar goals for Stellar, with key architectural differences.

Both systems:
- Use **Groth16 on BN254** for ZK proof verification
- Support **Google, Apple** (and other OAuth providers)
- Hide the user's **email and OAuth identity** from the chain
- Require a **trusted setup ceremony** (inherent to Groth16)
- Are **open source** under Apache 2.0

### Detailed Comparison

#### 1. Integration Level

| | Sui zkLogin | stellar-zkLogin |
|---|---|---|
| **Layer** | Protocol-native | Smart contract (Soroban) |
| **Verification** | Part of transaction validation (validators verify proofs) | Cross-contract call to `groth16-verifier` |
| **Gas** | Implicit (part of TX processing) | Explicit Soroban invocation cost |
| **Upgrade** | Requires protocol upgrade | Contract upgrade (admin-controlled) |

**Sui's advantage:** Protocol-level integration means every validator verifies zkLogin proofs as part of consensus. No separate contract deployment needed.

**stellar-zkLogin's advantage:** Deployable by any team without a protocol upgrade. Composable with existing Soroban contracts. Can be iterated independently of the Stellar protocol release cycle.

#### 2. JWK Management (OAuth Key Verification)

| | Sui zkLogin | stellar-zkLogin |
|---|---|---|
| **Approach** | JWK Oracle — validators fetch public keys from providers via consensus | Server attestation — trusted server validates OAuth tokens |
| **JWK source** | Direct from provider (e.g., `accounts.google.com/.well-known/openid-configuration`) | Server calls provider API, produces signed attestation |
| **Trust model** | Trust the provider's HTTPS endpoint + validator consensus | Trust the attestation server + provider's API |
| **Key rotation** | Automatic — validators observe new JWKs | Server updates; circuit binds to `serverPubCommitment` |

**Sui's advantage:** The JWK oracle removes the need for a trusted intermediary. Validators themselves fetch and agree on OAuth provider public keys, making the system closer to trustless.

**stellar-zkLogin's trade-off:** The attestation server is an additional trust assumption. However, the server CANNOT forge identities (it doesn't know the user's `blinding` or `nullifierSecret`), and its public commitment is fixed on-chain.

#### 3. Address / Identity Model

| | Sui zkLogin | stellar-zkLogin |
|---|---|---|
| **Address derivation** | `zkLoginAddress = Hash(iss \|\| address_seed)` where `address_seed = Poseidon(user_salt, sub)` | `commitment = Poseidon(identityHash, blinding)` stored in merkle tree |
| **Determinism** | Same OAuth identity → same address (given same `user_salt`) | Same OAuth identity → different commitments each time (different `blinding`) |
| **Linkability** | Address is stable — same user = same address across sessions | Unlinkable by default — each proof produces a fresh commitment |
| **Identity binding** | `sub` (OAuth subject) directly in address derivation | `identityHash = SHA256(provider:email:userId:verified:flag)` |

**Sui's advantage:** Deterministic addresses mean the user's Sui account is directly tied to their OAuth identity (via salt). Simple mental model: "my Google account IS my wallet."

**stellar-zkLogin's advantage:** Unlinkable commitments provide stronger privacy — an observer cannot tell if two authorizations came from the same user. The identity is bound to a merkle tree membership, not an address.

#### 4. Key Management

| | Sui zkLogin | stellar-zkLogin |
|---|---|---|
| **Signing model** | Ephemeral keypairs — short-lived keys authorized by ZK proof | Direct proof submission — no intermediate keypairs |
| **Key lifecycle** | Generate ephemeral key → bind to OAuth via ZK proof → use for signing → expires | Generate proof → submit in TX → done |
| **Session concept** | Yes — ephemeral key is valid for a configurable period | No — each action requires a fresh proof (or cached authorization) |
| **Multi-sig** | Supported — ephemeral key is one signer | Supported via `zk-wallet` contract with separate spending authorization |

**Sui's advantage:** Ephemeral keys enable a session-like UX — sign once with ZK, then use the ephemeral key for multiple transactions until it expires. Better for frequent interactions.

**stellar-zkLogin's approach:** Simpler model — prove identity when needed, no key management complexity. Better for infrequent but high-value operations (account recovery, key escrow).

#### 5. Privacy Properties

| Property | Sui zkLogin | stellar-zkLogin |
|----------|-------------|-----------------|
| **Email hidden** | Yes — only `address_seed` on-chain | Yes — only `commitment` on-chain |
| **Provider hidden** | No — `iss` is in the address | Yes — `identityHash` mixes provider opaquely |
| **Cross-session linkability** | Linkable (same address) | Unlinkable (different blinding per proof) |
| **User salt** | `user_salt` separates on-chain identity from OAuth identity; user controls it | `blinding` serves similar purpose; generated per-proof |
| **Nullifier** | Not used — ephemeral key expiry prevents replay | `nullifierHash = Poseidon(identityHash, nullifierSecret)` |

#### 6. Proof Generation

| | Sui zkLogin | stellar-zkLogin |
|---|---|---|
| **Prover** | Centralized prover service (Mysten Labs) or local | Client-side only (snarkjs in WebView/browser) |
| **Proving time** | ~2-5 seconds (centralized) | ~2-5 seconds (mobile, snarkjs) |
| **Circuit size** | Not disclosed | 2,295 constraints |
| **Witness** | JWT + ephemeral key + user salt | identityHash + attestation + blinding + nullifierSecret |

**Sui's advantage:** Mysten Labs operates a centralized prover service, offloading computation from the client. Users can also prove locally.

**stellar-zkLogin's approach:** Client-side only — the proof never leaves the user's device. No centralized prover service to trust or depend on.

### Summary: When Each Approach Wins

| Scenario | Better Fit |
|----------|-----------|
| Wallet where address = identity (Web3 UX) | Sui zkLogin |
| Privacy-preserving identity verification | stellar-zkLogin |
| Frequent transactions (gaming, social) | Sui zkLogin (ephemeral keys) |
| High-value operations (recovery, escrow) | stellar-zkLogin (per-action proofs) |
| No trusted intermediary required | Sui zkLogin (JWK oracle) |
| Deployable without protocol changes | stellar-zkLogin (contract-level) |
| Unlinkable multi-session privacy | stellar-zkLogin (fresh commitments) |
| Stable cross-dApp identity | Sui zkLogin (deterministic addresses) |

---

## Identity Hash Design

### Multi-Provider Formula

```
identityHash = SHA256("{provider}:{email}:{userId}:verified:{emailVerified}")
```

This formula is intentionally similar to how Sui constructs `address_seed`, but differs in key ways:

| Design Choice | stellar-zkLogin | Sui zkLogin |
|---------------|-----------------|-------------|
| Hash function (off-chain) | SHA256 | N/A (uses `sub` directly) |
| Hash function (in-circuit) | Poseidon | Poseidon |
| Input structure | `"provider:email:userId:verified:flag"` | `Poseidon(user_salt, sub)` |
| Provider in hash | Yes (prefix) | Separate (`iss` in address) |
| Email in hash | Yes | No (uses `sub` only) |

**Why include email?** Binding to both `email` and `userId` prevents edge cases where a provider reassigns a `sub` (user ID) to a different email, or where an email is transferred between provider accounts.

**Why SHA256 → then Poseidon?** The identity hash is computed off-chain (server-side) where SHA256 is standard. Inside the circuit, all hashing uses Poseidon (ZK-friendly, ~8x fewer constraints than SHA256).

### Provider Prefixes

| Provider | Prefix | Status |
|----------|--------|--------|
| Google | `gmail` | Implemented |
| Apple | `apple` | Designed, not yet deployed |
| Facebook | `facebook` | Future |
| GitHub | `github` | Future |

The `gmail` prefix is maintained for backward compatibility with existing deployments, even though the system is provider-agnostic.

---

## Circuit Design

### Constraint Breakdown

```
Step 1: Attestation verification     Poseidon(3)        ~800 constraints
Step 2: Server binding               Poseidon(2)        ~500 constraints
Step 3: Timestamp freshness          LessEqThan(64) ×2  ~200 constraints
Step 4: Commitment computation       Poseidon(2)        ~500 constraints
Step 5: Nullifier computation        Poseidon(2)        ~500 constraints
                                                    ─────────────────
                                     Total:          2,295 constraints
```

### Comparison with Sui's Circuit

Sui's zkLogin circuit is significantly larger because it verifies the JWT signature **inside the circuit** (RSA verification in BN254 arithmetic). stellar-zkLogin moves OAuth validation to the attestation server, keeping the circuit small.

| | Sui zkLogin Circuit | stellar-zkLogin Circuit |
|---|---|---|
| JWT parsing | In-circuit | Off-chain (server) |
| Signature verification | RSA in BN254 (~100K+ constraints) | Poseidon attestation (~800 constraints) |
| Total constraints | Estimated 100K+ | 2,295 |
| Proving time impact | Heavier (needs prover service) | Lightweight (mobile-friendly) |
| Trust trade-off | Trustless JWT verification | Trusted attestation server |

---

## Deployment Architecture

### Testnet (Current)

```
                          Stellar Testnet
                    ┌─────────────────────────┐
                    │  groth16-verifier       │◄── VK loaded at deploy
                    │  poseidon-hash          │
                    │  commitment-scheme      │
                    │  merkle-tree            │◄── Admin = identity-auth
                    │  bn254-basics           │
                    │  identity-auth          │◄── References verifier + merkle
                    │  zk-wallet              │
                    │  zk-key-escrow          │
                    └─────────────────────────┘

  Deploy order:
  1. groth16-verifier  → load VK (locked after first set)
  2. poseidon-hash, commitment-scheme, bn254-basics
  3. merkle-tree       → initialize(admin = identity-auth address)
  4. identity-auth     → initialize(config with verifier + merkle IDs)
  5. zk-wallet         → initialize(admin, verifier_id, token_id)
  6. zk-key-escrow     → initialize(admin, verifier_id)
```

### Mainnet (Target)

Same architecture with:
- Multi-party trusted setup ceremony (not single-party)
- VK locked permanently after first set (F9 fix)
- Rate limiting on attestation server
- Monitoring and alerting on contract state
- Third-party audit completed

---

## Future: Trustless Path

The semi-trusted model can evolve toward trustless in two ways:

### Option A: Stellar JWK Oracle (Requires Protocol Work)

Similar to Sui's approach — validators fetch OAuth provider JWKs and reach consensus. This eliminates the attestation server entirely.

**Requires:** Stellar protocol support for external data oracles (not currently available).

### Option B: DKIM Verification in Circuit (zkEmail)

Verify the OAuth provider's DKIM email signature inside the ZK circuit. No server needed — the user provides their email header and the circuit verifies the DKIM signature.

**Trade-off:** Circuit grows to ~500K-1M constraints. Proving time increases to 30-60 seconds. Reference: [zkEmail](https://github.com/zkemail/zk-email-verify).

### Option C: Multi-Attestation Threshold

Require attestations from N-of-M independent servers. No single server can forge identities.

**Trade-off:** Circuit grows linearly with N. Operational complexity of running M servers.

### Option D: Off-Chain Verification SDK (Sui-Inspired)

Provide a TypeScript/Rust SDK for verifying proofs without submitting transactions. Inspired by Sui's `verifyPersonalMessageSignature()` approach.

**How it works:**
1. Fetch the VK from `groth16-verifier` via Soroban RPC `getContractData()`
2. Run `snarkjs.groth16.verify(proof, publicInputs, vk)` locally (~50ms)
3. Check nullifier status via Soroban RPC `getContractData()`
4. Return verified result without paying gas

**Use cases:**
- Pre-validate proofs before submitting (avoid wasted gas)
- Server-side ZK authentication without on-chain calls
- Debug/test workflow without deploying contracts
- Rate-limit expensive on-chain calls by pre-checking off-chain

**Note:** This is not trustless off-chain verification — the chain remains the source of truth for the VK and nullifier state. The SDK queries chain state via RPC and performs Groth16 verification locally.

See [DESIGN_RATIONALE.md](DESIGN_RATIONALE.md) for the full analysis of Sui's off-chain verification and our planned approach.

---

## References

- [Sui zkLogin Docs](https://docs.sui.io/concepts/cryptography/zklogin)
- [Sui zkLogin Blog Post](https://blog.sui.io/zklogin-privacy/)
- [Tornado Cash — Nullifier Pattern](https://tornado.cash/audits/TornadoCash_circuit_audit_ABDK.pdf)
- [Poseidon Hash Paper](https://eprint.iacr.org/2019/458)
- [Groth16 Paper](https://eprint.iacr.org/2016/260)
- [zkEmail](https://github.com/zkemail/zk-email-verify)
- [Soroban BN254 Host Functions](https://soroban.stellar.org)
- [DESIGN_RATIONALE.md](DESIGN_RATIONALE.md) — why this architecture, lessons from Sui zkLogin
