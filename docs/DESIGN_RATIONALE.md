# Design Rationale: stellar-zkLogin

Why this architecture? What did we learn from Sui zkLogin, and where did we deliberately diverge?

This document captures the design reasoning behind stellar-zkLogin's key decisions. For the technical reference, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Why This Architecture?

stellar-zkLogin exists because Stellar has no native ZK social login — unlike Sui, where zkLogin is part of the validator consensus layer. We needed a system that:

1. **Deploys without protocol changes** — pure Soroban smart contracts
2. **Runs on mobile** — proof generation under 5 seconds on mid-range phones
3. **Supports multiple providers** — Google today, Apple/GitHub/etc. tomorrow
4. **Preserves privacy** — email never touches the chain

The semi-trusted attestation model is the key trade-off that makes all four goals achievable simultaneously.

---

## Lessons from Sui zkLogin

Sui's [zkLogin](https://docs.sui.io/concepts/cryptography/zklogin) (shipped September 2023) is the most mature ZK social login in production. We studied it closely and made deliberate choices about what to adopt, adapt, or reject.

### 1. JWK Oracle vs. Server Attestation

**Sui's approach:** Validators fetch OAuth provider JWKs via consensus — a JWK oracle protocol. No trusted intermediary between the user and the chain.

**Our approach:** A server validates OAuth tokens and produces a Poseidon attestation. The server's public commitment is fixed on-chain.

**Why we diverged:**

Stellar has no oracle protocol support. Building a JWK oracle requires validator-level changes — exactly what we wanted to avoid. The attestation model introduces a trust assumption (the server could refuse service) but enables a dramatically smaller circuit:

| Metric | Sui (JWK in-circuit) | stellar-zkLogin (attestation) |
|--------|---------------------|-------------------------------|
| Circuit constraints | ~100K+ (RSA verification in BN254) | 2,295 |
| Proving time | Needs prover service | Mobile-friendly (~2-5s) |
| Trust assumption | Provider HTTPS + validator consensus | Provider API + attestation server |

The attestation server cannot forge identities — it doesn't know the user's `blinding` or `nullifierSecret`. It can only deny service (refuse to attest), which is a liveness issue, not a security one.

### 2. Deterministic Addresses vs. Unlinkable Commitments

**Sui's approach:** `zkLoginAddress = Hash(iss || Poseidon(user_salt, sub))` — same user always maps to the same address. Simple mental model: "my Google account IS my wallet."

**Our approach:** `commitment = Poseidon(identityHash, blinding)` — each proof produces a fresh, unlinkable commitment stored in a merkle tree. An observer cannot tell if two authorizations came from the same user.

**Why we diverged:**

stellar-zkLogin targets privacy-preserving identity verification (account recovery, key escrow, access control) rather than "address = identity" wallets. Unlinkable commitments are strictly better for:

- Recovery operations where you don't want on-chain evidence of recovery events being linkable
- Multi-device authorization where device correlation is a privacy risk
- Escrow/custody where the identity binding should be one-way (prove membership, not reveal who)

Sui's deterministic addresses are better for the "my wallet" use case, but that wasn't our goal.

### 3. Ephemeral Keys vs. Per-Action Proofs

**Sui's approach:** A ZK proof authorizes a short-lived ephemeral keypair. That key can then sign multiple transactions during a session window — sign once, transact many times.

**Our approach:** Each action that requires identity verification needs a fresh ZK proof. No intermediate keypairs, no session concept.

**Why we diverged:**

Ephemeral keys optimize for high-frequency interactions (gaming, social, DeFi trading). stellar-zkLogin targets infrequent but high-value operations:

- Account recovery (once per device, ever)
- Key escrow deposit/retrieval (rare)
- Identity verification for compliance (occasional)

For these use cases, the extra complexity of ephemeral key management isn't justified. A 2-5 second proof per action is acceptable when you're recovering an account, not when you're placing rapid trades.

### 4. Protocol-Native vs. Contract-Level

**Sui's approach:** Validators verify zkLogin proofs as part of transaction validation. Deep protocol integration.

**Our approach:** Cross-contract calls to `groth16-verifier` on Soroban. No protocol changes needed.

**Why we diverged:**

Deploying at the contract level means:
- Any team can deploy stellar-zkLogin without waiting for Stellar protocol upgrades
- Contracts can be upgraded independently (admin-controlled `upgrade()`)
- Different deployments can use different circuits, verification keys, or trust models
- The explicit gas cost is the trade-off (vs. Sui's implicit verification cost)

This also means we can iterate on the circuit, trust model, and contract logic without coordinating with the Stellar validator network.

### 5. Off-Chain Verification

**Sui's approach:** Provides off-chain signature verification without submitting transactions:
- **TypeScript SDK:** `verifyPersonalMessageSignature()` — initializes a GraphQL client
- **GraphQL endpoint:** Query JWK state + verify locally
- **Keytool CLI:** `sui keytool verify-zklogin-sig` for debugging

**Critical nuance:** This is not trustless off-chain verification. It queries the blockchain's JWK state via GraphQL/RPC, then performs the Groth16 verify locally. It's a convenience layer — verify before submitting, without paying gas.

**Our current state:** All proofs must go through `identity-auth.authorize()` on Soroban. There is no off-chain verification path.

**Why this matters:**
- Clients can't validate proofs before submitting (wasted gas on bad proofs)
- Servers can't authenticate users via ZK proofs without on-chain calls
- No debug/testing path without deploying contracts

**Future path:** An off-chain verification SDK (TypeScript/Rust) that:

1. Fetches the VK from `groth16-verifier` via Soroban RPC `getContractData()`
2. Runs `snarkjs.groth16.verify(proof, publicInputs, vk)` locally (~50ms)
3. Checks nullifier status via Soroban RPC `getContractData()`
4. Returns the verified result without submitting a transaction

This is functionally equivalent to Sui's approach: query chain state + verify locally. The chain remains the source of truth for VK and nullifier state, but verification happens off-chain.

---

## Design Trade-Off Summary

| Decision | Choice | Alternative | Rationale |
|----------|--------|-------------|-----------|
| JWK verification | Server attestation | In-circuit JWK (Sui) | 40x smaller circuit, mobile-friendly proving |
| Address model | Unlinkable commitments | Deterministic addresses (Sui) | Privacy-preserving for recovery/escrow use cases |
| Key management | Per-action proofs | Ephemeral keys (Sui) | Simpler model, suited for infrequent high-value ops |
| Integration level | Soroban contracts | Protocol-native (Sui) | Deployable without protocol changes, independent iteration |
| Proof generation | Client-side only | Prover service (Sui) | No additional trust assumption, proof never leaves device |
| Verification | On-chain only (current) | On-chain + off-chain SDK (target) | Off-chain SDK is a planned enhancement |
| Hash function | SHA256 (off-chain) + Poseidon (in-circuit) | Poseidon everywhere | SHA256 is standard for server-side; Poseidon is ZK-friendly |
| Provider in hash | Yes (prefix in identityHash) | Separate field (Sui `iss`) | Single hash value simplifies circuit; prefix prevents cross-provider collisions |

---

## References

- [Sui zkLogin Documentation](https://docs.sui.io/concepts/cryptography/zklogin)
- [Sui zkLogin Blog Post](https://blog.sui.io/zklogin-privacy/)
- [ARCHITECTURE.md](ARCHITECTURE.md) — technical reference for stellar-zkLogin
- [SECURITY_MODEL.md](SECURITY_MODEL.md) — threat analysis and trust assumptions
