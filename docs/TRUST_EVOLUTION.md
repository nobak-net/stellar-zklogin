# Trust Evolution: Decentralization Roadmap

stellar-zkLogin uses a **semi-trusted** architecture today. This document describes the concrete path from the current single-server model to progressively more trustless configurations.

> See [SECURITY_MODEL.md](SECURITY_MODEL.md) for the current threat analysis and findings.

---

## Current Trust Dependencies

The attestation server (a single Cloudflare Worker) is the **sole trust point** beyond the OAuth provider itself. It performs two critical functions:

1. **OAuth validation** — Verifies Google JWT tokens against Google's public keys
2. **Attestation generation** — Computes `attestationHash = Poseidon(identityHash, timestamp, nonce)` using `ATTESTATION_SERVER_SECRET`

Everything downstream is trustless: the ZK proof is generated client-side (private inputs never leave the device), and proof verification happens on-chain via Soroban contracts.

**What the server CANNOT do:**
- Identify which on-chain commitment belongs to which user (blinding factor is client-generated)
- Replay a user's proof (nullifier protection)
- Create a valid ZK proof without the user's private witness data

**What the server CAN do (trust assumption):**
- Issue attestations for identities it didn't actually verify (attestation forgery)
- Refuse to issue attestations (denial of service)

---

## Decentralization Spectrum

```
Level 0 (Current)           Level 1                Level 2
┌─────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│ Single CF Worker │    │ Multi-Attestor    │    │ TEE Attestation  │
│ holds server     │───▶│ N-of-M threshold  │───▶│ Server runs in   │
│ secret           │    │ attestation       │    │ SGX/TDX/Nitro    │
│                  │    │                   │    │                  │
│ Trust: 1 server  │    │ Trust: majority   │    │ Trust: hardware  │
│                  │    │ of N servers      │    │ attestation      │
└─────────────────┘    └──────────────────┘    └──────────────────┘

Level 3                     Level 4
┌──────────────────┐    ┌──────────────────┐
│ DA-Layer Posted  │    │ DKIM Circuit      │
│ Attestations     │───▶│ (Fully Trustless) │
│ posted to        │    │                   │
│ Celestia/EigenDA │    │ JWT → DKIM sig    │
│                  │    │ → RSA verify      │
│ Trust: DA layer  │    │ → ALL in ZK       │
│ + attestor       │    │                   │
│                  │    │ Trust: NONE       │
│                  │    │ (math only)       │
└──────────────────┘    └──────────────────┘
```

### Level Details

| Level | Trust Assumption | Engineering Effort | Target Timeline |
|-------|-----------------|-------------------|-----------------|
| **0: Single Server** (current) | 1 Cloudflare Worker | Done | Now |
| **1: Multi-Attestor** | Majority of N attestors honest | 2-3 weeks | Q3 2026 |
| **2: TEE Attestation** | Intel SGX / AWS Nitro hardware honest | 4-6 weeks | Q4 2026 |
| **3: DA-Layer Posting** | DA layer + attestor(s) | 2-3 weeks (on top of L1/L2) | Future |
| **4: DKIM Circuit** | None (pure math — trustless) | 3-6 months (research) | 2027+ |

---

## Level 1: Multi-Attestor (Q3 2026)

**Goal:** Reduce single-server risk by requiring multiple independent attestors to agree.

**Design:**
- Deploy attestation servers to 2-3 independent cloud providers (e.g., Cloudflare + AWS + GCP)
- Each server holds a **different** server secret, deriving a different `serverPubCommitment`
- Threshold scheme: require 2-of-3 attestors to produce consistent attestations
- Client requests attestation from all servers, verifies consistency, uses any single valid attestation for proof generation
- Contract stores multiple valid `serverPubCommitments` (set of accepted servers)

**Impact on circuit:** None — the circuit already takes `serverPubCommitment` as a public input. The contract just needs to accept a set of valid commitments.

**Impact on trust:** An attacker must compromise a **majority** of independent servers to forge attestations.

---

## Level 2: TEE Attestation (Q4 2026)

**Goal:** Even the server operator cannot extract the attestation secret.

**Design:**
- Run attestation generation inside a Trusted Execution Environment (AWS Nitro Enclave or Intel SGX)
- The server secret is generated inside the TEE and never leaves it
- Remote attestation proves to clients that the expected code is running
- Clients verify the TEE attestation before accepting the ZK attestation

**Impact on circuit:** None — the TEE produces the same attestation format.

**Impact on trust:** The operator can see the code running (open source) but cannot extract the secret. Trust shifts from "operator is honest" to "hardware enclave is not compromised."

**TEE options:**
| Platform | Pros | Cons |
|----------|------|------|
| AWS Nitro Enclaves | Well-documented, good isolation | AWS-specific, vendor lock-in |
| Intel SGX | Widely available, battle-tested | Side-channel attacks (Spectre, Foreshadow) |
| Intel TDX | Newer, VM-level isolation | Limited availability |

---

## Level 4: DKIM Circuit (2027+)

**Goal:** Fully trustless — no server needed at all. The ZK circuit verifies the email provider's DKIM signature directly.

**How it works:**
1. User receives a verification email from Google
2. The email includes a DKIM signature (RSA-2048 signed by Google's mail servers)
3. The ZK circuit verifies the DKIM signature inside the proof
4. No attestation server needed — the proof demonstrates "Google signed an email to this address"

**Challenges:**
- RSA-2048 verification in ZK: ~200,000+ constraints (vs current 2,295)
- DKIM headers vary by provider (parsing complexity)
- Google's DKIM key rotation handling
- Active research area (ZK Email project, zk-regex)

**Impact:** Eliminates the attestation server entirely. The system becomes as trustless as Tornado Cash — pure math, no trusted parties beyond the OAuth provider itself.

---

## Secret Rotation Design

### Current State

```
Secret: ATTESTATION_SERVER_SECRET
Storage: Cloudflare Workers secret (wrangler secret put)
Rotation: None implemented
Derivation: SHA-256 → BN254 field element → Poseidon hash
Public form: serverPubCommitment = Poseidon(secret, 1)
```

### Rotation Mechanism (Phase 0 Design, Phase 3 Implementation)

The `serverPubCommitment` is a public circuit input, so rotation requires the contract to accept multiple valid commitments:

1. **Generate new secret** — New `ATTESTATION_SERVER_SECRET` value
2. **Register new commitment** — Admin call to add `newServerPubCommitment` to the accepted set
3. **Deploy new secret** — Update Cloudflare Workers secret
4. **Grace period** — Both old and new commitments accepted (proofs in flight may use either)
5. **Deprecate old** — After grace period, remove old commitment from accepted set

**Key insight:** Old proofs (generated with old commitment) remain valid — they are verified against their own `serverPubCommitment` public input. The contract just needs to check that the commitment is in the accepted set.

**CLI tool (planned):**
```bash
# Generate new secret and compute commitment
stellar-zklogin rotate-secret --generate

# Register new commitment on-chain
stellar-zklogin rotate-secret --register --contract <ID> --admin <KEY>

# After grace period, deprecate old
stellar-zklogin rotate-secret --deprecate --index 0
```

---

## Admin Pause Mechanism

**Requirement:** The `identity-auth` (gmail-auth) contract needs an admin-callable pause function as a mainnet go/no-go condition.

**Why it's needed:**
- If a critical vulnerability is discovered post-deployment, registrations should be pausable
- The pause only affects new `authorize()` calls — existing on-chain state (nullifiers, commitments) is unaffected
- This is a standard safety pattern for production smart contracts

**Design:**
```rust
pub fn pause(env: Env, admin: Address) {
    Self::require_admin(&env, &admin);
    env.storage().instance().set(&DataKey::Paused, &true);
}

pub fn unpause(env: Env, admin: Address) {
    Self::require_admin(&env, &admin);
    env.storage().instance().set(&DataKey::Paused, &false);
}

// In authorize():
if env.storage().instance().get(&DataKey::Paused).unwrap_or(false) {
    return Err(IdentityAuthError::ContractPaused);
}
```

**Decentralization path:** As the system moves to Level 1+, the pause function should require multi-sig or DAO governance rather than a single admin key.

---

## Comparison: Trust Assumptions Across Systems

| Trust Point | stellar-zkLogin (L0) | Sui zkLogin | Aptos Keyless |
|-------------|----------------------|-------------|---------------|
| OAuth validation | API server | Salt service (Mysten) | Pepper service (Aptos) |
| Attestation/salt | API server (single secret) | Salt service (single service) | Pepper service (single service) |
| Proof generation | **Client** (private inputs stay local) | **Server** (Mysten prover has private inputs) | **Server** (Aptos prover has private inputs) |
| On-chain verification | Soroban contracts | Move runtime | Move runtime |
| **Overall** | **Semi-trusted (server sees OAuth, not private inputs)** | **Semi-trusted (server sees OAuth AND private inputs)** | **Semi-trusted (server sees OAuth AND private inputs)** |

**Key advantage:** stellar-zkLogin's client-side proving is actually **more private** than Sui and Aptos. In both Sui zkLogin and Aptos Keyless, the proving service receives the user's private inputs (salt, randomness) to generate the proof server-side. In stellar-zkLogin, private inputs (blinding, nullifierSecret) never leave the device.

---

## References

- [SECURITY_MODEL.md](SECURITY_MODEL.md) — Current threat analysis and all 17 findings
- [SECURITY_TEST_MATRIX.md](SECURITY_TEST_MATRIX.md) — 55-test verification plan
- [ZK Email](https://prove.email/) — DKIM verification in ZK (Level 4 research)
- [AWS Nitro Enclaves](https://aws.amazon.com/ec2/nitro/nitro-enclaves/) — TEE option for Level 2
- [Sui zkLogin Security](https://docs.sui.io/concepts/cryptography/zklogin#security) — Comparison reference
