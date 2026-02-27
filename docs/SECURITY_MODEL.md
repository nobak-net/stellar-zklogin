# Security Model: stellar-zkLogin

## Trust Model

stellar-zkLogin uses a **semi-trusted** architecture. The system is not fully trustless — it relies on an attestation server to validate OAuth tokens — but the ZK proof layer ensures that the server cannot forge identities, link users across sessions, or replay proofs.

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────────┐
│                         TRUST BOUNDARY 1                            │
│                      OAuth Provider (Google, Apple)                  │
│                                                                     │
│  Trusted to:                                                        │
│  • Correctly authenticate users                                     │
│  • Issue valid JWT tokens with correct claims (sub, email)          │
│  • Not reassign user IDs (sub) to different users                   │
│  • Maintain HTTPS for JWK endpoint                                  │
│                                                                     │
│  Risk if compromised:                                               │
│  • Fake identities could be created (upstream of entire system)     │
│  • Mitigation: industry standard, regularly audited, used by        │
│    billions of accounts                                             │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         TRUST BOUNDARY 2                            │
│                      Attestation Server                             │
│                                                                     │
│  Trusted to:                                                        │
│  • Validate OAuth tokens against provider APIs                      │
│  • Compute identityHash correctly                                   │
│  • Not forge attestations for non-authenticated users               │
│  • Keep server signing key (serverNonce source) secret              │
│                                                                     │
│  NOT trusted with:                                                  │
│  • User's blinding factor (never sent to server)                    │
│  • User's nullifierSecret (never sent to server)                    │
│  • Linking on-chain commitments to real identities                  │
│  • Replaying proofs (doesn't know witness data)                     │
│                                                                     │
│  Risk if compromised:                                               │
│  • Could issue attestations for fake identities                     │
│  • Could deny service (refuse to issue attestations)                │
│  • CANNOT: forge proofs, link commitments, replay proofs            │
│  • Mitigation: server pubkey committed on-chain,                    │
│    could move to multi-server threshold model                       │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         TRUST BOUNDARY 3                            │
│                      ZK Circuit + Trusted Setup                     │
│                                                                     │
│  Trusted to:                                                        │
│  • Correctly enforce all constraints (open-source, auditable)       │
│  • Trusted setup ceremony participants didn't all collude           │
│    (at least 1 honest participant suffices for Groth16)             │
│                                                                     │
│  Risk if compromised:                                               │
│  • Colluded setup: attacker could forge proofs for any identity     │
│  • Circuit bug: could allow invalid proofs to pass                  │
│  • Mitigation: public ceremony, circuit audit, open source          │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         TRUST BOUNDARY 4                            │
│                      Soroban Contracts (On-Chain)                    │
│                                                                     │
│  Trusted to:                                                        │
│  • Execute correctly on Stellar validators                          │
│  • Verify Groth16 proofs via BN254 host functions                   │
│  • Maintain immutable state (nullifiers, merkle roots)              │
│                                                                     │
│  Risk if compromised:                                               │
│  • Contract bug: could accept invalid proofs                        │
│  • Admin key leak: could modify contract state                      │
│  • Mitigation: open source, audit, admin key rotation               │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Comparison: Trust Models

| Assumption | stellar-zkLogin | Sui zkLogin | Tornado Cash |
|------------|-----------------|-------------|--------------|
| OAuth provider honest | Yes | Yes | N/A |
| Attestation server honest | **Yes** | No (JWK oracle replaces server) | N/A |
| Trusted setup honest (≥1 participant) | Yes | Yes | Yes |
| Validators execute correctly | Yes | Yes | Yes (Ethereum) |
| Circuit is correct | Yes | Yes | Yes |

**Key difference from Sui:** Sui eliminates the attestation server via a JWK oracle built into the validator consensus layer. stellar-zkLogin retains the server as a lightweight trust assumption because Stellar does not currently support external data oracles at the protocol level.

**Key difference from Tornado Cash:** Tornado Cash is a pure privacy pool with no identity — users deposit ETH and withdraw without linking deposits to withdrawals. stellar-zkLogin is an identity system — users prove they own a social account, not that they made a deposit.

---

## Threat Analysis

### T1: Attestation Server Compromise

**Threat:** Attacker gains control of the attestation server's signing key.

**Impact:** Can issue attestations for any identity, enabling fake registrations.

**Cannot do:** Forge ZK proofs (doesn't know user's blinding/nullifier), link existing commitments to identities, replay past proofs.

**Mitigations:**
1. Server pubkey (`serverPubCommitment`) is committed on-chain during contract initialization
2. Key rotation requires admin contract call (detectable on-chain)
3. Future: multi-server attestation threshold (N-of-M)
4. Future: JWK oracle (eliminates server entirely)

**Detection:** Monitor `identity-auth.authorize()` call volume for anomalies. Unusual spikes may indicate mass fake attestations.

### T2: Nullifier Reuse (Replay Attack)

**Threat:** User tries to use the same proof twice.

**Impact:** Could double-register or double-recover.

**Protection:** `identity-auth` stores `nullifierHash` after each successful `authorize()`. Subsequent calls with the same nullifier are rejected.

**Verification:**
```rust
// In authorize():
if env.storage().persistent().has(&DataKey::Nullifier(request.nullifier_hash.clone())) {
    return Err(IdentityAuthError::NullifierAlreadyUsed);
}
// ... verify proof ...
env.storage().persistent().set(&DataKey::Nullifier(request.nullifier_hash.clone()), &true);
```

**Note:** The nullifier is stored AFTER proof verification (correct order — prevents marking nullifiers for invalid proofs).

### T3: Identity Linkability

**Threat:** Observer links multiple on-chain commitments to the same real-world identity.

**Protection:** Each proof uses a fresh `blinding` factor, producing a different `commitment`. An observer sees:

```
Authorization 1: commitment_A = Poseidon(identityHash, blinding_1)
Authorization 2: commitment_B = Poseidon(identityHash, blinding_2)
```

Without knowing `identityHash`, `commitment_A` and `commitment_B` are computationally indistinguishable from commitments of different users.

**Caveat:** If the same `nullifierSecret` is reused, the same `nullifierHash` appears — but this would be rejected as a replay. Different nullifier secrets produce different hashes.

### T4: Timestamp Manipulation

**Threat:** User submits a proof with a stale attestation (reusing old server data).

**Protection:** The circuit enforces freshness:
```circom
// Circuit: attestationTimestamp + maxAttestationAge >= currentTimestamp
timeDiff <== currentTimestamp - attestationTimestamp;
ageCheck.in[0] <== timeDiff;
ageCheck.in[1] <== maxAttestationAge;
ageCheck.out === 1;
```

`currentTimestamp` is a public input set from the ledger timestamp. `maxAttestationAge` is configurable (default: 86400 seconds = 24 hours).

**Contract-level check (planned F12 fix):** Additional timestamp validation against ledger time in the contract itself, not just the circuit.

### T5: Forged ZK Proof

**Threat:** Attacker constructs a proof without knowing a valid attestation.

**Protection:** Groth16 soundness — computationally infeasible to create a valid proof without satisfying all circuit constraints (attestation hash match, timestamp freshness, server binding).

**Quantification:** Breaking Groth16 on BN254 requires solving the discrete logarithm problem on the curve, estimated at ~128-bit security level.

### T6: Verification Key Replacement

**Threat:** Attacker (or compromised admin) replaces the verification key with one that accepts a forged proof.

**Current state:** `set_verification_key()` has admin auth but allows re-setting.

**Planned fix (F9):** Lock VK after first set. Once the verification key is stored, it cannot be changed.

```rust
pub fn set_verification_key(env: Env, admin: Address, vk: VerificationKey) {
    Self::require_admin(&env, &admin);
    if env.storage().persistent().has(&DataKey::VerificationKey) {
        panic!("VK already set — cannot replace");
    }
    env.storage().persistent().set(&DataKey::VerificationKey, &vk);
}
```

### T7: Merkle Tree Manipulation

**Threat:** Unauthorized party inserts fake commitments into the merkle tree.

**Current state (F13 finding):** `insert_leaf()` has no access control — any caller can insert.

**Planned fix:** Add admin check to `insert_leaf()`. Only `identity-auth` contract (set as admin during initialization) can insert leaves.

### T8: Storage Expiry (TTL)

**Threat:** Soroban persistent storage expires, deleting nullifiers or merkle nodes.

**Impact:** If a nullifier expires, the same proof could be replayed. If merkle nodes expire, membership proofs fail.

**Planned fix (F5):** Extend TTL on all critical storage entries:
```rust
const LIFETIME_THRESHOLD: u32 = 17_280;  // ~1 day
const BUMP_AMOUNT: u32 = 518_400;        // ~30 days
env.storage().persistent().extend_ttl(&key, LIFETIME_THRESHOLD, BUMP_AMOUNT);
```

### T9: Front-Running

**Threat:** Validator or MEV actor sees proof in mempool, front-runs the transaction.

**Impact:** Limited — the proof is bound to specific `commitment` and `nullifierHash` outputs. Front-running the TX would register the attacker's commitment, but they don't control the corresponding `identityHash`.

**Protection:** The ZK proof's public outputs (commitment, nullifier) are deterministically linked to the private witness. An attacker who replays the same TX would produce the same outputs — but the original user's commitment is what gets registered.

### T10: OAuth Token Interception

**Threat:** Man-in-the-middle captures the OAuth token during the attestation request.

**Impact:** Attacker could request an attestation for the victim's identity.

**Protection:**
1. HTTPS for all attestation server communication
2. OAuth tokens are short-lived (~1 hour for Google)
3. Even with a valid attestation, the attacker needs the user's `blinding` and `nullifierSecret` to produce a valid proof with the same commitment
4. The victim's identity would get a valid commitment registered — the attacker cannot steal it

---

## Known Limitations

### 1. Semi-Trusted Server

The attestation server is a single point of trust (not failure — if it goes down, users can't register but existing authorizations remain valid). This is the primary difference from Sui's trustless JWK oracle.

**Upgrade path:** Multi-server threshold attestation or Stellar-native JWK oracle.

### 2. Groth16 Trusted Setup

Groth16 requires a trusted setup ceremony. If ALL participants collude, the toxic waste could be used to forge proofs.

**Mitigation:** Use a large, public ceremony with many independent participants. Only ONE honest participant is needed for security. Production ceremonies typically have 100+ participants.

### 3. BN254 Security Level

BN254 provides ~100-128 bits of security, which is below the 128-bit standard recommended by NIST. However, it remains the industry standard for ZK-SNARKs (used by Ethereum, Sui, Polygon, Zcash).

**Upgrade path:** BLS12-381 (128-bit security) or BN254 replacement when tooling matures.

### 4. Client-Side Proof Generation

Proofs are generated on the user's device (mobile). If the device is compromised, the attacker has access to all private inputs (identityHash, blinding, nullifierSecret).

**Mitigation:** This is inherent to any client-side ZK system (including Sui zkLogin when using local proving). The secret inputs exist only in memory during proof generation.

### 5. Provider Dependency

If Google or Apple discontinue OAuth or change their token format, the system stops working for new registrations. Existing authorizations remain valid (they're on-chain and don't depend on the provider).

**Mitigation:** Multi-provider support — users can register with multiple providers.

---

## Audit Status

A white-hat security audit identified 17 findings across the contract and circuit layers. 14 are on-chain (within stellar-zkLogin scope), 3 are API-layer (separate repo).

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| F1 | Critical | Merkle tree insertion skipped in identity-auth | Partially fixed (verifier call works, merkle insertion pending) |
| F2 | Critical | zk-wallet uses stub proof verification | Open |
| F3 | Critical | zk-key-escrow uses stub proof verification | Open |
| F4 | Medium | Circuit not recompiled after rename | Open |
| F5 | Medium | No storage TTL on critical data | Open |
| F8 | Low | No VK loading script | Open |
| F9 | Medium | VK can be re-set by admin | Partially fixed (admin auth exists, lock pending) |
| F10 | Low | Dead `serverBindingCheck` signal in circuit | Open |
| F11 | Info | Nullifier stored before verification | Fixed (stored after verification) |
| F12 | Medium | No contract-level timestamp freshness check | Open |
| F13 | Critical | merkle-tree `insert_leaf()` has no access control | Open |
| F14 | Low | `is_known_root()` is O(n) linear scan | Open |

Full details: Internal audit document (not public until fixes complete).

---

## Security Checklist: Pre-Mainnet

- [ ] All 14 on-chain findings fixed
- [ ] 47-test security matrix passing
- [ ] Multi-party trusted setup ceremony completed
- [ ] Verification key locked after first set (F9)
- [ ] Merkle tree access control enforced (F13)
- [ ] Storage TTL on all critical entries (F5)
- [ ] Contract admin keys secured (HSM or multi-sig)
- [ ] Third-party audit completed
- [ ] Incident response plan documented
- [ ] Monitoring deployed (nullifier counts, auth volume)

---

## Responsible Disclosure

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public GitHub issue
2. Email security concerns to the maintainers (see SECURITY.md)
3. Allow 90 days for a fix before public disclosure
4. We will credit reporters in the security advisory

---

## References

- [Sui zkLogin Security Analysis](https://docs.sui.io/concepts/cryptography/zklogin#security)
- [Groth16 Security Properties](https://eprint.iacr.org/2016/260)
- [BN254 Security Estimation](https://eprint.iacr.org/2019/077)
- [OWASP Smart Contract Top 10](https://owasp.org/www-project-smart-contract-top-10/)
- [Tornado Cash Audit (ABDK)](https://tornado.cash/audits/TornadoCash_circuit_audit_ABDK.pdf)
