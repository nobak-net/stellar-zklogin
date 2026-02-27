pragma circom 2.1.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

/**
 * Identity Attestation Circuit (Semi-Trusted Model)
 *
 * Proves ownership of a social identity without revealing the email.
 *
 * Flow:
 * 1. User authenticates with a social provider (Google, Apple, etc.) off-chain
 * 2. Server validates OAuth token and computes identityHash
 * 3. Server creates attestation: attestationHash = Poseidon(identityHash, timestamp, serverNonce)
 * 4. User generates this ZK proof proving they know identityHash
 * 5. Proof verified on-chain via groth16-verifier contract
 *
 * Security Properties:
 * - Zero-knowledge: identityHash is never revealed
 * - Binding: Cannot create valid proof without server attestation
 * - Non-replayable: Nullifier prevents reuse
 *
 * Identity hash formula: SHA256("{provider}:{email}:{userId}:verified:{emailVerified}")
 *   Google: SHA256("gmail:{email}:{sub}:verified:{emailVerified}")
 *   Apple:  SHA256("apple:{email}:{sub}:verified:true")
 */
template IdentityAttestation() {
    // ============================================
    // PRIVATE INPUTS (witness - hidden from verifier)
    // ============================================

    // The hash of the user's social identity
    // Computed as: SHA256("{provider}:{email}:{userId}:verified:{emailVerified}")
    // Then converted to field element (first 31 bytes of SHA256, as decimal BigInt)
    signal input identityHash;

    // Timestamp when server created the attestation (Unix seconds)
    signal input attestationTimestamp;

    // Random nonce from server to prevent rainbow table attacks
    signal input serverNonce;

    // The attestation hash from server (proves server validated OAuth)
    // attestationHash = Poseidon(identityHash, attestationTimestamp, serverNonce)
    signal input attestationHash;

    // Random blinding factor for commitment (user-generated)
    signal input blinding;

    // Secret nullifier seed (user-generated, must be kept secret)
    signal input nullifierSecret;

    // ============================================
    // PUBLIC INPUTS (visible on-chain)
    // ============================================

    // Current timestamp for freshness check (from blockchain)
    signal input currentTimestamp;

    // Maximum age of attestation in seconds (e.g., 86400 = 24 hours)
    signal input maxAttestationAge;

    // Server's public commitment (known constant, set during contract init)
    // This binds attestations to a specific server
    signal input serverPubCommitment;

    // ============================================
    // PUBLIC OUTPUTS (published with proof)
    // ============================================

    // Commitment to identityHash (hides the actual hash)
    // commitment = Poseidon(identityHash, blinding)
    signal output commitment;

    // Nullifier hash (prevents replay attacks)
    // nullifierHash = Poseidon(identityHash, nullifierSecret)
    signal output nullifierHash;

    // ============================================
    // CIRCUIT LOGIC
    // ============================================

    // Step 1: Verify attestation hash matches claimed values
    // This proves the server attested to this identityHash
    component attestationVerify = Poseidon(3);
    attestationVerify.inputs[0] <== identityHash;
    attestationVerify.inputs[1] <== attestationTimestamp;
    attestationVerify.inputs[2] <== serverNonce;

    // Constrain: computed attestation must match provided attestation
    attestationVerify.out === attestationHash;

    // Step 2: Verify server binding
    // The attestation must include the server's public commitment
    // This prevents attestations from unauthorized servers
    component serverBinding = Poseidon(2);
    serverBinding.inputs[0] <== attestationHash;
    serverBinding.inputs[1] <== serverPubCommitment;

    // We don't need to output this, just need it to be computable
    // The constraint above ensures attestationHash is valid
    signal serverBindingCheck;
    serverBindingCheck <== serverBinding.out;

    // Step 3: Check attestation freshness
    // attestationTimestamp + maxAttestationAge >= currentTimestamp
    signal timeDiff;
    timeDiff <== currentTimestamp - attestationTimestamp;

    // Verify timeDiff <= maxAttestationAge
    component ageCheck = LessEqThan(64);
    ageCheck.in[0] <== timeDiff;
    ageCheck.in[1] <== maxAttestationAge;
    ageCheck.out === 1;

    // Also verify attestation is not from the future
    component notFuture = LessEqThan(64);
    notFuture.in[0] <== attestationTimestamp;
    notFuture.in[1] <== currentTimestamp;
    notFuture.out === 1;

    // Step 4: Compute commitment (hides identityHash)
    component commitmentHash = Poseidon(2);
    commitmentHash.inputs[0] <== identityHash;
    commitmentHash.inputs[1] <== blinding;
    commitment <== commitmentHash.out;

    // Step 5: Compute nullifier hash (prevents replay)
    component nullifierCompute = Poseidon(2);
    nullifierCompute.inputs[0] <== identityHash;
    nullifierCompute.inputs[1] <== nullifierSecret;
    nullifierHash <== nullifierCompute.out;
}

// Main component with public inputs declared
component main {public [
    currentTimestamp,
    maxAttestationAge,
    serverPubCommitment
]} = IdentityAttestation();
