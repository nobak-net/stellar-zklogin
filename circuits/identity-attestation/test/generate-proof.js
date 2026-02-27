/**
 * Identity Attestation Proof Generator
 *
 * This script simulates the full flow:
 * 1. Server creates attestation (simulated)
 * 2. User generates ZK proof
 * 3. Proof can be verified on-chain
 */

const snarkjs = require('snarkjs');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Poseidon hash implementation (circomlibjs)
let poseidon;
let F; // Finite field

async function initPoseidon() {
  const { buildPoseidon } = await import('circomlibjs');
  poseidon = await buildPoseidon();
  F = poseidon.F;
}

// Convert hex string to field element (BigInt)
function hexToField(hex) {
  // Remove 0x prefix if present
  hex = hex.replace(/^0x/, '');
  return BigInt('0x' + hex);
}

// Convert string to field element via SHA256
function stringToField(str) {
  const hash = crypto.createHash('sha256').update(str).digest('hex');
  // Take first 31 bytes to fit in BN254 field
  return hexToField(hash.slice(0, 62));
}

// Compute Poseidon hash
function poseidonHash(inputs) {
  const hash = poseidon(inputs.map(x => F.e(x)));
  return F.toObject(hash);
}

// Generate random field element
function randomField() {
  const bytes = crypto.randomBytes(31); // 31 bytes to fit in field
  return BigInt('0x' + bytes.toString('hex'));
}

async function main() {
  console.log('');
  console.log('==========================================');
  console.log(' Identity Attestation Proof Generator');
  console.log('==========================================');
  console.log('');

  await initPoseidon();

  // ============================================
  // STEP 1: Simulate user data (from Google OAuth)
  // ============================================
  console.log('Step 1: Simulating user data...');

  const email = 'testuser@gmail.com';
  const userId = '123456789012345678901';
  const emailVerified = true;

  // This is how identityHash is computed (same as mobile app)
  const identityString = `gmail:${email}:${userId}:verified:${emailVerified}`;
  const identityHash = stringToField(identityString);

  console.log(`  Email: ${email}`);
  console.log(`  Identity string: ${identityString}`);
  console.log(`  identityHash: ${identityHash.toString().slice(0, 20)}...`);
  console.log('');

  // ============================================
  // STEP 2: Simulate server attestation
  // ============================================
  console.log('Step 2: Simulating server attestation...');

  // Server's secret nonce (would be stored securely on server)
  const serverNonce = randomField();

  // Attestation timestamp (current time)
  const attestationTimestamp = BigInt(Math.floor(Date.now() / 1000));

  // Server computes attestation hash
  const attestationHash = poseidonHash([identityHash, attestationTimestamp, serverNonce]);

  // Server's public commitment (known constant)
  // In production, this would be derived from server's keypair
  const serverSecret = stringToField('server-secret-key-for-identity-attestation');
  const serverPubCommitment = poseidonHash([serverSecret, BigInt(1)]);

  console.log(`  Attestation timestamp: ${attestationTimestamp}`);
  console.log(`  Server nonce: ${serverNonce.toString().slice(0, 20)}...`);
  console.log(`  Attestation hash: ${attestationHash.toString().slice(0, 20)}...`);
  console.log(`  Server public commitment: ${serverPubCommitment.toString().slice(0, 20)}...`);
  console.log('');

  // ============================================
  // STEP 3: User generates proof inputs
  // ============================================
  console.log('Step 3: Generating user proof inputs...');

  // User's random values
  const blinding = randomField();
  const nullifierSecret = randomField();

  // Public inputs
  const currentTimestamp = attestationTimestamp + BigInt(60); // 60 seconds later
  const maxAttestationAge = BigInt(86400); // 24 hours

  // Compute expected outputs
  const expectedCommitment = poseidonHash([identityHash, blinding]);
  const expectedNullifierHash = poseidonHash([identityHash, nullifierSecret]);

  console.log(`  Blinding: ${blinding.toString().slice(0, 20)}...`);
  console.log(`  Nullifier secret: ${nullifierSecret.toString().slice(0, 20)}...`);
  console.log(`  Expected commitment: ${expectedCommitment.toString().slice(0, 20)}...`);
  console.log(`  Expected nullifier: ${expectedNullifierHash.toString().slice(0, 20)}...`);
  console.log('');

  // ============================================
  // STEP 4: Prepare circuit inputs
  // ============================================
  console.log('Step 4: Preparing circuit inputs...');

  const circuitInputs = {
    // Private inputs
    identityHash: identityHash.toString(),
    attestationTimestamp: attestationTimestamp.toString(),
    serverNonce: serverNonce.toString(),
    attestationHash: attestationHash.toString(),
    blinding: blinding.toString(),
    nullifierSecret: nullifierSecret.toString(),

    // Public inputs
    currentTimestamp: currentTimestamp.toString(),
    maxAttestationAge: maxAttestationAge.toString(),
    serverPubCommitment: serverPubCommitment.toString()
  };

  // Save inputs for debugging
  const inputsPath = path.join(__dirname, '..', 'build', 'input.json');
  fs.writeFileSync(inputsPath, JSON.stringify(circuitInputs, null, 2));
  console.log(`  Inputs saved to: ${inputsPath}`);
  console.log('');

  // ============================================
  // STEP 5: Generate the proof
  // ============================================
  console.log('Step 5: Generating ZK proof...');
  console.log('  This may take a few seconds...');
  console.log('');

  const wasmPath = path.join(__dirname, '..', 'build', 'identity_attestation_js', 'identity_attestation.wasm');
  const zkeyPath = path.join(__dirname, '..', 'keys', 'identity_attestation.zkey');

  // Check if files exist
  if (!fs.existsSync(wasmPath)) {
    console.error(`  ERROR: WASM file not found: ${wasmPath}`);
    console.error('  Run ./scripts/compile.sh first');
    process.exit(1);
  }

  if (!fs.existsSync(zkeyPath)) {
    console.error(`  ERROR: Proving key not found: ${zkeyPath}`);
    console.error('  Run ./scripts/trusted-setup.sh first');
    process.exit(1);
  }

  const startTime = Date.now();

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInputs,
    wasmPath,
    zkeyPath
  );

  const proofTime = Date.now() - startTime;

  console.log(`  Proof generated in ${proofTime}ms`);
  console.log('');

  // ============================================
  // STEP 6: Display results
  // ============================================
  console.log('Step 6: Proof results');
  console.log('');

  console.log('Public signals (outputs):');
  console.log(`  [0] commitment:     ${publicSignals[0].slice(0, 30)}...`);
  console.log(`  [1] nullifierHash:  ${publicSignals[1].slice(0, 30)}...`);
  console.log('');

  // Verify outputs match expected
  if (publicSignals[0] === expectedCommitment.toString()) {
    console.log('  ✓ Commitment matches expected');
  } else {
    console.log('  ✗ Commitment mismatch!');
  }

  if (publicSignals[1] === expectedNullifierHash.toString()) {
    console.log('  ✓ Nullifier hash matches expected');
  } else {
    console.log('  ✗ Nullifier hash mismatch!');
  }

  console.log('');
  console.log('Proof components (Groth16):');
  console.log(`  pi_a: [${proof.pi_a[0].slice(0, 20)}..., ${proof.pi_a[1].slice(0, 20)}...]`);
  console.log(`  pi_b: [[${proof.pi_b[0][0].slice(0, 15)}..., ...], ...]`);
  console.log(`  pi_c: [${proof.pi_c[0].slice(0, 20)}..., ${proof.pi_c[1].slice(0, 20)}...]`);
  console.log('');

  // ============================================
  // STEP 7: Save proof and public signals
  // ============================================
  const proofPath = path.join(__dirname, '..', 'build', 'proof.json');
  const publicPath = path.join(__dirname, '..', 'build', 'public.json');

  fs.writeFileSync(proofPath, JSON.stringify(proof, null, 2));
  fs.writeFileSync(publicPath, JSON.stringify(publicSignals, null, 2));

  console.log('Files saved:');
  console.log(`  Proof:          ${proofPath}`);
  console.log(`  Public signals: ${publicPath}`);
  console.log('');

  // ============================================
  // STEP 8: Save attestation data (for server reference)
  // ============================================
  const attestationData = {
    // Data server would store/provide
    serverPubCommitment: serverPubCommitment.toString(),
    attestationHash: attestationHash.toString(),
    attestationTimestamp: attestationTimestamp.toString(),
    serverNonce: serverNonce.toString(),

    // Data for verification
    publicInputs: {
      currentTimestamp: currentTimestamp.toString(),
      maxAttestationAge: maxAttestationAge.toString(),
      serverPubCommitment: serverPubCommitment.toString()
    },

    // Proof outputs
    commitment: publicSignals[0],
    nullifierHash: publicSignals[1],

    // Original identity (for testing only - never expose in production!)
    _testOnly: {
      email,
      identityHash: identityHash.toString()
    }
  };

  const attestationPath = path.join(__dirname, '..', 'build', 'attestation.json');
  fs.writeFileSync(attestationPath, JSON.stringify(attestationData, null, 2));
  console.log(`  Attestation data: ${attestationPath}`);
  console.log('');

  console.log('==========================================');
  console.log(' Proof generation complete!');
  console.log('==========================================');
  console.log('');
  console.log('Next: Run verification test');
  console.log('  npm run test:verify');
  console.log('');
}

main().catch(err => {
  console.error('Error:', err);
  process.exit(1);
});
