#!/usr/bin/env node
/**
 * Export snarkjs verification key to Soroban-compatible format
 *
 * Converts the verification_key.json from snarkjs to:
 * 1. Hex-encoded bytes for Soroban G1/G2 points
 * 2. CLI command to set verification key on the groth16-verifier contract
 *
 * Usage: node export-vk-to-soroban.js [verification_key.json]
 */

const fs = require('fs');
const path = require('path');

// BN254 field prime
const FIELD_PRIME = BigInt('21888242871839275222246405745257275088696311157297823662689037894645226208583');

/**
 * Convert decimal string to 32-byte big-endian hex
 */
function decimalTo32ByteHex(decimalStr) {
  const n = BigInt(decimalStr);
  const hex = n.toString(16).padStart(64, '0');
  if (hex.length > 64) {
    throw new Error(`Number too large for 32 bytes: ${decimalStr}`);
  }
  return hex;
}

/**
 * Convert G1 point from snarkjs format to Soroban bytes (64 bytes)
 * snarkjs: [x, y, z] in projective coordinates (z should be "1" for affine)
 * Soroban: 64 bytes = x (32 bytes) || y (32 bytes)
 */
function convertG1Point(point) {
  if (!Array.isArray(point) || point.length < 2) {
    throw new Error('Invalid G1 point format');
  }

  const x = decimalTo32ByteHex(point[0]);
  const y = decimalTo32ByteHex(point[1]);

  return x + y;
}

/**
 * Convert G2 point from snarkjs format to Soroban bytes (128 bytes)
 *
 * snarkjs format: [[x_c0, x_c1], [y_c0, y_c1], [z_c0, z_c1]]
 * where x, y are in Fp2 (extension field) with components c0 (real) and c1 (imaginary)
 *
 * Soroban BN254 G2 format (128 bytes):
 * - First 64 bytes: X coordinate (c1 || c0) - imaginary first
 * - Last 64 bytes: Y coordinate (c1 || c0) - imaginary first
 */
function convertG2Point(point) {
  if (!Array.isArray(point) || point.length < 2) {
    throw new Error('Invalid G2 point format');
  }

  const x = point[0]; // [c0, c1]
  const y = point[1]; // [c0, c1]

  // Soroban expects: x_c1 || x_c0 || y_c1 || y_c0
  const x_c1 = decimalTo32ByteHex(x[1]);
  const x_c0 = decimalTo32ByteHex(x[0]);
  const y_c1 = decimalTo32ByteHex(y[1]);
  const y_c0 = decimalTo32ByteHex(y[0]);

  return x_c1 + x_c0 + y_c1 + y_c0;
}

/**
 * Convert verification key to Soroban format
 */
function convertVerificationKey(vk) {
  const result = {
    alpha_g1: convertG1Point(vk.vk_alpha_1),
    beta_g2: convertG2Point(vk.vk_beta_2),
    gamma_g2: convertG2Point(vk.vk_gamma_2),
    delta_g2: convertG2Point(vk.vk_delta_2),
    ic: vk.IC.map(convertG1Point),
    nPublic: vk.nPublic
  };

  return result;
}

/**
 * Generate Stellar CLI command to set verification key
 */
function generateStellarCommand(sorobanVk, contractId, sourceKey, network) {
  // Build IC array for CLI
  const icPoints = sorobanVk.ic.map(hex => `--ic hex:${hex}`).join(' \\\n    ');

  return `
# Set Verification Key on Groth16 Verifier Contract
#
# Contract: ${contractId}
# Network: ${network}
# Public inputs: ${sorobanVk.nPublic}
# IC points: ${sorobanVk.ic.length} (nPublic + 1)

stellar contract invoke \\
  --id ${contractId} \\
  --source ${sourceKey} \\
  --network ${network} \\
  -- set_verification_key \\
    --vk '{
      "alpha_g1": "hex:${sorobanVk.alpha_g1}",
      "beta_g2": "hex:${sorobanVk.beta_g2}",
      "gamma_g2": "hex:${sorobanVk.gamma_g2}",
      "delta_g2": "hex:${sorobanVk.delta_g2}",
      "ic": [
        ${sorobanVk.ic.map(hex => `"hex:${hex}"`).join(',\n        ')}
      ]
    }'
`;
}

/**
 * Generate JSON format for use with SDK
 */
function generateSdkFormat(sorobanVk) {
  return {
    alpha_g1: { bytes: sorobanVk.alpha_g1 },
    beta_g2: { bytes: sorobanVk.beta_g2 },
    gamma_g2: { bytes: sorobanVk.gamma_g2 },
    delta_g2: { bytes: sorobanVk.delta_g2 },
    ic: sorobanVk.ic.map(hex => ({ bytes: hex }))
  };
}

// Main execution
const args = process.argv.slice(2);
const vkPath = args[0] || path.join(__dirname, '..', 'keys', 'verification_key.json');

if (!fs.existsSync(vkPath)) {
  console.error(`Verification key not found: ${vkPath}`);
  console.error('Run the trusted setup first: ./scripts/trusted-setup.sh');
  process.exit(1);
}

console.log(`Reading verification key from: ${vkPath}\n`);

const vk = JSON.parse(fs.readFileSync(vkPath, 'utf8'));

console.log('Verification Key Info:');
console.log(`  Protocol: ${vk.protocol}`);
console.log(`  Curve: ${vk.curve}`);
console.log(`  Public inputs: ${vk.nPublic}`);
console.log(`  IC points: ${vk.IC.length}\n`);

// Convert to Soroban format
const sorobanVk = convertVerificationKey(vk);

console.log('='.repeat(80));
console.log('SOROBAN VERIFICATION KEY (HEX BYTES)');
console.log('='.repeat(80));
console.log('\nalpha_g1 (64 bytes):');
console.log(`  ${sorobanVk.alpha_g1}`);
console.log('\nbeta_g2 (128 bytes):');
console.log(`  ${sorobanVk.beta_g2}`);
console.log('\ngamma_g2 (128 bytes):');
console.log(`  ${sorobanVk.gamma_g2}`);
console.log('\ndelta_g2 (128 bytes):');
console.log(`  ${sorobanVk.delta_g2}`);
console.log('\nIC points (64 bytes each):');
sorobanVk.ic.forEach((ic, i) => {
  console.log(`  [${i}]: ${ic}`);
});

// Save to file
const outputPath = path.join(__dirname, '..', 'keys', 'verification_key_soroban.json');
const sdkFormat = generateSdkFormat(sorobanVk);
fs.writeFileSync(outputPath, JSON.stringify(sdkFormat, null, 2));
console.log(`\nSaved SDK format to: ${outputPath}`);

// Generate CLI command
console.log('\n' + '='.repeat(80));
console.log('STELLAR CLI COMMAND');
console.log('='.repeat(80));
console.log(generateStellarCommand(
  sorobanVk,
  'CCTML7FQ2QAW4LG2NU33ZEH3CGMY6NV2DK7QQSROMDPZHU43WLNZGUNP',
  'deployer',
  'testnet'
));

console.log('\n' + '='.repeat(80));
console.log('PROOF CONVERSION');
console.log('='.repeat(80));
console.log(`
To convert a snarkjs proof for Soroban verification:

1. Generate proof with snarkjs:
   snarkjs groth16 fullprove input.json circuit.wasm circuit.zkey proof.json public.json

2. The proof.json contains:
   - pi_a: G1 point [x, y, z] -> convert to 64 bytes
   - pi_b: G2 point [[x0,x1], [y0,y1], [z0,z1]] -> convert to 128 bytes
   - pi_c: G1 point [x, y, z] -> convert to 64 bytes

3. The public.json contains the public inputs as decimal strings.
   Convert each to U256 for the Soroban contract.

Example proof conversion code in TypeScript:

  const proof = JSON.parse(fs.readFileSync('proof.json'));
  const sorobanProof = {
    a: convertG1Point(proof.pi_a),
    b: convertG2Point(proof.pi_b),
    c: convertG1Point(proof.pi_c)
  };
`);
