#![no_std]

use soroban_sdk::{
    contract, contractimpl,
    crypto::bn254::{Bn254G1Affine, Bn254G2Affine, Fr},
    Env, U256, Vec,
};

/// Contract 1: BN254 Basic Operations
///
/// Demonstrates the three core BN254 elliptic curve operations:
/// - G1 point addition
/// - G1 scalar multiplication
/// - Multi-pairing check (for zk-SNARK verification)
///
/// BN254 is the curve used by Ethereum's precompiles (EIP-196/EIP-197)
/// and most existing zk-SNARK tooling (Circom, snarkjs, Groth16).
#[contract]
pub struct Bn254BasicsContract;

#[contractimpl]
impl Bn254BasicsContract {
    /// Add two G1 points on the BN254 curve.
    ///
    /// This is the basic building block for elliptic curve cryptography.
    /// P + Q returns another point on the curve.
    ///
    /// # Arguments
    /// * `p0` - First G1 point
    /// * `p1` - Second G1 point
    ///
    /// # Returns
    /// The sum p0 + p1 as a G1 point
    pub fn g1_add(env: Env, p0: Bn254G1Affine, p1: Bn254G1Affine) -> Bn254G1Affine {
        env.crypto().bn254().g1_add(&p0, &p1)
    }

    /// Scalar multiplication on a G1 point.
    ///
    /// Computes scalar * P, essential for:
    /// - Generating public keys from private keys
    /// - Computing Pedersen commitments
    /// - zk-SNARK proof verification
    ///
    /// # Arguments
    /// * `point` - G1 point to multiply
    /// * `scalar` - Field element scalar (Fr)
    ///
    /// # Returns
    /// The result scalar * point
    pub fn g1_mul(env: Env, point: Bn254G1Affine, scalar: Fr) -> Bn254G1Affine {
        env.crypto().bn254().g1_mul(&point, &scalar)
    }

    /// Verify a multi-pairing equation.
    ///
    /// Checks if: e(g1[0], g2[0]) * e(g1[1], g2[1]) * ... = 1
    ///
    /// This is the core of Groth16 zk-SNARK verification.
    /// A valid proof satisfies the pairing equation.
    ///
    /// # Arguments
    /// * `g1_points` - Vector of G1 points
    /// * `g2_points` - Vector of G2 points (must be same length)
    ///
    /// # Returns
    /// true if the pairing check passes, false otherwise
    pub fn pairing_check(
        env: Env,
        g1_points: Vec<Bn254G1Affine>,
        g2_points: Vec<Bn254G2Affine>,
    ) -> bool {
        env.crypto().bn254().pairing_check(g1_points, g2_points)
    }

    /// Create an Fr scalar from a U256 value.
    ///
    /// Fr is the scalar field of BN254, values are mod r where:
    /// r = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
    pub fn make_scalar(env: Env, value: U256) -> Fr {
        let _ = env;
        Fr::from_u256(value)
    }

    /// Demonstrate: P + P = 2 * P
    ///
    /// This verifies that addition and scalar multiplication
    /// are consistent operations on the curve.
    pub fn verify_double_equals_add(
        env: Env,
        point: Bn254G1Affine,
    ) -> bool {
        // P + P via addition
        let sum = env.crypto().bn254().g1_add(&point, &point);

        // 2 * P via scalar multiplication
        let two = Fr::from_u256(U256::from_u32(&env, 2));
        let doubled = env.crypto().bn254().g1_mul(&point, &two);

        // They should be equal
        sum == doubled
    }

    /// Scalar multiplication by 0 returns the identity point.
    pub fn mul_by_zero(env: Env, point: Bn254G1Affine) -> Bn254G1Affine {
        let zero = Fr::from_u256(U256::from_u32(&env, 0));
        env.crypto().bn254().g1_mul(&point, &zero)
    }

    /// Scalar multiplication by 1 returns the same point.
    pub fn mul_by_one(env: Env, point: Bn254G1Affine) -> Bn254G1Affine {
        let one = Fr::from_u256(U256::from_u32(&env, 1));
        env.crypto().bn254().g1_mul(&point, &one)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{testutils::BytesN as _, BytesN, Env};

    // BN254 G1 generator point coordinates (big-endian, 32 bytes each)
    // G1 = (1, 2)
    fn g1_generator(env: &Env) -> Bn254G1Affine {
        let mut bytes = [0u8; 64];
        bytes[31] = 1; // X = 1
        bytes[63] = 2; // Y = 2
        Bn254G1Affine::from_bytes(BytesN::from_array(env, &bytes))
    }

    // Identity point (point at infinity) is (0, 0)
    fn g1_identity(env: &Env) -> Bn254G1Affine {
        Bn254G1Affine::from_bytes(BytesN::from_array(env, &[0u8; 64]))
    }

    #[test]
    fn test_add_identity() {
        let env = Env::default();
        let contract_id = env.register(Bn254BasicsContract, ());
        let client = Bn254BasicsContractClient::new(&env, &contract_id);

        let g = g1_generator(&env);
        let identity = g1_identity(&env);

        // G + 0 = G
        let result = client.g1_add(&g, &identity);
        assert_eq!(result, g);
    }

    #[test]
    fn test_double_equals_add() {
        let env = Env::default();
        let contract_id = env.register(Bn254BasicsContract, ());
        let client = Bn254BasicsContractClient::new(&env, &contract_id);

        let g = g1_generator(&env);
        assert!(client.verify_double_equals_add(&g));
    }

    #[test]
    fn test_mul_by_one() {
        let env = Env::default();
        let contract_id = env.register(Bn254BasicsContract, ());
        let client = Bn254BasicsContractClient::new(&env, &contract_id);

        let g = g1_generator(&env);
        let result = client.mul_by_one(&g);
        assert_eq!(result, g);
    }

    #[test]
    fn test_mul_by_zero() {
        let env = Env::default();
        let contract_id = env.register(Bn254BasicsContract, ());
        let client = Bn254BasicsContractClient::new(&env, &contract_id);

        let g = g1_generator(&env);
        let identity = g1_identity(&env);

        let result = client.mul_by_zero(&g);
        assert_eq!(result, identity);
    }
}
