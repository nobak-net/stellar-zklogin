#![no_std]

use soroban_sdk::{contract, contractimpl, crypto::bn254::Fr as BnScalar, Env, U256, Vec};
use soroban_poseidon::poseidon_hash;

/// Contract 2: Poseidon Hash Primitives (BN254 Only)
///
/// ZK-friendly hash function optimized for BN254 circuits (~8x faster than SHA-256).
///
/// This contract provides Poseidon hashing over the BN254 scalar field,
/// compatible with Circom's implementation.
///
/// Use cases:
/// - Merkle tree hashing in ZK proofs
/// - Commitment schemes
/// - Nullifier generation for privacy applications
#[contract]
pub struct PoseidonHashContract;

#[contractimpl]
impl PoseidonHashContract {
    /// Compute Poseidon hash over BN254 scalar field.
    ///
    /// Matches Circom's Poseidon implementation for inputs up to 5 elements.
    ///
    /// # Arguments
    /// * `inputs` - Vector of field elements to hash (1-5 elements)
    ///
    /// # Returns
    /// The Poseidon hash as a U256 field element
    pub fn hash(env: Env, inputs: Vec<U256>) -> U256 {
        match inputs.len() {
            1 => poseidon_hash::<2, BnScalar>(&env, &inputs),
            2 => poseidon_hash::<3, BnScalar>(&env, &inputs),
            3 => poseidon_hash::<4, BnScalar>(&env, &inputs),
            4 => poseidon_hash::<5, BnScalar>(&env, &inputs),
            5 => poseidon_hash::<6, BnScalar>(&env, &inputs),
            _ => panic!("Poseidon supports 1-5 inputs"),
        }
    }

    /// Hash two values (common for Merkle tree nodes).
    ///
    /// Computes H(left, right) - the standard Merkle tree operation.
    pub fn hash_pair(env: Env, left: U256, right: U256) -> U256 {
        let mut inputs = Vec::new(&env);
        inputs.push_back(left);
        inputs.push_back(right);
        poseidon_hash::<3, BnScalar>(&env, &inputs)
    }

    /// Hash a single value (useful for leaf hashing).
    pub fn hash_single(env: Env, value: U256) -> U256 {
        let mut inputs = Vec::new(&env);
        inputs.push_back(value);
        poseidon_hash::<2, BnScalar>(&env, &inputs)
    }

    /// Chain multiple hashes together.
    ///
    /// Computes H(H(H(values[0], values[1]), values[2]), ...)
    pub fn hash_chain(env: Env, values: Vec<U256>) -> U256 {
        if values.is_empty() {
            return U256::from_u32(&env, 0);
        }

        let mut result = values.get(0).unwrap();

        for i in 1..values.len() {
            let next = values.get(i).unwrap();
            let mut pair = Vec::new(&env);
            pair.push_back(result);
            pair.push_back(next);
            result = poseidon_hash::<3, BnScalar>(&env, &pair);
        }

        result
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::Env;

    #[test]
    fn test_hash_single() {
        let env = Env::default();
        let contract_id = env.register(PoseidonHashContract, ());
        let client = PoseidonHashContractClient::new(&env, &contract_id);

        let value = U256::from_u32(&env, 42);
        let hash = client.hash_single(&value);
        assert_ne!(hash, U256::from_u32(&env, 0));
    }

    #[test]
    fn test_hash_pair() {
        let env = Env::default();
        let contract_id = env.register(PoseidonHashContract, ());
        let client = PoseidonHashContractClient::new(&env, &contract_id);

        let left = U256::from_u32(&env, 1);
        let right = U256::from_u32(&env, 2);
        let hash = client.hash_pair(&left, &right);
        assert_ne!(hash, U256::from_u32(&env, 0));
    }

    #[test]
    fn test_determinism() {
        let env = Env::default();
        let contract_id = env.register(PoseidonHashContract, ());
        let client = PoseidonHashContractClient::new(&env, &contract_id);

        let value = U256::from_u32(&env, 123);
        let hash1 = client.hash_single(&value);
        let hash2 = client.hash_single(&value);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_chain() {
        let env = Env::default();
        let contract_id = env.register(PoseidonHashContract, ());
        let client = PoseidonHashContractClient::new(&env, &contract_id);

        let mut values = Vec::new(&env);
        values.push_back(U256::from_u32(&env, 1));
        values.push_back(U256::from_u32(&env, 2));
        values.push_back(U256::from_u32(&env, 3));

        let hash = client.hash_chain(&values);
        assert_ne!(hash, U256::from_u32(&env, 0));
    }

    #[test]
    fn test_hash_generic() {
        let env = Env::default();
        let contract_id = env.register(PoseidonHashContract, ());
        let client = PoseidonHashContractClient::new(&env, &contract_id);

        let mut inputs = Vec::new(&env);
        inputs.push_back(U256::from_u32(&env, 1));
        inputs.push_back(U256::from_u32(&env, 2));
        inputs.push_back(U256::from_u32(&env, 3));

        let hash = client.hash(&inputs);
        assert_ne!(hash, U256::from_u32(&env, 0));
    }
}
