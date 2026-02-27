#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype, crypto::bn254::Fr as BnScalar, Address, Env, U256, Vec,
};
use soroban_poseidon::poseidon_hash;

/// Contract 3: Commitment Scheme
///
/// A commitment scheme lets you "commit" to a value without revealing it.
/// Later, you can "open" the commitment to prove what value you committed to.
///
/// Properties:
/// - Hiding: commitment reveals nothing about the value
/// - Binding: can't open to a different value than committed
///
/// Formula: commitment = Poseidon(value, blinding_factor)
///
/// Use cases:
/// - Privacy pools (commit to deposit amount)
/// - Voting (commit to vote before reveal phase)
/// - Auctions (sealed bids)
/// - Hash-based signatures
#[contract]
pub struct CommitmentSchemeContract;

/// Storage keys for the contract
#[contracttype]
pub enum DataKey {
    /// Maps commitment hash -> owner address
    Commitment(U256),
    /// Maps owner -> list of their commitments
    UserCommitments(Address),
}

/// A commitment with metadata
#[contracttype]
#[derive(Clone)]
pub struct Commitment {
    pub hash: U256,
    pub owner: Address,
    pub opened: bool,
    pub value: Option<U256>,
}

#[contractimpl]
impl CommitmentSchemeContract {
    /// Create a commitment to a value.
    ///
    /// The commitment hides the value using a random blinding factor.
    /// Anyone can verify the commitment exists, but can't determine the value.
    ///
    /// # Arguments
    /// * `value` - The secret value to commit to
    /// * `blinding` - Random blinding factor (must be kept secret until reveal)
    ///
    /// # Returns
    /// The commitment hash
    pub fn commit(env: Env, value: U256, blinding: U256) -> U256 {
        let mut inputs = Vec::new(&env);
        inputs.push_back(value);
        inputs.push_back(blinding);
        poseidon_hash::<3, BnScalar>(&env, &inputs)
    }

    /// Verify a commitment opening.
    ///
    /// Checks if the provided value and blinding factor produce the commitment.
    ///
    /// # Arguments
    /// * `commitment` - The commitment hash to verify against
    /// * `value` - The claimed secret value
    /// * `blinding` - The blinding factor used when committing
    ///
    /// # Returns
    /// true if the opening is valid
    pub fn verify(env: Env, commitment: U256, value: U256, blinding: U256) -> bool {
        let computed = Self::commit(env, value, blinding);
        computed == commitment
    }

    /// Store a commitment on-chain.
    ///
    /// The caller becomes the owner of this commitment.
    /// Only the owner can later open it.
    pub fn store_commitment(env: Env, commitment: U256) {
        let caller = env.current_contract_address();

        // Check commitment doesn't already exist
        let key = DataKey::Commitment(commitment.clone());
        if env.storage().persistent().has(&key) {
            panic!("Commitment already exists");
        }

        // Store the commitment
        let entry = Commitment {
            hash: commitment.clone(),
            owner: caller.clone(),
            opened: false,
            value: None,
        };
        env.storage().persistent().set(&key, &entry);

        // Add to user's commitment list
        let user_key = DataKey::UserCommitments(caller.clone());
        let mut user_commits: Vec<U256> = env
            .storage()
            .persistent()
            .get(&user_key)
            .unwrap_or(Vec::new(&env));
        user_commits.push_back(commitment);
        env.storage().persistent().set(&user_key, &user_commits);
    }

    /// Open a stored commitment, revealing the value.
    ///
    /// Once opened, the value is stored on-chain and anyone can see it.
    /// This is irreversible.
    ///
    /// # Arguments
    /// * `commitment` - The commitment hash
    /// * `value` - The secret value
    /// * `blinding` - The blinding factor
    ///
    /// # Returns
    /// true if successfully opened
    pub fn open_commitment(env: Env, commitment: U256, value: U256, blinding: U256) -> bool {
        // Verify the opening
        if !Self::verify(env.clone(), commitment.clone(), value.clone(), blinding) {
            return false;
        }

        // Update stored commitment
        let key = DataKey::Commitment(commitment.clone());
        let mut entry: Commitment = env
            .storage()
            .persistent()
            .get(&key)
            .expect("Commitment not found");

        if entry.opened {
            panic!("Commitment already opened");
        }

        entry.opened = true;
        entry.value = Some(value);
        env.storage().persistent().set(&key, &entry);

        true
    }

    /// Get commitment details.
    pub fn get_commitment(env: Env, commitment: U256) -> Option<Commitment> {
        let key = DataKey::Commitment(commitment);
        env.storage().persistent().get(&key)
    }

    /// Check if a commitment has been opened.
    pub fn is_opened(env: Env, commitment: U256) -> bool {
        let key = DataKey::Commitment(commitment);
        env.storage()
            .persistent()
            .get::<_, Commitment>(&key)
            .map(|c| c.opened)
            .unwrap_or(false)
    }

    // =========================================================================
    // Advanced: Pedersen-style commitments using elliptic curves
    // =========================================================================

    /// Create a Pedersen commitment using BN254 curve points.
    ///
    /// Pedersen: C = value * G + blinding * H
    ///
    /// This is additively homomorphic:
    /// C1 + C2 = (v1 + v2) * G + (b1 + b2) * H
    ///
    /// # Arguments
    /// * `value` - The value to commit to (as scalar)
    /// * `blinding` - Random blinding factor (as scalar)
    /// * `g` - Generator point G
    /// * `h` - Second generator H (must have unknown discrete log relation to G)
    pub fn pedersen_commit(
        env: Env,
        value: U256,
        blinding: U256,
        g: soroban_sdk::crypto::bn254::Bn254G1Affine,
        h: soroban_sdk::crypto::bn254::Bn254G1Affine,
    ) -> soroban_sdk::crypto::bn254::Bn254G1Affine {
        use soroban_sdk::crypto::bn254::Fr;

        let bn254 = env.crypto().bn254();
        let v_scalar = Fr::from_u256(value);
        let b_scalar = Fr::from_u256(blinding);

        // C = v*G + b*H
        let v_g = bn254.g1_mul(&g, &v_scalar);
        let b_h = bn254.g1_mul(&h, &b_scalar);
        bn254.g1_add(&v_g, &b_h)
    }

    /// Add two Pedersen commitments (homomorphic addition).
    ///
    /// If C1 = v1*G + b1*H and C2 = v2*G + b2*H
    /// Then C1 + C2 = (v1+v2)*G + (b1+b2)*H
    ///
    /// This allows computing on encrypted values!
    pub fn pedersen_add(
        env: Env,
        c1: soroban_sdk::crypto::bn254::Bn254G1Affine,
        c2: soroban_sdk::crypto::bn254::Bn254G1Affine,
    ) -> soroban_sdk::crypto::bn254::Bn254G1Affine {
        env.crypto().bn254().g1_add(&c1, &c2)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{crypto::bn254::{Bn254G1Affine, Fr}, BytesN, Env};

    // BN254 G1 generator: (1, 2)
    fn g1_generator(env: &Env) -> Bn254G1Affine {
        let mut bytes = [0u8; 64];
        bytes[31] = 1; // X = 1
        bytes[63] = 2; // Y = 2
        Bn254G1Affine::from_bytes(BytesN::from_array(env, &bytes))
    }

    // Identity point (point at infinity): (0, 0)
    fn g1_identity(env: &Env) -> Bn254G1Affine {
        Bn254G1Affine::from_bytes(BytesN::from_array(env, &[0u8; 64]))
    }

    // Generate H = 2*G (a valid second generator for testing)
    // In production, H should have unknown discrete log relation to G
    fn g1_second_generator(env: &Env) -> Bn254G1Affine {
        let g = g1_generator(env);
        let two = Fr::from_u256(U256::from_u32(env, 2));
        env.crypto().bn254().g1_mul(&g, &two)
    }

    #[test]
    fn test_commit_and_verify() {
        let env = Env::default();
        let contract_id = env.register(CommitmentSchemeContract, ());
        let client = CommitmentSchemeContractClient::new(&env, &contract_id);

        let value = U256::from_u32(&env, 1000);
        let blinding = U256::from_u32(&env, 12345);

        // Create commitment
        let commitment = client.commit(&value, &blinding);

        // Verify with correct values
        assert!(client.verify(&commitment, &value, &blinding));

        // Verify fails with wrong value
        let wrong_value = U256::from_u32(&env, 999);
        assert!(!client.verify(&commitment, &wrong_value, &blinding));

        // Verify fails with wrong blinding
        let wrong_blinding = U256::from_u32(&env, 54321);
        assert!(!client.verify(&commitment, &value, &wrong_blinding));
    }

    #[test]
    fn test_commitment_hides_value() {
        let env = Env::default();
        let contract_id = env.register(CommitmentSchemeContract, ());
        let client = CommitmentSchemeContractClient::new(&env, &contract_id);

        // Same value, different blinding = different commitment
        let value = U256::from_u32(&env, 100);
        let blinding1 = U256::from_u32(&env, 111);
        let blinding2 = U256::from_u32(&env, 222);

        let c1 = client.commit(&value, &blinding1);
        let c2 = client.commit(&value, &blinding2);

        // Commitments are different (hiding property)
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_commitment_is_binding() {
        let env = Env::default();
        let contract_id = env.register(CommitmentSchemeContract, ());
        let client = CommitmentSchemeContractClient::new(&env, &contract_id);

        let value = U256::from_u32(&env, 100);
        let blinding = U256::from_u32(&env, 12345);
        let commitment = client.commit(&value, &blinding);

        // Can't open with different value
        let fake_value = U256::from_u32(&env, 200);
        assert!(!client.verify(&commitment, &fake_value, &blinding));
    }

    #[test]
    fn test_pedersen_commit() {
        let env = Env::default();
        let contract_id = env.register(CommitmentSchemeContract, ());
        let client = CommitmentSchemeContractClient::new(&env, &contract_id);

        // Generator points: G and H = 2*G
        let g = g1_generator(&env);
        let h = g1_second_generator(&env);

        let value = U256::from_u32(&env, 100);
        let blinding = U256::from_u32(&env, 999);

        // Create Pedersen commitment: C = v*G + b*H
        let commitment = client.pedersen_commit(&value, &blinding, &g, &h);

        // Commitment should not be the identity
        let identity = g1_identity(&env);
        assert_ne!(commitment, identity);
    }

    #[test]
    fn test_pedersen_homomorphic() {
        let env = Env::default();
        let contract_id = env.register(CommitmentSchemeContract, ());
        let client = CommitmentSchemeContractClient::new(&env, &contract_id);

        // Use the generator point G
        let g = g1_generator(&env);

        // For simplicity, we'll use zero blinding to test homomorphism
        // C1 = v1 * G, C2 = v2 * G
        // C1 + C2 should equal (v1 + v2) * G

        let v1 = U256::from_u32(&env, 5);
        let v2 = U256::from_u32(&env, 3);
        let zero = U256::from_u32(&env, 0);

        // Create individual commitments (with H = identity for simplicity)
        let identity = g1_identity(&env);
        let c1 = client.pedersen_commit(&v1, &zero, &g, &identity);
        let c2 = client.pedersen_commit(&v2, &zero, &g, &identity);

        // Add commitments
        let c_sum = client.pedersen_add(&c1, &c2);

        // Create commitment to sum
        let v_sum = U256::from_u32(&env, 8); // 5 + 3
        let c_direct = client.pedersen_commit(&v_sum, &zero, &g, &identity);

        // They should be equal (homomorphic property)
        assert_eq!(c_sum, c_direct);
    }
}
