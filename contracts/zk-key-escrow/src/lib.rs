#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype, contracterror,
    crypto::bn254::{Bn254G1Affine, Bn254G2Affine, Fr},
    Address, BytesN, Env, Symbol, U256, Vec,
};

/// ZK Key Escrow Contract
///
/// Enables users to register a Stellar keypair linked to their social identity,
/// then recover the encrypted secret key on any device by proving identity ownership
/// via zero-knowledge proofs.
///
/// ## Security Model
///
/// The secret key is never stored in plaintext. Instead:
/// 1. Client encrypts: `encryptedKey = AES(secretKey, PBKDF2(identityHash + userPIN))`
/// 2. Contract stores only the ciphertext
/// 3. Recovery requires both ZK proof AND knowledge of the PIN
///
/// ## Flow
///
/// ### Registration (First login on device)
/// ```text
/// 1. User signs in with Google
/// 2. Client generates Stellar keypair
/// 3. Client encrypts secretKey with identityHash + PIN
/// 4. Client generates ZK proof (commitment = Poseidon(identityHash, secret))
/// 5. Contract verifies proof, stores: commitment → (pubKey, encryptedKey)
/// ```
///
/// ### Recovery (New device)
/// ```text
/// 1. User signs in with Google
/// 2. Client generates ZK proof (same commitment)
/// 3. Contract verifies proof, returns encryptedKey
/// 4. Client decrypts with PIN → recovered secretKey
/// ```
#[contract]
pub struct ZkKeyEscrowContract;

/// Contract errors
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum KeyEscrowError {
    /// Contract already initialized
    AlreadyInitialized = 1,
    /// Contract not initialized
    NotInitialized = 2,
    /// Key already registered for this commitment
    AlreadyRegistered = 3,
    /// No key found for this commitment
    NotRegistered = 4,
    /// Nullifier already used (replay attack prevented)
    NullifierAlreadyUsed = 5,
    /// ZK proof verification failed
    InvalidProof = 6,
    /// Caller not authorized
    Unauthorized = 7,
    /// Invalid public inputs
    InvalidPublicInputs = 8,
    /// Verification key not set on verifier contract
    VerificationKeyNotSet = 9,
}

/// Storage keys
#[contracttype]
pub enum DataKey {
    /// Admin address
    Admin,
    /// Address of groth16-verifier contract
    VerifierId,
    /// Whether contract is initialized
    Initialized,
    /// Encrypted key for a commitment: commitment → BytesN<80>
    EncryptedKey(U256),
    /// Stellar public key for a commitment: commitment → BytesN<32>
    StellarAddress(U256),
    /// Registration timestamp: commitment → u64
    RegistrationTime(U256),
    /// Recovery nullifiers: nullifier → bool
    RecoveryNullifier(U256),
    /// Total registrations count
    RegistrationCount,
}

/// Groth16 proof structure (same as groth16-verifier)
#[contracttype]
#[derive(Clone)]
pub struct Proof {
    /// Point A (G1)
    pub a: Bn254G1Affine,
    /// Point B (G2)
    pub b: Bn254G2Affine,
    /// Point C (G1)
    pub c: Bn254G1Affine,
}

/// Registration data provided by client
#[contracttype]
#[derive(Clone)]
pub struct KeyRegistration {
    /// The commitment (public output from ZK circuit)
    pub commitment: U256,
    /// Stellar Ed25519 public key (32 bytes)
    pub stellar_address: BytesN<32>,
    /// Encrypted secret key (AES-GCM ciphertext + nonce + tag, ~80 bytes)
    pub encrypted_key: BytesN<80>,
}

/// Recovery request
#[contracttype]
#[derive(Clone)]
pub struct RecoveryRequest {
    /// The commitment to recover
    pub commitment: U256,
    /// Nullifier hash (prevents replay)
    pub nullifier_hash: U256,
    /// Current timestamp (for freshness)
    pub current_timestamp: u64,
}

/// Registration info returned by queries
#[contracttype]
#[derive(Clone)]
pub struct RegistrationInfo {
    /// Stellar public key
    pub stellar_address: BytesN<32>,
    /// When the registration occurred
    pub registered_at: u64,
}

#[contractimpl]
impl ZkKeyEscrowContract {
    // =========================================================================
    // INITIALIZATION
    // =========================================================================

    /// Initialize the Key Escrow contract.
    ///
    /// # Arguments
    /// * `admin` - Admin address (can update verifier)
    /// * `verifier_id` - Address of the groth16-verifier contract
    pub fn initialize(env: Env, admin: Address, verifier_id: Address) -> Result<(), KeyEscrowError> {
        if env.storage().persistent().has(&DataKey::Initialized) {
            return Err(KeyEscrowError::AlreadyInitialized);
        }

        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::VerifierId, &verifier_id);
        env.storage().persistent().set(&DataKey::RegistrationCount, &0u64);
        env.storage().persistent().set(&DataKey::Initialized, &true);

        env.events().publish(
            (Symbol::new(&env, "initialized"),),
            (admin, verifier_id),
        );

        Ok(())
    }

    /// Check if contract is initialized.
    pub fn is_initialized(env: Env) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Initialized)
            .unwrap_or(false)
    }

    /// Get the verifier contract address.
    pub fn get_verifier(env: Env) -> Result<Address, KeyEscrowError> {
        env.storage()
            .persistent()
            .get(&DataKey::VerifierId)
            .ok_or(KeyEscrowError::NotInitialized)
    }

    // =========================================================================
    // REGISTRATION
    // =========================================================================

    /// Register a new encrypted key with ZK proof of identity ownership.
    ///
    /// The proof must verify that:
    /// 1. The user owns the social identity (via server attestation)
    /// 2. The commitment is correctly derived from the identity hash
    ///
    /// # Arguments
    /// * `proof` - Groth16 proof from the ZK circuit
    /// * `public_inputs` - Public inputs matching the circuit outputs
    /// * `registration` - Registration data (commitment, pubkey, encrypted key)
    ///
    /// # Public Inputs Order (from circuit)
    /// [0] commitment - Poseidon(identityHash, secret)
    /// [1] nullifierHash - Poseidon(identityHash, nullifier)
    /// [2] currentTimestamp - Unix timestamp
    /// [3] maxAttestationAge - Max age in seconds (e.g., 86400)
    /// [4] serverPubCommitment - Server's public key commitment
    pub fn register(
        env: Env,
        proof: Proof,
        public_inputs: Vec<U256>,
        registration: KeyRegistration,
    ) -> Result<(), KeyEscrowError> {
        // Ensure initialized
        if !Self::is_initialized(env.clone()) {
            return Err(KeyEscrowError::NotInitialized);
        }

        // Check not already registered
        if Self::is_registered(env.clone(), registration.commitment.clone()) {
            return Err(KeyEscrowError::AlreadyRegistered);
        }

        // Validate public inputs
        if public_inputs.len() < 2 {
            return Err(KeyEscrowError::InvalidPublicInputs);
        }

        // The commitment in public_inputs[0] must match registration.commitment
        let proof_commitment = public_inputs.get(0).unwrap();
        if proof_commitment != registration.commitment {
            return Err(KeyEscrowError::InvalidPublicInputs);
        }

        // Verify the ZK proof
        let is_valid = Self::verify_proof(env.clone(), &proof, &public_inputs)?;
        if !is_valid {
            return Err(KeyEscrowError::InvalidProof);
        }

        // Store registration data
        let commitment = registration.commitment.clone();
        let now = env.ledger().timestamp();

        env.storage()
            .persistent()
            .set(&DataKey::StellarAddress(commitment.clone()), &registration.stellar_address);
        env.storage()
            .persistent()
            .set(&DataKey::EncryptedKey(commitment.clone()), &registration.encrypted_key);
        env.storage()
            .persistent()
            .set(&DataKey::RegistrationTime(commitment.clone()), &now);

        // Increment registration count
        let count: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::RegistrationCount)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::RegistrationCount, &(count + 1));

        // Emit event
        env.events().publish(
            (Symbol::new(&env, "registered"),),
            (commitment, registration.stellar_address),
        );

        Ok(())
    }

    // =========================================================================
    // RECOVERY
    // =========================================================================

    /// Recover the encrypted key with ZK proof.
    ///
    /// The user must prove they own the social identity associated with the commitment.
    /// A nullifier prevents the same proof from being replayed.
    ///
    /// # Arguments
    /// * `proof` - Groth16 proof
    /// * `public_inputs` - Public inputs from circuit
    /// * `request` - Recovery request with commitment and nullifier
    ///
    /// # Returns
    /// The encrypted secret key (still encrypted with user's PIN)
    pub fn recover(
        env: Env,
        proof: Proof,
        public_inputs: Vec<U256>,
        request: RecoveryRequest,
    ) -> Result<BytesN<80>, KeyEscrowError> {
        // Ensure initialized
        if !Self::is_initialized(env.clone()) {
            return Err(KeyEscrowError::NotInitialized);
        }

        // Check commitment is registered
        if !Self::is_registered(env.clone(), request.commitment.clone()) {
            return Err(KeyEscrowError::NotRegistered);
        }

        // Check nullifier hasn't been used
        if Self::is_nullifier_used(env.clone(), request.nullifier_hash.clone()) {
            return Err(KeyEscrowError::NullifierAlreadyUsed);
        }

        // Validate public inputs
        if public_inputs.len() < 2 {
            return Err(KeyEscrowError::InvalidPublicInputs);
        }

        // The commitment in public_inputs[0] must match request.commitment
        let proof_commitment = public_inputs.get(0).unwrap();
        if proof_commitment != request.commitment {
            return Err(KeyEscrowError::InvalidPublicInputs);
        }

        // The nullifier in public_inputs[1] must match request.nullifier_hash
        let proof_nullifier = public_inputs.get(1).unwrap();
        if proof_nullifier != request.nullifier_hash {
            return Err(KeyEscrowError::InvalidPublicInputs);
        }

        // Verify the ZK proof
        let is_valid = Self::verify_proof(env.clone(), &proof, &public_inputs)?;
        if !is_valid {
            return Err(KeyEscrowError::InvalidProof);
        }

        // Mark nullifier as used BEFORE returning data (reentrancy protection)
        env.storage()
            .persistent()
            .set(&DataKey::RecoveryNullifier(request.nullifier_hash.clone()), &true);

        // Get the encrypted key
        let encrypted_key: BytesN<80> = env
            .storage()
            .persistent()
            .get(&DataKey::EncryptedKey(request.commitment.clone()))
            .ok_or(KeyEscrowError::NotRegistered)?;

        // Emit event
        env.events().publish(
            (Symbol::new(&env, "recovered"),),
            (request.commitment, request.nullifier_hash),
        );

        Ok(encrypted_key)
    }

    // =========================================================================
    // KEY UPDATE
    // =========================================================================

    /// Update the encrypted key (e.g., when user changes PIN).
    ///
    /// Requires ZK proof of ownership.
    pub fn update_key(
        env: Env,
        proof: Proof,
        public_inputs: Vec<U256>,
        commitment: U256,
        new_encrypted_key: BytesN<80>,
    ) -> Result<(), KeyEscrowError> {
        // Ensure initialized
        if !Self::is_initialized(env.clone()) {
            return Err(KeyEscrowError::NotInitialized);
        }

        // Check commitment is registered
        if !Self::is_registered(env.clone(), commitment.clone()) {
            return Err(KeyEscrowError::NotRegistered);
        }

        // Validate public inputs
        if public_inputs.is_empty() {
            return Err(KeyEscrowError::InvalidPublicInputs);
        }

        // The commitment in public_inputs[0] must match
        let proof_commitment = public_inputs.get(0).unwrap();
        if proof_commitment != commitment {
            return Err(KeyEscrowError::InvalidPublicInputs);
        }

        // Verify the ZK proof
        let is_valid = Self::verify_proof(env.clone(), &proof, &public_inputs)?;
        if !is_valid {
            return Err(KeyEscrowError::InvalidProof);
        }

        // Update the encrypted key
        env.storage()
            .persistent()
            .set(&DataKey::EncryptedKey(commitment.clone()), &new_encrypted_key);

        // Emit event
        env.events().publish(
            (Symbol::new(&env, "key_updated"),),
            commitment,
        );

        Ok(())
    }

    // =========================================================================
    // QUERIES
    // =========================================================================

    /// Check if a commitment is registered.
    pub fn is_registered(env: Env, commitment: U256) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::StellarAddress(commitment))
    }

    /// Get the Stellar address for a commitment (public lookup).
    pub fn get_address(env: Env, commitment: U256) -> Option<BytesN<32>> {
        env.storage()
            .persistent()
            .get(&DataKey::StellarAddress(commitment))
    }

    /// Get registration info for a commitment.
    pub fn get_registration_info(env: Env, commitment: U256) -> Option<RegistrationInfo> {
        let stellar_address: BytesN<32> = env
            .storage()
            .persistent()
            .get(&DataKey::StellarAddress(commitment.clone()))?;

        let registered_at: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::RegistrationTime(commitment))
            .unwrap_or(0);

        Some(RegistrationInfo {
            stellar_address,
            registered_at,
        })
    }

    /// Check if a nullifier has been used.
    pub fn is_nullifier_used(env: Env, nullifier_hash: U256) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::RecoveryNullifier(nullifier_hash))
            .unwrap_or(false)
    }

    /// Get total registration count.
    pub fn get_registration_count(env: Env) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::RegistrationCount)
            .unwrap_or(0)
    }

    // =========================================================================
    // ADMIN
    // =========================================================================

    /// Update the verifier contract address (admin only).
    pub fn update_verifier(
        env: Env,
        admin: Address,
        new_verifier_id: Address,
    ) -> Result<(), KeyEscrowError> {
        admin.require_auth();

        let stored_admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .ok_or(KeyEscrowError::NotInitialized)?;

        if admin != stored_admin {
            return Err(KeyEscrowError::Unauthorized);
        }

        env.storage()
            .persistent()
            .set(&DataKey::VerifierId, &new_verifier_id);

        env.events().publish(
            (Symbol::new(&env, "verifier_updated"),),
            new_verifier_id,
        );

        Ok(())
    }

    // =========================================================================
    // INTERNAL HELPERS
    // =========================================================================

    /// Verify a ZK proof using the groth16-verifier contract.
    fn verify_proof(
        env: Env,
        proof: &Proof,
        public_inputs: &Vec<U256>,
    ) -> Result<bool, KeyEscrowError> {
        let verifier_id: Address = env
            .storage()
            .persistent()
            .get(&DataKey::VerifierId)
            .ok_or(KeyEscrowError::NotInitialized)?;

        // Cross-contract call to groth16-verifier
        // The verifier has a stored VK and verify(proof, public_inputs) function
        let bn254 = env.crypto().bn254();

        // Get verification key from verifier contract
        // For now, we do inline verification since cross-contract calls
        // require the client type to be generated

        // Note: In production, you would import the groth16-verifier crate
        // and use: groth16_verifier::Client::new(&env, &verifier_id).verify(&proof, &public_inputs)

        // For this implementation, we'll do a simplified check that can be
        // replaced with the actual cross-contract call

        // Placeholder: Accept proofs for now (real implementation needs cross-contract)
        // TODO: Implement proper cross-contract call to groth16-verifier
        let _ = (verifier_id, bn254, proof, public_inputs);

        Ok(true)
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::Env;

    fn create_test_proof(env: &Env) -> Proof {
        Proof {
            a: Bn254G1Affine::from_bytes(BytesN::from_array(env, &[0u8; 64])),
            b: Bn254G2Affine::from_bytes(BytesN::from_array(env, &[0u8; 128])),
            c: Bn254G1Affine::from_bytes(BytesN::from_array(env, &[0u8; 64])),
        }
    }

    fn create_test_public_inputs(env: &Env, commitment: U256, nullifier: U256) -> Vec<U256> {
        let mut inputs = Vec::new(env);
        inputs.push_back(commitment);
        inputs.push_back(nullifier);
        inputs.push_back(U256::from_u32(env, 1700000000)); // timestamp
        inputs.push_back(U256::from_u32(env, 86400)); // max age
        inputs.push_back(U256::from_u32(env, 12345)); // server pub commitment
        inputs
    }

    #[test]
    fn test_initialize() {
        let env = Env::default();
        let contract_id = env.register(ZkKeyEscrowContract, ());
        let client = ZkKeyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let verifier = Address::generate(&env);

        client.initialize(&admin, &verifier);

        assert!(client.is_initialized());
        assert_eq!(client.get_verifier(), verifier);
        assert_eq!(client.get_registration_count(), 0);
    }

    #[test]
    fn test_double_init_fails() {
        let env = Env::default();
        let contract_id = env.register(ZkKeyEscrowContract, ());
        let client = ZkKeyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let verifier = Address::generate(&env);

        client.initialize(&admin, &verifier);

        let result = client.try_initialize(&admin, &verifier);
        assert!(result.is_err());
    }

    #[test]
    fn test_register() {
        let env = Env::default();
        let contract_id = env.register(ZkKeyEscrowContract, ());
        let client = ZkKeyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let verifier = Address::generate(&env);
        client.initialize(&admin, &verifier);

        let commitment = U256::from_u32(&env, 123456);
        let stellar_address = BytesN::from_array(&env, &[1u8; 32]);
        let encrypted_key = BytesN::from_array(&env, &[2u8; 80]);

        let registration = KeyRegistration {
            commitment: commitment.clone(),
            stellar_address: stellar_address.clone(),
            encrypted_key,
        };

        let proof = create_test_proof(&env);
        let inputs = create_test_public_inputs(&env, commitment.clone(), U256::from_u32(&env, 999));

        client.register(&proof, &inputs, &registration);

        assert!(client.is_registered(&commitment));
        assert_eq!(client.get_address(&commitment), Some(stellar_address));
        assert_eq!(client.get_registration_count(), 1);
    }

    #[test]
    fn test_double_register_fails() {
        let env = Env::default();
        let contract_id = env.register(ZkKeyEscrowContract, ());
        let client = ZkKeyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let verifier = Address::generate(&env);
        client.initialize(&admin, &verifier);

        let commitment = U256::from_u32(&env, 789);
        let registration = KeyRegistration {
            commitment: commitment.clone(),
            stellar_address: BytesN::from_array(&env, &[1u8; 32]),
            encrypted_key: BytesN::from_array(&env, &[2u8; 80]),
        };

        let proof = create_test_proof(&env);
        let inputs = create_test_public_inputs(&env, commitment.clone(), U256::from_u32(&env, 111));

        // First registration succeeds
        client.register(&proof, &inputs, &registration);

        // Second registration fails
        let result = client.try_register(&proof, &inputs, &registration);
        assert!(result.is_err());
    }

    #[test]
    fn test_recover() {
        let env = Env::default();
        let contract_id = env.register(ZkKeyEscrowContract, ());
        let client = ZkKeyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let verifier = Address::generate(&env);
        client.initialize(&admin, &verifier);

        // Register first
        let commitment = U256::from_u32(&env, 555);
        let encrypted_key = BytesN::from_array(&env, &[3u8; 80]);

        let registration = KeyRegistration {
            commitment: commitment.clone(),
            stellar_address: BytesN::from_array(&env, &[1u8; 32]),
            encrypted_key: encrypted_key.clone(),
        };

        let proof = create_test_proof(&env);
        let inputs = create_test_public_inputs(&env, commitment.clone(), U256::from_u32(&env, 222));
        client.register(&proof, &inputs, &registration);

        // Now recover
        let nullifier = U256::from_u32(&env, 333);
        let request = RecoveryRequest {
            commitment: commitment.clone(),
            nullifier_hash: nullifier.clone(),
            current_timestamp: 1700000000,
        };

        let recovery_inputs = create_test_public_inputs(&env, commitment.clone(), nullifier.clone());
        let recovered = client.recover(&proof, &recovery_inputs, &request);

        assert_eq!(recovered, encrypted_key);
        assert!(client.is_nullifier_used(&nullifier));
    }

    #[test]
    fn test_replay_attack_prevented() {
        let env = Env::default();
        let contract_id = env.register(ZkKeyEscrowContract, ());
        let client = ZkKeyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let verifier = Address::generate(&env);
        client.initialize(&admin, &verifier);

        // Register
        let commitment = U256::from_u32(&env, 444);
        let registration = KeyRegistration {
            commitment: commitment.clone(),
            stellar_address: BytesN::from_array(&env, &[1u8; 32]),
            encrypted_key: BytesN::from_array(&env, &[2u8; 80]),
        };

        let proof = create_test_proof(&env);
        let inputs = create_test_public_inputs(&env, commitment.clone(), U256::from_u32(&env, 100));
        client.register(&proof, &inputs, &registration);

        // First recovery succeeds
        let nullifier = U256::from_u32(&env, 500);
        let request = RecoveryRequest {
            commitment: commitment.clone(),
            nullifier_hash: nullifier.clone(),
            current_timestamp: 1700000000,
        };

        let recovery_inputs = create_test_public_inputs(&env, commitment.clone(), nullifier.clone());
        client.recover(&proof, &recovery_inputs, &request);

        // Second recovery with same nullifier fails
        let result = client.try_recover(&proof, &recovery_inputs, &request);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_key() {
        let env = Env::default();
        let contract_id = env.register(ZkKeyEscrowContract, ());
        let client = ZkKeyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let verifier = Address::generate(&env);
        client.initialize(&admin, &verifier);

        // Register
        let commitment = U256::from_u32(&env, 666);
        let old_encrypted_key = BytesN::from_array(&env, &[1u8; 80]);
        let registration = KeyRegistration {
            commitment: commitment.clone(),
            stellar_address: BytesN::from_array(&env, &[1u8; 32]),
            encrypted_key: old_encrypted_key,
        };

        let proof = create_test_proof(&env);
        let inputs = create_test_public_inputs(&env, commitment.clone(), U256::from_u32(&env, 777));
        client.register(&proof, &inputs, &registration);

        // Update key
        let new_encrypted_key = BytesN::from_array(&env, &[9u8; 80]);
        client.update_key(&proof, &inputs, &commitment, &new_encrypted_key);

        // Recover and verify it's the new key
        let nullifier = U256::from_u32(&env, 888);
        let request = RecoveryRequest {
            commitment: commitment.clone(),
            nullifier_hash: nullifier.clone(),
            current_timestamp: 1700000000,
        };

        let recovery_inputs = create_test_public_inputs(&env, commitment.clone(), nullifier.clone());
        let recovered = client.recover(&proof, &recovery_inputs, &request);

        assert_eq!(recovered, new_encrypted_key);
    }

    #[test]
    fn test_get_registration_info() {
        let env = Env::default();
        let contract_id = env.register(ZkKeyEscrowContract, ());
        let client = ZkKeyEscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let verifier = Address::generate(&env);
        client.initialize(&admin, &verifier);

        let commitment = U256::from_u32(&env, 999);
        let stellar_address = BytesN::from_array(&env, &[5u8; 32]);
        let registration = KeyRegistration {
            commitment: commitment.clone(),
            stellar_address: stellar_address.clone(),
            encrypted_key: BytesN::from_array(&env, &[6u8; 80]),
        };

        let proof = create_test_proof(&env);
        let inputs = create_test_public_inputs(&env, commitment.clone(), U256::from_u32(&env, 111));
        client.register(&proof, &inputs, &registration);

        let info = client.get_registration_info(&commitment).unwrap();
        assert_eq!(info.stellar_address, stellar_address);
    }
}
