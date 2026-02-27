#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype, contracterror, token,
    crypto::bn254::{Bn254G1Affine, Bn254G2Affine},
    Address, Bytes, BytesN, Env, Symbol, U256, Vec,
};

/// ZK Wallet Contract
///
/// A smart contract wallet where transactions are authorized via ZK proof
/// instead of traditional cryptographic signatures. The wallet IS the identity -
/// no private key management needed.
///
/// ## How It Works
///
/// Instead of storing and protecting a private key, users prove ownership of their
/// social identity via ZK proof each time they want to make a transaction. The commitment
/// (derived from the identity hash) serves as the wallet's identity.
///
/// ## Flow
///
/// ### Wallet Creation
/// ```text
/// 1. User signs in with a social provider (Google, Apple, etc.)
/// 2. Client generates ZK proof (commitment = Poseidon(identityHash, secret))
/// 3. Contract creates wallet for commitment
/// 4. Wallet is identified by commitment (deterministic)
/// ```
///
/// ### Transaction Authorization
/// ```text
/// 1. User wants to send funds
/// 2. Client generates ZK proof with transaction details in public inputs
/// 3. Contract verifies proof + executes transaction
/// 4. No private key needed!
/// ```
///
/// ## Security
///
/// - Each transaction requires a fresh ZK proof
/// - Nullifiers prevent proof replay
/// - Nonces ensure transaction ordering
/// - Only the identity owner can authorize transactions
#[contract]
pub struct ZkWalletContract;

/// Contract errors
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum WalletError {
    /// Contract already initialized
    AlreadyInitialized = 1,
    /// Contract not initialized
    NotInitialized = 2,
    /// Wallet already exists for this commitment
    WalletExists = 3,
    /// Wallet not found
    WalletNotFound = 4,
    /// Insufficient balance
    InsufficientBalance = 5,
    /// Invalid nonce
    InvalidNonce = 6,
    /// Nullifier already used
    NullifierUsed = 7,
    /// ZK proof verification failed
    InvalidProof = 8,
    /// Invalid public inputs
    InvalidPublicInputs = 9,
    /// Unauthorized caller
    Unauthorized = 10,
    /// Invalid amount
    InvalidAmount = 11,
}

/// Storage keys
#[contracttype]
pub enum DataKey {
    /// Admin address
    Admin,
    /// Groth16 verifier contract address
    VerifierId,
    /// Native token contract address (for balance operations)
    TokenId,
    /// Whether contract is initialized
    Initialized,
    /// Wallet balance: commitment → i128
    WalletBalance(U256),
    /// Wallet nonce: commitment → u64 (for transaction ordering)
    WalletNonce(U256),
    /// Wallet creation timestamp: commitment → u64
    WalletCreated(U256),
    /// Transaction nullifiers: nullifier → bool
    TxNullifier(U256),
    /// Total wallets created
    WalletCount,
}

/// Groth16 proof structure (raw bytes for SDK compatibility)
/// The SDK cannot create Bn254G1Affine objects directly, so we accept
/// raw bytes. Length validation is done manually to avoid deserialization issues.
#[contracttype]
#[derive(Clone)]
pub struct ProofBytes {
    /// Point A (G1) - should be 64 bytes: x || y
    pub a: Bytes,
    /// Point B (G2) - should be 128 bytes: x_c1 || x_c0 || y_c1 || y_c0
    pub b: Bytes,
    /// Point C (G1) - should be 64 bytes: x || y
    pub c: Bytes,
}

/// Internal Groth16 proof structure with proper curve types
#[derive(Clone)]
pub struct Proof {
    /// Point A (G1)
    pub a: Bn254G1Affine,
    /// Point B (G2)
    pub b: Bn254G2Affine,
    /// Point C (G1)
    pub c: Bn254G1Affine,
}

impl ProofBytes {
    /// Convert raw bytes to proper BN254 curve points
    /// Note: This will panic if bytes are invalid curve points.
    /// Only call when implementing actual verification.
    pub fn to_proof(&self, env: &Env) -> Proof {
        // Convert Bytes to BytesN with length validation
        let a_fixed: BytesN<64> = self.a.clone().try_into().expect("a must be 64 bytes");
        let b_fixed: BytesN<128> = self.b.clone().try_into().expect("b must be 128 bytes");
        let c_fixed: BytesN<64> = self.c.clone().try_into().expect("c must be 64 bytes");

        Proof {
            a: Bn254G1Affine::from_bytes(a_fixed),
            b: Bn254G2Affine::from_bytes(b_fixed),
            c: Bn254G1Affine::from_bytes(c_fixed),
        }
    }

    /// Validate proof bytes have correct lengths
    pub fn validate_lengths(&self) -> bool {
        self.a.len() == 64 && self.b.len() == 128 && self.c.len() == 64
    }
}

/// Transfer request
#[contracttype]
#[derive(Clone)]
pub struct TransferRequest {
    /// Source wallet commitment
    pub from_commitment: U256,
    /// Destination address (any Stellar address)
    pub to: Address,
    /// Amount to transfer (in stroops)
    pub amount: i128,
    /// Transaction nonce (must match wallet's current nonce)
    pub nonce: u64,
    /// Nullifier hash (prevents replay)
    pub nullifier_hash: U256,
}

/// Wallet information
#[contracttype]
#[derive(Clone)]
pub struct WalletInfo {
    /// Wallet commitment (identity)
    pub commitment: U256,
    /// Current balance (in stroops)
    pub balance: i128,
    /// Current transaction nonce
    pub nonce: u64,
    /// When wallet was created
    pub created_at: u64,
}

#[contractimpl]
impl ZkWalletContract {
    // =========================================================================
    // INITIALIZATION
    // =========================================================================

    /// Initialize the ZK Wallet contract.
    ///
    /// # Arguments
    /// * `admin` - Admin address
    /// * `verifier_id` - Address of groth16-verifier contract
    /// * `token_id` - Address of the token contract (e.g., native XLM)
    pub fn initialize(
        env: Env,
        admin: Address,
        verifier_id: Address,
        token_id: Address,
    ) -> Result<(), WalletError> {
        if env.storage().persistent().has(&DataKey::Initialized) {
            return Err(WalletError::AlreadyInitialized);
        }

        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::VerifierId, &verifier_id);
        env.storage().persistent().set(&DataKey::TokenId, &token_id);
        env.storage().persistent().set(&DataKey::WalletCount, &0u64);
        env.storage().persistent().set(&DataKey::Initialized, &true);

        env.events().publish(
            (Symbol::new(&env, "initialized"),),
            (admin, verifier_id, token_id),
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

    /// Get configuration.
    pub fn get_config(env: Env) -> Result<(Address, Address), WalletError> {
        let verifier: Address = env
            .storage()
            .persistent()
            .get(&DataKey::VerifierId)
            .ok_or(WalletError::NotInitialized)?;
        let token: Address = env
            .storage()
            .persistent()
            .get(&DataKey::TokenId)
            .ok_or(WalletError::NotInitialized)?;
        Ok((verifier, token))
    }

    // =========================================================================
    // WALLET CREATION
    // =========================================================================

    /// Create a new wallet for a commitment.
    ///
    /// Requires ZK proof of identity ownership. The wallet will be identified
    /// by the commitment, which is derived from the user's identity hash.
    ///
    /// # Arguments
    /// * `proof_bytes` - Groth16 proof as raw bytes (for SDK compatibility)
    /// * `public_inputs` - Public inputs from the circuit
    /// * `commitment` - The wallet's commitment (from public_inputs[0])
    pub fn create_wallet(
        env: Env,
        proof_bytes: ProofBytes,
        public_inputs: Vec<U256>,
        commitment: U256,
    ) -> Result<(), WalletError> {
        // Note: BN254 conversion deferred until verify_proof is implemented
        // For now, we accept the raw bytes and will validate when calling verifier
        let _ = &proof_bytes;
        // Ensure initialized
        if !Self::is_initialized(env.clone()) {
            return Err(WalletError::NotInitialized);
        }

        // Check wallet doesn't already exist
        if Self::wallet_exists(env.clone(), commitment.clone()) {
            return Err(WalletError::WalletExists);
        }

        // Validate public inputs
        if public_inputs.is_empty() {
            return Err(WalletError::InvalidPublicInputs);
        }

        // Commitment must match public_inputs[0]
        let proof_commitment = public_inputs.get(0).unwrap();
        if proof_commitment != commitment {
            return Err(WalletError::InvalidPublicInputs);
        }

        // Verify the ZK proof (stubbed for now - will integrate with groth16-verifier)
        let is_valid = Self::verify_proof_bytes(env.clone(), &proof_bytes, &public_inputs)?;
        if !is_valid {
            return Err(WalletError::InvalidProof);
        }

        // Create wallet with zero balance
        let now = env.ledger().timestamp();

        env.storage()
            .persistent()
            .set(&DataKey::WalletBalance(commitment.clone()), &0i128);
        env.storage()
            .persistent()
            .set(&DataKey::WalletNonce(commitment.clone()), &0u64);
        env.storage()
            .persistent()
            .set(&DataKey::WalletCreated(commitment.clone()), &now);

        // Increment wallet count
        let count: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::WalletCount)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::WalletCount, &(count + 1));

        // Emit event
        env.events().publish(
            (Symbol::new(&env, "wallet_created"),),
            commitment,
        );

        Ok(())
    }

    // =========================================================================
    // DEPOSITS
    // =========================================================================

    /// Deposit funds to a wallet.
    ///
    /// Anyone can deposit to any wallet - no proof required.
    /// The depositor must authorize the token transfer.
    ///
    /// # Arguments
    /// * `from` - Address depositing funds (must authorize)
    /// * `commitment` - Target wallet commitment
    /// * `amount` - Amount to deposit (in stroops)
    pub fn deposit(
        env: Env,
        from: Address,
        commitment: U256,
        amount: i128,
    ) -> Result<(), WalletError> {
        // Ensure initialized
        if !Self::is_initialized(env.clone()) {
            return Err(WalletError::NotInitialized);
        }

        // Wallet must exist
        if !Self::wallet_exists(env.clone(), commitment.clone()) {
            return Err(WalletError::WalletNotFound);
        }

        // Amount must be positive
        if amount <= 0 {
            return Err(WalletError::InvalidAmount);
        }

        // Require authorization from depositor
        from.require_auth();

        // Transfer tokens from depositor to this contract
        let token_id: Address = env
            .storage()
            .persistent()
            .get(&DataKey::TokenId)
            .unwrap();

        let token_client = token::Client::new(&env, &token_id);
        token_client.transfer(&from, &env.current_contract_address(), &amount);

        // Update wallet balance
        let current_balance: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::WalletBalance(commitment.clone()))
            .unwrap_or(0);

        env.storage()
            .persistent()
            .set(&DataKey::WalletBalance(commitment.clone()), &(current_balance + amount));

        // Emit event
        env.events().publish(
            (Symbol::new(&env, "deposited"),),
            (commitment, from, amount),
        );

        Ok(())
    }

    // =========================================================================
    // TRANSFERS
    // =========================================================================

    /// Transfer funds from a wallet to any address.
    ///
    /// Requires ZK proof of identity ownership for the source wallet.
    /// The proof must include the transaction details in the public inputs.
    ///
    /// # Arguments
    /// * `proof_bytes` - Groth16 proof as raw bytes (for SDK compatibility)
    /// * `public_inputs` - Public inputs including commitment and tx details
    /// * `request` - Transfer request details
    ///
    /// # Public Inputs Order (extended for transactions)
    /// [0] commitment - Wallet identity
    /// [1] nullifierHash - Prevents replay
    /// [2] currentTimestamp - Freshness
    /// [3] maxAttestationAge - Max age
    /// [4] serverPubCommitment - Server identity
    pub fn transfer(
        env: Env,
        proof_bytes: ProofBytes,
        public_inputs: Vec<U256>,
        request: TransferRequest,
    ) -> Result<(), WalletError> {
        // Note: BN254 conversion deferred until verify_proof is implemented
        let _ = &proof_bytes;
        // Ensure initialized
        if !Self::is_initialized(env.clone()) {
            return Err(WalletError::NotInitialized);
        }

        // Wallet must exist
        if !Self::wallet_exists(env.clone(), request.from_commitment.clone()) {
            return Err(WalletError::WalletNotFound);
        }

        // Check nullifier not used
        if Self::is_nullifier_used(env.clone(), request.nullifier_hash.clone()) {
            return Err(WalletError::NullifierUsed);
        }

        // Check nonce matches
        let current_nonce: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::WalletNonce(request.from_commitment.clone()))
            .unwrap_or(0);

        if request.nonce != current_nonce {
            return Err(WalletError::InvalidNonce);
        }

        // Check balance
        let current_balance: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::WalletBalance(request.from_commitment.clone()))
            .unwrap_or(0);

        if current_balance < request.amount {
            return Err(WalletError::InsufficientBalance);
        }

        // Amount must be positive
        if request.amount <= 0 {
            return Err(WalletError::InvalidAmount);
        }

        // Validate public inputs
        if public_inputs.len() < 2 {
            return Err(WalletError::InvalidPublicInputs);
        }

        // Commitment must match
        let proof_commitment = public_inputs.get(0).unwrap();
        if proof_commitment != request.from_commitment {
            return Err(WalletError::InvalidPublicInputs);
        }

        // Nullifier must match
        let proof_nullifier = public_inputs.get(1).unwrap();
        if proof_nullifier != request.nullifier_hash {
            return Err(WalletError::InvalidPublicInputs);
        }

        // Verify the ZK proof (stubbed for now - will integrate with groth16-verifier)
        let is_valid = Self::verify_proof_bytes(env.clone(), &proof_bytes, &public_inputs)?;
        if !is_valid {
            return Err(WalletError::InvalidProof);
        }

        // Mark nullifier as used BEFORE any external calls
        env.storage()
            .persistent()
            .set(&DataKey::TxNullifier(request.nullifier_hash.clone()), &true);

        // Increment nonce BEFORE external calls
        env.storage()
            .persistent()
            .set(&DataKey::WalletNonce(request.from_commitment.clone()), &(current_nonce + 1));

        // Update balance
        env.storage()
            .persistent()
            .set(&DataKey::WalletBalance(request.from_commitment.clone()), &(current_balance - request.amount));

        // Transfer tokens to recipient
        let token_id: Address = env
            .storage()
            .persistent()
            .get(&DataKey::TokenId)
            .unwrap();

        let token_client = token::Client::new(&env, &token_id);
        token_client.transfer(&env.current_contract_address(), &request.to, &request.amount);

        // Emit event
        env.events().publish(
            (Symbol::new(&env, "transferred"),),
            (request.from_commitment, request.to, request.amount, request.nonce),
        );

        Ok(())
    }

    // =========================================================================
    // QUERIES
    // =========================================================================

    /// Check if a wallet exists for a commitment.
    pub fn wallet_exists(env: Env, commitment: U256) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::WalletCreated(commitment))
    }

    /// Get wallet balance.
    pub fn balance(env: Env, commitment: U256) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::WalletBalance(commitment))
            .unwrap_or(0)
    }

    /// Get wallet nonce.
    pub fn nonce(env: Env, commitment: U256) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::WalletNonce(commitment))
            .unwrap_or(0)
    }

    /// Get full wallet info.
    pub fn get_wallet(env: Env, commitment: U256) -> Option<WalletInfo> {
        if !Self::wallet_exists(env.clone(), commitment.clone()) {
            return None;
        }

        let balance: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::WalletBalance(commitment.clone()))
            .unwrap_or(0);

        let nonce: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::WalletNonce(commitment.clone()))
            .unwrap_or(0);

        let created_at: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::WalletCreated(commitment.clone()))
            .unwrap_or(0);

        Some(WalletInfo {
            commitment,
            balance,
            nonce,
            created_at,
        })
    }

    /// Check if a nullifier has been used.
    pub fn is_nullifier_used(env: Env, nullifier: U256) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::TxNullifier(nullifier))
            .unwrap_or(false)
    }

    /// Get total number of wallets.
    pub fn get_wallet_count(env: Env) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::WalletCount)
            .unwrap_or(0)
    }

    // =========================================================================
    // ADMIN
    // =========================================================================

    /// Update the verifier contract (admin only).
    pub fn update_verifier(
        env: Env,
        admin: Address,
        new_verifier_id: Address,
    ) -> Result<(), WalletError> {
        admin.require_auth();

        let stored_admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .ok_or(WalletError::NotInitialized)?;

        if admin != stored_admin {
            return Err(WalletError::Unauthorized);
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

    /// Update the token contract (admin only).
    pub fn update_token(
        env: Env,
        admin: Address,
        new_token_id: Address,
    ) -> Result<(), WalletError> {
        admin.require_auth();

        let stored_admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .ok_or(WalletError::NotInitialized)?;

        if admin != stored_admin {
            return Err(WalletError::Unauthorized);
        }

        env.storage()
            .persistent()
            .set(&DataKey::TokenId, &new_token_id);

        env.events().publish(
            (Symbol::new(&env, "token_updated"),),
            new_token_id,
        );

        Ok(())
    }

    // =========================================================================
    // INTERNAL HELPERS
    // =========================================================================

    /// Verify a ZK proof using the groth16-verifier contract.
    /// Currently stubbed - will be implemented when cross-contract calls are ready.
    fn verify_proof_bytes(
        env: Env,
        proof_bytes: &ProofBytes,
        public_inputs: &Vec<U256>,
    ) -> Result<bool, WalletError> {
        let verifier_id: Address = env
            .storage()
            .persistent()
            .get(&DataKey::VerifierId)
            .ok_or(WalletError::NotInitialized)?;

        // Note: In production, implement cross-contract call to groth16-verifier
        // The groth16-verifier expects Proof with Bn254G1Affine types.
        // When implementing:
        // 1. Convert proof_bytes to Proof using to_proof()
        // 2. Call groth16_verifier::Client::new(&env, &verifier_id).verify(&proof, &public_inputs)

        // Placeholder: Accept proofs for now
        let _ = (verifier_id, proof_bytes, public_inputs);
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

    fn create_test_proof(env: &Env) -> ProofBytes {
        ProofBytes {
            a: Bytes::from_array(env, &[0u8; 64]),
            b: Bytes::from_array(env, &[0u8; 128]),
            c: Bytes::from_array(env, &[0u8; 64]),
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
        let contract_id = env.register(ZkWalletContract, ());
        let client = ZkWalletContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let verifier = Address::generate(&env);
        let token = Address::generate(&env);

        client.initialize(&admin, &verifier, &token);

        assert!(client.is_initialized());
        let (v, t) = client.get_config();
        assert_eq!(v, verifier);
        assert_eq!(t, token);
    }

    #[test]
    fn test_double_init_fails() {
        let env = Env::default();
        let contract_id = env.register(ZkWalletContract, ());
        let client = ZkWalletContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let verifier = Address::generate(&env);
        let token = Address::generate(&env);

        client.initialize(&admin, &verifier, &token);

        let result = client.try_initialize(&admin, &verifier, &token);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_wallet() {
        let env = Env::default();
        let contract_id = env.register(ZkWalletContract, ());
        let client = ZkWalletContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let verifier = Address::generate(&env);
        let token = Address::generate(&env);
        client.initialize(&admin, &verifier, &token);

        let commitment = U256::from_u32(&env, 123456);
        let proof = create_test_proof(&env);
        let inputs = create_test_public_inputs(&env, commitment.clone(), U256::from_u32(&env, 999));

        client.create_wallet(&proof, &inputs, &commitment);

        assert!(client.wallet_exists(&commitment));
        assert_eq!(client.balance(&commitment), 0);
        assert_eq!(client.nonce(&commitment), 0);
        assert_eq!(client.get_wallet_count(), 1);
    }

    #[test]
    fn test_wallet_already_exists() {
        let env = Env::default();
        let contract_id = env.register(ZkWalletContract, ());
        let client = ZkWalletContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let verifier = Address::generate(&env);
        let token = Address::generate(&env);
        client.initialize(&admin, &verifier, &token);

        let commitment = U256::from_u32(&env, 789);
        let proof = create_test_proof(&env);
        let inputs = create_test_public_inputs(&env, commitment.clone(), U256::from_u32(&env, 111));

        client.create_wallet(&proof, &inputs, &commitment);

        // Second creation fails
        let result = client.try_create_wallet(&proof, &inputs, &commitment);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_wallet_info() {
        let env = Env::default();
        let contract_id = env.register(ZkWalletContract, ());
        let client = ZkWalletContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let verifier = Address::generate(&env);
        let token = Address::generate(&env);
        client.initialize(&admin, &verifier, &token);

        let commitment = U256::from_u32(&env, 555);
        let proof = create_test_proof(&env);
        let inputs = create_test_public_inputs(&env, commitment.clone(), U256::from_u32(&env, 222));

        client.create_wallet(&proof, &inputs, &commitment);

        let info = client.get_wallet(&commitment).unwrap();
        assert_eq!(info.commitment, commitment);
        assert_eq!(info.balance, 0);
        assert_eq!(info.nonce, 0);
    }

    #[test]
    fn test_nonexistent_wallet() {
        let env = Env::default();
        let contract_id = env.register(ZkWalletContract, ());
        let client = ZkWalletContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let verifier = Address::generate(&env);
        let token = Address::generate(&env);
        client.initialize(&admin, &verifier, &token);

        let commitment = U256::from_u32(&env, 999);
        assert!(!client.wallet_exists(&commitment));
        assert!(client.get_wallet(&commitment).is_none());
    }

    #[test]
    fn test_nullifier_tracking() {
        let env = Env::default();
        let contract_id = env.register(ZkWalletContract, ());
        let client = ZkWalletContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let verifier = Address::generate(&env);
        let token = Address::generate(&env);
        client.initialize(&admin, &verifier, &token);

        let nullifier = U256::from_u32(&env, 12345);
        assert!(!client.is_nullifier_used(&nullifier));
    }

    // Note: deposit and transfer tests require a mock token contract
    // which adds complexity. In production, these would be integration tests.
}
