/**
 * Mini wallet — client-side Stellar account management.
 *
 * Uses the Stellar SDK UMD bundle (loaded via <script> tag as global).
 * Keypair stored in localStorage keyed by identityField so
 * the same ZK identity always maps to the same wallet.
 */

// Stellar SDK loaded via script tag — declared globally
declare const StellarSdk: any;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface WalletKeypair {
  publicKey: string;
  secretKey: string;
}

export interface WalletBalance {
  xlm: string;
  funded: boolean;
}

export interface SendResult {
  hash: string;
  ledger: number;
  stellarExpertUrl: string;
}

// ---------------------------------------------------------------------------
// Keypair Management
// ---------------------------------------------------------------------------

const STORAGE_PREFIX = 'zkwallet:';

/**
 * Derive a deterministic Stellar keypair from the identity field.
 *
 * Same Google account (or passkey) → same identityField → same wallet,
 * regardless of which device or browser is used.
 *
 * Derivation: SHA-256("stellar-zklogin-demo:wallet-seed:" + identityField)
 * → 32-byte Ed25519 seed → Stellar Keypair.
 *
 * The domain separator ensures the raw identity hash is never used directly
 * as a secret key.
 */
export async function generateOrLoadKeypair(identityField: string): Promise<WalletKeypair> {
  const encoder = new TextEncoder();
  const material = encoder.encode(`stellar-zklogin-demo:wallet-seed:${identityField}`);
  const digest = await crypto.subtle.digest('SHA-256', material);
  const seed = new Uint8Array(digest);

  const kp = StellarSdk.Keypair.fromRawEd25519Seed(seed);
  const wallet: WalletKeypair = {
    publicKey: kp.publicKey(),
    secretKey: kp.secret(),
  };

  // Cache in localStorage for quick access on return visits
  const key = STORAGE_PREFIX + identityField;
  localStorage.setItem(key, JSON.stringify(wallet));
  return wallet;
}

// ---------------------------------------------------------------------------
// Friendbot Funding (testnet only)
// ---------------------------------------------------------------------------

export async function fundWithFriendbot(publicKey: string): Promise<boolean> {
  const resp = await fetch(
    `https://friendbot.stellar.org?addr=${encodeURIComponent(publicKey)}`,
  );

  if (resp.ok) return true;

  // Already funded returns 400 with "createAccountAlreadyExist"
  const body = await resp.text();
  if (body.includes('createAccountAlreadyExist') || body.includes('op_already_exists')) {
    return true; // Already funded — not an error
  }

  throw new Error(`Friendbot failed: ${resp.status} ${body.substring(0, 200)}`);
}

// ---------------------------------------------------------------------------
// Balance
// ---------------------------------------------------------------------------

function horizonUrl(network: string): string {
  return network === 'mainnet'
    ? 'https://horizon.stellar.org'
    : 'https://horizon-testnet.stellar.org';
}

function explorerBase(network: string): string {
  return network === 'mainnet'
    ? 'https://stellar.expert/explorer/public'
    : 'https://stellar.expert/explorer/testnet';
}

export async function fetchBalance(
  publicKey: string,
  network: string,
): Promise<WalletBalance> {
  const resp = await fetch(`${horizonUrl(network)}/accounts/${publicKey}`);

  if (resp.status === 404) {
    return { xlm: '0', funded: false };
  }
  if (!resp.ok) {
    throw new Error(`Horizon error: ${resp.status}`);
  }

  const data = await resp.json();
  const native = data.balances.find(
    (b: any) => b.asset_type === 'native',
  );
  return {
    xlm: native ? native.balance : '0',
    funded: true,
  };
}

// ---------------------------------------------------------------------------
// Send Payment
// ---------------------------------------------------------------------------

export async function sendPayment(
  secretKey: string,
  destination: string,
  amount: string,
  network: string,
): Promise<SendResult> {
  // Validate destination address
  if (!destination.startsWith('G') || destination.length !== 56) {
    throw new Error('Invalid destination address (must be a G... Stellar address)');
  }

  const amountNum = parseFloat(amount);
  if (isNaN(amountNum) || amountNum <= 0) {
    throw new Error('Amount must be a positive number');
  }

  const server = new StellarSdk.Horizon.Server(horizonUrl(network));
  const keypair = StellarSdk.Keypair.fromSecret(secretKey);
  const networkPassphrase = network === 'mainnet'
    ? StellarSdk.Networks.PUBLIC
    : StellarSdk.Networks.TESTNET;

  // Load source account (gets sequence number)
  const sourceAccount = await server.loadAccount(keypair.publicKey());

  // Build transaction
  const tx = new StellarSdk.TransactionBuilder(sourceAccount, {
    fee: '100',
    networkPassphrase,
  })
    .addOperation(
      StellarSdk.Operation.payment({
        destination,
        asset: StellarSdk.Asset.native(),
        amount: amountNum.toFixed(7),
      }),
    )
    .setTimeout(30)
    .build();

  // Sign
  tx.sign(keypair);

  // Submit
  const result = await server.submitTransaction(tx);

  return {
    hash: result.hash,
    ledger: result.ledger,
    stellarExpertUrl: `${explorerBase(network)}/tx/${result.hash}`,
  };
}
