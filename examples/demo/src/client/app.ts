/**
 * Client-side orchestration for ZK Login demo.
 *
 * Bundled to public/app.js via esbuild (IIFE format).
 * No framework — vanilla JS for maximum readability.
 *
 * Dual-mode: Google Sign-In OR Passkey registration.
 * Steps 3-5 are identical regardless of identity provider —
 * the circuit only cares about the identityField (a BN254 field element).
 *
 * Flow (Google):
 *   1. Google Sign-In → idToken
 *   2. POST /api/auth → identityHash, identityField
 *   3-5. Attestation → Proof → Verify (shared)
 *
 * Flow (Passkey):
 *   1. navigator.credentials.create() → credential
 *   2. POST /api/passkey/register → identityHash, identityField (Steps 1+2 collapse)
 *   3-5. Attestation → Proof → Verify (shared)
 */

import { registerPasskey } from './passkey';
import {
  generateOrLoadKeypair,
  fundWithFriendbot,
  fetchBalance,
  sendPayment,
} from './wallet';

// snarkjs is loaded via script tag — declared globally
declare const snarkjs: {
  groth16: {
    fullProve(
      input: Record<string, string>,
      wasmFile: string,
      zkeyFile: string,
    ): Promise<{ proof: any; publicSignals: string[] }>;
    verify(
      vk: any,
      publicSignals: string[],
      proof: any,
    ): Promise<boolean>;
  };
};

// Google Identity Services callback type
declare const google: {
  accounts: {
    id: {
      initialize(config: any): void;
      renderButton(el: HTMLElement, config: any): void;
    };
  };
};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

type Provider = 'google' | 'passkey';

interface AppState {
  provider: Provider;
  idToken: string | null;
  email: string | null;
  credentialId: string | null;
  identityHash: string | null;
  identityField: string | null;
  attestation: any | null;
  proof: any | null;
  publicSignals: string[] | null;
  walletPublicKey: string | null;
  walletSecretKey: string | null;
  walletBalance: string | null;
  walletFunded: boolean;
}

const state: AppState = {
  provider: 'google',
  idToken: null,
  email: null,
  credentialId: null,
  identityHash: null,
  identityField: null,
  attestation: null,
  proof: null,
  publicSignals: null,
  walletPublicKey: null,
  walletSecretKey: null,
  walletBalance: null,
  walletFunded: false,
};

let balanceInterval: ReturnType<typeof setInterval> | null = null;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function $(id: string): HTMLElement {
  return document.getElementById(id)!;
}

function show(id: string): void {
  $(id).style.display = '';
}

function hide(id: string): void {
  $(id).style.display = 'none';
}

// ---------------------------------------------------------------------------
// Phone Stepper — step metadata and panel switching
// ---------------------------------------------------------------------------

const PANEL_IDS = ['chapter-1', 'step-2', 'chapter-2', 'chapter-3', 'chapter-4', 'chapter-5'];

const STEP_META: Record<string, { title: string; badge: string; badgeClass: string }> = {
  'chapter-1': { title: 'Identity Provider', badge: 'OFF-CHAIN', badgeClass: 'offchain' },
  'step-2':    { title: 'Identity Hash', badge: 'OFF-CHAIN', badgeClass: 'offchain' },
  'chapter-2': { title: 'Server Attestation', badge: 'OFF-CHAIN', badgeClass: 'offchain' },
  'chapter-3': { title: 'ZK Proof Generation', badge: 'CLIENT', badgeClass: 'client' },
  'chapter-4': { title: 'Verification', badge: 'ON-CHAIN', badgeClass: 'onchain' },
  'chapter-5': { title: 'ZK Wallet', badge: 'TESTNET', badgeClass: 'wallet' },
};

const completedSteps = new Set<string>();

function isTryStepper(): boolean {
  return document.querySelector('.try-scene') !== null;
}

function activateStep(stepId: string): void {
  const el = $(stepId);
  el.classList.add('active');

  if (!isTryStepper()) {
    el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    return;
  }

  // Mark the previous active step as completed
  const currentActive = document.querySelector('.stepper-step.active') as HTMLElement | null;
  if (currentActive && currentActive.dataset.step !== stepId) {
    completedSteps.add(currentActive.dataset.step!);
  }

  // Show only the target panel (except chapter-5 which show() controls separately)
  PANEL_IDS.forEach((id) => {
    const panel = document.getElementById(id);
    if (!panel) return;
    if (id === stepId) {
      panel.style.display = '';
    } else if (id !== 'chapter-5' || stepId === 'chapter-5') {
      if (id === 'chapter-5' && stepId !== 'chapter-5') return;
      panel.style.display = 'none';
    }
  });

  // Update stepper dots
  document.querySelectorAll('.stepper-step').forEach((dot) => {
    const dotStep = (dot as HTMLElement).dataset.step!;
    dot.classList.remove('active', 'completed');
    if (dotStep === stepId) {
      dot.classList.add('active');
    } else if (completedSteps.has(dotStep)) {
      dot.classList.add('completed');
    }
  });

  // Update header
  const meta = STEP_META[stepId];
  if (meta) {
    const titleEl = document.getElementById('try-header-title');
    const badgeEl = document.getElementById('try-header-badge');
    if (titleEl) titleEl.textContent = meta.title;
    if (badgeEl) {
      badgeEl.textContent = meta.badge;
      badgeEl.className = `trust-badge ${meta.badgeClass}`;
    }
  }

  // Scroll content to top
  const content = document.getElementById('try-content');
  if (content) content.scrollTop = 0;
}

function enableBtn(id: string): void {
  ($(id) as HTMLButtonElement).disabled = false;
}

function disableBtn(id: string): void {
  ($(id) as HTMLButtonElement).disabled = true;
}

function decodeJwtPayload(token: string): any {
  const payload = token.split('.')[1];
  return JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
}

/** Generate a 31-byte random field element (matches server-side randomField). */
function randomField(): string {
  const bytes = new Uint8Array(31);
  crypto.getRandomValues(bytes);
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return BigInt('0x' + hex).toString();
}

async function apiPost(url: string, body: any): Promise<any> {
  const resp = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ error: resp.statusText }));
    throw new Error(err.error || err.details || `HTTP ${resp.status}`);
  }
  return resp.json();
}

// ---------------------------------------------------------------------------
// Provider Switching
// ---------------------------------------------------------------------------

/** Set provider and update step-2 visibility (called when user authenticates). */
function setProvider(provider: Provider): void {
  state.provider = provider;

  // Update Step 2 visibility based on provider
  const step2 = document.getElementById('step-2');
  if (step2) {
    step2.style.display = provider === 'passkey' ? 'none' : '';
  }

  // Also hide/show the step-2 stepper dot + connector
  const step2Stepper = document.querySelector('.stepper-step[data-step="step-2"]') as HTMLElement | null;
  if (step2Stepper) {
    step2Stepper.style.display = provider === 'passkey' ? 'none' : '';
    const prev = step2Stepper.previousElementSibling as HTMLElement | null;
    if (prev?.classList.contains('stepper-connector')) {
      prev.style.display = provider === 'passkey' ? 'none' : '';
    }
  }
}

// ---------------------------------------------------------------------------
// Step 1: Google Sign-In
// ---------------------------------------------------------------------------

function initGoogleSignIn(): void {
  const clientId = (window as any).__GOOGLE_CLIENT_ID__;
  if (!clientId) {
    $('google-signin-btn').innerHTML =
      '<p class="error">GOOGLE_CLIENT_ID not configured</p>';
    return;
  }

  google.accounts.id.initialize({
    client_id: clientId,
    callback: handleCredentialResponse,
  });

  google.accounts.id.renderButton($('google-signin-btn'), {
    theme: 'outline',
    size: 'large',
    text: 'signin_with',
    width: 300,
  });
}

function handleCredentialResponse(response: { credential: string }): void {
  state.idToken = response.credential;
  setProvider('google');
  console.log('[Step 1] Got idToken:', state.idToken.substring(0, 50) + '...');

  // Show result
  const decoded = decodeJwtPayload(state.idToken);
  $('step-1-jwt').textContent = state.idToken.substring(0, 80) + '... (' + state.idToken.length + ' chars)';
  $('step-1-decoded').textContent = JSON.stringify({
    email: decoded.email,
    sub: decoded.sub,
    email_verified: decoded.email_verified,
    aud: decoded.aud?.substring(0, 30) + '...',
    iss: decoded.iss,
  }, null, 2);
  show('step-1-result');

  // Enable next step (Google flow goes to Step 1b: identity hash)
  activateStep('step-2');
  enableBtn('btn-identity');
}

// ---------------------------------------------------------------------------
// Step 1 (alt): Passkey Registration
// ---------------------------------------------------------------------------

async function handlePasskeyRegister(): Promise<void> {
  disableBtn('btn-passkey-register');
  show('spinner-passkey');

  try {
    const result = await registerPasskey();

    setProvider('passkey');
    state.identityHash = result.identityHash;
    state.identityField = result.identityField;
    state.credentialId = result.credentialId;

    console.log('[Step 1+2] Passkey registered');
    console.log('[Step 1+2] credentialId:', state.credentialId);
    console.log('[Step 1+2] identityField:', state.identityField);

    // Show passkey result
    $('passkey-credential-id').textContent = state.credentialId;
    $('passkey-identity-hash').textContent = state.identityHash;
    $('passkey-identity-field').textContent = state.identityField;
    show('step-1-passkey-result');

    // Passkey flow skips Step 2 — jump straight to Chapter 2 (attestation)
    activateStep('chapter-2');
    enableBtn('btn-attestation');
  } catch (err: any) {
    const resultEl = $('step-1-passkey-result');
    resultEl.innerHTML = `<div class="error">${err.message}</div>`;
    show('step-1-passkey-result');
    enableBtn('btn-passkey-register');
  } finally {
    hide('spinner-passkey');
  }
}

// ---------------------------------------------------------------------------
// Step 2: Identity Hash (Google flow only)
// ---------------------------------------------------------------------------

async function handleIdentityHash(): Promise<void> {
  disableBtn('btn-identity');
  show('spinner-2');

  try {
    const result = await apiPost('/api/auth', { idToken: state.idToken });
    state.identityHash = result.identityHash;
    state.identityField = result.identityField;
    state.email = result.email;

    console.log('[Step 2] identityHash:', state.identityHash);
    console.log('[Step 2] identityField:', state.identityField);

    $('step-2-input').textContent = `gmail:${state.email}:<sub>:verified:true`;
    $('step-2-hash').textContent = state.identityHash!;
    $('step-2-field').textContent = state.identityField!;
    show('step-2-result');

    activateStep('chapter-2');
    enableBtn('btn-attestation');
  } catch (err: any) {
    $('step-2-result').innerHTML = `<div class="error">${err.message}</div>`;
    show('step-2-result');
    enableBtn('btn-identity');
  } finally {
    hide('spinner-2');
  }
}

// ---------------------------------------------------------------------------
// Step 3: Server Attestation
// ---------------------------------------------------------------------------

async function handleAttestation(): Promise<void> {
  disableBtn('btn-attestation');
  show('spinner-3');

  try {
    const result = await apiPost('/api/attestation', {
      identityField: state.identityField,
    });

    state.attestation = result.attestation;
    console.log('[Step 3] attestation:', state.attestation);

    $('step-3-data').textContent = JSON.stringify({
      attestationHash: state.attestation.attestationHash,
      serverPubCommitment: state.attestation.serverPubCommitment,
      timestamp: state.attestation.timestamp,
      nonce: state.attestation.nonce.substring(0, 20) + '...',
      serverSecretField: state.attestation.serverSecretField.substring(0, 20) + '...',
      expiresAt: new Date(state.attestation.expiresAt * 1000).toISOString(),
    }, null, 2);
    show('step-3-result');

    activateStep('chapter-3');
    enableBtn('btn-prove');
  } catch (err: any) {
    $('step-3-result').innerHTML = `<div class="error">${err.message}</div>`;
    show('step-3-result');
    enableBtn('btn-attestation');
  } finally {
    hide('spinner-3');
  }
}

// ---------------------------------------------------------------------------
// Step 4: ZK Proof Generation
// ---------------------------------------------------------------------------

async function handleProveGeneration(): Promise<void> {
  disableBtn('btn-prove');
  show('spinner-4');
  $('prove-time').textContent = 'Generating proof...';

  const start = performance.now();

  try {
    // Build circuit inputs
    const blinding = randomField();
    const nullifierSecret = randomField();
    const currentTimestamp = Math.floor(Date.now() / 1000).toString();

    // v1 circuit uses signal name "gmailHash" (pre-rename)
    const circuitInputs: Record<string, string> = {
      gmailHash: state.identityField!,         // v1 signal name
      blinding,
      nullifierSecret,
      attestationTimestamp: state.attestation.timestamp.toString(),
      serverNonce: state.attestation.nonce,
      serverPubCommitment: state.attestation.serverPubCommitment,
      currentTimestamp,
      maxAttestationAge: '86400',
      attestationHash: state.attestation.attestationHash,
    };

    console.log('[Step 4] Circuit inputs:', circuitInputs);

    // Generate proof using snarkjs in the browser
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      circuitInputs,
      '/circuits/gmail_attestation.wasm',
      '/circuits/gmail_attestation.zkey',
    );

    const elapsed = ((performance.now() - start) / 1000).toFixed(1);

    state.proof = proof;
    state.publicSignals = publicSignals;

    console.log('[Step 4] Proof generated in', elapsed, 'seconds');
    console.log('[Step 4] Public signals:', publicSignals);

    $('prove-time').textContent = `${elapsed}s`;

    // Show circuit inputs (redacted secrets)
    const displayInputs = { ...circuitInputs };
    displayInputs.blinding = blinding.substring(0, 20) + '... (random, private)';
    displayInputs.nullifierSecret = nullifierSecret.substring(0, 20) + '... (random, private)';
    $('step-4-inputs').textContent = JSON.stringify(displayInputs, null, 2);

    // Show public signals with labels
    $('step-4-signals').textContent = JSON.stringify({
      'commitment (Poseidon(identity, blinding))': publicSignals[0],
      'nullifierHash (Poseidon(identity, nullifierSecret))': publicSignals[1],
      'currentTimestamp': publicSignals[2],
      'maxAttestationAge': publicSignals[3],
      'serverPubCommitment': publicSignals[4],
    }, null, 2);

    // Show proof (compact)
    $('step-4-proof').textContent = JSON.stringify({
      protocol: proof.protocol,
      curve: proof.curve,
      pi_a: [proof.pi_a[0].substring(0, 20) + '...', proof.pi_a[1].substring(0, 20) + '...'],
      pi_b: '[[...], [...]]',
      pi_c: [proof.pi_c[0].substring(0, 20) + '...', proof.pi_c[1].substring(0, 20) + '...'],
    }, null, 2);
    show('step-4-result');

    // Enable verification chapter
    activateStep('chapter-4');
    enableBtn('btn-verify-offchain');
    enableBtn('btn-verify-onchain');
  } catch (err: any) {
    $('prove-time').textContent = 'Failed';
    $('step-4-result').innerHTML = `<div class="error">${err.message}</div>`;
    show('step-4-result');
    enableBtn('btn-prove');
  } finally {
    hide('spinner-4');
  }
}

// ---------------------------------------------------------------------------
// Step 5a: Off-Chain Verification (browser-side snarkjs)
// ---------------------------------------------------------------------------

async function handleVerifyOffchain(): Promise<void> {
  disableBtn('btn-verify-offchain');
  show('spinner-5a');

  const start = performance.now();

  try {
    // Load verification key from static assets
    const vkResponse = await fetch('/circuits/verification_key.json');
    const vk = await vkResponse.json();

    // Verify proof using snarkjs (real BN254 pairing check)
    const verified = await snarkjs.groth16.verify(vk, state.publicSignals!, state.proof);

    const elapsed = ((performance.now() - start)).toFixed(0);
    $('verify-offchain-time').textContent = `${elapsed}ms`;

    // Show verdict
    const verdictEl = $('step-5a-verdict');
    if (verified) {
      verdictEl.className = 'verdict verified';
      verdictEl.innerHTML = 'VERIFIED &mdash; Proof is mathematically valid (BN254 pairing check passed)';
    } else {
      verdictEl.className = 'verdict failed';
      verdictEl.textContent = 'FAILED — Proof verification failed';
    }

    // Show parsed public signals
    const [commitment, nullifierHash, currentTimestamp, maxAge, serverCommitment] = state.publicSignals!;
    $('step-5a-parsed').textContent = JSON.stringify({
      commitment: commitment.substring(0, 30) + '...',
      nullifierHash: nullifierHash.substring(0, 30) + '...',
      currentTimestamp: `${currentTimestamp} (${new Date(Number(currentTimestamp) * 1000).toISOString()})`,
      maxAttestationAge: `${maxAge} seconds (${Number(maxAge) / 3600}h)`,
      serverPubCommitment: serverCommitment.substring(0, 30) + '...',
    }, null, 2);

    show('step-5a-result');
    console.log('[Step 5a] Off-chain verification:', verified, `(${elapsed}ms)`);
  } catch (err: any) {
    $('step-5a-result').innerHTML = `<div class="error">${err.message}</div>`;
    show('step-5a-result');
    enableBtn('btn-verify-offchain');
  } finally {
    hide('spinner-5a');
  }
}

// ---------------------------------------------------------------------------
// Step 5b: On-Chain Submission
// ---------------------------------------------------------------------------

async function handleVerifyOnchain(): Promise<void> {
  disableBtn('btn-verify-onchain');
  show('spinner-5b');

  try {
    const result = await apiPost('/api/verify/onchain', {
      proof: state.proof,
      publicSignals: state.publicSignals,
    });

    console.log('[Step 5b] On-chain result:', result);

    $('step-5b-data').textContent = JSON.stringify(result, null, 2);

    if (result.stellarExpertUrl) {
      $('step-5b-link').innerHTML =
        `<a href="${result.stellarExpertUrl}" target="_blank" class="btn btn-link">` +
        `View on Stellar Expert &rarr;</a>`;
    }

    show('step-5b-result');

    // Activate wallet after successful on-chain verification
    if (result.success) {
      await initWallet();
    }
  } catch (err: any) {
    $('step-5b-data').textContent = JSON.stringify({ error: err.message }, null, 2);
    show('step-5b-result');
    enableBtn('btn-verify-onchain');
  } finally {
    hide('spinner-5b');
  }
}

// ---------------------------------------------------------------------------
// Step 6: ZK Wallet
// ---------------------------------------------------------------------------

async function initWallet(): Promise<void> {
  if (!state.identityField) return;

  const wallet = await generateOrLoadKeypair(state.identityField);
  state.walletPublicKey = wallet.publicKey;
  state.walletSecretKey = wallet.secretKey;

  // Display address
  $('wallet-address').textContent = wallet.publicKey;
  $('wallet-address-short').textContent =
    wallet.publicKey.substring(0, 8) + '...' + wallet.publicKey.substring(48);

  activateStep('chapter-5');
  show('chapter-5');

  // Initial balance check
  handleRefreshBalance();

  // Auto-refresh every 10s
  if (balanceInterval) clearInterval(balanceInterval);
  balanceInterval = setInterval(handleRefreshBalance, 10000);

  console.log('[Step 6] Wallet initialized:', wallet.publicKey);
}

async function handleFundWallet(): Promise<void> {
  disableBtn('btn-fund');
  show('spinner-fund');

  try {
    await fundWithFriendbot(state.walletPublicKey!);
    console.log('[Step 6] Funded via Friendbot');

    // Refresh balance after funding
    await handleRefreshBalance();
  } catch (err: any) {
    $('wallet-status').textContent = `Fund error: ${err.message}`;
    $('wallet-status').className = 'wallet-status error';
  } finally {
    hide('spinner-fund');
    enableBtn('btn-fund');
  }
}

async function handleRefreshBalance(): Promise<void> {
  if (!state.walletPublicKey) return;

  try {
    const balance = await fetchBalance(state.walletPublicKey, 'testnet');
    state.walletBalance = balance.xlm;
    state.walletFunded = balance.funded;

    $('wallet-balance-value').textContent = balance.funded
      ? `${parseFloat(balance.xlm).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 7 })} XLM`
      : 'Not funded';
    $('wallet-balance-value').className = balance.funded
      ? 'wallet-balance-amount'
      : 'wallet-balance-amount unfunded';

    // Show/hide fund button based on funding status
    const fundSection = document.getElementById('wallet-fund-section');
    if (fundSection) {
      fundSection.style.display = balance.funded ? 'none' : '';
    }

    // Enable send form only if funded
    const sendBtn = document.getElementById('btn-send') as HTMLButtonElement;
    if (sendBtn) sendBtn.disabled = !balance.funded;
  } catch (err: any) {
    console.warn('[Step 6] Balance check failed:', err.message);
  }
}

async function handleSendPayment(): Promise<void> {
  const destInput = document.getElementById('send-destination') as HTMLInputElement;
  const amountInput = document.getElementById('send-amount') as HTMLInputElement;
  const destination = destInput.value.trim();
  const amount = amountInput.value.trim();

  if (!destination || !amount) {
    $('send-result').textContent = 'Enter destination and amount';
    $('send-result').className = 'wallet-status error';
    show('send-result');
    return;
  }

  disableBtn('btn-send');
  show('spinner-send');
  hide('send-result');

  try {
    const result = await sendPayment(
      state.walletSecretKey!,
      destination,
      amount,
      'testnet',
    );

    console.log('[Step 6] Payment sent:', result.hash);

    $('send-result').innerHTML =
      `<div class="send-success">` +
      `<span>Sent ${amount} XLM</span>` +
      `<a href="${result.stellarExpertUrl}" target="_blank" class="btn btn-link">View TX &rarr;</a>` +
      `</div>`;
    $('send-result').className = 'wallet-status';
    show('send-result');

    // Clear inputs
    destInput.value = '';
    amountInput.value = '';

    // Refresh balance
    await handleRefreshBalance();
  } catch (err: any) {
    $('send-result').textContent = `Send failed: ${err.message}`;
    $('send-result').className = 'wallet-status error';
    show('send-result');
  } finally {
    hide('spinner-send');
    enableBtn('btn-send');
  }
}

function handleCopyAddress(): void {
  if (!state.walletPublicKey) return;
  navigator.clipboard.writeText(state.walletPublicKey).then(() => {
    const btn = $('btn-copy-address');
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
  });
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

function init(): void {
  // Passkey button
  const passkeyBtn = document.getElementById('btn-passkey-register');
  if (passkeyBtn) {
    passkeyBtn.addEventListener('click', handlePasskeyRegister);
  }

  // Wait for Google Identity Services to load (non-blocking for passkey flow)
  const waitForGoogle = setInterval(() => {
    if (typeof google !== 'undefined' && google.accounts) {
      clearInterval(waitForGoogle);
      initGoogleSignIn();
    }
  }, 100);

  // Bind button handlers (shared steps)
  $('btn-identity').addEventListener('click', handleIdentityHash);
  $('btn-attestation').addEventListener('click', handleAttestation);
  $('btn-prove').addEventListener('click', handleProveGeneration);
  $('btn-verify-offchain').addEventListener('click', handleVerifyOffchain);
  $('btn-verify-onchain').addEventListener('click', handleVerifyOnchain);

  // Wallet button handlers
  const fundBtn = document.getElementById('btn-fund');
  if (fundBtn) fundBtn.addEventListener('click', handleFundWallet);

  const sendBtn = document.getElementById('btn-send');
  if (sendBtn) sendBtn.addEventListener('click', handleSendPayment);

  const copyBtn = document.getElementById('btn-copy-address');
  if (copyBtn) copyBtn.addEventListener('click', handleCopyAddress);

  const refreshBtn = document.getElementById('btn-refresh-balance');
  if (refreshBtn) refreshBtn.addEventListener('click', handleRefreshBalance);

  // Stepper: hide all panels except chapter-1 on startup
  if (isTryStepper()) {
    PANEL_IDS.forEach((id) => {
      const panel = document.getElementById(id);
      if (panel && id !== 'chapter-1') {
        panel.style.display = 'none';
      }
    });
  }

  console.log('[ZK Login Demo] Initialized (dual-mode: Google + Passkey). Open DevTools to see each step.');
}

// Start when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
