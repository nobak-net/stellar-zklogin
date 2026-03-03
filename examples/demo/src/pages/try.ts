/**
 * Try It page — interactive guided tutorial, full-canvas layout.
 *
 * Full viewport height, stepper bar at top, content fills remaining space.
 * Each step: Learn (always visible) → Do (action) → Result
 * Reuses the same client-side state machine as app.ts.
 */

import { layout } from './layout';

export function tryPage(googleClientId: string): string {
  return layout({
    title: 'Try It',
    activePage: 'try',
    bodyClass: 'page-try',
    headExtra: `
      <script src="https://accounts.google.com/gsi/client" async defer></script>
      <script src="/snarkjs.min.js"></script>
      <script src="/stellar-sdk.min.js"></script>
    `,
    bodyEnd: `
      <script>
        window.__GOOGLE_CLIENT_ID__ = ${JSON.stringify(googleClientId)};
      </script>
      <script src="/app.js"></script>
    `,
    content: `
    <div class="try-scene">

      <!-- ========================================= -->
      <!-- Stepper Bar -->
      <!-- ========================================= -->
      <div class="try-stepper">
        <div class="stepper-step active" data-step="chapter-1">
          <div class="stepper-dot">1</div>
          <span class="stepper-label">Identity</span>
        </div>
        <div class="stepper-connector"></div>
        <div class="stepper-step" data-step="step-2">
          <div class="stepper-dot">1b</div>
          <span class="stepper-label">Hash</span>
        </div>
        <div class="stepper-connector"></div>
        <div class="stepper-step" data-step="chapter-2">
          <div class="stepper-dot">2</div>
          <span class="stepper-label">Attest</span>
        </div>
        <div class="stepper-connector"></div>
        <div class="stepper-step" data-step="chapter-3">
          <div class="stepper-dot">3</div>
          <span class="stepper-label">Prove</span>
        </div>
        <div class="stepper-connector"></div>
        <div class="stepper-step" data-step="chapter-4">
          <div class="stepper-dot">4</div>
          <span class="stepper-label">Verify</span>
        </div>
        <div class="stepper-connector"></div>
        <div class="stepper-step" data-step="chapter-5">
          <div class="stepper-dot">5</div>
          <span class="stepper-label">Wallet</span>
        </div>
      </div>

      <!-- ========================================= -->
      <!-- Content Area -->
      <!-- ========================================= -->
      <div class="try-content" id="try-content">
        <!-- Header — updates per step -->
        <div class="try-header">
          <span id="try-header-title" class="try-header-title">Identity Provider</span>
          <span id="try-header-badge" class="trust-badge offchain">OFF-CHAIN</span>
        </div>

        <!-- ========================================= -->
        <!-- Panel 1: Identity -->
        <!-- ========================================= -->
        <div class="try-panel active" id="chapter-1">

          <div class="chapter-learn">
              <p>
                <strong>Google:</strong> Returns a signed JWT (id_token) containing your email, user ID,
                and verification status. The JWT is validated by the server using Google&rsquo;s public keys.
                RSA JWT verification inside a ZK circuit would require ~200K constraints &mdash;
                so we verify it off-chain (same tradeoff as Sui zkLogin).
              </p>
              <p>
                <strong>Passkey:</strong> Creates a WebAuthn credential bound to this origin.
                The credential ID becomes your identity anchor &mdash; no email, no OAuth, no PII.
                The tradeoff: a lost credential = a new identity (unlike Google, which can be recovered from any device).
              </p>
              <p>
                <strong>Identity hash:</strong>
                <code>SHA-256("{provider}:{email}:{userId}:verified:{emailVerified}")</code>
                truncated to 31 bytes (248 bits) to fit the BN254 scalar field.
                The circuit is identity-agnostic &mdash; it only sees a field element.
              </p>
          </div>

          <div class="chapter-do">
            <!-- Google Sign-In -->
            <div id="panel-google" class="provider-panel">
              <div class="step-action">
                <div id="google-signin-btn"></div>
              </div>
              <div class="step-result" id="step-1-result" style="display:none">
                <div class="result-label">Received: idToken (JWT)</div>
                <pre id="step-1-jwt" class="result-data"></pre>
                <div class="result-label">Decoded payload:</div>
                <pre id="step-1-decoded" class="result-data"></pre>
              </div>
            </div>

            <!-- Divider -->
            <div class="login-divider"><span>or</span></div>

            <!-- Passkey -->
            <div id="panel-passkey" class="provider-panel">
              <div class="step-action">
                <button id="btn-passkey-register" class="btn">Register Passkey</button>
                <span class="spinner" id="spinner-passkey" style="display:none"></span>
              </div>
              <div class="step-result" id="step-1-passkey-result" style="display:none">
                <div class="result-row">
                  <span class="result-label">credentialId:</span>
                  <code id="passkey-credential-id" class="mono"></code>
                </div>
                <div class="result-row">
                  <span class="result-label">identityHash (hex):</span>
                  <code id="passkey-identity-hash" class="mono"></code>
                </div>
                <div class="result-row">
                  <span class="result-label">identityField (decimal):</span>
                  <code id="passkey-identity-field" class="mono"></code>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- ========================================= -->
        <!-- Panel 1b: Identity Hash (Google only) -->
        <!-- ========================================= -->
        <div class="try-panel" id="step-2" style="display:none">

          <div class="chapter-learn">
              <p>
                <strong>Formula:</strong> <code>SHA-256("gmail:{email}:{sub}:verified:true")</code>
                produces a 32-byte hash. We take the first 31 bytes (248 bits) and interpret them as a
                big-endian integer. This guarantees the value is less than the BN254 field prime
                (~2<sup>254</sup>), avoiding silent modular reduction.
              </p>
              <p>
                This hash is <strong>deterministic</strong> &mdash; the same Google account always produces
                the same identity hash. But it&rsquo;s <strong>one-way</strong> &mdash; you can&rsquo;t recover
                the email from the hash.
              </p>
          </div>

          <div class="chapter-do">
            <div class="step-action">
              <button id="btn-identity" class="btn" disabled>Compute Identity Hash</button>
              <span class="spinner" id="spinner-2" style="display:none"></span>
            </div>
          </div>

          <div class="chapter-result" id="step-2-result" style="display:none">
            <div class="result-row">
              <span class="result-label">Input:</span>
              <code id="step-2-input"></code>
            </div>
            <div class="result-row">
              <span class="result-label">identityHash (hex):</span>
              <code id="step-2-hash" class="mono"></code>
            </div>
            <div class="result-row">
              <span class="result-label">identityField (decimal):</span>
              <code id="step-2-field" class="mono"></code>
            </div>
          </div>
        </div>

        <!-- ========================================= -->
        <!-- Panel 2: Attestation -->
        <!-- ========================================= -->
        <div class="try-panel" id="chapter-2" style="display:none">

          <div class="chapter-learn">
              <p>
                The server generates a <strong>Poseidon hash</strong> binding your identity to a timestamp
                and random nonce: <code>Poseidon(identityHash, timestamp, nonce)</code>.
              </p>
              <p>
                <strong>Why Poseidon?</strong> SHA-256 costs ~25,000 constraints inside a ZK circuit.
                Poseidon costs ~250 &mdash; a 100x reduction. It&rsquo;s an algebraic hash designed
                specifically for finite field arithmetic.
              </p>
              <p>
                <strong>Trust model:</strong> The server attests &ldquo;I verified this identity at this time.&rdquo;
                The attestation includes a <code>serverPubCommitment</code> = Poseidon(serverSecret, 1),
                which is verified on-chain. A different server = different commitment = proof fails.
              </p>
              <p><a href="/learn#poseidon-attestation" style="color: var(--accent);">Read the full explanation &rarr;</a></p>
          </div>

          <div class="chapter-do" id="step-3">
            <div class="step-action">
              <button id="btn-attestation" class="btn" disabled>Request Attestation</button>
              <span class="spinner" id="spinner-3" style="display:none"></span>
            </div>
          </div>

          <div class="chapter-result" id="step-3-result" style="display:none">
            <pre id="step-3-data" class="result-data"></pre>
          </div>
        </div>

        <!-- ========================================= -->
        <!-- Panel 3: Proof Generation -->
        <!-- ========================================= -->
        <div class="try-panel" id="chapter-3" style="display:none">

          <div class="chapter-learn">
              <p>
                Your browser generates a <strong>Groth16 proof</strong> using the identity attestation circuit
                (2,295 constraints on BN254). The proof is 3 elliptic curve points (A, B, C) = 256 bytes.
              </p>
              <p>
                <strong>Private inputs (never leave your device):</strong> identityHash, blinding,
                nullifierSecret, attestation data, serverPubCommitment.
              </p>
              <p>
                <strong>Public outputs (go on-chain):</strong><br>
                &bull; <code>commitment</code> = Poseidon(identity, blinding) &mdash; hides your identity<br>
                &bull; <code>nullifierHash</code> = Poseidon(identity, nullifierSecret) &mdash; prevents replay
              </p>
              <p>
                The circuit is <strong>identity-agnostic</strong> &mdash; same WASM, zkey, and verification key
                for both Google and passkey providers.
              </p>
              <p><a href="/learn#the-circuit" style="color: var(--accent);">See the full circuit code &rarr;</a></p>
          </div>

          <div class="chapter-do" id="step-4">
            <div class="step-action">
              <button id="btn-prove" class="btn" disabled>Generate Proof</button>
              <span class="spinner" id="spinner-4" style="display:none"></span>
              <span id="prove-time" class="timing"></span>
            </div>
          </div>

          <div class="chapter-result" id="step-4-result" style="display:none">
            <div class="result-label">Circuit inputs (what entered the circuit):</div>
            <pre id="step-4-inputs" class="result-data"></pre>
            <div class="result-label">Public signals (5 values):</div>
            <pre id="step-4-signals" class="result-data"></pre>
            <div class="result-label">Proof (pi_a, pi_b, pi_c):</div>
            <pre id="step-4-proof" class="result-data compact"></pre>
          </div>
        </div>

        <!-- ========================================= -->
        <!-- Panel 4: Verification -->
        <!-- ========================================= -->
        <div class="try-panel" id="chapter-4" style="display:none">

          <div class="chapter-learn">
              <p>
                <strong>Off-chain:</strong> <code>snarkjs.groth16.verify()</code> runs the BN254 pairing
                check entirely in your browser. This is real cryptographic verification &mdash; the same
                math the contract uses.
              </p>
              <p>
                <strong>On-chain:</strong> The proof is encoded to Soroban bytes and submitted as a transaction.
                The <code>identity-auth</code> contract calls <code>groth16-verifier</code> for the BN254
                pairing check, then stores the nullifier to prevent replay.
              </p>
              <p>
                The verification equation:
                <code>e(A, B) = e(&alpha;, &beta;) &middot; e(&Sigma; vk_k &middot; x_k, &gamma;) &middot; e(C, &delta;)</code>
              </p>
              <p><a href="/learn#onchain" style="color: var(--accent);">See the contract code &rarr;</a></p>
          </div>

          <div class="chapter-do">
            <div style="margin-bottom: 1rem;" id="step-5a">
              <div class="result-label">Off-Chain (browser)</div>
              <div class="step-action">
                <button id="btn-verify-offchain" class="btn" disabled>Verify in Browser</button>
                <span class="spinner" id="spinner-5a" style="display:none"></span>
                <span id="verify-offchain-time" class="timing"></span>
              </div>
              <div class="step-result" id="step-5a-result" style="display:none">
                <div id="step-5a-verdict" class="verdict"></div>
                <div class="result-label">Parsed public signals:</div>
                <pre id="step-5a-parsed" class="result-data"></pre>
              </div>
            </div>

            <div id="step-5b">
              <div class="result-label">On-Chain (Soroban testnet)</div>
              <div class="step-action">
                <button id="btn-verify-onchain" class="btn btn-warn" disabled>Submit to Testnet</button>
                <span class="spinner" id="spinner-5b" style="display:none"></span>
              </div>
              <div class="step-result" id="step-5b-result" style="display:none">
                <pre id="step-5b-data" class="result-data"></pre>
                <div id="step-5b-link"></div>
              </div>
            </div>
          </div>
        </div>

        <!-- ========================================= -->
        <!-- Panel 5: Wallet -->
        <!-- ========================================= -->
        <div class="try-panel" id="chapter-5" style="display:none">

          <div class="chapter-learn">
              <p>
                Your ZK-proven identity now controls a Stellar account. The keypair is generated
                in your browser and stored in localStorage, linked to your identity hash.
                <strong>Same Google account or passkey = same wallet on return.</strong>
              </p>
              <p>
                <strong>Self-custody:</strong> The secret key never leaves your browser. Transactions
                are signed client-side using the Stellar SDK. In production, an encrypted backup
                (keyed by identity) would enable cross-device recovery.
              </p>
              <p>
                <strong>No seed phrase:</strong> Your Google account or passkey IS your recovery
                mechanism. Authenticate again &rarr; same identity hash &rarr; same wallet.
              </p>
          </div>

          <div class="chapter-do" id="step-6">
            <!-- Address -->
            <div class="wallet-section">
              <div class="result-label">Your Stellar Address</div>
              <div class="wallet-address-row">
                <code id="wallet-address-short" class="wallet-address"></code>
                <button id="btn-copy-address" class="btn btn-sm">Copy</button>
              </div>
              <div id="wallet-address" class="wallet-address-full" style="display:none"></div>
            </div>

            <!-- Balance -->
            <div class="wallet-section">
              <div class="result-label">Balance</div>
              <div class="wallet-balance-row">
                <span id="wallet-balance-value" class="wallet-balance-amount unfunded">Checking...</span>
                <button id="btn-refresh-balance" class="btn btn-sm">Refresh</button>
              </div>
            </div>

            <!-- Fund -->
            <div class="wallet-section" id="wallet-fund-section">
              <p style="font-size: var(--text-sm); color: var(--text-secondary); margin-bottom: var(--space-2);">
                <strong style="color: var(--text);">Get testnet XLM:</strong> Friendbot sends 10,000 XLM to any testnet address.
              </p>
              <div class="step-action">
                <button id="btn-fund" class="btn btn-primary">Fund with Friendbot</button>
                <span class="spinner" id="spinner-fund" style="display:none"></span>
              </div>
            </div>

            <!-- Send -->
            <div class="wallet-section">
              <div class="result-label">Send XLM</div>
              <div class="wallet-send-form">
                <input id="send-destination" type="text" class="wallet-input"
                  placeholder="Destination address (G...)" autocomplete="off" spellcheck="false" />
                <div class="wallet-send-row">
                  <input id="send-amount" type="text" class="wallet-input wallet-input-amount"
                    placeholder="Amount" autocomplete="off" />
                  <span class="wallet-input-label">XLM</span>
                  <button id="btn-send" class="btn btn-warn" disabled>Send</button>
                  <span class="spinner" id="spinner-send" style="display:none"></span>
                </div>
              </div>
              <div id="send-result" class="wallet-status" style="display:none"></div>
            </div>

            <div id="wallet-status" class="wallet-status" style="display:none"></div>
          </div>
        </div>

      </div><!-- /try-content -->

    </div><!-- /try-scene -->
    `,
  });
}
