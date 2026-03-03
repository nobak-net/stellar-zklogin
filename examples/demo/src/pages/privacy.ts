/**
 * Privacy Policy page — required for Google OAuth production consent screen.
 */

import { layout } from './layout';

export function privacyPage(): string {
  return layout({
    title: 'Privacy Policy',
    activePage: 'privacy',
    content: `
    <div class="container legal-page">
      <h1>Privacy Policy</h1>
      <p class="legal-updated">Last updated: March 3, 2026</p>

      <p>
        Stellar ZK Login is an open-source, educational demo that demonstrates zero-knowledge
        social authentication on the Stellar blockchain. This policy explains how data is handled
        when you use the demo at <strong>stellar-zklogin-demo.pages.dev</strong>.
      </p>

      <h2>What We Collect</h2>

      <h3>Google Sign-In</h3>
      <p>
        When you sign in with Google, the demo receives your <strong>email address</strong>,
        <strong>user ID (sub)</strong>, and <strong>email verification status</strong> from Google&rsquo;s
        OAuth service. These values are used <em>only</em> to compute a one-way identity hash:
      </p>
      <pre class="legal-code">identityHash = SHA-256("gmail:{email}:{sub}:verified:{emailVerified}")</pre>
      <p>
        The identity hash is a cryptographic digest. Your email address and user ID <strong>cannot be
        recovered</strong> from the hash. The raw email and user ID are processed in memory during
        the request and are <strong>never stored</strong> on any server or database.
      </p>

      <h3>Passkey Authentication</h3>
      <p>
        If you use passkey authentication, a WebAuthn credential is created in your browser.
        The credential ID is hashed to produce an identity anchor. No personal information is
        collected or transmitted.
      </p>

      <h3>ZK Proofs</h3>
      <p>
        Groth16 proofs are generated entirely in your browser. Private witness data (identity hash,
        blinding factor, nullifier secret) <strong>never leaves your device</strong>. Only the proof
        and public signals (commitment, nullifier hash) are submitted for verification.
      </p>

      <h3>Wallet</h3>
      <p>
        Stellar keypairs are generated and stored in your browser&rsquo;s <code>localStorage</code>.
        Secret keys are never transmitted to any server. The demo operates on <strong>Stellar Testnet
        only</strong> &mdash; no real assets are involved.
      </p>

      <h2>What We Do NOT Collect</h2>
      <ul>
        <li>No cookies (no session cookies, no tracking cookies)</li>
        <li>No analytics or tracking scripts</li>
        <li>No advertising identifiers</li>
        <li>No IP address logging</li>
        <li>No persistent storage of personal data</li>
      </ul>

      <h2>Data Processing</h2>
      <p>
        All server-side processing runs on <strong>Cloudflare Workers</strong> &mdash; a stateless,
        edge-compute platform. Requests are processed in memory and discarded. There is no database,
        no log retention, and no data replication.
      </p>

      <h2>Third-Party Services</h2>
      <ul>
        <li>
          <strong>Google Identity Services</strong> &mdash; OAuth token issuance.
          See <a href="https://policies.google.com/privacy" target="_blank">Google&rsquo;s Privacy Policy</a>.
        </li>
        <li>
          <strong>Cloudflare Pages</strong> &mdash; Hosting and edge compute.
          See <a href="https://www.cloudflare.com/privacypolicy/" target="_blank">Cloudflare&rsquo;s Privacy Policy</a>.
        </li>
        <li>
          <strong>Stellar Testnet</strong> &mdash; Blockchain transactions (testnet only, no real value).
        </li>
      </ul>

      <h2>Open Source</h2>
      <p>
        This entire application is open source under the Apache 2.0 license. You can inspect
        exactly how data is processed:
        <a href="https://github.com/nobak-net/stellar-zklogin" target="_blank">github.com/nobak-net/stellar-zklogin</a>.
      </p>

      <h2>Children&rsquo;s Privacy</h2>
      <p>
        This demo is an educational developer tool. It is not directed at children under 13 and
        does not knowingly collect data from children.
      </p>

      <h2>Changes</h2>
      <p>
        This policy may be updated as the demo evolves. Changes will be reflected on this page
        with an updated date.
      </p>

      <h2>Contact</h2>
      <p>
        Questions or concerns? Open an issue on
        <a href="https://github.com/nobak-net/stellar-zklogin/issues" target="_blank">GitHub</a>.
      </p>
    </div>
    `,
  });
}
