/**
 * Terms of Service page — required for Google OAuth production consent screen.
 */

import { layout } from './layout';

export function termsPage(): string {
  return layout({
    title: 'Terms of Service',
    activePage: 'terms',
    content: `
    <div class="container legal-page">
      <h1>Terms of Service</h1>
      <p class="legal-updated">Last updated: March 3, 2026</p>

      <h2>1. Purpose</h2>
      <p>
        Stellar ZK Login (<strong>stellar-zklogin-demo.pages.dev</strong>) is an open-source,
        educational demonstration of zero-knowledge social authentication on the Stellar blockchain.
        It is provided for <strong>learning, research, and experimentation</strong> purposes only.
      </p>

      <h2>2. Testnet Only</h2>
      <p>
        This demo operates exclusively on <strong>Stellar Testnet</strong>. All XLM tokens used
        in the demo are testnet tokens with <strong>no real-world value</strong>. The testnet may
        be reset at any time by the Stellar Development Foundation, which will erase all accounts
        and transaction history.
      </p>

      <h2>3. No Warranty</h2>
      <p>
        This software is provided <strong>&ldquo;as is&rdquo;</strong> without warranty of any kind,
        express or implied. The authors and contributors make no guarantees regarding:
      </p>
      <ul>
        <li>Availability or uptime of the demo</li>
        <li>Accuracy or completeness of the educational content</li>
        <li>Security of the ZK circuits or smart contracts (pre-audit)</li>
        <li>Persistence of testnet accounts, proofs, or wallet data</li>
      </ul>

      <h2>4. Pre-Audit Status</h2>
      <p>
        The ZK circuits and Soroban smart contracts have <strong>not been formally audited</strong>.
        They are published for educational purposes and community review. Do not use this system
        for any production or financial application until a security audit has been completed.
      </p>

      <h2>5. Your Responsibilities</h2>
      <ul>
        <li>You understand this is a testnet demo, not a production service</li>
        <li>You will not attempt to use the demo for financial transactions with real assets</li>
        <li>You will not attempt to disrupt or abuse the demo infrastructure</li>
        <li>You are responsible for any browser-stored data (keypairs in localStorage)</li>
      </ul>

      <h2>6. Intellectual Property</h2>
      <p>
        Stellar ZK Login is open source under the
        <a href="https://www.apache.org/licenses/LICENSE-2.0" target="_blank">Apache License 2.0</a>.
        You are free to use, modify, and distribute the code under the terms of that license.
        Source code:
        <a href="https://github.com/nobak-net/stellar-zklogin" target="_blank">github.com/nobak-net/stellar-zklogin</a>.
      </p>

      <h2>7. Third-Party Services</h2>
      <p>
        The demo integrates with third-party services (Google OAuth, Cloudflare, Stellar Testnet)
        that have their own terms of service. Your use of those services is governed by their
        respective terms.
      </p>

      <h2>8. Limitation of Liability</h2>
      <p>
        To the maximum extent permitted by law, the authors and contributors shall not be liable
        for any damages arising from the use of this demo, including but not limited to loss of
        data, loss of testnet tokens, or inability to access the service.
      </p>

      <h2>9. Changes</h2>
      <p>
        These terms may be updated as the project evolves. Changes will be reflected on this page
        with an updated date. Continued use of the demo after changes constitutes acceptance.
      </p>

      <h2>10. Contact</h2>
      <p>
        Questions? Open an issue on
        <a href="https://github.com/nobak-net/stellar-zklogin/issues" target="_blank">GitHub</a>.
      </p>
    </div>
    `,
  });
}
