/**
 * Stellar ZK Login Demo — Hono on Cloudflare Pages
 *
 * Single deployment: API routes + server-rendered HTML pages.
 * Static assets (circuit artifacts, snarkjs, CSS) served by CF Pages CDN.
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { authRoute } from './api/auth';
import { attestationRoute } from './api/attestation';
import { verifyOnchainRoute } from './api/verify-onchain';
import { passkeyRoute } from './api/passkey';
import { homePage } from './pages/home';
import { learnPage } from './pages/learn';
import { tryPage } from './pages/try';
import { flowPage } from './pages/flow';
import { privacyPage } from './pages/privacy';
import { termsPage } from './pages/terms';

export interface Env {
  SERVER_SECRET: string;
  SOROBAN_RPC_URL: string;
  STELLAR_NETWORK: string;
  GMAIL_AUTH_CONTRACT_ID?: string;
  SPONSOR_SECRET_KEY?: string;
  GOOGLE_CLIENT_ID?: string;
  PASSKEY_RP_ID?: string;
  PASSKEY_RP_NAME?: string;
  PASSKEY_ORIGIN?: string;
}

const app = new Hono<{ Bindings: Env }>();

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------
app.use('*', cors());

// ---------------------------------------------------------------------------
// Pages (server-rendered HTML)
// ---------------------------------------------------------------------------
app.get('/', (c) => {
  const clientId = c.env.GOOGLE_CLIENT_ID || '';
  return c.html(homePage(clientId));
});

app.get('/learn', (c) => {
  return c.html(learnPage());
});

app.get('/try', (c) => {
  const clientId = c.env.GOOGLE_CLIENT_ID || '';
  return c.html(tryPage(clientId));
});

app.get('/privacy', (c) => c.html(privacyPage()));
app.get('/terms', (c) => c.html(termsPage()));

// Backward compat: /flow redirects to /try
app.get('/flow', (c) => {
  return c.redirect('/try', 301);
});

// ---------------------------------------------------------------------------
// API routes
// ---------------------------------------------------------------------------
app.route('/api/auth', authRoute);
app.route('/api/attestation', attestationRoute);
app.route('/api/verify/onchain', verifyOnchainRoute);
app.route('/api/passkey', passkeyRoute);

// Health check
app.get('/api/health', (c) => c.json({
  status: 'ok',
  circuit: { name: 'gmail_attestation', constraints: 2295, curve: 'BN254', protocol: 'Groth16' },
  network: c.env.STELLAR_NETWORK || 'testnet',
}));

// 404 fallback (only for non-static routes)
app.notFound((c) => c.json({ error: 'Not found' }, 404));

app.onError((err, c) => {
  console.error('Unhandled error:', err);
  return c.json({ error: 'Internal server error', message: err.message }, 500);
});

export default app;
