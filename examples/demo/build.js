/**
 * Build script — bundles server + client, copies static assets.
 *
 * Output:
 *   dist/_worker.js       — Hono app (CF Pages advanced mode)
 *   dist/app.js           — Client-side orchestration
 *   dist/style.css        — Styles
 *   dist/circuits/*.wasm  — Circuit artifacts (copied from circuits/identity-attestation)
 *   dist/snarkjs.min.js   — Browser snarkjs (copied from node_modules)
 */

const { build } = require('esbuild');
const { cpSync, mkdirSync, existsSync, writeFileSync } = require('fs');
const { resolve } = require('path');

async function main() {
  const dist = resolve(__dirname, 'dist');
  mkdirSync(dist, { recursive: true });

  // 1. Bundle server → _worker.js
  await build({
    entryPoints: [resolve(__dirname, 'src/index.ts')],
    outfile: resolve(dist, '_worker.js'),
    bundle: true,
    format: 'esm',
    target: 'es2022',
    platform: 'browser', // CF Workers use browser-like env
    minify: process.env.NODE_ENV === 'production',
    sourcemap: process.env.NODE_ENV !== 'production',
    conditions: ['worker', 'browser'],
    define: { 'process.env.NODE_ENV': '"production"' },
    external: ['__STATIC_CONTENT_MANIFEST', 'node:*'],
  });

  // 2. Bundle client → app.js
  await build({
    entryPoints: [resolve(__dirname, 'src/client/app.ts')],
    outfile: resolve(dist, 'app.js'),
    bundle: true,
    format: 'iife',
    target: 'es2020',
    platform: 'browser',
    minify: process.env.NODE_ENV === 'production',
    sourcemap: process.env.NODE_ENV !== 'production',
  });

  // 2b. Bundle learn page scroll-spy → learn.js
  await build({
    entryPoints: [resolve(__dirname, 'src/client/learn.ts')],
    outfile: resolve(dist, 'learn.js'),
    bundle: true,
    format: 'iife',
    target: 'es2020',
    platform: 'browser',
    minify: process.env.NODE_ENV === 'production',
    sourcemap: process.env.NODE_ENV !== 'production',
  });

  // 3. Copy static assets
  cpSync(resolve(__dirname, 'public'), dist, { recursive: true });

  // 4. Copy circuit artifacts from the real circuit build output
  const circuitsDir = resolve(dist, 'circuits');
  mkdirSync(circuitsDir, { recursive: true });

  const wasmSrc = resolve(__dirname, '../../circuits/identity-attestation/build/gmail_attestation_js');
  const keysSrc = resolve(__dirname, '../../circuits/identity-attestation/keys');

  const artifacts = [
    { src: resolve(wasmSrc, 'gmail_attestation.wasm'), name: 'gmail_attestation.wasm' },
    { src: resolve(keysSrc, 'gmail_attestation.zkey'), name: 'gmail_attestation.zkey' },
    { src: resolve(keysSrc, 'verification_key.json'), name: 'verification_key.json' },
  ];

  let copied = 0;
  for (const { src, name } of artifacts) {
    if (existsSync(src)) {
      cpSync(src, resolve(circuitsDir, name));
      copied++;
    } else {
      console.warn(`  WARNING: ${name} not found at ${src}`);
    }
  }
  if (copied > 0) console.log(`  Copied ${copied} circuit artifact(s) from circuits/identity-attestation`);
  if (copied < 3) console.warn('  Some artifacts missing — run circuits/identity-attestation/scripts/compile.sh');

  // 5. Copy snarkjs browser build
  const snarkjsSrc = resolve(__dirname, 'node_modules/snarkjs/build/snarkjs.min.js');
  if (existsSync(snarkjsSrc)) {
    cpSync(snarkjsSrc, resolve(dist, 'snarkjs.min.js'));
    console.log('  Copied snarkjs.min.js');
  } else {
    // Try monorepo root
    const rootSnarkjs = resolve(__dirname, '../../node_modules/snarkjs/build/snarkjs.min.js');
    if (existsSync(rootSnarkjs)) {
      cpSync(rootSnarkjs, resolve(dist, 'snarkjs.min.js'));
      console.log('  Copied snarkjs.min.js from monorepo root');
    } else {
      console.warn('  WARNING: snarkjs.min.js not found. Install snarkjs: npm install snarkjs');
    }
  }

  // 6. Copy Stellar SDK browser build (UMD — same pattern as snarkjs)
  const sdkSrc = resolve(__dirname, 'node_modules/@stellar/stellar-sdk/dist/stellar-sdk.min.js');
  if (existsSync(sdkSrc)) {
    cpSync(sdkSrc, resolve(dist, 'stellar-sdk.min.js'));
    console.log('  Copied stellar-sdk.min.js');
  } else {
    const rootSdk = resolve(__dirname, '../../node_modules/@stellar/stellar-sdk/dist/stellar-sdk.min.js');
    if (existsSync(rootSdk)) {
      cpSync(rootSdk, resolve(dist, 'stellar-sdk.min.js'));
      console.log('  Copied stellar-sdk.min.js from monorepo root');
    } else {
      console.warn('  WARNING: stellar-sdk.min.js not found');
    }
  }

  // 7. Copy Radix Themes CSS (design tokens, reset, typography)
  const radixCss = resolve(__dirname, 'node_modules/@radix-ui/themes/styles.css');
  if (existsSync(radixCss)) {
    cpSync(radixCss, resolve(dist, 'radix-themes.css'));
    console.log('  Copied radix-themes.css');
  } else {
    const rootRadix = resolve(__dirname, '../../node_modules/@radix-ui/themes/styles.css');
    if (existsSync(rootRadix)) {
      cpSync(rootRadix, resolve(dist, 'radix-themes.css'));
      console.log('  Copied radix-themes.css from monorepo root');
    } else {
      console.warn('  WARNING: radix-themes.css not found');
    }
  }

  // 8. Write _routes.json — tells CF Pages which routes go to the worker vs static assets
  writeFileSync(resolve(dist, '_routes.json'), JSON.stringify({
    version: 1,
    include: ['/', '/learn', '/try', '/privacy', '/terms', '/flow', '/api/*'],
    exclude: [],
  }, null, 2));
  console.log('  Wrote _routes.json');

  console.log('Build complete → dist/');
}

main().catch((err) => {
  console.error('Build failed:', err);
  process.exit(1);
});
