# stellar-zkLogin Demo

Interactive educational site for [stellar-zkLogin](../../README.md) — explore the architecture, learn how ZK social login works, and try a guided proving flow.

**Live:** [stellar-zklogin-demo.pages.dev](https://stellar-zklogin-demo.pages.dev)

## Pages

| Route | Page | Description |
|-------|------|-------------|
| `/` | Home | Architecture overview, feature status, comparison table |
| `/learn` | Learn | 8-section deep dive with real code snippets |
| `/try` | Try It | Guided 6-step tutorial: sign in → hash → attest → prove → verify → wallet |
| `/flow` | Flow | Visual authentication flow diagram |

## Stack

- **Hono** — Server-side rendering on Cloudflare Pages
- **Vanilla JS** — No frontend framework
- **Radix UI Themes** — CSS-only theming
- **@nobak/stellar-zklogin** — SDK for proving and verification
- **snarkjs** — Client-side Groth16 proof generation

## Development

```bash
npm install
npm run dev       # Build + wrangler dev server (localhost:8788)
npm run build     # Production build → dist/
npm test          # Vitest (11 tests)
npm run deploy    # Deploy to Cloudflare Pages
```

## Project Structure

```
src/
├── index.ts          # Hono app entry point + routes
├── pages/            # Server-rendered HTML pages
│   ├── home.ts
│   ├── learn.ts
│   ├── try.ts
│   ├── flow.ts
│   └── layout.ts    # Shared HTML shell + Radix theme
├── api/              # API routes (attestation, verification)
├── client/           # Client-side JS (proof generation, UI interactions)
└── crypto/           # Identity hashing, Poseidon helpers
```
