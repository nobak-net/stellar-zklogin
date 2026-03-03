# Contributing to stellar-zkLogin

Thank you for your interest in contributing to stellar-zkLogin.

## Getting Started

### Prerequisites

- Rust 1.74+
- [Stellar CLI](https://developers.stellar.org/docs/tools/developer-tools/cli/install-cli) 23.4+
- Node.js 18+ (for circuit tooling)
- [Circom](https://docs.circom.io/getting-started/installation/) 2.1.0+ (for circuit work)

### Build & Test

```bash
# Build all contracts
stellar contract build

# Run all tests
cargo test --workspace

# Build circuit (if working on circuits)
cd circuits/identity-attestation
npm install
./scripts/compile.sh
```

## How to Contribute

### Bug Reports

Open a GitHub issue with:
- Steps to reproduce
- Expected vs actual behavior
- Contract/circuit name and function

For **security vulnerabilities**, see [SECURITY.md](SECURITY.md) — do not open a public issue.

### Code Contributions

1. Fork the repository
2. Create a feature branch from `main`
3. Write your changes with tests
4. Run `cargo test --workspace` and `stellar contract build`
5. Submit a pull request

### Pull Request Guidelines

- Keep PRs focused — one fix or feature per PR
- Include tests for new functionality
- Update documentation if behavior changes
- Ensure `cargo test --workspace` passes
- Ensure `stellar contract build` succeeds (all 8 WASMs compile)

### Code Style

- Follow existing patterns in the codebase
- Use `rustfmt` for Rust formatting
- Use `clippy` for linting: `cargo clippy --workspace`
- Circuit code: follow Circom conventions from [circomlib](https://github.com/iden3/circomlib)

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full system architecture and contract dependency graph.

### TypeScript Packages

| Package | Path | What |
|---------|------|------|
| `@nobak/stellar-zklogin` | `packages/sdk/` | Client-side SDK (proving, verification, identity) |
| `@nobak/stellar-zklogin-server` | `packages/server/` | Reference attestation server (Hono/CF Workers) |
| `stellar-zklogin-demo` | `examples/demo/` | Educational demo site (CF Pages) |

```bash
# Build all TS packages
npm run build

# Run all TS tests
npm test
```

### Contract Overview

| Contract | Purpose |
|----------|---------|
| `identity-auth` | Orchestrator — verifies proofs, tracks identities |
| `groth16-verifier` | On-chain Groth16 proof verification |
| `merkle-tree` | Poseidon merkle tree for identity membership |
| `poseidon-hash` | ZK-friendly hash functions |
| `commitment-scheme` | Hiding/binding commitments |
| `bn254-basics` | BN254 elliptic curve operations |
| `zk-wallet` | ZK-gated token wallet |
| `zk-key-escrow` | ZK-gated key recovery escrow |

### Testing

Each contract has tests in its `src/lib.rs` under `#[cfg(test)]`. Circuit tests are in `circuits/identity-attestation/test/`.

When adding security-relevant functionality, include negative tests (invalid inputs, unauthorized callers, replay attempts).

## License

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](LICENSE).
