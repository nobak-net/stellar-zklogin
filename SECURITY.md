# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in stellar-zkLogin, **please do not open a public GitHub issue.**

### How to Report

Email your findings to the maintainers with:

1. A description of the vulnerability
2. Steps to reproduce (proof of concept if possible)
3. The affected component (contract name, circuit, or script)
4. Your assessment of severity and impact

### What to Expect

- **Acknowledgment** within 48 hours
- **Assessment** within 7 days
- **Fix timeline** communicated within 14 days
- **Public disclosure** after fix is deployed (coordinated with reporter)

We will credit reporters in the security advisory unless they prefer to remain anonymous.

### Scope

The following are in scope:

- Soroban contracts (`contracts/*/src/lib.rs`)
- Circom circuit (`circuits/identity-attestation/src/identity_attestation.circom`)
- Deployment scripts (`scripts/`)
- Trusted setup process

The following are out of scope:

- The attestation server (separate repo)
- Mobile client implementations (separate repo)
- OAuth provider vulnerabilities (report to Google/Apple directly)

## Security Model

stellar-zkLogin uses a **semi-trusted model**. For the full threat analysis, trust boundary diagram, and known limitations, see [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).

### Key Trust Assumptions

1. **OAuth provider** correctly authenticates users
2. **Attestation server** correctly validates tokens (does not forge attestations)
3. **Trusted setup ceremony** had at least one honest participant
4. **Soroban runtime** correctly executes contract logic

### Known Limitations

- The attestation server is an additional trust assumption compared to fully trustless systems (e.g., Sui zkLogin's JWK oracle)
- BN254 provides ~100-128 bit security (industry standard for ZK-SNARKs, below NIST 128-bit recommendation)
- Groth16 requires a trusted setup — if all ceremony participants collude, proofs can be forged

## Audit Status

An internal white-hat audit identified 14 on-chain findings. Fixes are in progress. A third-party audit is planned before mainnet deployment.

See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for the full audit status table.
