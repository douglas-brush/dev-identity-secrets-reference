# Future Enhancements

## Completed in v0.3.0

The following items from the original roadmap have been implemented:

| Capability | Delivered In |
|------------|-------------|
| Artifact signing using centralized keys | `tools/signing/`, `examples/signing/` |
| Service mesh integration for mTLS policy | `examples/mtls/`, `docs/16-mtls-workload-identity-guide.md` |
| Broader PAM / JIT elevation integration | `examples/jit-access/`, `docs/17-jit-access-patterns.md` |
| Hardware-backed root and intermediate ceremony formalization | `tools/ceremony/`, `docs/18-key-ceremony-guide.md` |
| Richer repo secret scanning and DLP | `tools/scanning/`, `examples/dlp/` |

## Remaining Future Work

These are logical next steps that remain outside the current implementation scope:

### Near-term

- **SPIFFE / SPIRE production rollout** — workload identity federation beyond mTLS examples; production-grade SPIRE server deployment, registration APIs, and federation across trust domains
- **Full PAM product integration** — native connectors for CyberArk, Delinea, BeyondTrust; session recording and credential checkout workflows beyond the JIT elevation patterns
- **Automated certificate inventory and expiry reporting** — scheduled scanning of all PKI endpoints with alerting on approaching expiry thresholds

### Medium-term

- **Go SDK** — native Go client library for secrets management (mirrors Python SDK patterns in `lib/python/`)
- **TypeScript SDK** — Node.js/TypeScript client library for secrets management
- **Terraform provider for policy-as-code** — custom Terraform provider to manage Vault policies, SOPS rules, and scanning configuration declaratively
- **Richer DLP with ML-based detection** — move beyond regex and entropy patterns to ML-based classifiers for PII, PHI, and custom sensitive data types

### Long-term

- **GUI dashboard for secrets health** — web-based dashboard aggregating secrets-doctor output, rotation status, certificate expiry, and compliance posture across environments
- **Multi-cluster secrets federation** — cross-cluster Vault replication patterns with conflict resolution and split-brain recovery
- **Hardware security module (HSM) abstraction layer** — unified interface across CloudHSM, Luna, YubiHSM for ceremony and transit operations
