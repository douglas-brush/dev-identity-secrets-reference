# Future Enhancements

## Completed in v0.5.0

| Capability | Delivered In |
|---|---|
| Go SDK — VaultClient, SOPS decrypt, config validation, Cobra CLI, 84 tests | `lib/go/`, `lib/go/cmd/secrets-sdk/` |
| TypeScript SDK — VaultClient, SOPS, config, rotation, Commander CLI, 87 tests | `lib/typescript/` |
| Vault policy library — 8 HCL policies + 3 Sentinel EGPs | `platform/vault/policies/` |
| Certificate inventory and expiry monitoring with alerting | `tools/audit/cert_inventory.sh`, `tools/audit/cert_monitor.sh` |
| Compliance automation — evidence generation + control matrix | `tools/compliance/`, `examples/compliance/` |
| Compliance automation guide | `docs/21-compliance-automation.md` |
| CI workflows for Go tests, TS tests, cert monitoring, enhanced scanning | `.github/workflows/` |
| BATS test suite — 236 shell tests across 10 test files | `tests/unit/` |

## Completed in v0.4.0

| Capability | Delivered In |
|---|---|
| SIRM session framework for IR, forensics, and audits | `tools/sirm/`, `docs/19-sirm-framework.md`, `docs/20-sirm-session-protocol.md`, `examples/sirm/` |

## Completed in v0.3.0

| Capability | Delivered In |
|---|---|
| Artifact signing using centralized keys | `tools/signing/`, `examples/signing/` |
| Service mesh integration for mTLS policy | `examples/mtls/`, `docs/16-mtls-workload-identity-guide.md` |
| Broader PAM / JIT elevation integration | `examples/jit-access/`, `docs/17-jit-access-patterns.md` |
| Hardware-backed root and intermediate ceremony formalization | `tools/ceremony/`, `docs/18-key-ceremony-guide.md` |
| Richer repo secret scanning and DLP | `tools/scanning/`, `examples/dlp/` |

---

## Remaining Future Work

Most of the original roadmap has been delivered. The items below are aspirational extensions beyond the current reference architecture scope.

### Near-term

- **SPIFFE / SPIRE production rollout** — workload identity federation beyond mTLS examples; production-grade SPIRE server deployment, registration APIs, and federation across trust domains
- **Full PAM product integration** — native connectors for CyberArk, Delinea, BeyondTrust; session recording and credential checkout workflows beyond the JIT elevation patterns
- **Terraform provider for policy-as-code** — custom Terraform provider to manage Vault policies, SOPS rules, and scanning configuration declaratively

### Medium-term

- **Richer DLP with ML-based detection** — move beyond regex and entropy patterns to ML-based classifiers for PII, PHI, and custom sensitive data types
- **GUI dashboard for secrets health** — web-based dashboard aggregating secrets-doctor output, rotation status, certificate expiry, and compliance posture across environments
- **Rust SDK** — native Rust client library for secrets management in performance-critical contexts

### Long-term

- **Multi-cluster secrets federation** — cross-cluster Vault replication patterns with conflict resolution and split-brain recovery
- **Hardware security module (HSM) abstraction layer** — unified interface across CloudHSM, Luna, YubiHSM for ceremony and transit operations
- **Secrets mesh** — distributed secrets delivery fabric with gossip-based invalidation, cross-region failover, and zero-downtime rotation propagation
