# Future Enhancements

These are deliberately outside the first iteration but are logical next steps.

- artifact signing using centralized keys
- SPIFFE / SPIRE production rollout (reference manifests available in `platform/kubernetes/spiffe/` — production hardening per the checklist in that directory's README is a future step)
- service mesh integration for mTLS policy
- automated certificate inventory and expiry reporting
- broader PAM / JIT elevation integration
- hardware-backed root and intermediate ceremony formalization
- richer repo secret scanning and DLP
