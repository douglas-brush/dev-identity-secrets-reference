# Decision Log

Use this file as the starting point for ADRs and operating decisions.

## Open decisions

### DEC-001 — Central credential broker
Options:
- Vault as the central broker
- cloud secret services only
- hybrid model

Default recommendation:
- hybrid model where Vault handles dynamic credentials, SSH, Transit, and possibly PKI while cloud secret services store static unavoidable secrets

Status:
- open

### DEC-002 — PKI authority for endpoints and workloads
Options:
- dedicated private PKI provider
- Vault PKI for selected populations
- Microsoft Cloud PKI for endpoints with BYOCA
- mixed model

Default recommendation:
- enterprise CA hierarchy plus workload-focused automation path

Status:
- open

### DEC-003 — Runtime secret delivery pattern
Options:
- external secrets sync only
- volume-mount driver only
- mixed model
- secrets agent sidecars for specific apps

Default recommendation:
- mixed model

Status:
- open

### DEC-004 — SSH administration model
Options:
- Vault SSH CA
- access broker
- cloud control-plane access
- mixed model

Default recommendation:
- mixed model with cloud control-plane where available and short-lived SSH elsewhere

Status:
- open

### DEC-005 — SOPS recipient strategy
Options:
- cloud KMS only
- KMS + age break-glass
- age only

Default recommendation:
- cloud KMS plus tightly controlled break-glass recipient

Status:
- open
