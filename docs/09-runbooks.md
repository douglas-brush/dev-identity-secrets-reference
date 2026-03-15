# Runbooks

## Runbook 1 — New repository onboarding
1. add `.sops.yaml`
2. configure environment key recipients
3. add pre-commit hooks
4. create `secrets/dev`, `secrets/stage`, `secrets/prod`
5. encrypt first config file with SOPS
6. validate merge blocking

## Runbook 2 — New application onboarding
1. define app owner and environment
2. create service account
3. define secret path and policy
4. choose delivery method:
   - external secrets sync
   - volume-mount driver
   - secrets agent sidecar
5. define certificate need
6. test rotation, restart, and revocation behavior

## Runbook 3 — New developer onboarding
1. confirm IdP group assignment
2. confirm device management status
3. install required CLI tooling
4. run local bootstrap
5. verify scoped secret retrieval
6. verify no local durable secrets were created outside approved locations

## Runbook 4 — Admin access recovery
1. declare emergency use
2. invoke dual-control
3. retrieve break-glass material
4. access through approved recovery path
5. capture evidence and logs
6. rotate/revoke any material used

## Runbook 5 — Secret exposure response
1. identify secret class
2. revoke/rotate immediately
3. identify distribution surface (repo, CI, logs, artifacts)
4. audit access history
5. remediate guardrail gap
6. document lessons learned
