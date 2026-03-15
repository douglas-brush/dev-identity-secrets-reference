#!/usr/bin/env bash
set -euo pipefail

vault secrets enable -path=kv kv-v2
vault secrets enable -path=database database
vault secrets enable -path=pki pki
vault secrets enable -path=pki_int pki
vault secrets enable -path=ssh ssh
vault secrets enable -path=transit transit

vault auth enable oidc || true
vault auth enable -path=jwt/github jwt || true
vault auth enable kubernetes || true

echo "[ok] enabled baseline engines and auth methods"
