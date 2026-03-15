# PKI administration — intermediate CA management and certificate operations.

path "pki_int/sign/*" {
  capabilities = ["create", "update"]
}

path "pki_int/issue/*" {
  capabilities = ["create", "update"]
}

path "pki_int/revoke" {
  capabilities = ["create", "update"]
}

path "pki_int/certs" {
  capabilities = ["list"]
}

path "pki_int/cert/*" {
  capabilities = ["read"]
}

path "pki_int/ca/pem" {
  capabilities = ["read"]
}

path "pki_int/crl" {
  capabilities = ["read"]
}

path "pki_int/roles/*" {
  capabilities = ["read", "list"]
}
