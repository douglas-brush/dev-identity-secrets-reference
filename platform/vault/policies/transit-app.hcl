# Transit access for encryption/signature use cases.

path "transit/encrypt/demo-app" {
  capabilities = ["create", "update"]
}

path "transit/decrypt/demo-app" {
  capabilities = ["create", "update"]
}

path "transit/sign/demo-app" {
  capabilities = ["create", "update"]
}

path "transit/verify/demo-app" {
  capabilities = ["create", "update"]
}
