# Vault Audit Device Configuration — Elasticsearch/Logstash (ELK) Integration
#
# Two complementary audit devices:
#   1. File device   — primary, tailed by Filebeat or Logstash file input
#   2. Socket device — secondary, direct push to Logstash TCP input
#
# Enable via CLI after Vault is initialized and unsealed:
#
#   vault audit enable file \
#     file_path="/vault/audit/audit.log" \
#     log_raw=false \
#     hmac_accessor=true \
#     mode="0600"
#
#   vault audit enable -path=socket-elk socket \
#     address="logstash.example.internal:5044" \
#     socket_type="tcp" \
#     log_raw=false \
#     hmac_accessor=true
#
# IMPORTANT: Vault blocks requests if ALL audit devices are down.
# Always maintain at least two audit devices.

# ─── Filebeat Configuration ─────────────────────────────────────────────────
#
# Deploy Filebeat on the Vault host (or as a sidecar in Kubernetes).
# File: /etc/filebeat/filebeat.yml
#
# filebeat.inputs:
#   - type: log
#     enabled: true
#     paths:
#       - /vault/audit/audit.log
#     json.keys_under_root: true
#     json.add_error_key: true
#     json.overwrite_keys: true
#     fields:
#       service: vault
#       log_type: audit
#     fields_under_root: false
#     # Multiline is not needed — Vault audit logs are single-line JSON
#     close_inactive: 5m
#     clean_inactive: 72h
#     harvester_buffer_size: 65536
#     max_bytes: 1048576
#
# processors:
#   - timestamp:
#       field: time
#       layouts:
#         - '2006-01-02T15:04:05.999999999Z'
#       target_field: '@timestamp'
#   - drop_fields:
#       fields: ["time"]
#       ignore_missing: true
#   - add_fields:
#       target: event
#       fields:
#         kind: event
#         category: authentication
#         module: vault
#
# output.elasticsearch:
#   hosts: ["https://elasticsearch.example.internal:9200"]
#   index: "vault-audit-%{+yyyy.MM.dd}"
#   ssl.certificate_authorities: ["/etc/pki/tls/certs/ca.crt"]
#   ssl.certificate: "/etc/pki/tls/certs/filebeat.crt"
#   ssl.key: "/etc/pki/tls/private/filebeat.key"
#   bulk_max_size: 1024
#   worker: 2
#
# setup.template.name: "vault-audit"
# setup.template.pattern: "vault-audit-*"
# setup.template.settings:
#   index.number_of_shards: 2
#   index.number_of_replicas: 1
# setup.ilm.enabled: true
# setup.ilm.policy_name: "vault-audit-policy"
# setup.ilm.rollover_alias: "vault-audit"

# ─── Logstash Pipeline (alternative to Filebeat direct) ─────────────────────
#
# File: /etc/logstash/conf.d/vault-audit.conf
#
# input {
#   # Option 1: TCP socket input (for Vault socket audit device)
#   tcp {
#     port => 5044
#     codec => json_lines
#     ssl_enabled => true
#     ssl_certificate => "/etc/pki/tls/certs/logstash.crt"
#     ssl_key => "/etc/pki/tls/private/logstash.key"
#     ssl_certificate_authorities => ["/etc/pki/tls/certs/ca.crt"]
#     ssl_client_authentication => "required"
#     tags => ["vault", "audit", "socket"]
#   }
#
#   # Option 2: Beats input (for Filebeat forwarding)
#   beats {
#     port => 5045
#     ssl_enabled => true
#     ssl_certificate => "/etc/pki/tls/certs/logstash.crt"
#     ssl_key => "/etc/pki/tls/private/logstash.key"
#     ssl_certificate_authorities => ["/etc/pki/tls/certs/ca.crt"]
#     tags => ["vault", "audit", "filebeat"]
#   }
# }
#
# filter {
#   # Parse the Vault audit JSON
#   json {
#     source => "message"
#     target => "vault"
#   }
#
#   # Extract key fields for indexing and alerting
#   if [vault][type] == "response" {
#     mutate {
#       add_field => {
#         "vault_operation"    => "%{[vault][request][operation]}"
#         "vault_path"         => "%{[vault][request][path]}"
#         "vault_remote_addr"  => "%{[vault][request][remote_address]}"
#         "vault_policies"     => "%{[vault][auth][policies]}"
#         "vault_token_type"   => "%{[vault][auth][token_type]}"
#         "vault_entity_id"    => "%{[vault][auth][entity_id]}"
#       }
#     }
#   }
#
#   # Parse timestamp
#   date {
#     match => ["[vault][time]", "ISO8601"]
#     target => "@timestamp"
#   }
#
#   # Tag failed auth attempts for alerting
#   if [vault][type] == "response" and [vault][error] {
#     mutate {
#       add_tag => ["vault_auth_failure"]
#     }
#   }
#
#   # Tag privileged operations
#   if [vault][request][path] =~ /^sys\/(seal|unseal|init|policies|auth|audit)/ {
#     mutate {
#       add_tag => ["vault_privileged_operation"]
#     }
#   }
#
#   # GeoIP enrichment on client address
#   if [vault][request][remote_address] {
#     geoip {
#       source => "[vault][request][remote_address]"
#       target => "geoip"
#     }
#   }
#
#   # Remove the raw message to save space
#   mutate {
#     remove_field => ["message"]
#   }
# }
#
# output {
#   elasticsearch {
#     hosts => ["https://elasticsearch.example.internal:9200"]
#     index => "vault-audit-%{+YYYY.MM.dd}"
#     ssl_enabled => true
#     ssl_certificate_authorities => ["/etc/pki/tls/certs/ca.crt"]
#     ssl_certificate => "/etc/pki/tls/certs/logstash.crt"
#     ssl_key => "/etc/pki/tls/private/logstash.key"
#     ilm_enabled => true
#     ilm_rollover_alias => "vault-audit"
#     ilm_policy => "vault-audit-policy"
#   }
# }

# ─── Elasticsearch Index Lifecycle Management (ILM) Policy ──────────────────
#
# Apply via Elasticsearch API:
#
# PUT _ilm/policy/vault-audit-policy
# {
#   "policy": {
#     "phases": {
#       "hot": {
#         "min_age": "0ms",
#         "actions": {
#           "rollover": {
#             "max_primary_shard_size": "25gb",
#             "max_age": "1d"
#           },
#           "set_priority": { "priority": 100 }
#         }
#       },
#       "warm": {
#         "min_age": "7d",
#         "actions": {
#           "shrink": { "number_of_shards": 1 },
#           "forcemerge": { "max_num_segments": 1 },
#           "set_priority": { "priority": 50 }
#         }
#       },
#       "cold": {
#         "min_age": "30d",
#         "actions": {
#           "set_priority": { "priority": 0 },
#           "freeze": {}
#         }
#       },
#       "delete": {
#         "min_age": "365d",
#         "actions": { "delete": {} }
#       }
#     }
#   }
# }

# ─── Elasticsearch Index Template ───────────────────────────────────────────
#
# PUT _index_template/vault-audit
# {
#   "index_patterns": ["vault-audit-*"],
#   "template": {
#     "settings": {
#       "number_of_shards": 2,
#       "number_of_replicas": 1,
#       "index.lifecycle.name": "vault-audit-policy",
#       "index.lifecycle.rollover_alias": "vault-audit"
#     },
#     "mappings": {
#       "properties": {
#         "vault.type":                    { "type": "keyword" },
#         "vault.request.operation":       { "type": "keyword" },
#         "vault.request.path":            { "type": "keyword" },
#         "vault.request.remote_address":  { "type": "ip" },
#         "vault.auth.entity_id":          { "type": "keyword" },
#         "vault.auth.token_type":         { "type": "keyword" },
#         "vault.auth.policies":           { "type": "keyword" },
#         "vault.error":                   { "type": "text" }
#       }
#     }
#   }
# }

# ─── Vault Terraform Configuration ──────────────────────────────────────────
#
# resource "vault_audit" "file" {
#   type = "file"
#
#   options = {
#     file_path      = "/vault/audit/audit.log"
#     log_raw        = "false"
#     hmac_accessor  = "true"
#     mode           = "0600"
#   }
# }
#
# resource "vault_audit" "socket_elk" {
#   type = "socket"
#   path = "socket-elk"
#
#   options = {
#     address        = "logstash.example.internal:5044"
#     socket_type    = "tcp"
#     log_raw        = "false"
#     hmac_accessor  = "true"
#   }
# }
