# Vault Audit Device Configuration — Splunk Integration
#
# Two complementary audit devices for resilient log delivery:
#   1. Syslog device  — real-time push to Splunk via HEC or syslog input
#   2. File device     — local log for backup/replay if syslog fails
#
# Enable via CLI after Vault is initialized and unsealed:
#
#   vault audit enable syslog \
#     tag="vault-audit" \
#     facility="AUTH" \
#     log_raw=false \
#     hmac_accessor=true \
#     mode="0600"
#
#   vault audit enable -path=file-backup file \
#     file_path="/vault/audit/audit.log" \
#     log_raw=false \
#     hmac_accessor=true \
#     mode="0600"
#
# IMPORTANT: Vault blocks requests if ALL audit devices are down.
# Always maintain at least two audit devices.

# ─── Primary: Syslog to Splunk ───────────────────────────────────────────────
#
# Option A: rsyslog forwarding to Splunk
# Configure rsyslog on the Vault host to forward auth facility to Splunk HEC:
#
#   # /etc/rsyslog.d/50-vault-audit.conf
#   auth.* action(
#     type="omhttp"
#     server="splunk-hec.example.internal"
#     serverport="8088"
#     restpath="services/collector/event"
#     httpheaderkey="Authorization"
#     httpheadervalue="Splunk YOUR-HEC-TOKEN"
#     template="VaultAuditJSON"
#     usehttps="on"
#     tls.cacert="/etc/pki/tls/certs/ca-bundle.crt"
#     action.resumeRetryCount="-1"
#     queue.type="LinkedList"
#     queue.filename="vault_audit_fwd"
#     queue.maxDiskSpace="500m"
#     queue.saveOnShutdown="on"
#   )
#
# Option B: Splunk Universal Forwarder monitoring the file audit device.
# See inputs.conf below.

# ─── Splunk inputs.conf for File Audit Device ────────────────────────────────
#
# Deploy this on the Splunk Universal Forwarder running on the Vault host.
# File: $SPLUNK_HOME/etc/apps/vault_audit/local/inputs.conf
#
# [monitor:///vault/audit/audit.log]
# disabled = false
# sourcetype = hashicorp:vault:audit
# index = vault_audit
# crcSalt = <SOURCE>
# ignoreOlderThan = 7d
#
# ─── Splunk props.conf ───────────────────────────────────────────────────────
#
# File: $SPLUNK_HOME/etc/apps/vault_audit/local/props.conf
#
# [hashicorp:vault:audit]
# SHOULD_LINEMERGE = false
# LINE_BREAKER = ([\r\n]+)
# TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6N%Z
# TIME_PREFIX = "time":"
# MAX_TIMESTAMP_LOOKAHEAD = 40
# TRUNCATE = 999999
# KV_MODE = json
# CHARSET = UTF-8
# category = Security
# description = HashiCorp Vault Audit Logs

# ─── Splunk transforms.conf ─────────────────────────────────────────────────
#
# File: $SPLUNK_HOME/etc/apps/vault_audit/local/transforms.conf
#
# [vault_auth_accessor]
# REGEX = "accessor":"([^"]+)"
# FORMAT = vault_accessor::$1

# ─── Splunk savedsearches.conf — Example Alert ──────────────────────────────
#
# File: $SPLUNK_HOME/etc/apps/vault_audit/local/savedsearches.conf
#
# [Vault - Multiple Authentication Failures]
# search = index=vault_audit type=response error!="" auth.client_token="" \
#   | stats count by auth.metadata.role, request.remote_address \
#   | where count > 10
# dispatch.earliest_time = -15m
# dispatch.latest_time = now
# cron_schedule = */5 * * * *
# alert.severity = 4
# alert_type = number of events
# alert_comparator = greater than
# alert_threshold = 0
# action.email.to = security-team@example.com
# action.email.subject = Vault Authentication Failure Spike

# ─── Vault Terraform Configuration ──────────────────────────────────────────
#
# If managing Vault audit devices via Terraform:
#
# resource "vault_audit" "syslog" {
#   type = "syslog"
#
#   options = {
#     tag            = "vault-audit"
#     facility       = "AUTH"
#     log_raw        = "false"
#     hmac_accessor  = "true"
#   }
# }
#
# resource "vault_audit" "file_backup" {
#   type = "file"
#   path = "file-backup"
#
#   options = {
#     file_path      = "/vault/audit/audit.log"
#     log_raw        = "false"
#     hmac_accessor  = "true"
#     mode           = "0600"
#   }
# }
