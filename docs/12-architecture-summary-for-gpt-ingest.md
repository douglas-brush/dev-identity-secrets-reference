# Architecture Summary for GPT Ingest

## Purpose

Provide a reusable reference architecture for centralized identity, PKI, secrets, and credential management across developer workstations, CI, Kubernetes, VMs, and internal administrative operations.

## Core architecture summary

- Human identity is centralized in the IdP.
- Device trust is reinforced through MDM / posture.
- Secrets and dynamic credentials are issued from a central broker.
- Repository-stored secrets are encrypted with SOPS and master keys from centralized KMS.
- CI authenticates using OIDC federation, not stored secrets.
- Kubernetes retrieves secrets using operator sync or CSI, depending on sensitivity and application design.
- Certificates are centrally issued through a private PKI path and delivered with lifecycle control.
- SSH access is short-lived and centrally revocable.

## Important design principles

- no static human cloud keys
- no plaintext secrets in source control
- no shared unmanaged admin keys
- no collapsed trust domains
- no break-glass path without tests
