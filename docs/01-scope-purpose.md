# Scope and Purpose

## Purpose

This project establishes a **foundational security architecture** for development environments, platform tooling, and administrative operations where centralized key management and credential management are mandatory.

The purpose is not merely to “store secrets better.” The purpose is to replace unstable, person-dependent, and opaque trust practices with a model that is:

- centrally governed
- short-lived by default
- auditable
- adaptable to hybrid environments
- realistic for daily developer workflows

## Problem this project solves

Most organizations fail in the same predictable ways:

- developers keep local API keys and SSH keys indefinitely
- CI/CD systems rely on stored static secrets
- Kubernetes accumulates unmanaged secrets
- service credentials live far longer than the workloads that need them
- certificate issuance is inconsistent and poorly tracked
- one operator becomes the hidden break-glass plan

This project removes those patterns.

## In-scope capabilities

- centralized human and machine credential management
- internal certificate issuance and lifecycle automation
- encrypted configuration and secrets in Git using SOPS
- short-lived secrets for CI, Kubernetes, VMs, and application services
- SSH access that does not depend on a single private key owner
- break-glass and escrow design that is controlled, logged, and tested

## Out-of-scope items for the first iteration

- full enterprise PAM replacement
- public PKI and external website TLS
- every possible platform integration on day one
- “passwordless everywhere” for all users and apps before core workflows are stable

## Design intent

The design intent is to produce a platform that is:

- secure enough to survive compromise assumptions
- simple enough that engineers will actually use it
- modular enough to support Microsoft-heavy, hybrid, and multi-cloud environments
- documented well enough that a future operator can inherit it without guesswork

## Primary architecture statement

The architecture is built around the idea that **identity, keys, credentials, and secret delivery are separate concerns that must be coordinated but not collapsed into one opaque product decision**.

That means:

- identity providers control who
- device management influences trust
- secret managers control what can be retrieved
- KMS/HSM systems protect master cryptographic material
- PKI systems issue certificates under explicit policy
- runtime delivery components move secrets and certs into applications under least privilege

## Delivery approach

This work is treated as agile infrastructure and security architecture:

- define the operating model
- build the MVP
- validate through pilots
- review conflicts and friction
- expand only after proving core flows work
