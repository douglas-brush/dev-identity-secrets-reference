# Workshop & Training Materials

Hands-on training workshops for the Dev Identity & Secrets Reference Architecture. Each workshop is self-contained, uses the local Docker Compose dev environment, and can be delivered independently or as a progressive series.

---

## Workshop Catalog

| # | Workshop | Duration | Audience | Prerequisites |
|---|----------|----------|----------|---------------|
| 01 | [Vault Fundamentals](01-vault-fundamentals.md) | 2 hours | All developers | Docker, terminal basics |
| 02 | [Secrets in CI/CD](02-secrets-in-cicd.md) | 2 hours | DevOps, platform engineers | Workshop 01 or Vault familiarity |
| 03 | [Incident Response with SIRM](03-incident-response-with-sirm.md) | 2 hours | Security teams, incident responders | Workshop 01, IR fundamentals |
| 04 | [SDK Development](04-sdk-development.md) | 2 hours | Application developers | Workshop 01, Python/Go/TS experience |

---

## Audience Guide

| Role | Recommended Path | Notes |
|------|-----------------|-------|
| Application developer | 01 -> 04 | Core Vault skills + SDK integration |
| DevOps / Platform engineer | 01 -> 02 | Vault fundamentals + CI/CD pipeline integration |
| Security engineer | 01 -> 02 -> 03 | Full stack from secrets through incident response |
| Security operations / IR | 01 -> 03 | Vault context + SIRM framework |
| Engineering manager | 01 (Labs 1-2 only) | Awareness-level understanding |

---

## Scheduling Guide

### Half-Day Training (4 hours)

**Option A -- Developer Focus:**
- Workshop 01: Vault Fundamentals (2h)
- Workshop 04: SDK Development (2h)

**Option B -- Platform Focus:**
- Workshop 01: Vault Fundamentals (2h)
- Workshop 02: Secrets in CI/CD (2h)

**Option C -- Security Focus:**
- Workshop 01: Vault Fundamentals (2h)
- Workshop 03: Incident Response with SIRM (2h)

### Full-Day Training (8 hours)

- Workshop 01: Vault Fundamentals (2h)
- Workshop 02: Secrets in CI/CD (2h)
- Lunch break (1h)
- Workshop 03: Incident Response with SIRM (2h)
- Workshop 04: SDK Development (2h)

### Multi-Day Deep Dive (2 days)

Day 1:
- Workshop 01: Vault Fundamentals (2h) -- extended with additional exercises
- Workshop 02: Secrets in CI/CD (2h) -- extended with real pipeline setup
- Open lab time (2h) -- participants configure their own projects

Day 2:
- Workshop 03: Incident Response with SIRM (2h) -- extended with full tabletop
- Workshop 04: SDK Development (2h) -- extended with custom tool build
- Capstone exercise (2h) -- end-to-end: build, secure, deploy, respond

---

## Environment Setup (All Workshops)

Every workshop uses the same local dev environment. Facilitators should verify this works before the session.

### Prerequisites

| Requirement | Minimum Version | Check Command |
|-------------|----------------|---------------|
| Docker | 24.0+ | `docker --version` |
| Docker Compose | 2.20+ | `docker compose version` |
| Git | 2.40+ | `git --version` |
| curl | any | `curl --version` |
| jq | 1.6+ | `jq --version` |
| Make | any | `make --version` |

**Workshop-specific additions:**

| Workshop | Additional Requirements |
|----------|----------------------|
| 02 | GitHub account, `gh` CLI, `sops`, `age` |
| 03 | `sha256sum` (or `shasum` on macOS) |
| 04 | Python 3.10+ or Go 1.22+ or Node 18+ (per chosen SDK) |

### Environment Bootstrap

```bash
# Clone the repository
git clone https://github.com/BrushCyber/dev-identity-secrets-reference.git
cd dev-identity-secrets-reference

# Start the dev environment
make dev-up        # Starts Vault + PostgreSQL + Vault Agent
make dev-setup     # Bootstraps Vault (engines, policies, AppRole, PKI, demo data)

# Verify
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=dev-root-token
vault status
```

### Environment Teardown

```bash
make dev-reset     # Destroys and recreates everything
# or
make dev-down      # Just stops containers (preserves data)
```

---

## Facilitator Notes

### Before the Workshop

1. **Test the environment** on the exact hardware/OS participants will use. Docker Desktop on macOS behaves differently from Docker on Linux.
2. **Pre-pull images** to avoid slow downloads during the session:
   ```bash
   docker pull hashicorp/vault:1.15
   docker pull postgres:16-alpine
   ```
3. **Prepare a clean clone** -- run `make dev-reset && make dev-up && make dev-setup` and verify all labs work end-to-end.
4. **Have a backup plan** -- if Docker fails, the Vault CLI can connect to a shared remote Vault dev instance. Prepare one if running for a large group.
5. **Print or share the workshop doc** -- participants should have the lab steps visible on a second screen or printed.

### During the Workshop

- **Pacing:** Each lab has a time estimate. If a lab runs long, skip the review questions rather than the verification steps.
- **Troubleshooting:** Common issues are documented at the end of each workshop. Start there before debugging live.
- **Checkpoints:** After each lab, ask 1-2 participants to share their terminal output. This catches environment issues early.
- **Pair programming:** For groups with mixed experience, pair senior and junior participants.

### After the Workshop

- Participants keep the repository clone -- all materials are self-contained.
- Point teams to the full documentation set: `docs/01-scope-purpose.md` through `docs/26-security-hardening-checklist.md`.
- Assign follow-up reading based on role (see Audience Guide above).
- Schedule a 30-minute follow-up session 2 weeks later to address implementation questions.

### Common Environment Issues

| Problem | Solution |
|---------|----------|
| Port 8200 already in use | `lsof -i :8200` to find the process; kill it or change `VAULT_PORT` in `dev/.env` |
| Port 5432 already in use | Stop local PostgreSQL: `brew services stop postgresql` or change `POSTGRES_PORT` |
| Docker containers not healthy | `docker compose -f dev/docker-compose.yml logs` to check errors |
| Vault sealed after restart | Dev mode Vault auto-unseals; if sealed, run `make dev-reset` |
| Permission denied on scripts | `chmod +x dev/scripts/*.sh tools/**/*.sh` |
| macOS `sha256sum` not found | Use `shasum -a 256` instead, or `brew install coreutils` |
