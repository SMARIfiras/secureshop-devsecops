# SecureShop — DevSecOps Workshop 3

A complete **microservices e-commerce platform** demonstrating a full **DevSecOps pipeline**:
SAST → SCA → Secrets Detection → Container Scanning → DAST.

---

## 🏗️ Architecture

```
    ┌──────────────────────────────────────────┐
    │  External Clients                        │
    │  (Browser / Mobile / REST Client)        │
    └──────────────────┬───────────────────────┘
                       │ HTTPS
                       ▼
     ┌─────────────────────────────────────────┐
     │          API Gateway (Nginx)            │
     └──┬──────┬──────┬──────────┬────────┬───┘
        │      │      │          │        │
        ▼      ▼      ▼          ▼        ▼
  ┌─────────┐ ┌────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐
  │  User   │ │Product │ │  Order   │ │ Payment  │ │Notification  │
  │service: │ │service:│ │ service: │ │ service: │ │  service:    │
  │  8001   │ │  8002  │ │   8003   │ │   8004   │ │    8005      │
  └─────────┘ └────────┘ └──────────┘ └────┬─────┘ └──────────────┘
                                            │
                                            ▼
                                    ┌───────────────┐
                                    │   Inventory   │
                                    │   service:    │
                                    │     8006      │
                                    └───────────────┘
```

## 📦 Services

| Service | Language | Port | Key Tech |
|---------|----------|------|----------|
| User | Python / FastAPI | 8001 | JWT, bcrypt, SQLite |
| Product | Node.js / Express | 8002 | SQLite, JWT validation |
| Order | Python / FastAPI | 8003 | RabbitMQ publish, httpx |
| Payment | Node.js / Express | 8004 | Idempotency keys, SQLite |
| Notification | Python / FastAPI | 8005 | RabbitMQ consumer thread |
| Inventory | Node.js / Express | 8006 | Atomic reserve/release, WAL |
| Gateway | Nginx | 8080 | Rate limiting, security headers |

---

## 🚀 Quick Start

### Prerequisites
- Docker ≥ 24 + Docker Compose ≥ 2.20
- Git

### Run Locally

```bash
# Clone the repository
git clone https://github.com/<your-org>/secureshop.git
cd secureshop

# Create .env (never commit this file!)
cat > .env <<EOF
JWT_SECRET=$(openssl rand -hex 32)
RABBITMQ_USER=guest
RABBITMQ_PASS=guest
EOF

# Build and start all services
docker compose up --build

# Verify all services are healthy
docker compose ps
```

### Smoke Tests

```bash
BASE=http://localhost:8080

# 1. Health check
curl $BASE/health

# 2. Register a user
curl -X POST $BASE/api/users/register \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"Alice1234!","full_name":"Alice"}'

# 3. Login → get JWT
TOKEN=$(curl -sX POST $BASE/api/users/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"Alice1234!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# 4. Browse products (public)
curl $BASE/api/products/

# 5. Search products
curl "$BASE/api/products/search?q=laptop"

# 6. Check inventory
curl $BASE/api/inventory/

# 7. Create an order (requires JWT)
curl -X POST $BASE/api/orders/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"items":[{"product_id":"laptop-pro-x1","quantity":1,"unit_price":1299.99}]}'

# 8. Initiate payment
curl -X POST $BASE/api/payments/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"order_id":"<order-id>","amount":1299.99,"method":"card"}'
```

---

## 🔒 DevSecOps Pipeline

All checks run automatically on every `push` to `main` and every Pull Request.

### Step 0 — Threat Modeling
See [`docs/threat-model.md`](docs/threat-model.md) for the full STRIDE analysis.

### Step 2 — SAST (Static Analysis)

| Tool | Target | Config | SARIF Upload |
|------|--------|--------|-------------|
| **Bandit** | Python services | `bandit.yaml` | ✅ GitHub Security tab |
| **Semgrep** | Node.js services | `p/nodejs`, `p/owasp-top-ten` | ✅ GitHub Security tab |

Workflow: [`.github/workflows/sast.yml`](.github/workflows/sast.yml)

```bash
# Run locally
pip install bandit
bandit -r services/user-service services/order-service services/notification-service -c bandit.yaml

# Semgrep (requires Docker or pip install semgrep)
semgrep --config "p/nodejs" --config "p/owasp-top-ten" services/product-service/
```

### Step 3 — SCA (Dependency Scanning)

| Tool | Scope | Fail threshold |
|------|-------|---------------|
| **OWASP Dependency-Check** | All dependency files | CVSS ≥ 9.0 |
| **Trivy fs** | Whole repository | CRITICAL CVE |

Workflow: [`.github/workflows/sca.yml`](.github/workflows/sca.yml)

```bash
# Trivy locally
trivy fs . --severity HIGH,CRITICAL
```

### Step 4 — Secrets Detection

| Tool | Method | Scope |
|------|--------|-------|
| **Gitleaks** | Pattern + ruleset | Full git history |
| **TruffleHog** | Entropy + verified patterns | Commits + filesystem |

Workflow: [`.github/workflows/secrets.yml`](.github/workflows/secrets.yml)

```bash
# Gitleaks locally (requires Docker)
docker run --rm -v "$(pwd):/repo" ghcr.io/gitleaks/gitleaks:latest \
  detect --source /repo --config /repo/.gitleaks.toml -v
```

### Step 5 — Container Image Scanning

| Tool | Role | Fail threshold |
|------|------|---------------|
| **Trivy** | Primary scanner | CRITICAL (unfixed) |
| **Grype** | Second opinion | HIGH |

Workflow: [`.github/workflows/container.yml`](.github/workflows/container.yml) — matrix strategy scans all 7 images.

```bash
# Trivy locally
docker build -t secureshop/user-service services/user-service
trivy image --severity HIGH,CRITICAL secureshop/user-service
```

### Step 6 — DAST (Dynamic Testing)

Workflow: [`.github/workflows/dast.yml`](.github/workflows/dast.yml)

1. Starts all services via `docker compose up`
2. Registers a test user and obtains JWT
3. Runs **OWASP ZAP Baseline** scan through the gateway
4. Archives HTML + SARIF reports as GitHub Actions artifacts

```bash
# Run ZAP locally against a running stack
docker compose up -d
docker run --rm --network host \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://localhost:8080 -r zap-report.html
```

### Additional: IaC + SBOM

| Workflow | Tools | Purpose |
|----------|-------|---------|
| [`iac.yml`](.github/workflows/iac.yml) | Hadolint + Checkov | Dockerfile & Compose security |
| [`sbom.yml`](.github/workflows/sbom.yml) | Syft | CycloneDX + SPDX SBOM per image |

---

## 📁 Repository Structure

```
secureshop/
├── .github/workflows/
│   ├── sast.yml          # Step 2: Bandit + Semgrep
│   ├── sca.yml           # Step 3: OWASP Dep-Check + Trivy FS
│   ├── secrets.yml       # Step 4: Gitleaks + TruffleHog
│   ├── container.yml     # Step 5: Trivy + Grype image scan
│   ├── dast.yml          # Step 6: OWASP ZAP
│   ├── iac.yml           # IaC: Hadolint + Checkov
│   └── sbom.yml          # SBOM: Syft CycloneDX/SPDX
├── .zap/rules.tsv        # ZAP alert rules (IGNORE/WARN/FAIL)
├── docs/
│   └── threat-model.md   # Step 0: STRIDE threat model
├── gateway/
│   ├── nginx.conf        # Rate limiting, security headers, routing
│   └── Dockerfile
├── services/
│   ├── user-service/     # Python/FastAPI  — JWT, bcrypt
│   ├── product-service/  # Node.js/Express — catalogue, search
│   ├── order-service/    # Python/FastAPI  — lifecycle, RabbitMQ
│   ├── payment-service/  # Node.js/Express — idempotency, transactions
│   ├── notification-service/ # Python/FastAPI — RabbitMQ consumer
│   └── inventory-service/    # Node.js/Express — atomic stock mgmt
├── docker-compose.yml    # Full stack + healthchecks
├── bandit.yaml           # Bandit SAST config
├── .gitleaks.toml        # Gitleaks rules + allowlist
├── .semgrepignore        # Semgrep exclusions
└── .gitignore
```

---

## 🔐 Security Design Decisions

| Decision | Rationale |
|----------|-----------|
| JWT validated at each service | Defense-in-depth; gateway compromise doesn't bypass auth |
| bcrypt cost factor 12 | Balances security vs. latency for workshop |
| WAL mode for Inventory SQLite | Enables concurrent readers + atomic reserve/release |
| `no-new-privileges: true` | Prevents privilege escalation in containers |
| `server_tokens off` in Nginx | Hides version information |
| Rate limiting at gateway | 100 req/min per IP with burst=20 |
| Secrets via env vars | No hard-coded credentials; `.env` in `.gitignore` |

---

## 📋 Workshop Steps Summary

| Step | Name | Status |
|------|------|--------|
| 0 | Threat Modeling (STRIDE) | ✅ `docs/threat-model.md` |
| 1 | Project Setup | ✅ This repository |
| 2 | SAST | ✅ `sast.yml` — Bandit + Semgrep |
| 3 | SCA | ✅ `sca.yml` — Dep-Check + Trivy |
| 4 | Secrets Detection | ✅ `secrets.yml` — Gitleaks + TruffleHog |
| 5 | Container Scanning | ✅ `container.yml` — Trivy + Grype |
| 6 | DAST | ✅ `dast.yml` — OWASP ZAP |
| + | IaC Scanning | ✅ `iac.yml` — Hadolint + Checkov |
| + | SBOM Generation | ✅ `sbom.yml` — Syft |
