# Workshop 3: DevSecOps — Complete Answers Report
## SecureShop Microservices Platform

---

## Step 0 — Threat Modeling

### Methodology: STRIDE

STRIDE is a threat classification model developed by Microsoft. Each letter represents a category of threat:

| Letter | Threat | Security Property Violated |
|--------|--------|---------------------------|
| **S** | Spoofing | Authentication |
| **T** | Tampering | Integrity |
| **R** | Repudiation | Non-repudiation |
| **I** | Information Disclosure | Confidentiality |
| **D** | Denial of Service | Availability |
| **E** | Elevation of Privilege | Authorization |

### Data Flow Diagram

```
[Browser/Mobile] ──HTTPS──► [Nginx Gateway]
                                   │
        ┌──────────────────────────┼──────────────────────────┐
        │              │           │           │              │
        ▼              ▼           ▼           ▼              ▼
 [User Svc      [Product     [Order       [Payment      [Notification
  :8001]         Svc:8002]    Svc:8003]    Svc:8004]     Svc:8005]
   (Python)       (Node.js)    (Python)     (Node.js)     (Python)
                                  │               │
                             [RabbitMQ]     [Inventory
                                  │          Svc:8006]
                                  ▼          (Node.js)
                            [Notification
                              Svc:8005]
```

### Key Threats & Mitigations

| Service | STRIDE Threat | Mitigation Implemented |
|---------|--------------|----------------------|
| Gateway | DoS — request flood | `limit_req_zone`: 100 req/min/IP |
| Gateway | Info Disclosure — version leak | `server_tokens off` |
| User Svc | Spoofing — brute-force login | Rate limit on `/login`; bcrypt cost 12 |
| User Svc | Tampering — JWT forgery | HS256 with 256-bit secret; 1h expiry |
| Order Svc | Tampering — price manipulation | Price fetched server-side from Product Svc |
| Order Svc | Elevation — IDOR | JWT `sub` checked against order `user_id` |
| Payment Svc | Spoofing — replay attack | Idempotency key per transaction |
| Inventory Svc | Tampering — race condition | SQLite WAL + atomic SQL `WHERE available >= qty` |
| All services | Info Disclosure — secrets in code | Env-var injection; Gitleaks CI scan |

### Residual Risks (accepted for workshop scope)

- No mTLS between microservices (mitigate with service mesh in production)
- RabbitMQ uses default credentials (replace via Vault in production)
- SQLite not suitable for high-concurrency production load

---

## Step 1 — Project Setup & Repository Structure

### Repository Layout

```
secureshop/
├── .github/
│   └── workflows/
│       ├── sast.yml           # Step 2 — Bandit + Semgrep
│       ├── sca.yml            # Step 3 — OWASP Dep-Check + Trivy FS
│       ├── secrets.yml        # Step 4 — Gitleaks + TruffleHog
│       ├── container.yml      # Step 5 — Trivy + Grype image scan
│       ├── dast.yml           # Step 6 — OWASP ZAP
│       ├── iac.yml            # IaC — Hadolint + Checkov
│       └── sbom.yml           # SBOM — Syft CycloneDX/SPDX
├── .zap/rules.tsv             # ZAP alert rules (IGNORE/WARN/FAIL)
├── docs/
│   ├── threat-model.md        # Step 0
│   └── workshop-report.md     # This file
├── gateway/
│   ├── nginx.conf             # Rate limiting, routing, security headers
│   └── Dockerfile
├── services/
│   ├── user-service/          # Python/FastAPI — JWT, bcrypt
│   ├── product-service/       # Node.js/Express — catalogue
│   ├── order-service/         # Python/FastAPI — lifecycle + RabbitMQ
│   ├── payment-service/       # Node.js/Express — idempotency
│   ├── notification-service/  # Python/FastAPI — RabbitMQ consumer
│   └── inventory-service/     # Node.js/Express — atomic stock
├── docker-compose.yml
├── bandit.yaml
├── .gitleaks.toml
└── .semgrepignore
```

### Technology Stack Justification

**Two programming languages** were chosen to demonstrate that DevSecOps tooling must cover a polyglot codebase:

| Language | Services | SAST Tool | SCA Tool |
|----------|----------|-----------|----------|
| Python 3.12 / FastAPI | User, Order, Notification | **Bandit** | OWASP Dep-Check + Trivy |
| Node.js 20 / Express | Product, Payment, Inventory | **Semgrep** (`p/nodejs`) | OWASP Dep-Check + Trivy |

### Running the Stack

```bash
# 1. Generate a strong JWT secret
JWT_SECRET=$(openssl rand -hex 32)

# 2. Create .env (never commit this)
echo "JWT_SECRET=$JWT_SECRET" > .env
echo "RABBITMQ_USER=guest"   >> .env
echo "RABBITMQ_PASS=guest"   >> .env

# 3. Build and start all containers
docker compose up --build -d

# 4. Verify health
curl http://localhost:8080/health
# → {"gateway":"ok"}

docker compose ps
# All services should show "healthy"
```

---

## Step 2 — SAST (Static Application Security Testing)

### What is SAST?

SAST analyses **source code without executing it**, looking for insecure coding patterns such as SQL injection, hard-coded credentials, use of weak cryptography, and dangerous API usage. It runs early in the pipeline (shift-left) before any build or deployment.

### Tools Used

#### 2.1 Bandit — Python Services

Bandit is purpose-built for Python. It traverses the AST and applies a library of security plugins (e.g., B105 hard-coded passwords, B602 `subprocess` shell injection, B324 weak hash).

**Run locally:**
```bash
pip install bandit bandit-sarif-formatter

# Scan all Python services
bandit \
  -r services/user-service/main.py \
     services/order-service/main.py \
     services/notification-service/main.py \
  -c bandit.yaml \
  --severity-level medium \
  -f txt
```

**Example finding (B105 — Hardcoded Password Default):**
```
>> Issue: [B105:hardcoded_password_string] Possible hardcoded password: 'dev-secret-change-me'
   Severity: Low   Confidence: Medium
   Location: services/user-service/main.py:14
   More Info: https://bandit.readthedocs.io/en/latest/plugins/b105_hardcoded_password_string.html
```

**Why this is flagged & how to fix it:**
The `os.environ.get("JWT_SECRET", "dev-secret-change-me")` fallback is intentionally flagged. In production, the environment variable must always be set (no default), and the code should raise an error if missing:
```python
SECRET_KEY = os.environ["JWT_SECRET"]  # raises KeyError if not set → fail fast
```
The `# nosec B105` comment suppresses the finding in CI where the default is a known workshop placeholder.

**SARIF output** is uploaded to the **GitHub Security → Code scanning** tab automatically by the workflow.

#### 2.2 Semgrep — Node.js Services

Semgrep uses pattern-matching rules that operate on the AST. The `p/nodejs` and `p/owasp-top-ten` rule packs cover injection, path traversal, prototype pollution, and more.

**Run locally:**
```bash
# Via Docker (no install needed)
docker run --rm -v "$(pwd):/src" semgrep/semgrep:latest \
  semgrep \
  --config "p/nodejs" \
  --config "p/owasp-top-ten" \
  --config "p/secrets" \
  /src/services/product-service/ \
  /src/services/payment-service/ \
  /src/services/inventory-service/
```

**Example finding (hardcoded secret default):**
```
services/product-service/index.js:13
  const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  javascript.jwt.security.jwt-hardcoded-secret.jwt-hardcoded-secret
  Hardcoded JWT secret. Consider using an environment variable.
```

**GitHub Actions workflow** (`sast.yml`): Both Bandit and Semgrep run in parallel jobs. SARIF files are uploaded to the GitHub Security tab using `github/codeql-action/upload-sarif`.

### SAST Results Summary

| Finding | Tool | Severity | Status |
|---------|------|----------|--------|
| Hardcoded JWT secret default | Bandit B105 | Low | Suppressed (`nosec`) — workshop placeholder |
| Hardcoded RabbitMQ URL default | Bandit B106 | Low | Suppressed — workshop placeholder |
| JWT secret default in Node.js | Semgrep | Warning | Workshop placeholder; env var takes precedence |
| No findings in business logic | Both | — | SQL uses parameterised queries throughout |

---

## Step 3 — SCA (Software Composition Analysis)

### What is SCA?

SCA identifies **known vulnerabilities (CVEs)** in third-party libraries and frameworks used by the application. Unlike SAST, SCA does not read application logic — it compares dependency manifests (`requirements.txt`, `package.json`) against the National Vulnerability Database (NVD).

### Tools Used

#### 3.1 OWASP Dependency-Check

Matches dependency names and versions against the NVD CVE database.

**Run locally:**
```bash
# Via Docker
docker run --rm \
  -v "$(pwd):/src" \
  -v "$(pwd)/reports:/report" \
  owasp/dependency-check:latest \
  --project "SecureShop" \
  --scan /src \
  --format HTML \
  --format SARIF \
  --out /report \
  --failOnCVSS 9
```

**Reading the HTML report:**  
Open `reports/dependency-check-report.html`. Key columns:
- **Dependency** — the library file
- **CVE** — vulnerability identifier
- **CVSS Score** — 0–10; ≥ 9.0 = CRITICAL (pipeline fail threshold)
- **Evidence** — how the tool matched the dependency

**Example output (illustrative):**
```
Dependency: express-4.19.2.tgz
  CVE-2024-XXXX  CVSS: 5.3  Medium
  Description: Open redirect vulnerability in Express...
  Solution: Upgrade to express >=4.19.3
```

#### 3.2 Trivy Filesystem Scan

Trivy scans all dependency files in the repository in seconds.

**Run locally:**
```bash
trivy fs . \
  --severity HIGH,CRITICAL \
  --format table

# Example output:
# ┌──────────────────────┬──────────────────┬──────────┬────────┐
# │ Library              │ Vulnerability    │ Severity │ Fixed  │
# ├──────────────────────┼──────────────────┼──────────┼────────┤
# │ python-jose 3.3.0    │ CVE-2024-33664   │ HIGH     │ No fix │
# └──────────────────────┴──────────────────┴──────────┴────────┘
```

**Note on `python-jose`:** CVE-2024-33664 (algorithm confusion attack) exists in `python-jose`. For production, migrate to `PyJWT` with `algorithms=["HS256"]` explicitly enforced. This finding is left in place intentionally to demonstrate the SCA pipeline catching a real vulnerability.

### SCA Results Summary

| Dependency | CVE | Severity | Action |
|------------|-----|----------|--------|
| `python-jose 3.3.0` | CVE-2024-33664 | HIGH | Migrate to `PyJWT` in production |
| Node.js `express 4.19.x` | — | No critical at time of writing | Monitor daily via scheduled workflow |
| `pika 1.3.2` | — | No critical | Monitor |

**Scheduled scan:** The `sca.yml` workflow includes a `schedule: cron: "0 2 * * *"` trigger to catch newly published CVEs even without a code push.

---

## Step 4 — Secrets Detection

### What are Hardcoded Secrets?

Hard-coded API keys, passwords, and tokens committed to source control are one of the most exploited vulnerability classes. Once in git history, a secret persists even after it is "deleted" from the latest commit.

### Tools Used

#### 4.1 Gitleaks — Git History Scanning

Gitleaks scans the entire git history using regex patterns and entropy analysis.

**Run locally:**
```bash
# Scan working directory
docker run --rm -v "$(pwd):/repo" \
  ghcr.io/gitleaks/gitleaks:latest \
  detect \
  --source /repo \
  --config /repo/.gitleaks.toml \
  --verbose

# Example clean output:
#   ○
#   │╲
#   │ ○
#   ○ ░
#   ░    gitleaks
#
# 4:11PM INF 15 commits scanned.
# 4:11PM INF scan completed in 348ms
# 4:11PM INF no leaks found
```

**Custom rules in `.gitleaks.toml`:**
- `jwt-secret-env` — flags `JWT_SECRET = "..."` patterns not from environment
- `rabbitmq-password` — flags `amqp://user:password@...` patterns
- Allowlist for known workshop placeholder strings

#### 4.2 TruffleHog — Entropy + Pattern Scanning

TruffleHog uses both regex patterns and Shannon entropy to detect secrets that don't match known patterns.

**Run locally:**
```bash
docker run --rm -v "$(pwd):/repo" \
  trufflesecurity/trufflehog:latest \
  filesystem /repo \
  --only-verified \
  --json | python3 -m json.tool
```

**Key difference from Gitleaks:**
- Gitleaks: fast pattern matching against known secret formats
- TruffleHog: entropy scoring catches *unknown* secret types (random-looking strings)

### Secrets Best Practices Implemented

```bash
# ✅ Correct: secret from environment variable
SECRET_KEY = os.environ.get("JWT_SECRET")

# ❌ Wrong: hardcoded secret (would be caught by Gitleaks)
SECRET_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# ✅ Correct: .env in .gitignore — never committed
echo ".env" >> .gitignore

# ✅ Correct: CI uses GitHub Actions secrets
# In workflow: ${{ secrets.JWT_SECRET }}
```

### How to Remediate a Leaked Secret

1. **Immediately revoke** the exposed secret at the provider (JWT secret → rotate; API key → invalidate)
2. **Remove from history** using `git filter-repo` or BFG Repo Cleaner
3. **Audit access logs** for the period the secret was exposed
4. **Add to `.gitleaks.toml` allowlist** only if it is a known non-sensitive placeholder

---

## Step 5 — Container Image Scanning

### Why Scan Container Images?

A Docker image bundles:
1. **OS base layer** (e.g., `python:3.12-slim`) — contains system packages with potential CVEs
2. **Application dependencies** — same as SCA, but resolved inside the image
3. **Application code** — already covered by SAST

Container scanning catches CVEs in the OS layer that SCA misses.

### Tools Used

#### 5.1 Trivy — Primary Scanner

**Run locally (after building an image):**
```bash
# Build the image
docker build -t secureshop/user-service:local services/user-service/

# Scan it
trivy image \
  --severity HIGH,CRITICAL \
  --ignore-unfixed \
  secureshop/user-service:local
```

**Example output:**
```
secureshop/user-service:local (debian 12.5)
==========================================
Total: 3 (HIGH: 2, CRITICAL: 1)

┌──────────────┬──────────────────┬──────────┬───────────┬──────────────────────────┐
│   Library    │  Vulnerability   │ Severity │ Installed │         Fixed In         │
├──────────────┼──────────────────┼──────────┼───────────┼──────────────────────────┤
│ libssl3      │ CVE-2024-XXXXX   │ CRITICAL │ 3.0.11    │ 3.0.13                   │
│ zlib1g       │ CVE-2023-XXXXX   │ HIGH     │ 1:1.2.13  │ Will not fix             │
└──────────────┴──────────────────┴──────────┴───────────┴──────────────────────────┘
```

**`--ignore-unfixed` flag:** Only fails the pipeline on vulnerabilities that have a patch available. Unfixed CVEs are reported but do not block deployment.

#### 5.2 Grype — Second Opinion (Anchore)

Grype uses the Anchore vulnerability database and provides a useful cross-reference.

```bash
# Install Grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
  | sh -s -- -b /usr/local/bin

# Scan
grype secureshop/user-service:local --output table
```

**Why two tools?** Different databases → different coverage. A CVE missed by Trivy might be caught by Grype and vice versa.

### Container Security Best Practices Applied

| Best Practice | Implementation |
|--------------|----------------|
| Non-root user | `RUN useradd -r appuser` + `USER appuser` in all Dockerfiles |
| Minimal base image | `python:3.12-slim` / `node:20-slim` (not `latest` or full) |
| Pinned base image tag | `python:3.12-slim` not `python:latest` |
| No secrets in image | All secrets via env vars at runtime |
| `no-new-privileges` | `security_opt: - no-new-privileges:true` in docker-compose |
| Healthchecks | `HEALTHCHECK` instruction in every Dockerfile |
| Hadolint compliance | IaC workflow runs Hadolint on all Dockerfiles |

### GitHub Actions Matrix Strategy

The `container.yml` workflow uses a **matrix strategy** to scan all 7 images in parallel:

```yaml
matrix:
  service:
    - { name: user-service,         context: services/user-service }
    - { name: product-service,      context: services/product-service }
    - { name: order-service,        context: services/order-service }
    - { name: payment-service,      context: services/payment-service }
    - { name: notification-service, context: services/notification-service }
    - { name: inventory-service,    context: services/inventory-service }
    - { name: gateway,              context: gateway }
```

Each job: **Build → Trivy (SARIF) → Grype (SARIF) → Trivy fail on CRITICAL**

---

## Step 6 — DAST (Dynamic Application Security Testing)

### What is DAST?

DAST interacts with a **running application** — sending crafted HTTP requests and analysing responses — to find vulnerabilities that SAST cannot detect:

| Vulnerability | Why SAST misses it | How DAST finds it |
|--------------|-------------------|--------------------|
| SQL Injection | Logic depends on runtime DB state | Sends `' OR 1=1--` payloads; observes DB errors |
| XSS (Reflected) | Depends on how response is rendered | Injects `<script>alert(1)</script>`; checks echo |
| Auth weaknesses | Depends on JWT library behaviour | Tests missing/malformed/expired tokens |
| CORS misconfiguration | Runtime server config | Sends cross-origin requests; checks headers |

### Tool: OWASP ZAP

OWASP ZAP (Zed Attack Proxy) is the industry standard open-source DAST tool.

### CI Workflow (`dast.yml`)

The workflow follows this sequence:

```
1. docker compose up --build    ← Start all 8 containers
2. Wait for /health → 200       ← Readiness probe (30 attempts × 5s)
3. POST /api/users/register     ← Create ZAP test account
4. POST /api/users/login        ← Obtain JWT
5. ZAP Baseline Scan            ← Passive + active scan with JWT header
6. ZAP API Scan                 ← OpenAPI spec scan (Swagger /docs)
7. Upload SARIF + HTML reports  ← GitHub Security tab + Artifacts
8. docker compose down -v       ← Cleanup
```

### Running ZAP Locally

```bash
# 1. Start the stack
docker compose up -d

# 2. Get a JWT
TOKEN=$(curl -sX POST http://localhost:8080/api/users/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@secureshop.local","password":"Admin1234!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# 3. Run ZAP Baseline scan
docker run --rm \
  --network host \
  -v "$(pwd)/zap-reports:/zap/wrk" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py \
  -t http://localhost:8080 \
  -r /zap/wrk/zap-report.html \
  -J /zap/wrk/zap-report.json \
  -H "Authorization: Bearer $TOKEN"

# 4. Open the report
open zap-reports/zap-report.html   # macOS
# Or: start zap-reports\zap-report.html  (Windows)
```

### Reading the ZAP Report

The HTML report categorises findings by **Risk** (High / Medium / Low / Informational):

| Risk | Example Alert | Action |
|------|--------------|--------|
| 🔴 High | SQL Injection | Fix immediately — pipeline FAIL |
| 🔴 High | Remote OS Command Injection | Fix immediately — pipeline FAIL |
| 🟠 Medium | CSP header missing | Add `Content-Security-Policy` header |
| 🟡 Low | Cookie without Secure flag | Set `Secure` flag on cookies |
| ℹ️ Info | Server leaks info in headers | `server_tokens off` (already set) |

**`.zap/rules.tsv`** configures alert handling per rule ID:
- `FAIL` — SQLi, XSS, RCE → pipeline fails
- `WARN` — CSP, cookies → reported but pipeline continues
- `IGNORE` — known false positives for this architecture

### Expected ZAP Findings for SecureShop

| Alert | Risk | Root Cause | Fix |
|-------|------|-----------|-----|
| Missing Anti-clickjacking | Medium | Nginx missing `X-Frame-Options` | Already added: `add_header X-Frame-Options "DENY"` |
| CSP not set | Medium | API returns JSON, no CSP needed | Gateway has `Content-Security-Policy: default-src 'none'` |
| No rate limit on login | Medium | ZAP sees HTTP 200 on repeated attempts | Gateway `limit_req` applies globally |
| JWT in Authorization header | Info | Standard OAuth2 bearer pattern | Expected; not a finding |

---

## DevSecOps Pipeline Summary

```
 ┌─────────────────────────────────────────────────────────────────────┐
 │                    GitHub Actions CI/CD Pipeline                    │
 │                                                                     │
 │  git push / PR                                                      │
 │       │                                                             │
 │       ├──► sast.yml ──────► Bandit (Python) + Semgrep (Node.js)    │
 │       │                     └── SARIF → GitHub Security tab         │
 │       │                                                             │
 │       ├──► sca.yml ───────► OWASP Dep-Check + Trivy FS             │
 │       │                     └── SARIF → GitHub Security tab         │
 │       │                                                             │
 │       ├──► secrets.yml ───► Gitleaks + TruffleHog                  │
 │       │                     └── SARIF → GitHub Security tab         │
 │       │                                                             │
 │       ├──► iac.yml ────────► Hadolint + Checkov                    │
 │       │                     └── SARIF → GitHub Security tab         │
 │       │                                                             │
 │       ├──► container.yml ─► Build → Trivy + Grype (×7 images)      │
 │       │                     └── SARIF → GitHub Security tab         │
 │       │                                                             │
 │       ├──► dast.yml ───────► docker-compose up → ZAP scan          │
 │       │                     └── HTML + SARIF → Artifacts            │
 │       │                                                             │
 │       └──► sbom.yml ───────► Syft → CycloneDX + SPDX (×6 images)  │
 │                              └── JSON → Artifacts (90 days)         │
 └─────────────────────────────────────────────────────────────────────┘
```

### Tool Mapping to Workshop Steps

| Workshop Step | Tool(s) | Language Coverage | Output |
|--------------|---------|------------------|--------|
| Step 2 — SAST | Bandit, Semgrep | Python ✅, Node.js ✅ | SARIF |
| Step 3 — SCA | OWASP Dep-Check, Trivy FS | All languages ✅ | SARIF + HTML |
| Step 4 — Secrets | Gitleaks, TruffleHog | Language-agnostic ✅ | SARIF + JSON |
| Step 5 — Container | Trivy, Grype | OS + app layers ✅ | SARIF |
| Step 6 — DAST | OWASP ZAP | Runtime (black-box) ✅ | HTML + SARIF |
| + IaC | Hadolint, Checkov | Dockerfile, Compose ✅ | SARIF |
| + SBOM | Syft | All images ✅ | CycloneDX + SPDX |

### Viewing Results in GitHub

1. Navigate to your repository → **Security** tab → **Code scanning**
2. All SARIF uploads appear here, filterable by tool, severity, and file
3. Each finding links directly to the offending line of code
4. Dismiss findings with a rationale (false positive / risk accepted / fix in progress)

---

## Conclusion

This workshop demonstrates how a **polyglot microservices platform** (Python + Node.js) can be secured at every stage of the software development lifecycle:

- **Shift-left**: SAST and SCA run on every commit, before any deployment
- **Secrets hygiene**: Two tools with different detection methods scan the full git history
- **Supply chain security**: Container images scanned with two independent tools + SBOM generated for traceability
- **Runtime validation**: DAST finds what static analysis cannot — real HTTP interactions reveal authentication gaps, injection vulnerabilities, and misconfigured headers
- **Infrastructure as Code**: Dockerfiles and Compose files are linted for security misconfigurations before images are even built

The **defence-in-depth** approach — where each microservice validates JWTs independently, the gateway enforces rate limits, and every container runs as a non-root user — ensures that no single control failure leads to a complete system compromise.
