# SecureShop — Threat Model (STRIDE)

## 1. System Overview

SecureShop is a microservices e-commerce platform. All external traffic enters via an Nginx API Gateway. Internal services communicate over a private Docker network (`secureshop-net`). An optional RabbitMQ broker handles asynchronous Order→Notification events.

---

## 2. Assets

| Asset | Sensitivity |
|-------|-------------|
| User credentials (passwords, tokens) | CRITICAL |
| JWT signing secret | CRITICAL |
| Payment transaction data | CRITICAL |
| Customer PII (email, address) | HIGH |
| Product & inventory data | MEDIUM |
| Order history | HIGH |
| RabbitMQ credentials | HIGH |

---

## 3. Trust Boundaries

```
[Internet] ──HTTPS──► [Nginx Gateway :443/80]
                              │
         ┌────────────────────┼────────────────────────┐
         │            │       │          │              │
         ▼            ▼       ▼          ▼              ▼
[User Svc :8001] [Prod :8002] [Order :8003] [Payment :8004] [Notif :8005]
                                                   │
                                                   ▼
                                         [Inventory Svc :8006]

[Order :8003] ──RabbitMQ──► [Notification Svc :8005]
[Order :8003] ──HTTP──► [Inventory Svc :8006]  (stock reservation)
```

Trust zones:
- **Zone 0 (Untrusted):** Internet / External clients
- **Zone 1 (DMZ):** Nginx API Gateway
- **Zone 2 (Trusted Internal):** All microservices on `secureshop-net`
- **Zone 3 (Data):** SQLite files, RabbitMQ queues

---

## 4. STRIDE Analysis

### 4.1 API Gateway (Nginx)

| STRIDE | Threat | Mitigation |
|--------|--------|-----------|
| **S**poofing | Attacker bypasses gateway, calls services directly | Services only bind to internal Docker network; gateway validates JWT |
| **T**ampering | HTTP request smuggling | Nginx patched version; `proxy_pass` with strict headers |
| **R**epudiation | No access logs | Nginx `access_log` to stdout; collected by Docker logging driver |
| **I**nformation Disclosure | Error pages leak version info | `server_tokens off;` in nginx.conf |
| **D**enial of Service | Flood of requests | Rate limiting: 100 req/min per IP (`limit_req_zone`) |
| **E**levation of Privilege | Unauthenticated access to protected routes | JWT validation on every non-public route |

### 4.2 User Service

| STRIDE | Threat | Mitigation |
|--------|--------|-----------|
| **S**poofing | Credential stuffing / brute force | Rate limiting at gateway; account lockout logic |
| **T**ampering | JWT forgery | HS256 with 256-bit secret; token expiry 1 h |
| **R**epudiation | Deny actions performed | Structured audit log per request |
| **I**nformation Disclosure | Password leak in logs | Passwords hashed with bcrypt (cost 12); never logged |
| **D**enial of Service | Registration flood | Rate limit on `/register` endpoint |
| **E**levation of Privilege | Horizontal privilege escalation | User ID taken from verified JWT, never from request body |

### 4.3 Order Service

| STRIDE | Threat | Mitigation |
|--------|--------|-----------|
| **S**poofing | User A accesses User B orders | JWT sub claim checked against order owner |
| **T**ampering | Price manipulation via crafted payload | Price always fetched from Product Service, not client |
| **I**nformation Disclosure | Order data returned for wrong user | Row-level filtering by `user_id` from JWT |
| **D**enial of Service | Order flood | Rate limiting + inventory reservation check |

### 4.4 Payment Service

| STRIDE | Threat | Mitigation |
|--------|--------|-----------|
| **S**poofing | Replay attack with old transaction | Idempotency key per transaction; timestamp validation |
| **T**ampering | Amount tampering in transit | Amount validated server-side from Order Service |
| **I**nformation Disclosure | PAN / card data in logs | No card data stored (payment processor handles PCI) |
| **E**levation of Privilege | Initiate payment for another user's order | Order ownership verified before payment initiation |

### 4.5 Notification Service

| STRIDE | Threat | Mitigation |
|--------|--------|-----------|
| **S**poofing | Malicious messages injected in RabbitMQ | RabbitMQ credentials required; internal network only |
| **T**ampering | Message body modification | Message schema validation on consumption |
| **D**enial of Service | Queue flood causing memory exhaustion | Queue max-length and TTL configured |

### 4.6 Inventory Service

| STRIDE | Threat | Mitigation |
|--------|--------|-----------|
| **T**ampering | Negative stock manipulation | Server-side stock validation; atomic reserve/release |
| **D**enial of Service | Reservation exhaustion | Reservation TTL; automatic release on order failure |

---

## 5. Mitigations Mapped to DevSecOps Controls

| Mitigation | DevSecOps Control |
|-----------|------------------|
| No hard-coded secrets | Gitleaks + TruffleHog (Step 4) |
| No vulnerable dependencies | OWASP Dependency-Check + Trivy (Step 3) |
| No insecure code patterns (SQLi, command injection) | Bandit + Semgrep SAST (Step 2) |
| No vulnerable OS packages in images | Trivy + Grype container scan (Step 5) |
| No runtime XSS / injection vulnerabilities | OWASP ZAP DAST (Step 6) |
| Secure Dockerfile best practices | Hadolint + Checkov (Step 6 IaC) |
| Known CVEs in infra (Nginx, RabbitMQ) | Trivy image scan (Step 5) |

---

## 6. Residual Risks

- RabbitMQ TLS not configured (workshop scope; production must use TLS + mutual auth)
- SQLite not suitable for production concurrency; replace with PostgreSQL
- JWT secret stored as Docker env var (acceptable for workshop; production → Vault)
- No mTLS between microservices (service mesh recommended for production)
