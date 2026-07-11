# target-service

**THE SAFETY BOUNDARY** for the Scantinel security-scanning platform.

This service owns target registration, proof-of-ownership verification, authorization scope, and the discovered asset inventory. No intrusive scan phase (port scans, credential-resilience tests, active web exploitation, AI agent probing) may proceed until `POST /internal/v1/scope/check` returns `{"authorized": true}`.

## Why it exists as a separate service

Isolating the authorization gate makes it auditable and hard to accidentally bypass (see `06_AUTHORIZATION_AND_SAFETY.md`). Every other Scantinel service — especially `scan-service` and `agent-service` — is a client of this gate.

## Endpoints

### Customer-facing (via Traefik `/api/target`, prefix stripped)

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/targets` | Register a domain/URL/IP/CIDR target. Returns verification challenge token. |
| `GET` | `/v1/targets` | List caller's targets + verification status. |
| `GET` | `/v1/targets/{uid}` | Target detail + current authorized scope. |
| `POST` | `/v1/targets/{uid}/verify` | Trigger ownership verification (DNS TXT / HTTP file / meta tag). |
| `DELETE` | `/v1/targets/{uid}` | Remove target and its scope. |
| `GET` | `/v1/targets/{uid}/assets` | Discovered asset inventory (subdomains/IPs/ports/services). |

### Cluster-internal only (NetworkPolicy; NOT via Traefik)

| Method | Path | Callers | Description |
|---|---|---|---|
| `POST` | `/internal/v1/scope/check` | scan-service, agent-service | **The gate.** `{target_uid, host\|ip, phase}` → `{authorized, reason}`. |
| `POST` | `/internal/v1/targets/{uid}/assets` | scan-service | Upsert recon-discovered assets into inventory. |

## Scope model (06 §3)

- **Registrable-domain scope**: verifying `example.com` authorizes `example.com` and all subdomains. A different TLD (`example.net`) requires separate verification.
- **IP-range scope**: IP/CIDR targets require RIR-registered registry-contact confirmation. DNS/HTTP tokens on a website do NOT authorize scanning arbitrary IPs.
- **Shared-infra exclusion**: known CDN/PaaS ranges (Cloudflare, Fastly, Akamai, …) are always denied for intrusive testing even if they resolve from a verified host.

## Verification methods (06 §2)

1. **DNS TXT** — add `scantinel-verify=<token>` TXT record (real DNS lookup at verify time).
2. **HTTP file** — serve `GET /.well-known/scantinel-verify/<token>` returning the token (real HTTP fetch).
3. **HTML meta tag** — add `<meta name="scantinel-verify" content="<token>">` to homepage (real HTTP fetch).
4. **Email challenge** / **IP registry contact** — async/manual; confirmed out-of-band.

Authorizations expire after 60 days and must be re-verified periodically.

## Module layout

```
target-service/
├── cmd/target-service/main.go          # bootstrap (port 8080)
├── internal/
│   ├── handler/                        # Echo handlers (target, asset, internal)
│   ├── service/                        # Business logic (target, asset, scope, verification)
│   ├── repository/                     # DB layer (target, authorization, asset)
│   ├── model/                          # DB structs + request/response DTOs
│   ├── store/                          # godb wrapper + SQL migrations
│   │   └── sql/01_schema.sql           # idempotent DDL (schema: target)
│   ├── middleware/                     # CORS + AppID middleware
│   └── producer/                       # go-kafka audit-events producer
├── helm/                               # Helm chart (parent: service-deployment-helm-chart)
├── gitops/                             # Argo CD Application manifests (dev + prod)
├── Dockerfile                          # distroless build
├── ci-cd-config                        # CI/CD configuration
└── local_start.sh                      # Local dev runner
```

## Configuration (env vars)

| Variable | Example | Description |
|---|---|---|
| `APP_PORT` | `8080` | HTTP listen port |
| `ENV` | `local\|dev\|prod` | Deployment environment |
| `APP_ID` | `scantinel` | Platform app ID stamped on outbound calls |
| `DB_URI` | `postgresql://target-service-user:…@host/db` | PostgreSQL connection string |
| `KAFKA_BOOTSTRAP_SERVER` | `kafka:9092` | Kafka broker for audit-events |
| `KAFKA_CLIENT_ID` | `target-service` | Kafka producer client ID |
| `LOG_LEVEL` | `info` | Logger level |
| `LOG_FORMAT` | `json` | Logger format |

## Shared-libs note

The `go.mod` uses `replace` directives pointing three levels up to `../../../shared-libs/`:

```
SecScanApp/services/target-service/  →  ../../../  →  backend_apps/shared-libs/
```

This is correct for the workspace layout. CI/CD uses the published versions from the module proxy.

## Local development

```bash
# Set DB_URI and Kafka in .secrets (gitignored), then:
bash local_start.sh
```

Swagger UI available at `http://localhost:8080/swagger/index.html` in non-prod environments.
