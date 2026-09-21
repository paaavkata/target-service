# target-service

**THE SAFETY BOUNDARY** for the Scantinel security-scanning platform. **Layer: app-layer** (Scantinel-specific; holds a configured `APP_ID`, default `scantinel`, and only stamps it outbound — it does not thread inbound `X-App-Id` into its own authorization logic).

This service owns target registration, proof-of-ownership verification, authorization scope, and the discovered asset inventory. No intrusive scan phase (port scans, credential-resilience tests, active web exploitation, AI agent probing) may proceed until `POST /internal/v1/scope/check` returns `{"authorized": true}`.

## Why it exists as a separate service

Isolating the authorization gate makes it auditable and hard to accidentally bypass (see `06_AUTHORIZATION_AND_SAFETY.md`). Every other Scantinel service — especially `scan-service` and `agent-service` — is a client of this gate.

The ownership-verification and scope-check gate is **verified real and load-bearing, not stubbed**: DNS TXT lookups, HTTP file fetch, and HTML meta-tag checks (`internal/service/verification_service.go`) perform real network calls; email/IP-registry methods honestly return "pending manual review" rather than faking success. The gate is fail-closed: the reserved/internal-IP denylist, the fail-closed DNS-rebinding resolver, and the hardened verification HTTP client (redirects refused, proxy disabled, dials rejected to reserved/private/link-local/CGNAT IPs including `169.254.0.0/16` cloud metadata, checked against the *already-resolved* address to close the DNS-rebinding TOCTOU window) come from the shared library [`github.com/paaavkata/go-safedial`](../../../shared-libs/go-safedial) (`internal/service/scope_service.go`, `internal/service/verification_service.go`) — unified with the identical guards in scan-service and agent-service. `internal/service/safe_http_client.go` only keeps a thin package-level alias so its pre-existing dial-guard unit tests still exercise the same guard directly; `isSharedInfra`/`knownSharedInfraRanges` (the CDN/shared-infrastructure exclusion in `scope_service.go`) stay in target-service because that list is authorization policy, not network safety. IP/CIDR targets are currently hard-disabled at creation (`IPTargetsEnabled = false` in `internal/service/target_service.go`) because real RIR registry-contact verification isn't implemented yet — attempting to create or authorize one returns 422, not a silent allow.

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
│   ├── middleware/                     # CORS middleware (gateway also does CORS; this service's copy is redundant but harmless — no credentials with the wildcard origin)
│   └── producer/                       # go-nats audit-events producer (wraps go-nats)
├── helm/                               # Helm chart (parent: service-deployment-helm-chart)
├── gitops/                             # Argo CD Application manifests (dev + prod)
├── Dockerfile                          # distroless build
├── ci-cd-config                        # CI/CD configuration
└── local_start.sh                      # Local dev runner
```

## Configuration (env vars)

| Variable | Example | Description |
|---|---|---|
| `APP_PORT` | `8080` (default if unset) | HTTP listen port |
| `DB_URI` | *(required, fatal if empty)* | PostgreSQL connection string |
| `ENV` | — | Deployment environment |
| `HOST` | — | External host, used in Swagger docs/verification links |
| `LOG_LEVEL` | — | Logger level |
| `LOG_FORMAT` | — | Logger format |
| `APP_ID` | `scantinel` (default if unset) | App ID stamped on outbound NATS audit events; not threaded into own authorization logic |
| `NATS_URL` | `nats://nats.data-dev:4222` (default if unset) | NATS JetStream connection URL |
| `NATS_CLIENT_ID` | `target-service` (default if unset) | NATS client ID |
| `AUDIT_TOPIC` | `audit-events` (default if unset) | NATS subject the audit producer publishes to |

Verified directly against `cmd/target-service/main.go` (viper-based, `AutomaticEnv()`); the previous version of this table listed `KAFKA_BOOTSTRAP_SERVER`/`KAFKA_CLIENT_ID`, which do not exist in code — the broker is NATS JetStream via `go-nats`, not Kafka.

## Shared-libs note

The `go.mod` `replace` block points to `../shared-libs/go-X` (one level up, resolved via the `services/shared-libs` symlink to the workspace-level `backend_apps/shared-libs/`), not three levels up. It now covers exactly the imported (per `require`) libs: `go-db`, `go-events`, `go-logger`, `go-nats` (v0.2.0), `go-server`. The `go-config` and `go-middleware` replace directives were removed — neither had a corresponding `require` entry and neither is imported anywhere. CI/CD uses the published versions from the module proxy, not the local replace paths.

## Data

Postgres, schema `target`, migrations auto-applied at startup from `internal/store/sql/01_schema.sql` (idempotent DDL). Key tables: targets, authorizations/scope grants (60-day expiry), discovered assets.

## Local development

```bash
# Set DB_URI in a gitignored .secrets file (see local_start.sh header), then:
bash local_start.sh
```

This starts against a local NATS JetStream server (`docker run -p 4222:4222 nats -js`) and local Postgres — see `local_start.sh` for the exact env vars it exports. Run tests with `go test ./internal/... -short`. Swagger UI available at `http://localhost:8080/swagger/index.html` in non-prod environments (regenerate with `swag init -g main.go -d cmd/target-service,internal/handler,internal/model -o cmd/target-service/docs`).

## Deployment

GitOps: push to `main` → Argo Workflows `service-ci` → Kaniko → Zot (`registry.internal.cloudfusion.tech`) → bumps the `target-service` Application in `infra-gitops` (dev auto-deploys via Argo CD). Prod deployment is manual via the `promote-to-prod` workflow. See `ci/README.md` and `gitops/` for details. Helm chart parent: `service-deployment-helm-chart` (pinned 1.2.0/1.3.0-style; do not bump without coordinating).

## Related docs

- `06_AUTHORIZATION_AND_SAFETY.md` (SecScanApp top level) — design rationale for this gate; historical/design record, current behavior is documented above.
- `plans/00-PRODUCTION-READINESS-MASTER-PLAN.md` — production-readiness checklist; the SSRF-hardening and IP-pinning items referencing this service are now implemented (see status banner in that doc).
- `scantinel-scanner-images/verify/README.md` — describes a different, unused job-dispatch verification design; this service performs all verification in-process (see banner added to that README).

_Last verified against code: 2026-09-21_
