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

`POST /v1/targets` answers `409` when `(user_id, kind, value)` already exists and `422` for ip/cidr kinds while IP targets are disabled.

**Plan target cap** (`internal/service/target_cap.go`, SecScanApp/plans/12-ENTITLEMENTS.md): on the customer path
`POST /v1/targets` answers `403 {status:"error", message, data:{code:"plan_upgrade_required", plan, max_targets}}` when the
caller already owns `>= max_targets` targets. The plan is the trusted `X-User-Plan` header (gateway / website stamped), else
service-service `GET /v1/apps/{app_id}/customers/{user_id}/rate-tier` (30 s cache, default `free`). `max_targets` comes from
scan-service `GET /internal/v1/entitlements/{plan}` (cached 60 s; `-1` = unlimited) — target-service does not own the matrix.
If scan-service is unreachable the check **fails open** (warning logged) so an outage never blocks onboarding. Admin requests
(`X-Is-Admin` / admin role) bypass the cap.

### Admin panel (`/v1/admin`, plans/10-ADMIN-PANEL.md §3)

Registered on the same Echo app behind `handler.RequireAdmin`: **403** `{status:"error", message:"admin only"}` unless the request carries `X-Is-Admin: true` **or** an `admin`/`owner` role in `X-User-Roles` (`handler.IsAdminRequest`, copied from identity-service). Both headers are trusted only because the gateway strips client-supplied copies and the in-cluster admin panel (`scantinel-website`) self-stamps them after checking the Keycloak token; admin-ness is never read from body or query. Every write emits an audit event on `audit-events` with actor `{type:"user", uid:<admin X-User-Id>}`.

| Method | Path | Description | Audit type |
|---|---|---|---|
| `GET` | `/v1/admin/targets?user_id=&status=&source=&q=&page=&page_size=` | Cross-user list → `{items, total, page, page_size}` (page_size default 50, max 200; unknown `status`/`source`/`user_id` values → 400; `q` is a case-insensitive substring match on value or label). | — |
| `GET` | `/v1/admin/targets/{uid}` | `TargetAdminDTO` incl. current authorization (with `evidence`, `attested_by`) and assets. 404 if unknown. | — |
| `POST` | `/v1/admin/targets` | Create a **program target** (below). 201 / 400 / 409 duplicate / 422 ip-cidr. | `admin.target.created` |
| `POST` | `/v1/admin/targets/{uid}/authorize` | `{note, authorized_days}` — confirm a pending challenge (email / ip_registry) in place, else insert a `method=manual` authorization with `evidence={note}`; sets `status=verified`. | `admin.target.authorized` |
| `POST` | `/v1/admin/targets/{uid}/revoke` | `{reason}` — kill switch: `status=revoked` and every active authorization gets `expires_at=now()`, so the scope gate denies every new task. | `admin.target.revoked` |
| `DELETE` | `/v1/admin/targets/{uid}` | Delete regardless of owner (cascades authorizations + assets). | `admin.target.deleted` |
| `GET` | `/v1/admin/stats` | `{total, by_status:{…}, by_source:{…}}` (all known keys always present). | — |

`TargetAdminDTO` always carries `user_id`, `source` and `label` in addition to the customer `TargetDTO` fields, plus `authorization` (`uid, method, scope_kind, scope_value, verified_at, expires_at, attested_by, evidence`) and — on the detail route only — `assets`.

### Cluster-internal only (NetworkPolicy; NOT via Traefik)

| Method | Path | Callers | Description |
|---|---|---|---|
| `POST` | `/internal/v1/scope/check` | scan-service, agent-service | **The gate.** `{target_uid, host\|ip, phase}` → `{authorized, reason}`. |
| `GET` | `/internal/v1/targets/{uid}/verified?user_id=` | scan-service (`StartScan`) | `{verified, reason, kind, value, registrable_domain}` — `kind`/`value`/`registrable_domain` are set **only** when `verified` is true (scan-service writes them into `scan_tasks.target_asset` so the per-task scope gate resolves the real host); `verified` ⇔ `status=verified` **and** an active (verified, non-expired) authorization exists **and**, when `user_id` is given, it equals the owner (`reason: not_owner` otherwise). A missing target is a **200** `{verified:false, reason:"not_found"}` — scan-service treats non-200 as an outage. Reasons: `verified \| not_found \| not_owner \| not_verified \| no_active_authorization`. |
| `POST` | `/internal/v1/targets/{uid}/assets` | scan-service | Upsert recon-discovered assets into inventory. |

## Scope model (06 §3)

- **Registrable-domain scope**: verifying `example.com` authorizes `example.com` and all subdomains. A different TLD (`example.net`) requires separate verification.
- **IP-range scope**: IP/CIDR targets require RIR-registered registry-contact confirmation. DNS/HTTP tokens on a website do NOT authorize scanning arbitrary IPs.
- **Shared-infra exclusion**: known CDN/PaaS ranges (Cloudflare, Fastly, Akamai, …) are always denied for intrusive testing even if they resolve from a verified host.

## Verification methods (06 §2)

1. **DNS TXT** — add `scantinel-verify=<token>` TXT record (real DNS lookup at verify time).
2. **HTTP file** — serve `GET /.well-known/scantinel-verify/<token>` returning the token (real HTTP fetch).
3. **HTML meta tag** — add `<meta name="scantinel-verify" content="<token>">` to homepage (real HTTP fetch).
4. **Email challenge** / **IP registry contact** — async/manual; confirmed out-of-band by an admin via `POST /v1/admin/targets/{uid}/authorize`.

Customer authorizations expire after 60 days (`service.CustomerAuthorizationTTL`) and must be re-verified periodically.

### Program targets (admin-added, plans/10-ADMIN-PANEL.md §3)

A customer `POST /v1/targets/{uid}/verify` on a program- or manually-authorized target returns
**409** (`ErrTargetAdminAuthorized`): those targets carry no challenge token, so running the
check would only demote them. The customer `TargetDTO.authorization` never includes
`attested_by` / `evidence`; only the admin DTO does.

Public bug-bounty programs (HackerOne, Bugcrowd, Intigriti, YesWeHack, …) are not customer-owned, so they cannot pass the DNS/HTTP challenge. Instead a platform admin records the **program itself as the authorization evidence**:

- `POST /v1/admin/targets` body: `{kind: domain|url, value, user_id?, label?, program: {platform: hackerone|bugcrowd|intigriti|yeswehack|other, name, url, policy_url?, scope_notes?, authorized_days?}}`. `program.platform/name/url` are required; `authorized_days` is 1..365 (default 90); `user_id` defaults to the admin's own `X-User-Id`. Value normalisation, eTLD+1 derivation and the ip/cidr hard-disable are **the same code path** as the customer `Create` (`repository.NormalizeTargetValue`, `service.checkKindAllowed`).
- The target is inserted with `status=verified, source=program` and one `authorizations` row `method=program, token="", scope from scopeForTarget (registrable domain), verified_at=now, expires_at=now+days, attested_by=<admin>, evidence=<program json>`. If the authorization insert fails the target is deleted again — a `verified` target never exists without its authorization row.
- The scope gate (`/internal/v1/scope/check`) is **unchanged**: a program/manual authorization is just another verified, expiring `authorizations` row, so 06 §1–§3 (per-asset check, registrable-domain scope, shared-infra denylist, expiry) apply exactly as for customer targets. Revoking a program target expires its authorizations and the gate denies immediately.
- New constants: `model.TargetSourceCustomer/Program`, `model.VerificationMethodProgram/Manual`, `model.ProgramPlatform*`.

## Module layout

```
target-service/
├── cmd/target-service/main.go          # bootstrap (port 8080)
├── internal/
│   ├── handler/                        # Echo handlers (target, asset, admin, internal) + IsAdminRequest/RequireAdmin
│   ├── client/                         # scan-service entitlements client (60 s cache) + service-service plan resolver (30 s cache)
│   ├── service/                        # Business logic (target + target_admin, target_cap, asset, scope, verification)
│   ├── repository/                     # DB layer (target, authorization, asset)
│   ├── model/                          # DB structs + request/response DTOs
│   ├── store/                          # godb wrapper + SQL migrations
│   │   ├── sql/01_schema.sql           # idempotent DDL (schema: target)
│   │   └── sql/02_admin_program_targets.sql  # targets.source/label, authorizations.evidence (admin panel)
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
| `SCAN_SERVICE_URL` | `http://scan-service.scantinel-dev` (default if unset) | Source of plan entitlements (`/internal/v1/entitlements/{plan}`) for the target cap |
| `SERVICE_SERVICE_URL` | `http://service-service.platform-dev` (default if unset) | Plan resolution when `X-User-Plan` is absent |

Verified directly against `cmd/target-service/main.go` (viper-based, `AutomaticEnv()`); the previous version of this table listed `KAFKA_BOOTSTRAP_SERVER`/`KAFKA_CLIENT_ID`, which do not exist in code — the broker is NATS JetStream via `go-nats`, not Kafka.

## Shared-libs note

The `go.mod` `replace` block points to `../shared-libs/go-X` (one level up, resolved via the `services/shared-libs` symlink to the workspace-level `backend_apps/shared-libs/`), not three levels up. It now covers exactly the imported (per `require`) libs: `go-db`, `go-events`, `go-logger`, `go-nats` (v0.2.0), `go-server`. The `go-config` and `go-middleware` replace directives were removed — neither had a corresponding `require` entry and neither is imported anywhere. CI/CD uses the published versions from the module proxy, not the local replace paths.

## Data

Postgres, schema `target`, migrations auto-applied at startup from `internal/store/sql/*.sql` in file-name order (each file idempotent, each run in its own `Exec`, so every file sets `search_path` itself). Key tables: targets, authorizations/scope grants (60-day expiry for customer methods, 1..365 days for program/manual), discovered assets.

Columns added by `02_admin_program_targets.sql` (all `IF NOT EXISTS`, safe on existing rows):

| Table | Column | Meaning |
|---|---|---|
| `targets` | `source TEXT NOT NULL DEFAULT 'customer'` | `customer` (self-registered) or `program` (admin-added bug-bounty program) |
| `targets` | `label TEXT` | admin-facing display name, e.g. `Acme (HackerOne)` |
| `authorizations` | `evidence JSONB` | why the authorization exists when it was not proven by a token: the program `{platform, name, url, policy_url, scope_notes}` (`method=program`) or `{note}` (`method=manual`); `NULL` for token methods |

Indexes `idx_targets_status` and `idx_targets_source` back the admin list filters and stats.

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

_Last verified against code: 2026-09-22 (admin panel routes added)_
