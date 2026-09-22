package model

import "time"

// TargetKind enumerates the target types accepted by the service.
const (
	TargetKindDomain = "domain"
	TargetKindURL    = "url"
	TargetKindIP     = "ip"
	TargetKindCIDR   = "cidr"
)

// TargetStatus enumerates the lifecycle states of a target.
const (
	TargetStatusUnverified = "unverified"
	TargetStatusVerifying  = "verifying"
	TargetStatusVerified   = "verified"
	TargetStatusRevoked    = "revoked"
)

// TargetSource records who registered the target (plans/10-ADMIN-PANEL.md §3).
//   - customer: self-registered through /v1/targets and proven via a challenge.
//   - program:  added by a platform admin; a public bug-bounty program is the
//     authorization evidence (authorizations.method = "program").
const (
	TargetSourceCustomer = "customer"
	TargetSourceProgram  = "program"
)

// VerificationMethod enumerates the proof-of-control methods (06 §2) plus the
// two admin-only methods from plans/10-ADMIN-PANEL.md §3.
const (
	VerificationMethodDNSTXT     = "dns_txt"
	VerificationMethodHTTPFile   = "http_file"
	VerificationMethodMetaTag    = "meta_tag"
	VerificationMethodEmail      = "email"
	VerificationMethodIPRegistry = "ip_registry"
	// VerificationMethodProgram: a public bug-bounty program recorded by an admin
	// (evidence = {platform, name, url, policy_url, scope_notes}).
	VerificationMethodProgram = "program"
	// VerificationMethodManual: an admin attested ownership out-of-band
	// (evidence = {note}). This is the "separate admin flow" for email/ip_registry.
	VerificationMethodManual = "manual"
)

// ProgramPlatform enumerates the bug-bounty platforms accepted for program targets.
const (
	ProgramPlatformHackerOne = "hackerone"
	ProgramPlatformBugcrowd  = "bugcrowd"
	ProgramPlatformIntigriti = "intigriti"
	ProgramPlatformYesWeHack = "yeswehack"
	ProgramPlatformOther     = "other"
)

// ScopeKind enumerates the two kinds of authorization scope (06 §3).
const (
	ScopeKindRegistrableDomain = "registrable_domain"
	ScopeKindIPRange           = "ip_range"
)

// ScopeClass classifies a discovered asset for intrusive-phase gating (06 §3).
const (
	ScopeClassInScope     = "in_scope"
	ScopeClassOutOfScope  = "out_of_scope"
	ScopeClassSharedInfra = "shared_infra"
	ScopeClassUnknown     = "unknown"
)

// AssetType enumerates the kinds of discovered assets.
const (
	AssetTypeSubdomain = "subdomain"
	AssetTypeIP        = "ip"
	AssetTypePort      = "port"
	AssetTypeService   = "service"
	AssetTypeEndpoint  = "endpoint"
)

// ----------------------------------------------------------------------------
// DB structs (map 1-to-1 to table rows)
// ----------------------------------------------------------------------------

// Target is the database row for the targets table.
type Target struct {
	ID                int64     `json:"id"                db:"id"`
	UID               string    `json:"uid"               db:"uid"`
	UserID            int64     `json:"user_id"           db:"user_id"`
	Kind              string    `json:"kind"              db:"kind"`
	Value             string    `json:"value"             db:"value"`
	RegistrableDomain *string   `json:"registrable_domain" db:"registrable_domain"`
	Status            string    `json:"status"            db:"status"`
	Source            string    `json:"source"            db:"source"` // 'customer'|'program'
	Label             *string   `json:"label"             db:"label"`  // admin-facing display name (program targets)
	CreatedAt         time.Time `json:"created_at"        db:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"        db:"updated_at"`
}

// Authorization is the database row for the authorizations table.
// A non-expired row with verified_at set is the proof an intrusive scan may proceed.
type Authorization struct {
	ID         int64      `json:"id"           db:"id"`
	UID        string     `json:"uid"          db:"uid"`
	TargetID   int64      `json:"target_id"    db:"target_id"`
	Method     string     `json:"method"       db:"method"`
	Token      string     `json:"token"        db:"token"`
	ScopeKind  string     `json:"scope_kind"   db:"scope_kind"`
	ScopeValue string     `json:"scope_value"  db:"scope_value"`
	VerifiedAt *time.Time `json:"verified_at"  db:"verified_at"`
	ExpiresAt  *time.Time `json:"expires_at"   db:"expires_at"`
	AttestedBy *int64     `json:"attested_by"  db:"attested_by"`
	// Evidence is free-form JSON describing WHY this authorization exists when it
	// was not proven by a challenge token: the bug-bounty program (method=program)
	// or the admin's note (method=manual). nil for token-based methods.
	Evidence  map[string]interface{} `json:"evidence"     db:"evidence"`
	CreatedAt time.Time              `json:"created_at"   db:"created_at"`
}

// Asset is the database row for the assets table.
type Asset struct {
	ID            int64                  `json:"id"              db:"id"`
	UID           string                 `json:"uid"             db:"uid"`
	TargetID      int64                  `json:"target_id"       db:"target_id"`
	AssetType     string                 `json:"asset_type"      db:"asset_type"`
	Value         string                 `json:"value"           db:"value"`
	ParentAssetID *int64                 `json:"parent_asset_id" db:"parent_asset_id"`
	ScopeClass    string                 `json:"scope_class"     db:"scope_class"`
	Metadata      map[string]interface{} `json:"metadata"        db:"metadata"`
	DiscoveredBy  *string                `json:"discovered_by"   db:"discovered_by"`
	FirstSeen     time.Time              `json:"first_seen"      db:"first_seen"`
	LastSeen      time.Time              `json:"last_seen"       db:"last_seen"`
}

// ----------------------------------------------------------------------------
// Request DTOs (inbound validation)
// ----------------------------------------------------------------------------

// CreateTargetRequest is the body for POST /v1/targets.
type CreateTargetRequest struct {
	Kind  string `json:"kind"  validate:"required,oneof=domain url ip cidr"`
	Value string `json:"value" validate:"required,min=1,max=512"`
}

// VerifyTargetRequest is the body for POST /v1/targets/{uid}/verify.
type VerifyTargetRequest struct {
	Method string `json:"method" validate:"required,oneof=dns_txt http_file meta_tag email ip_registry"`
}

// UpsertAssetsRequest is the internal body for POST /internal/v1/targets/{uid}/assets.
type UpsertAssetsRequest struct {
	Assets []AssetUpsertItem `json:"assets" validate:"required,min=1,dive"`
}

// AssetUpsertItem is a single asset in the upsert batch.
type AssetUpsertItem struct {
	AssetType    string                 `json:"asset_type"    validate:"required,oneof=subdomain ip port service endpoint"`
	Value        string                 `json:"value"         validate:"required,min=1,max=512"`
	DiscoveredBy *string                `json:"discovered_by"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// ProgramEvidence is the bug-bounty program an admin records as the authorization
// evidence for a program target (plans/10-ADMIN-PANEL.md §3). Stored verbatim in
// authorizations.evidence.
type ProgramEvidence struct {
	Platform       string `json:"platform"        validate:"required,oneof=hackerone bugcrowd intigriti yeswehack other"`
	Name           string `json:"name"            validate:"required,min=1,max=255"`
	URL            string `json:"url"             validate:"required,url,max=2048"`
	PolicyURL      string `json:"policy_url"      validate:"omitempty,url,max=2048"`
	ScopeNotes     string `json:"scope_notes"     validate:"max=4000"`
	AuthorizedDays int    `json:"authorized_days" validate:"omitempty,min=1,max=365"`
}

// AdminCreateProgramTargetRequest is the body for POST /v1/admin/targets.
// Kind/value validation is identical to CreateTargetRequest (ip/cidr are still
// refused while service.IPTargetsEnabled is false).
type AdminCreateProgramTargetRequest struct {
	Kind    string          `json:"kind"    validate:"required,oneof=domain url ip cidr"`
	Value   string          `json:"value"   validate:"required,min=1,max=512"`
	UserID  int64           `json:"user_id" validate:"omitempty,min=1"` // defaults to the admin's own X-User-Id
	Label   string          `json:"label"   validate:"max=255"`
	Program ProgramEvidence `json:"program" validate:"required"`
}

// AdminAuthorizeTargetRequest is the body for POST /v1/admin/targets/{uid}/authorize.
type AdminAuthorizeTargetRequest struct {
	Note           string `json:"note"            validate:"max=4000"`
	AuthorizedDays int    `json:"authorized_days" validate:"omitempty,min=1,max=365"`
}

// AdminRevokeTargetRequest is the body for POST /v1/admin/targets/{uid}/revoke.
type AdminRevokeTargetRequest struct {
	Reason string `json:"reason" validate:"max=4000"`
}

// ScopeCheckRequest is the body for POST /internal/v1/scope/check (the authorization gate).
type ScopeCheckRequest struct {
	TargetUID string `json:"target_uid" validate:"required,uuid"`
	// Host or IP being queried — exactly one must be provided.
	Host  string `json:"host,omitempty"`
	IP    string `json:"ip,omitempty"`
	Phase string `json:"phase"      validate:"required"`
}

// ----------------------------------------------------------------------------
// Response DTOs
// ----------------------------------------------------------------------------

// TargetDTO is what the external API returns for a target.
type TargetDTO struct {
	UID               string    `json:"uid"`
	Kind              string    `json:"kind"`
	Value             string    `json:"value"`
	RegistrableDomain *string   `json:"registrable_domain,omitempty"`
	Status            string    `json:"status"`
	Source            string    `json:"source"`
	Label             *string   `json:"label,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// TargetDetailDTO extends TargetDTO with the current authorization scope and challenge token.
type TargetDetailDTO struct {
	TargetDTO
	Authorization      *AuthorizationDTO `json:"authorization,omitempty"`
	VerifyToken        *string           `json:"verify_token,omitempty"`
	VerifyInstructions string            `json:"verify_instructions,omitempty"`
}

// AuthorizationDTO is the external representation of an authorization row.
type AuthorizationDTO struct {
	UID        string     `json:"uid"`
	Method     string     `json:"method"`
	ScopeKind  string     `json:"scope_kind"`
	ScopeValue string     `json:"scope_value"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	AttestedBy *int64     `json:"attested_by,omitempty"`
	// Evidence is only populated for program/manual authorizations.
	Evidence map[string]interface{} `json:"evidence,omitempty"`
}

// TargetAdminDTO is the cross-user representation returned by /v1/admin routes
// (plans/10-ADMIN-PANEL.md §3). It always carries user_id so the panel can join
// across services. Assets are only populated on the detail route.
type TargetAdminDTO struct {
	UID               string            `json:"uid"`
	UserID            int64             `json:"user_id"`
	Kind              string            `json:"kind"`
	Value             string            `json:"value"`
	RegistrableDomain *string           `json:"registrable_domain,omitempty"`
	Status            string            `json:"status"`
	Source            string            `json:"source"`
	Label             *string           `json:"label,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
	Authorization     *AuthorizationDTO `json:"authorization,omitempty"`
	Assets            []AssetDTO        `json:"assets,omitempty"`
}

// AdminTargetListResponse is the paged envelope payload for GET /v1/admin/targets.
type AdminTargetListResponse struct {
	Items    []TargetAdminDTO `json:"items"`
	Total    int64            `json:"total"`
	Page     int              `json:"page"`
	PageSize int              `json:"page_size"`
}

// AdminStatsResponse is the payload for GET /v1/admin/stats.
type AdminStatsResponse struct {
	Total    int64            `json:"total"`
	ByStatus map[string]int64 `json:"by_status"`
	BySource map[string]int64 `json:"by_source"`
}

// VerifiedCheckResponse is returned by GET /internal/v1/targets/{uid}/verified.
// verified ⇔ status=verified AND an active (verified, non-expired) authorization
// exists AND (when user_id is supplied) the caller owns the target. Reason is a
// stable machine-readable token (verified | not_found | not_owner | not_verified |
// no_active_authorization).
type VerifiedCheckResponse struct {
	Verified bool   `json:"verified"`
	Reason   string `json:"reason"`
}

// AssetDTO is the external representation of an asset.
type AssetDTO struct {
	UID          string                 `json:"uid"`
	AssetType    string                 `json:"asset_type"`
	Value        string                 `json:"value"`
	ScopeClass   string                 `json:"scope_class"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	DiscoveredBy *string                `json:"discovered_by,omitempty"`
	FirstSeen    time.Time              `json:"first_seen"`
	LastSeen     time.Time              `json:"last_seen"`
}

// ScopeCheckResponse is returned by POST /internal/v1/scope/check.
// authorized=true means the caller MAY proceed with an intrusive phase.
//
// AllowedIPs is the set of public IPs the host resolved to AT GATE TIME. Callers
// MUST pin their connections to these addresses (and refuse to follow DNS to any
// other IP) to close the DNS-rebinding TOCTOU window between this check and the
// actual scan. For an IP-scoped request it echoes the queried IP.
type ScopeCheckResponse struct {
	Authorized bool     `json:"authorized"`
	Reason     string   `json:"reason"`
	AllowedIPs []string `json:"allowed_ips,omitempty"`
}

// SearchParameters carries pagination and filtering for list endpoints.
type SearchParameters struct {
	UserID *int64
	Status *string
	// Source filters on targets.source ('customer'|'program'); admin list only.
	Source *string
	// Query is a case-insensitive substring match on value OR label; admin list only.
	Query      *string
	SortBy     string
	SortOrder  string
	PageNumber int
	PageSize   int
}
