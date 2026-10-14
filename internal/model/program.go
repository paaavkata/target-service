package model

import (
	"encoding/json"
	"time"
)

// ProgramStatus enumerates the lifecycle states of a synced bug-bounty program
// (17 §10). A non-active program refuses every job.
const (
	ProgramStatusActive = "active"
	ProgramStatusPaused = "paused"
)

// ProgramAssetType enumerates the kinds of program scope asset.
const (
	ProgramAssetTypeDomain   = "domain"   // exact host
	ProgramAssetTypeWildcard = "wildcard" // '*.example.com' — apex + any subdomain
	ProgramAssetTypeURL      = "url"      // matched on its host
	ProgramAssetTypeIP       = "ip"       // exact IP
	ProgramAssetTypeCIDR     = "cidr"     // IP within CIDR
	ProgramAssetTypeOther    = "other"    // exact string
)

// BugbountyProgram is the DB row for target.bugbounty_programs — the structured,
// machine-readable program policy that the scope gate enforces in program mode.
type BugbountyProgram struct {
	ID                   string          `json:"id"                     db:"id"`
	Platform             string          `json:"platform"               db:"platform"`
	Handle               string          `json:"handle"                 db:"handle"`
	Name                 string          `json:"name"                   db:"name"`
	PolicyURL            string          `json:"policy_url"             db:"policy_url"`
	AutomationAllowed    bool            `json:"automation_allowed"     db:"automation_allowed"`
	RateLimitRPS         *int            `json:"rate_limit_rps"         db:"rate_limit_rps"`
	ProhibitedTechniques []string        `json:"prohibited_techniques"  db:"prohibited_techniques"`
	SafeHarbor           bool            `json:"safe_harbor"            db:"safe_harbor"`
	RawPolicy            json.RawMessage `json:"raw_policy,omitempty"   db:"raw_policy"`
	SyncedAt             time.Time       `json:"synced_at"              db:"synced_at"`
	StaleAfterSeconds    int             `json:"stale_after_seconds"    db:"stale_after_seconds"`
	Status               string          `json:"status"                 db:"status"`
	CreatedAt            time.Time       `json:"created_at"             db:"created_at"`
	UpdatedAt            time.Time       `json:"updated_at"             db:"updated_at"`
}

// ProgramAsset is the DB row for target.program_assets — one in-scope or
// excluded scope entry of a program.
type ProgramAsset struct {
	ID         string    `json:"id"          db:"id"`
	ProgramID  string    `json:"program_id"  db:"program_id"`
	AssetType  string    `json:"asset_type"  db:"asset_type"`
	Identifier string    `json:"identifier"  db:"identifier"`
	InScope    bool      `json:"in_scope"    db:"in_scope"`
	CreatedAt  time.Time `json:"created_at"  db:"created_at"`
}

// ----------------------------------------------------------------------------
// Connector contract (ingest/sync)
// ----------------------------------------------------------------------------

// ProgramPolicy is what a ProgramPolicyConnector returns from the platform API:
// the scope assets plus the policy metadata the platform exposes
// machine-readably. Automation/rate/prohibited-technique rules are generally
// NOT machine-readable on the platforms, so they are supplied by the admin on
// sync (see SyncProgramRequest) rather than fabricated here.
type ProgramPolicy struct {
	Platform   string
	Handle     string
	Name       string
	PolicyURL  string
	SafeHarbor bool
	RawPolicy  json.RawMessage
	Assets     []ProgramPolicyAsset
}

// ProgramPolicyAsset is one scope entry from the platform.
type ProgramPolicyAsset struct {
	AssetType  string
	Identifier string
	InScope    bool
}

// ----------------------------------------------------------------------------
// Request / response DTOs
// ----------------------------------------------------------------------------

// SyncProgramRequest is the body for POST /v1/admin/programs/sync. platform +
// handle select the program on the platform; the remaining fields are the
// admin's attestation of the policy terms the platform API does not expose
// machine-readably (default-deny: absent automation_allowed stays false).
type SyncProgramRequest struct {
	Platform             string   `json:"platform"              validate:"required,oneof=hackerone bugcrowd intigriti yeswehack other"`
	Handle               string   `json:"handle"                validate:"required,min=1,max=255"`
	AutomationAllowed    bool     `json:"automation_allowed"`
	RateLimitRPS         *int     `json:"rate_limit_rps"        validate:"omitempty,min=1"`
	ProhibitedTechniques []string `json:"prohibited_techniques" validate:"omitempty,dive,max=64"`
	StaleAfterSeconds    int      `json:"stale_after_seconds"   validate:"omitempty,min=0"`
	Status               string   `json:"status"                validate:"omitempty,oneof=active paused"`
}

// ProgramDTO is the external representation of a synced program with its assets.
type ProgramDTO struct {
	ID                   string         `json:"id"`
	Platform             string         `json:"platform"`
	Handle               string         `json:"handle"`
	Name                 string         `json:"name"`
	PolicyURL            string         `json:"policy_url"`
	AutomationAllowed    bool           `json:"automation_allowed"`
	RateLimitRPS         *int           `json:"rate_limit_rps,omitempty"`
	ProhibitedTechniques []string       `json:"prohibited_techniques"`
	SafeHarbor           bool           `json:"safe_harbor"`
	SyncedAt             time.Time      `json:"synced_at"`
	StaleAfterSeconds    int            `json:"stale_after_seconds"`
	Status               string         `json:"status"`
	Assets               []ProgramAsset `json:"assets"`
}
