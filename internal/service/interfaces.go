package service

import (
	"context"
	"target-service/internal/model"
)

// TargetServiceInterface defines all business operations for targets.
type TargetServiceInterface interface {
	CreateTarget(ctx context.Context, userID int64, req *model.CreateTargetRequest) (*model.TargetDetailDTO, error)
	ListTargets(ctx context.Context, userID int64, params model.SearchParameters) ([]model.TargetDTO, error)
	GetTarget(ctx context.Context, userID int64, uid string) (*model.TargetDetailDTO, error)
	TriggerVerification(ctx context.Context, userID int64, uid string, req *model.VerifyTargetRequest) (*model.TargetDetailDTO, error)
	DeleteTarget(ctx context.Context, userID int64, uid string) error

	// ── Admin panel (plans/10-ADMIN-PANEL.md §3) — callers MUST be behind RequireAdmin ──

	// ListAll lists targets across users with the optional filters in params
	// (UserID/Status/Source/Query) and returns the total matching count.
	ListAll(ctx context.Context, params model.SearchParameters) ([]model.TargetAdminDTO, int64, error)
	// GetAnyByUID returns any user's target with its current authorization and assets.
	GetAnyByUID(ctx context.Context, uid string) (*model.TargetAdminDTO, error)
	// CreateProgramTarget registers a bug-bounty program target as verified with a
	// method=program authorization whose evidence is the program itself.
	CreateProgramTarget(ctx context.Context, adminUserID int64, req *model.AdminCreateProgramTargetRequest) (*model.TargetAdminDTO, error)
	// AuthorizeManually marks a target verified: confirms a pending challenge if
	// one exists, otherwise inserts a method=manual authorization.
	AuthorizeManually(ctx context.Context, adminUserID int64, uid string, req *model.AdminAuthorizeTargetRequest) (*model.TargetAdminDTO, error)
	// Revoke is the kill switch: status=revoked and every active authorization expires now.
	Revoke(ctx context.Context, adminUserID int64, uid string, reason string) (*model.TargetAdminDTO, error)
	// DeleteAny deletes a target regardless of owner.
	DeleteAny(ctx context.Context, adminUserID int64, uid string) error
	// Stats returns counts by status and source.
	Stats(ctx context.Context) (*model.AdminStatsResponse, error)
}

// AssetServiceInterface defines operations for the asset inventory.
type AssetServiceInterface interface {
	ListAssets(ctx context.Context, userID int64, targetUID string) ([]model.AssetDTO, error)
	UpsertAssets(ctx context.Context, targetUID string, req *model.UpsertAssetsRequest) ([]model.AssetDTO, error)
}

// ScopeServiceInterface owns the authorization gate logic (06 §1–§3).
// This is the most critical interface in the service — every intrusive phase
// must call CheckScope before dispatch.
type ScopeServiceInterface interface {
	// CheckScope is the authorization gate.
	// It returns {authorized, reason} for a given (target_uid, host|ip, phase).
	CheckScope(ctx context.Context, req *model.ScopeCheckRequest) (*model.ScopeCheckResponse, error)
	// CheckVerified answers GET /internal/v1/targets/{uid}/verified: verified ⇔
	// status=verified AND an active (verified, non-expired) authorization exists
	// AND, when userID is non-nil, the target is owned by that user. Never
	// errors on a missing target — that is {verified:false, reason:"not_found"}.
	CheckVerified(ctx context.Context, targetUID string, userID *int64) (*model.VerifiedCheckResponse, error)
}

// VerifierInterface abstracts the per-method verification implementations.
type VerifierInterface interface {
	// Verify attempts to confirm the token for the given authorization record.
	// Returns true if the check passes, with a human-readable detail string.
	Verify(ctx context.Context, target *model.Target, auth *model.Authorization) (bool, string, error)
}
