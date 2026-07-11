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
}

// VerifierInterface abstracts the per-method verification implementations.
type VerifierInterface interface {
	// Verify attempts to confirm the token for the given authorization record.
	// Returns true if the check passes, with a human-readable detail string.
	Verify(ctx context.Context, target *model.Target, auth *model.Authorization) (bool, string, error)
}
