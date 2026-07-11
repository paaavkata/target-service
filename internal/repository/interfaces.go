package repository

import (
	"context"
	"target-service/internal/model"
)

// TargetRepositoryInterface defines all persistence operations for targets.
type TargetRepositoryInterface interface {
	Create(ctx context.Context, userID int64, req *model.CreateTargetRequest) (*model.Target, error)
	GetByUID(ctx context.Context, userID int64, uid string) (*model.Target, error)
	// GetByUIDInternal looks up a target by uid without user_id scoping.
	// Use ONLY on cluster-internal paths (scope check, asset upsert).
	GetByUIDInternal(ctx context.Context, uid string) (*model.Target, error)
	GetByID(ctx context.Context, id int64) (*model.Target, error)
	List(ctx context.Context, params model.SearchParameters) ([]model.Target, error)
	UpdateStatus(ctx context.Context, id int64, status string) error
	Delete(ctx context.Context, userID int64, uid string) error
}

// AuthorizationRepositoryInterface defines persistence operations for
// the authorization (proof-of-control) records.
type AuthorizationRepositoryInterface interface {
	Create(ctx context.Context, auth *model.Authorization) (*model.Authorization, error)
	GetByTargetID(ctx context.Context, targetID int64) (*model.Authorization, error)
	GetPendingByToken(ctx context.Context, token string) (*model.Authorization, error)
	MarkVerified(ctx context.Context, id int64, expiresAt string) error
	// GetActiveAuthorizations returns all non-expired, verified authorizations for a target.
	// Used by the scope gate to determine if an intrusive phase is permitted.
	GetActiveAuthorizations(ctx context.Context, targetID int64) ([]model.Authorization, error)
}

// AssetRepositoryInterface defines persistence operations for discovered assets.
type AssetRepositoryInterface interface {
	Upsert(ctx context.Context, targetID int64, items []model.AssetUpsertItem) ([]model.Asset, error)
	ListByTargetUID(ctx context.Context, userID int64, targetUID string) ([]model.Asset, error)
}
