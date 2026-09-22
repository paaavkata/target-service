package repository

import (
	"context"
	"errors"
	"target-service/internal/model"
	"time"
)

// ErrNotFound is returned by single-row lookups when no row matches.
var ErrNotFound = errors.New("not found")

// ErrDuplicateTarget is returned by the target inserts when
// (user_id, kind, value) already exists.
var ErrDuplicateTarget = errors.New("target already exists for this user")

// TargetRepositoryInterface defines all persistence operations for targets.
type TargetRepositoryInterface interface {
	// Create registers a customer-owned target (source=customer, status=unverified).
	Create(ctx context.Context, userID int64, req *model.CreateTargetRequest) (*model.Target, error)
	// CreateProgram registers an admin-added bug-bounty program target
	// (source=program, status=verified). Value normalisation and eTLD+1
	// derivation are shared with Create. label may be empty (stored as NULL).
	CreateProgram(ctx context.Context, userID int64, kind, value, label string) (*model.Target, error)
	GetByUID(ctx context.Context, userID int64, uid string) (*model.Target, error)
	// GetByUIDInternal looks up a target by uid without user_id scoping.
	// Use ONLY on cluster-internal paths (scope check, asset upsert) and on
	// admin-gated routes.
	GetByUIDInternal(ctx context.Context, uid string) (*model.Target, error)
	GetByID(ctx context.Context, id int64) (*model.Target, error)
	List(ctx context.Context, params model.SearchParameters) ([]model.Target, error)
	// Count returns the number of rows List would match, ignoring pagination.
	Count(ctx context.Context, params model.SearchParameters) (int64, error)
	CountByStatus(ctx context.Context) (map[string]int64, error)
	CountBySource(ctx context.Context) (map[string]int64, error)
	UpdateStatus(ctx context.Context, id int64, status string) error
	Delete(ctx context.Context, userID int64, uid string) error
	// DeleteByUID removes a target regardless of owner (admin only).
	DeleteByUID(ctx context.Context, uid string) error
}

// AuthorizationRepositoryInterface defines persistence operations for
// the authorization (proof-of-control) records.
type AuthorizationRepositoryInterface interface {
	// Create inserts an authorization row. VerifiedAt/ExpiresAt/Evidence are
	// persisted when set, so an already-verified row (method=program/manual)
	// and a pending challenge row (token-based methods) share one insert.
	Create(ctx context.Context, auth *model.Authorization) (*model.Authorization, error)
	GetByTargetID(ctx context.Context, targetID int64) (*model.Authorization, error)
	GetPendingByToken(ctx context.Context, token string) (*model.Authorization, error)
	// MarkVerified sets verified_at=now() and expires_at; a non-nil evidence
	// replaces the row's evidence, nil leaves it untouched.
	MarkVerified(ctx context.Context, id int64, expiresAt time.Time, evidence map[string]interface{}) error
	// GetActiveAuthorizations returns all non-expired, verified authorizations for a target.
	// Used by the scope gate to determine if an intrusive phase is permitted.
	GetActiveAuthorizations(ctx context.Context, targetID int64) ([]model.Authorization, error)
	// ExpireActiveAuthorizations sets expires_at=now() on every active
	// authorization of the target (admin kill switch). Returns the number of
	// rows expired.
	ExpireActiveAuthorizations(ctx context.Context, targetID int64) (int64, error)
}

// AssetRepositoryInterface defines persistence operations for discovered assets.
type AssetRepositoryInterface interface {
	Upsert(ctx context.Context, targetID int64, items []model.AssetUpsertItem) ([]model.Asset, error)
	ListByTargetUID(ctx context.Context, userID int64, targetUID string) ([]model.Asset, error)
	// ListByTargetID lists assets without user scoping (admin / internal only).
	ListByTargetID(ctx context.Context, targetID int64) ([]model.Asset, error)
}
