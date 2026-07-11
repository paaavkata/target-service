package repository

import (
	"context"
	"fmt"
	"target-service/internal/model"
	"target-service/internal/store"
)

type authorizationRepository struct {
	db *store.DBService
}

// NewAuthorizationRepository constructs the concrete authorization repository.
func NewAuthorizationRepository(db *store.DBService) AuthorizationRepositoryInterface {
	return &authorizationRepository{db: db}
}

func (r *authorizationRepository) Create(ctx context.Context, auth *model.Authorization) (*model.Authorization, error) {
	query := `
		INSERT INTO target.authorizations
		    (target_id, method, token, scope_kind, scope_value, attested_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, now())
		RETURNING id, uid, target_id, method, token, scope_kind, scope_value,
		          verified_at, expires_at, attested_by, created_at`

	row := r.db.QueryRow(ctx, query,
		auth.TargetID, auth.Method, auth.Token,
		auth.ScopeKind, auth.ScopeValue, auth.AttestedBy,
	)
	a := &model.Authorization{}
	if err := row.Scan(
		&a.ID, &a.UID, &a.TargetID, &a.Method, &a.Token,
		&a.ScopeKind, &a.ScopeValue,
		&a.VerifiedAt, &a.ExpiresAt, &a.AttestedBy, &a.CreatedAt,
	); err != nil {
		return nil, fmt.Errorf("authorizationRepository.Create: %w", err)
	}
	return a, nil
}

func (r *authorizationRepository) GetByTargetID(ctx context.Context, targetID int64) (*model.Authorization, error) {
	query := `
		SELECT id, uid, target_id, method, token, scope_kind, scope_value,
		       verified_at, expires_at, attested_by, created_at
		FROM target.authorizations
		WHERE target_id = $1
		ORDER BY created_at DESC
		LIMIT 1`

	row := r.db.QueryRow(ctx, query, targetID)
	a := &model.Authorization{}
	if err := row.Scan(
		&a.ID, &a.UID, &a.TargetID, &a.Method, &a.Token,
		&a.ScopeKind, &a.ScopeValue,
		&a.VerifiedAt, &a.ExpiresAt, &a.AttestedBy, &a.CreatedAt,
	); err != nil {
		return nil, fmt.Errorf("authorizationRepository.GetByTargetID: %w", err)
	}
	return a, nil
}

func (r *authorizationRepository) GetPendingByToken(ctx context.Context, token string) (*model.Authorization, error) {
	query := `
		SELECT id, uid, target_id, method, token, scope_kind, scope_value,
		       verified_at, expires_at, attested_by, created_at
		FROM target.authorizations
		WHERE token = $1 AND verified_at IS NULL
		LIMIT 1`

	row := r.db.QueryRow(ctx, query, token)
	a := &model.Authorization{}
	if err := row.Scan(
		&a.ID, &a.UID, &a.TargetID, &a.Method, &a.Token,
		&a.ScopeKind, &a.ScopeValue,
		&a.VerifiedAt, &a.ExpiresAt, &a.AttestedBy, &a.CreatedAt,
	); err != nil {
		return nil, fmt.Errorf("authorizationRepository.GetPendingByToken: %w", err)
	}
	return a, nil
}

func (r *authorizationRepository) MarkVerified(ctx context.Context, id int64, expiresAt string) error {
	query := `
		UPDATE target.authorizations
		SET verified_at = now(), expires_at = $1::TIMESTAMPTZ
		WHERE id = $2`
	if err := r.db.Exec(ctx, query, expiresAt, id); err != nil {
		return fmt.Errorf("authorizationRepository.MarkVerified: %w", err)
	}
	return nil
}

// GetActiveAuthorizations returns all non-expired verified authorizations for a target.
func (r *authorizationRepository) GetActiveAuthorizations(ctx context.Context, targetID int64) ([]model.Authorization, error) {
	query := `
		SELECT id, uid, target_id, method, token, scope_kind, scope_value,
		       verified_at, expires_at, attested_by, created_at
		FROM target.authorizations
		WHERE target_id = $1
		  AND verified_at IS NOT NULL
		  AND (expires_at IS NULL OR expires_at > now())`

	rows, err := r.db.Query(ctx, query, targetID)
	if err != nil {
		return nil, fmt.Errorf("authorizationRepository.GetActiveAuthorizations: %w", err)
	}
	defer rows.Close()

	var auths []model.Authorization
	for rows.Next() {
		var a model.Authorization
		if err := rows.Scan(
			&a.ID, &a.UID, &a.TargetID, &a.Method, &a.Token,
			&a.ScopeKind, &a.ScopeValue,
			&a.VerifiedAt, &a.ExpiresAt, &a.AttestedBy, &a.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("authorizationRepository.GetActiveAuthorizations scan: %w", err)
		}
		auths = append(auths, a)
	}
	return auths, nil
}
