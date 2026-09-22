package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"target-service/internal/model"
	"target-service/internal/store"
	"time"

	"github.com/jackc/pgx/v5"
)

// authorizationColumns is the canonical SELECT list; keep in sync with scanAuthorization.
const authorizationColumns = `id, uid, target_id, method, token, scope_kind, scope_value,
		       verified_at, expires_at, attested_by, evidence, created_at`

type authorizationRepository struct {
	db *store.DBService
}

// NewAuthorizationRepository constructs the concrete authorization repository.
func NewAuthorizationRepository(db *store.DBService) AuthorizationRepositoryInterface {
	return &authorizationRepository{db: db}
}

func scanAuthorization(row rowScanner, a *model.Authorization) error {
	var evidenceRaw []byte
	if err := row.Scan(
		&a.ID, &a.UID, &a.TargetID, &a.Method, &a.Token,
		&a.ScopeKind, &a.ScopeValue,
		&a.VerifiedAt, &a.ExpiresAt, &a.AttestedBy, &evidenceRaw, &a.CreatedAt,
	); err != nil {
		return err
	}
	if len(evidenceRaw) > 0 {
		_ = json.Unmarshal(evidenceRaw, &a.Evidence)
	}
	return nil
}

// marshalEvidence returns a JSONB-ready value, or nil (SQL NULL) when unset.
func marshalEvidence(evidence map[string]interface{}) (interface{}, error) {
	if evidence == nil {
		return nil, nil
	}
	b, err := json.Marshal(evidence)
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

func (r *authorizationRepository) Create(ctx context.Context, auth *model.Authorization) (*model.Authorization, error) {
	evidence, err := marshalEvidence(auth.Evidence)
	if err != nil {
		return nil, fmt.Errorf("authorizationRepository.Create: marshal evidence: %w", err)
	}

	query := `
		INSERT INTO target.authorizations
		    (target_id, method, token, scope_kind, scope_value, verified_at, expires_at, attested_by, evidence, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, now())
		RETURNING ` + authorizationColumns

	row := r.db.QueryRow(ctx, query,
		auth.TargetID, auth.Method, auth.Token,
		auth.ScopeKind, auth.ScopeValue,
		auth.VerifiedAt, auth.ExpiresAt, auth.AttestedBy, evidence,
	)
	a := &model.Authorization{}
	if err := scanAuthorization(row, a); err != nil {
		return nil, fmt.Errorf("authorizationRepository.Create: %w", err)
	}
	return a, nil
}

func (r *authorizationRepository) getOne(ctx context.Context, op, where string, args ...interface{}) (*model.Authorization, error) {
	query := `SELECT ` + authorizationColumns + ` FROM target.authorizations WHERE ` + where
	a := &model.Authorization{}
	if err := scanAuthorization(r.db.QueryRow(ctx, query, args...), a); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("authorizationRepository.%s: %w", op, ErrNotFound)
		}
		return nil, fmt.Errorf("authorizationRepository.%s: %w", op, err)
	}
	return a, nil
}

func (r *authorizationRepository) GetByTargetID(ctx context.Context, targetID int64) (*model.Authorization, error) {
	return r.getOne(ctx, "GetByTargetID", "target_id = $1 ORDER BY created_at DESC, id DESC LIMIT 1", targetID)
}

func (r *authorizationRepository) GetPendingByToken(ctx context.Context, token string) (*model.Authorization, error) {
	return r.getOne(ctx, "GetPendingByToken", "token = $1 AND verified_at IS NULL LIMIT 1", token)
}

func (r *authorizationRepository) MarkVerified(ctx context.Context, id int64, expiresAt time.Time, evidence map[string]interface{}) error {
	ev, err := marshalEvidence(evidence)
	if err != nil {
		return fmt.Errorf("authorizationRepository.MarkVerified: marshal evidence: %w", err)
	}
	query := `
		UPDATE target.authorizations
		SET verified_at = now(),
		    expires_at  = $1,
		    evidence    = COALESCE($2::jsonb, evidence)
		WHERE id = $3`
	if err := r.db.Exec(ctx, query, expiresAt, ev, id); err != nil {
		return fmt.Errorf("authorizationRepository.MarkVerified: %w", err)
	}
	return nil
}

// GetActiveAuthorizations returns all non-expired verified authorizations for a target.
func (r *authorizationRepository) GetActiveAuthorizations(ctx context.Context, targetID int64) ([]model.Authorization, error) {
	query := `
		SELECT ` + authorizationColumns + `
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
		if err := scanAuthorization(rows, &a); err != nil {
			return nil, fmt.Errorf("authorizationRepository.GetActiveAuthorizations scan: %w", err)
		}
		auths = append(auths, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("authorizationRepository.GetActiveAuthorizations rows: %w", err)
	}
	return auths, nil
}

// ExpireActiveAuthorizations is the admin kill switch (plans/10-ADMIN-PANEL.md §3):
// every currently-active authorization of the target expires immediately, so the
// scope gate denies every new intrusive task.
func (r *authorizationRepository) ExpireActiveAuthorizations(ctx context.Context, targetID int64) (int64, error) {
	query := `
		UPDATE target.authorizations
		SET expires_at = now()
		WHERE target_id = $1
		  AND verified_at IS NOT NULL
		  AND (expires_at IS NULL OR expires_at > now())`
	tag, err := r.db.Pool().Exec(ctx, query, targetID)
	if err != nil {
		return 0, fmt.Errorf("authorizationRepository.ExpireActiveAuthorizations: %w", err)
	}
	return tag.RowsAffected(), nil
}
