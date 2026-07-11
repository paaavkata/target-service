package repository

import (
	"context"
	"fmt"
	"strings"
	"target-service/internal/model"
	"target-service/internal/store"
)

type targetRepository struct {
	db *store.DBService
}

// NewTargetRepository constructs the concrete target repository.
func NewTargetRepository(db *store.DBService) TargetRepositoryInterface {
	return &targetRepository{db: db}
}

func (r *targetRepository) Create(ctx context.Context, userID int64, req *model.CreateTargetRequest) (*model.Target, error) {
	// Normalise value: lowercase for domains/URLs; keep as-is for IPs/CIDRs.
	value := strings.ToLower(strings.TrimSpace(req.Value))

	var registrableDomain *string
	if req.Kind == model.TargetKindDomain || req.Kind == model.TargetKindURL {
		rd := extractRegistrableDomain(value)
		registrableDomain = &rd
	}

	query := `
		INSERT INTO target.targets (user_id, kind, value, registrable_domain, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'unverified', now(), now())
		ON CONFLICT (user_id, kind, value) DO NOTHING
		RETURNING id, uid, user_id, kind, value, registrable_domain, status, created_at, updated_at`

	row := r.db.QueryRow(ctx, query, userID, req.Kind, value, registrableDomain)
	t := &model.Target{}
	if err := row.Scan(
		&t.ID, &t.UID, &t.UserID, &t.Kind, &t.Value,
		&t.RegistrableDomain, &t.Status, &t.CreatedAt, &t.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("targetRepository.Create: %w", err)
	}
	return t, nil
}

func (r *targetRepository) GetByUID(ctx context.Context, userID int64, uid string) (*model.Target, error) {
	query := `
		SELECT id, uid, user_id, kind, value, registrable_domain, status, created_at, updated_at
		FROM target.targets
		WHERE uid = $1 AND user_id = $2`

	row := r.db.QueryRow(ctx, query, uid, userID)
	t := &model.Target{}
	if err := row.Scan(
		&t.ID, &t.UID, &t.UserID, &t.Kind, &t.Value,
		&t.RegistrableDomain, &t.Status, &t.CreatedAt, &t.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("targetRepository.GetByUID: %w", err)
	}
	return t, nil
}

func (r *targetRepository) GetByUIDInternal(ctx context.Context, uid string) (*model.Target, error) {
	query := `
		SELECT id, uid, user_id, kind, value, registrable_domain, status, created_at, updated_at
		FROM target.targets
		WHERE uid = $1`

	row := r.db.QueryRow(ctx, query, uid)
	t := &model.Target{}
	if err := row.Scan(
		&t.ID, &t.UID, &t.UserID, &t.Kind, &t.Value,
		&t.RegistrableDomain, &t.Status, &t.CreatedAt, &t.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("targetRepository.GetByUIDInternal: %w", err)
	}
	return t, nil
}

func (r *targetRepository) GetByID(ctx context.Context, id int64) (*model.Target, error) {
	query := `
		SELECT id, uid, user_id, kind, value, registrable_domain, status, created_at, updated_at
		FROM target.targets
		WHERE id = $1`

	row := r.db.QueryRow(ctx, query, id)
	t := &model.Target{}
	if err := row.Scan(
		&t.ID, &t.UID, &t.UserID, &t.Kind, &t.Value,
		&t.RegistrableDomain, &t.Status, &t.CreatedAt, &t.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("targetRepository.GetByID: %w", err)
	}
	return t, nil
}

func (r *targetRepository) List(ctx context.Context, params model.SearchParameters) ([]model.Target, error) {
	where := []string{"1=1"}
	args := []interface{}{}
	idx := 1

	if params.UserID != nil {
		where = append(where, fmt.Sprintf("user_id = $%d", idx))
		args = append(args, *params.UserID)
		idx++
	}
	if params.Status != nil {
		where = append(where, fmt.Sprintf("status = $%d", idx))
		args = append(args, *params.Status)
		idx++
	}

	sortBy := "created_at"
	sortOrder := "desc"
	if params.SortBy != "" {
		sortBy = params.SortBy
	}
	if params.SortOrder == "asc" {
		sortOrder = "asc"
	}

	offset := (params.PageNumber - 1) * params.PageSize

	query := fmt.Sprintf(`
		SELECT id, uid, user_id, kind, value, registrable_domain, status, created_at, updated_at
		FROM target.targets
		WHERE %s
		ORDER BY %s %s
		LIMIT $%d OFFSET $%d`,
		strings.Join(where, " AND "), sortBy, sortOrder, idx, idx+1,
	)
	args = append(args, params.PageSize, offset)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("targetRepository.List: %w", err)
	}
	defer rows.Close()

	var targets []model.Target
	for rows.Next() {
		var t model.Target
		if err := rows.Scan(
			&t.ID, &t.UID, &t.UserID, &t.Kind, &t.Value,
			&t.RegistrableDomain, &t.Status, &t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("targetRepository.List scan: %w", err)
		}
		targets = append(targets, t)
	}
	return targets, nil
}

func (r *targetRepository) UpdateStatus(ctx context.Context, id int64, status string) error {
	query := `UPDATE target.targets SET status = $1, updated_at = now() WHERE id = $2`
	if err := r.db.Exec(ctx, query, status, id); err != nil {
		return fmt.Errorf("targetRepository.UpdateStatus: %w", err)
	}
	return nil
}

func (r *targetRepository) Delete(ctx context.Context, userID int64, uid string) error {
	query := `DELETE FROM target.targets WHERE uid = $1 AND user_id = $2`
	if err := r.db.Exec(ctx, query, uid, userID); err != nil {
		return fmt.Errorf("targetRepository.Delete: %w", err)
	}
	return nil
}

// extractRegistrableDomain derives the eTLD+1 from a host string.
// For scaffold purposes this uses a simple heuristic (last two labels).
// In production, replace with golang.org/x/net/publicsuffix.
func extractRegistrableDomain(host string) string {
	// Strip scheme
	if idx := strings.Index(host, "://"); idx >= 0 {
		host = host[idx+3:]
	}
	// Strip path
	if idx := strings.Index(host, "/"); idx >= 0 {
		host = host[:idx]
	}
	// Strip port
	if idx := strings.LastIndex(host, ":"); idx >= 0 {
		host = host[:idx]
	}
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
