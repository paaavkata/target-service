package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"target-service/internal/model"
	"target-service/internal/store"

	"github.com/jackc/pgx/v5"
	"golang.org/x/net/publicsuffix"
)

// targetColumns is the canonical SELECT list; keep in sync with scanTarget.
const targetColumns = `id, uid, user_id, kind, value, registrable_domain, status, source, label, created_at, updated_at`

// allowedSortColumns whitelists ORDER BY columns (the sort key is interpolated
// into SQL, so it must never come straight from the request).
var allowedSortColumns = map[string]bool{
	"created_at": true,
	"updated_at": true,
	"status":     true,
	"value":      true,
	"source":     true,
	"user_id":    true,
}

type targetRepository struct {
	db *store.DBService
}

// NewTargetRepository constructs the concrete target repository.
func NewTargetRepository(db *store.DBService) TargetRepositoryInterface {
	return &targetRepository{db: db}
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanTarget(row rowScanner, t *model.Target) error {
	return row.Scan(
		&t.ID, &t.UID, &t.UserID, &t.Kind, &t.Value,
		&t.RegistrableDomain, &t.Status, &t.Source, &t.Label,
		&t.CreatedAt, &t.UpdatedAt,
	)
}

// NormalizeTargetValue applies the canonical value normalisation used by every
// target insert: trim + lowercase, and eTLD+1 derivation for domain/url kinds.
// IPs/CIDRs are kept as-is (apart from trim/lowercase, which is a no-op for them).
func NormalizeTargetValue(kind, raw string) (value string, registrableDomain *string) {
	value = strings.ToLower(strings.TrimSpace(raw))
	if kind == model.TargetKindDomain || kind == model.TargetKindURL {
		rd := extractRegistrableDomain(value)
		registrableDomain = &rd
	}
	return value, registrableDomain
}

// insert is the single INSERT path shared by Create and CreateProgram.
func (r *targetRepository) insert(ctx context.Context, userID int64, kind, rawValue, status, source string, label *string) (*model.Target, error) {
	value, registrableDomain := NormalizeTargetValue(kind, rawValue)

	query := `
		INSERT INTO target.targets (user_id, kind, value, registrable_domain, status, source, label, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, now(), now())
		ON CONFLICT (user_id, kind, value) DO NOTHING
		RETURNING ` + targetColumns

	row := r.db.QueryRow(ctx, query, userID, kind, value, registrableDomain, status, source, label)
	t := &model.Target{}
	if err := scanTarget(row, t); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// ON CONFLICT DO NOTHING yields no row → the (user_id, kind, value) exists.
			return nil, fmt.Errorf("targetRepository.insert: %w", ErrDuplicateTarget)
		}
		return nil, fmt.Errorf("targetRepository.insert: %w", err)
	}
	return t, nil
}

func (r *targetRepository) Create(ctx context.Context, userID int64, req *model.CreateTargetRequest) (*model.Target, error) {
	return r.insert(ctx, userID, req.Kind, req.Value, model.TargetStatusUnverified, model.TargetSourceCustomer, nil)
}

func (r *targetRepository) CreateProgram(ctx context.Context, userID int64, kind, value, label string) (*model.Target, error) {
	var lbl *string
	if l := strings.TrimSpace(label); l != "" {
		lbl = &l
	}
	return r.insert(ctx, userID, kind, value, model.TargetStatusVerified, model.TargetSourceProgram, lbl)
}

func (r *targetRepository) getOne(ctx context.Context, op, where string, args ...interface{}) (*model.Target, error) {
	query := `SELECT ` + targetColumns + ` FROM target.targets WHERE ` + where
	t := &model.Target{}
	if err := scanTarget(r.db.QueryRow(ctx, query, args...), t); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("targetRepository.%s: %w", op, ErrNotFound)
		}
		return nil, fmt.Errorf("targetRepository.%s: %w", op, err)
	}
	return t, nil
}

func (r *targetRepository) GetByUID(ctx context.Context, userID int64, uid string) (*model.Target, error) {
	return r.getOne(ctx, "GetByUID", "uid = $1 AND user_id = $2", uid, userID)
}

func (r *targetRepository) GetByUIDInternal(ctx context.Context, uid string) (*model.Target, error) {
	return r.getOne(ctx, "GetByUIDInternal", "uid = $1", uid)
}

func (r *targetRepository) GetByID(ctx context.Context, id int64) (*model.Target, error) {
	return r.getOne(ctx, "GetByID", "id = $1", id)
}

// buildWhere turns the optional filters into a WHERE clause + args. The
// placeholder index continues from len(args)+1 so callers can append more.
func buildWhere(params model.SearchParameters) (string, []interface{}) {
	where := []string{"1=1"}
	args := []interface{}{}

	if params.UserID != nil {
		args = append(args, *params.UserID)
		where = append(where, fmt.Sprintf("user_id = $%d", len(args)))
	}
	if params.Status != nil {
		args = append(args, *params.Status)
		where = append(where, fmt.Sprintf("status = $%d", len(args)))
	}
	if params.Source != nil {
		args = append(args, *params.Source)
		where = append(where, fmt.Sprintf("source = $%d", len(args)))
	}
	if params.Query != nil && strings.TrimSpace(*params.Query) != "" {
		args = append(args, "%"+escapeLike(strings.TrimSpace(*params.Query))+"%")
		where = append(where, fmt.Sprintf("(value ILIKE $%d OR label ILIKE $%d)", len(args), len(args)))
	}
	return strings.Join(where, " AND "), args
}

// escapeLike neutralises LIKE metacharacters so `q` is a literal substring match.
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

func (r *targetRepository) List(ctx context.Context, params model.SearchParameters) ([]model.Target, error) {
	where, args := buildWhere(params)

	sortBy := "created_at"
	if allowedSortColumns[params.SortBy] {
		sortBy = params.SortBy
	}
	sortOrder := "DESC"
	if params.SortOrder == "asc" {
		sortOrder = "ASC"
	}

	page := params.PageNumber
	if page < 1 {
		page = 1
	}
	size := params.PageSize
	if size < 1 {
		size = 50
	}
	offset := (page - 1) * size

	query := fmt.Sprintf(`
		SELECT %s
		FROM target.targets
		WHERE %s
		ORDER BY %s %s, id %s
		LIMIT $%d OFFSET $%d`,
		targetColumns, where, sortBy, sortOrder, sortOrder, len(args)+1, len(args)+2,
	)
	args = append(args, size, offset)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("targetRepository.List: %w", err)
	}
	defer rows.Close()

	targets := []model.Target{}
	for rows.Next() {
		var t model.Target
		if err := scanTarget(rows, &t); err != nil {
			return nil, fmt.Errorf("targetRepository.List scan: %w", err)
		}
		targets = append(targets, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("targetRepository.List rows: %w", err)
	}
	return targets, nil
}

func (r *targetRepository) Count(ctx context.Context, params model.SearchParameters) (int64, error) {
	where, args := buildWhere(params)
	var n int64
	if err := r.db.QueryRow(ctx, `SELECT count(*) FROM target.targets WHERE `+where, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("targetRepository.Count: %w", err)
	}
	return n, nil
}

func (r *targetRepository) countBy(ctx context.Context, column string) (map[string]int64, error) {
	rows, err := r.db.Query(ctx, fmt.Sprintf(`SELECT %s, count(*) FROM target.targets GROUP BY %s`, column, column))
	if err != nil {
		return nil, fmt.Errorf("targetRepository.CountBy%s: %w", column, err)
	}
	defer rows.Close()

	out := map[string]int64{}
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			return nil, fmt.Errorf("targetRepository.CountBy%s scan: %w", column, err)
		}
		out[k] = n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("targetRepository.CountBy%s rows: %w", column, err)
	}
	return out, nil
}

func (r *targetRepository) CountByStatus(ctx context.Context) (map[string]int64, error) {
	return r.countBy(ctx, "status")
}

func (r *targetRepository) CountBySource(ctx context.Context) (map[string]int64, error) {
	return r.countBy(ctx, "source")
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

func (r *targetRepository) DeleteByUID(ctx context.Context, uid string) error {
	query := `DELETE FROM target.targets WHERE uid = $1`
	if err := r.db.Exec(ctx, query, uid); err != nil {
		return fmt.Errorf("targetRepository.DeleteByUID: %w", err)
	}
	return nil
}

// extractRegistrableDomain derives the eTLD+1 from a host string using the
// ICANN public suffix list (golang.org/x/net/publicsuffix). This correctly
// handles multi-label TLDs (e.g. .co.uk, .com.au) and rejects prefix-spoofing.
func extractRegistrableDomain(host string) string {
	// Strip scheme
	if idx := strings.Index(host, "://"); idx >= 0 {
		host = host[idx+3:]
	}
	// Strip path
	if idx := strings.Index(host, "/"); idx >= 0 {
		host = host[:idx]
	}
	// Strip port (only if it looks like a port, not an IPv6 address)
	if !strings.Contains(host, "[") {
		if idx := strings.LastIndex(host, ":"); idx >= 0 {
			host = host[:idx]
		}
	}
	host = strings.ToLower(strings.TrimSpace(host))
	// Use the public suffix list for correct eTLD+1 derivation.
	rd, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		// Fallback: use last two labels for private TLDs or IPs.
		parts := strings.Split(host, ".")
		if len(parts) < 2 {
			return host
		}
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return rd
}
