package repository

import (
	"context"
	"errors"
	"fmt"
	"target-service/internal/model"
	"target-service/internal/store"

	"github.com/jackc/pgx/v5"
)

// programColumns is the canonical SELECT list; keep in sync with scanProgram.
const programColumns = `id, platform, handle, name, policy_url, automation_allowed,
		       rate_limit_rps, prohibited_techniques, safe_harbor, raw_policy,
		       synced_at, stale_after_seconds, status, created_at, updated_at`

type programRepository struct {
	db *store.DBService
}

// NewProgramRepository constructs the concrete program repository.
func NewProgramRepository(db *store.DBService) ProgramRepositoryInterface {
	return &programRepository{db: db}
}

func scanProgram(row rowScanner, p *model.BugbountyProgram) error {
	var raw []byte
	if err := row.Scan(
		&p.ID, &p.Platform, &p.Handle, &p.Name, &p.PolicyURL, &p.AutomationAllowed,
		&p.RateLimitRPS, &p.ProhibitedTechniques, &p.SafeHarbor, &raw,
		&p.SyncedAt, &p.StaleAfterSeconds, &p.Status, &p.CreatedAt, &p.UpdatedAt,
	); err != nil {
		return err
	}
	p.RawPolicy = raw
	return nil
}

func (r *programRepository) Sync(ctx context.Context, program *model.BugbountyProgram, assets []model.ProgramAsset) (*model.BugbountyProgram, error) {
	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("programRepository.Sync begin: %w", err)
	}
	defer tx.Rollback(ctx) // no-op after a successful Commit

	var rawPolicy interface{}
	if len(program.RawPolicy) > 0 {
		rawPolicy = []byte(program.RawPolicy)
	}
	techniques := program.ProhibitedTechniques
	if techniques == nil {
		techniques = []string{}
	}
	status := program.Status
	if status == "" {
		status = model.ProgramStatusActive
	}

	upsert := `
		INSERT INTO target.bugbounty_programs
		    (platform, handle, name, policy_url, automation_allowed, rate_limit_rps,
		     prohibited_techniques, safe_harbor, raw_policy, synced_at,
		     stale_after_seconds, status, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,now(),$10,$11,now())
		ON CONFLICT (platform, handle) DO UPDATE SET
		    name                  = EXCLUDED.name,
		    policy_url            = EXCLUDED.policy_url,
		    automation_allowed    = EXCLUDED.automation_allowed,
		    rate_limit_rps        = EXCLUDED.rate_limit_rps,
		    prohibited_techniques = EXCLUDED.prohibited_techniques,
		    safe_harbor           = EXCLUDED.safe_harbor,
		    raw_policy            = EXCLUDED.raw_policy,
		    synced_at             = now(),
		    stale_after_seconds   = EXCLUDED.stale_after_seconds,
		    status                = EXCLUDED.status,
		    updated_at            = now()
		RETURNING ` + programColumns

	stored := &model.BugbountyProgram{}
	row := tx.QueryRow(ctx, upsert,
		program.Platform, program.Handle, program.Name, program.PolicyURL,
		program.AutomationAllowed, program.RateLimitRPS, techniques, program.SafeHarbor,
		rawPolicy, program.StaleAfterSeconds, status,
	)
	if err := scanProgram(row, stored); err != nil {
		return nil, fmt.Errorf("programRepository.Sync upsert: %w", err)
	}

	// Replace assets atomically: delete all, re-insert.
	if _, err := tx.Exec(ctx, `DELETE FROM target.program_assets WHERE program_id = $1`, stored.ID); err != nil {
		return nil, fmt.Errorf("programRepository.Sync delete assets: %w", err)
	}
	for _, a := range assets {
		if _, err := tx.Exec(ctx,
			`INSERT INTO target.program_assets (program_id, asset_type, identifier, in_scope)
			 VALUES ($1,$2,$3,$4)`,
			stored.ID, a.AssetType, a.Identifier, a.InScope,
		); err != nil {
			return nil, fmt.Errorf("programRepository.Sync insert asset %q: %w", a.Identifier, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("programRepository.Sync commit: %w", err)
	}
	return stored, nil
}

func (r *programRepository) GetByPlatformHandle(ctx context.Context, platform, handle string) (*model.BugbountyProgram, error) {
	query := `SELECT ` + programColumns + ` FROM target.bugbounty_programs WHERE platform = $1 AND handle = $2`
	p := &model.BugbountyProgram{}
	if err := scanProgram(r.db.QueryRow(ctx, query, platform, handle), p); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("programRepository.GetByPlatformHandle: %w", ErrNotFound)
		}
		return nil, fmt.Errorf("programRepository.GetByPlatformHandle: %w", err)
	}
	return p, nil
}

func (r *programRepository) ListAssets(ctx context.Context, programID string) ([]model.ProgramAsset, error) {
	query := `SELECT id, program_id, asset_type, identifier, in_scope, created_at
		  FROM target.program_assets WHERE program_id = $1 ORDER BY in_scope DESC, identifier`
	rows, err := r.db.Query(ctx, query, programID)
	if err != nil {
		return nil, fmt.Errorf("programRepository.ListAssets: %w", err)
	}
	defer rows.Close()

	var assets []model.ProgramAsset
	for rows.Next() {
		var a model.ProgramAsset
		if err := rows.Scan(&a.ID, &a.ProgramID, &a.AssetType, &a.Identifier, &a.InScope, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("programRepository.ListAssets scan: %w", err)
		}
		assets = append(assets, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("programRepository.ListAssets rows: %w", err)
	}
	return assets, nil
}
