package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"target-service/internal/model"
	"target-service/internal/store"
)

type assetRepository struct {
	db *store.DBService
}

// NewAssetRepository constructs the concrete asset repository.
func NewAssetRepository(db *store.DBService) AssetRepositoryInterface {
	return &assetRepository{db: db}
}

func (r *assetRepository) Upsert(ctx context.Context, targetID int64, items []model.AssetUpsertItem) ([]model.Asset, error) {
	var result []model.Asset
	for _, item := range items {
		meta, _ := json.Marshal(item.Metadata)
		query := `
			INSERT INTO target.assets (target_id, asset_type, value, scope_class, metadata, discovered_by, first_seen, last_seen)
			VALUES ($1, $2, $3, 'unknown', $4, $5, now(), now())
			ON CONFLICT (target_id, asset_type, value)
			DO UPDATE SET last_seen = now(), metadata = EXCLUDED.metadata, discovered_by = COALESCE(EXCLUDED.discovered_by, assets.discovered_by)
			RETURNING id, uid, target_id, asset_type, value, parent_asset_id, scope_class, metadata, discovered_by, first_seen, last_seen`

		row := r.db.QueryRow(ctx, query, targetID, item.AssetType, item.Value, string(meta), item.DiscoveredBy)
		var a model.Asset
		var metaRaw []byte
		if err := row.Scan(
			&a.ID, &a.UID, &a.TargetID, &a.AssetType, &a.Value,
			&a.ParentAssetID, &a.ScopeClass, &metaRaw, &a.DiscoveredBy,
			&a.FirstSeen, &a.LastSeen,
		); err != nil {
			return nil, fmt.Errorf("assetRepository.Upsert: %w", err)
		}
		if len(metaRaw) > 0 {
			_ = json.Unmarshal(metaRaw, &a.Metadata)
		}
		result = append(result, a)
	}
	return result, nil
}

func (r *assetRepository) ListByTargetUID(ctx context.Context, userID int64, targetUID string) ([]model.Asset, error) {
	query := `
		SELECT a.id, a.uid, a.target_id, a.asset_type, a.value, a.parent_asset_id,
		       a.scope_class, a.metadata, a.discovered_by, a.first_seen, a.last_seen
		FROM target.assets a
		JOIN target.targets t ON t.id = a.target_id
		WHERE t.uid = $1 AND t.user_id = $2
		ORDER BY a.first_seen DESC`
	return r.list(ctx, "ListByTargetUID", query, targetUID, userID)
}

// ListByTargetID lists a target's assets without user scoping (admin detail).
func (r *assetRepository) ListByTargetID(ctx context.Context, targetID int64) ([]model.Asset, error) {
	query := `
		SELECT a.id, a.uid, a.target_id, a.asset_type, a.value, a.parent_asset_id,
		       a.scope_class, a.metadata, a.discovered_by, a.first_seen, a.last_seen
		FROM target.assets a
		WHERE a.target_id = $1
		ORDER BY a.first_seen DESC`
	return r.list(ctx, "ListByTargetID", query, targetID)
}

func (r *assetRepository) list(ctx context.Context, op, query string, args ...interface{}) ([]model.Asset, error) {
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("assetRepository.%s: %w", op, err)
	}
	defer rows.Close()

	var assets []model.Asset
	for rows.Next() {
		var a model.Asset
		var metaRaw []byte
		if err := rows.Scan(
			&a.ID, &a.UID, &a.TargetID, &a.AssetType, &a.Value, &a.ParentAssetID,
			&a.ScopeClass, &metaRaw, &a.DiscoveredBy, &a.FirstSeen, &a.LastSeen,
		); err != nil {
			return nil, fmt.Errorf("assetRepository.%s scan: %w", op, err)
		}
		if len(metaRaw) > 0 {
			_ = json.Unmarshal(metaRaw, &a.Metadata)
		}
		assets = append(assets, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("assetRepository.%s rows: %w", op, err)
	}
	return assets, nil
}
