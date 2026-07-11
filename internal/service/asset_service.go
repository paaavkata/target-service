package service

import (
	"context"
	"fmt"
	"target-service/internal/model"
	"target-service/internal/producer"
	"target-service/internal/repository"
)

type assetService struct {
	targetRepo    repository.TargetRepositoryInterface
	assetRepo     repository.AssetRepositoryInterface
	kafkaProducer *producer.AuditProducer
	appID         string
}

// NewAssetService constructs the asset inventory service.
func NewAssetService(
	targetRepo repository.TargetRepositoryInterface,
	assetRepo repository.AssetRepositoryInterface,
	kafkaProducer *producer.AuditProducer,
	appID string,
) AssetServiceInterface {
	return &assetService{
		targetRepo:    targetRepo,
		assetRepo:     assetRepo,
		kafkaProducer: kafkaProducer,
		appID:         appID,
	}
}

func (s *assetService) ListAssets(ctx context.Context, userID int64, targetUID string) ([]model.AssetDTO, error) {
	assets, err := s.assetRepo.ListByTargetUID(ctx, userID, targetUID)
	if err != nil {
		return nil, fmt.Errorf("assetService.ListAssets: %w", err)
	}
	dtos := make([]model.AssetDTO, 0, len(assets))
	for _, a := range assets {
		dtos = append(dtos, assetToDTO(&a))
	}
	return dtos, nil
}

func (s *assetService) UpsertAssets(ctx context.Context, targetUID string, req *model.UpsertAssetsRequest) ([]model.AssetDTO, error) {
	// Resolve target by uid (internal call — no user_id check; trust scan-service).
	// GetByUIDInternal skips the user_id filter; see scope_service.go note.
	target, err := s.targetRepo.GetByUIDInternal(ctx, targetUID)
	if err != nil {
		return nil, fmt.Errorf("assetService.UpsertAssets: target not found: %w", err)
	}

	upserted, err := s.assetRepo.Upsert(ctx, target.ID, req.Assets)
	if err != nil {
		return nil, fmt.Errorf("assetService.UpsertAssets: %w", err)
	}

	// Emit scope_expanded audit event for new in-scope assets.
	_ = s.kafkaProducer.EmitScopeExpanded(ctx, s.appID, target, len(upserted))

	dtos := make([]model.AssetDTO, 0, len(upserted))
	for _, a := range upserted {
		dtos = append(dtos, assetToDTO(&a))
	}
	return dtos, nil
}

func assetToDTO(a *model.Asset) model.AssetDTO {
	return model.AssetDTO{
		UID:          a.UID,
		AssetType:    a.AssetType,
		Value:        a.Value,
		ScopeClass:   a.ScopeClass,
		Metadata:     a.Metadata,
		DiscoveredBy: a.DiscoveredBy,
		FirstSeen:    a.FirstSeen,
		LastSeen:     a.LastSeen,
	}
}
