// Bug-bounty program-policy sync (17 §10). SyncProgram pulls a program's scope
// from its platform through a ProgramPolicyConnector and upserts it (plus its
// assets) into target-service's own authorization store. The admin attests the
// automation / rate-limit / prohibited-technique terms that the platform APIs
// do not expose machine-readably; absent ⇒ default-deny (automation stays off).
package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"target-service/internal/ingest"
	"target-service/internal/model"
	"target-service/internal/repository"
)

// ErrNoPolicyConnector is returned when no connector is registered for the
// requested platform. The admin cannot sync a platform we cannot reach.
var ErrNoPolicyConnector = errors.New("no program-policy connector configured for this platform")

// ErrPolicySourceUnavailable is re-exported for handler error mapping.
var ErrPolicySourceUnavailable = ingest.ErrPolicySourceUnavailable

type programService struct {
	repo       repository.ProgramRepositoryInterface
	connectors map[string]ingest.ProgramPolicyConnector
}

// NewProgramService builds the program service with the given connectors keyed
// by platform.
func NewProgramService(repo repository.ProgramRepositoryInterface, connectors ...ingest.ProgramPolicyConnector) ProgramServiceInterface {
	m := make(map[string]ingest.ProgramPolicyConnector, len(connectors))
	for _, c := range connectors {
		if c != nil {
			m[c.Platform()] = c
		}
	}
	return &programService{repo: repo, connectors: m}
}

func (s *programService) SyncProgram(ctx context.Context, req *model.SyncProgramRequest) (*model.ProgramDTO, error) {
	conn, ok := s.connectors[req.Platform]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNoPolicyConnector, req.Platform)
	}

	policy, err := conn.FetchProgram(ctx, req.Handle)
	if err != nil {
		return nil, fmt.Errorf("programService.SyncProgram: %w", err)
	}

	status := req.Status
	if status == "" {
		status = model.ProgramStatusActive
	}
	program := &model.BugbountyProgram{
		Platform:             req.Platform,
		Handle:               strings.TrimSpace(req.Handle),
		Name:                 policy.Name,
		PolicyURL:            policy.PolicyURL,
		AutomationAllowed:    req.AutomationAllowed,
		RateLimitRPS:         req.RateLimitRPS,
		ProhibitedTechniques: normalizeTechniques(req.ProhibitedTechniques),
		SafeHarbor:           policy.SafeHarbor,
		RawPolicy:            policy.RawPolicy,
		StaleAfterSeconds:    req.StaleAfterSeconds,
		Status:               status,
	}

	assets := make([]model.ProgramAsset, 0, len(policy.Assets))
	for _, a := range policy.Assets {
		assets = append(assets, model.ProgramAsset{
			AssetType:  a.AssetType,
			Identifier: strings.ToLower(strings.TrimSpace(a.Identifier)),
			InScope:    a.InScope,
		})
	}

	stored, err := s.repo.Sync(ctx, program, assets)
	if err != nil {
		return nil, fmt.Errorf("programService.SyncProgram: %w", err)
	}
	storedAssets, err := s.repo.ListAssets(ctx, stored.ID)
	if err != nil {
		return nil, fmt.Errorf("programService.SyncProgram list assets: %w", err)
	}
	return programToDTO(stored, storedAssets), nil
}

func programToDTO(p *model.BugbountyProgram, assets []model.ProgramAsset) *model.ProgramDTO {
	techniques := p.ProhibitedTechniques
	if techniques == nil {
		techniques = []string{}
	}
	if assets == nil {
		assets = []model.ProgramAsset{}
	}
	return &model.ProgramDTO{
		ID:                   p.ID,
		Platform:             p.Platform,
		Handle:               p.Handle,
		Name:                 p.Name,
		PolicyURL:            p.PolicyURL,
		AutomationAllowed:    p.AutomationAllowed,
		RateLimitRPS:         p.RateLimitRPS,
		ProhibitedTechniques: techniques,
		SafeHarbor:           p.SafeHarbor,
		SyncedAt:             p.SyncedAt,
		StaleAfterSeconds:    p.StaleAfterSeconds,
		Status:               p.Status,
		Assets:               assets,
	}
}
