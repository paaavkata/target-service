// Admin-panel operations on targets (plans/10-ADMIN-PANEL.md §3).
//
// Every method here is cross-user by design and MUST only be reachable through
// handler.RequireAdmin. The scope gate (scope_service.go) is untouched: a
// program/manual authorization is just another verified, expiring
// authorizations row, so 06 §1–§3 keep working unchanged.
package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"target-service/internal/model"
	"target-service/internal/repository"
	"time"
)

func (s *targetService) ListAll(ctx context.Context, params model.SearchParameters) ([]model.TargetAdminDTO, int64, error) {
	targets, err := s.targetRepo.List(ctx, params)
	if err != nil {
		return nil, 0, fmt.Errorf("targetService.ListAll: %w", err)
	}
	total, err := s.targetRepo.Count(ctx, params)
	if err != nil {
		return nil, 0, fmt.Errorf("targetService.ListAll count: %w", err)
	}
	dtos := make([]model.TargetAdminDTO, 0, len(targets))
	for i := range targets {
		t := targets[i]
		auth, _ := s.authRepo.GetByTargetID(ctx, t.ID)
		dtos = append(dtos, targetToAdminDTO(&t, auth, nil))
	}
	return dtos, total, nil
}

func (s *targetService) GetAnyByUID(ctx context.Context, uid string) (*model.TargetAdminDTO, error) {
	t, err := s.getAny(ctx, uid)
	if err != nil {
		return nil, err
	}
	auth, _ := s.authRepo.GetByTargetID(ctx, t.ID)
	var assets []model.Asset
	if s.assetRepo != nil {
		assets, _ = s.assetRepo.ListByTargetID(ctx, t.ID)
	}
	dto := targetToAdminDTO(t, auth, assets)
	return &dto, nil
}

func (s *targetService) CreateProgramTarget(ctx context.Context, adminUserID int64, req *model.AdminCreateProgramTargetRequest) (*model.TargetAdminDTO, error) {
	// Same kind gate as the customer path: ip/cidr stay refused while
	// IPTargetsEnabled is false, program or not.
	if err := checkKindAllowed(req.Kind); err != nil {
		return nil, err
	}
	ownerID := req.UserID
	if ownerID == 0 {
		ownerID = adminUserID
	}
	days := req.Program.AuthorizedDays
	if days == 0 {
		days = DefaultAdminAuthorizedDays
	}

	t, err := s.targetRepo.CreateProgram(ctx, ownerID, req.Kind, req.Value, req.Label)
	if err != nil {
		if errors.Is(err, repository.ErrDuplicateTarget) {
			return nil, ErrTargetExists
		}
		return nil, fmt.Errorf("targetService.CreateProgramTarget: %w", err)
	}

	now := time.Now()
	expires := now.Add(time.Duration(days) * 24 * time.Hour)
	scopeKind, scopeValue := scopeForTarget(t)
	auth, err := s.authRepo.Create(ctx, &model.Authorization{
		TargetID:   t.ID,
		Method:     model.VerificationMethodProgram,
		Token:      "",
		ScopeKind:  scopeKind,
		ScopeValue: scopeValue,
		VerifiedAt: &now,
		ExpiresAt:  &expires,
		AttestedBy: &adminUserID,
		Evidence:   programEvidence(req.Program),
	})
	if err != nil {
		// Never leave a status=verified target without its authorization row:
		// the scope gate would deny anyway (no active authorization), but the
		// admin would see a "verified" target that cannot be scanned.
		_ = s.targetRepo.DeleteByUID(ctx, t.UID)
		return nil, fmt.Errorf("targetService.CreateProgramTarget: authorization: %w", err)
	}

	_ = s.auditProducer.EmitAdminTargetCreated(ctx, s.appID, adminUserID, t, auth)

	dto := targetToAdminDTO(t, auth, nil)
	return &dto, nil
}

func (s *targetService) AuthorizeManually(ctx context.Context, adminUserID int64, uid string, req *model.AdminAuthorizeTargetRequest) (*model.TargetAdminDTO, error) {
	t, err := s.getAny(ctx, uid)
	if err != nil {
		return nil, err
	}
	// Manual attestation cannot bypass the ip/cidr hard-disable either: the
	// scope gate refuses ip_range authorizations while IPTargetsEnabled is
	// false, so marking one verified would only produce an unusable target.
	if err := checkKindAllowed(t.Kind); err != nil {
		return nil, err
	}
	days := req.AuthorizedDays
	if days == 0 {
		days = DefaultAdminAuthorizedDays
	}
	now := time.Now()
	expires := now.Add(time.Duration(days) * 24 * time.Hour)
	evidence := map[string]interface{}{"note": strings.TrimSpace(req.Note)}

	var auth *model.Authorization
	latest, _ := s.authRepo.GetByTargetID(ctx, t.ID)
	if latest != nil && latest.VerifiedAt == nil {
		// A pending challenge exists (e.g. email / ip_registry awaiting the
		// out-of-band confirmation): confirm it in place.
		if err := s.authRepo.MarkVerified(ctx, latest.ID, expires, evidence); err != nil {
			return nil, fmt.Errorf("targetService.AuthorizeManually.MarkVerified: %w", err)
		}
		latest.VerifiedAt = &now
		latest.ExpiresAt = &expires
		latest.Evidence = evidence
		auth = latest
	} else {
		scopeKind, scopeValue := scopeForTarget(t)
		auth, err = s.authRepo.Create(ctx, &model.Authorization{
			TargetID:   t.ID,
			Method:     model.VerificationMethodManual,
			Token:      "",
			ScopeKind:  scopeKind,
			ScopeValue: scopeValue,
			VerifiedAt: &now,
			ExpiresAt:  &expires,
			AttestedBy: &adminUserID,
			Evidence:   evidence,
		})
		if err != nil {
			return nil, fmt.Errorf("targetService.AuthorizeManually.Create: %w", err)
		}
	}

	if err := s.targetRepo.UpdateStatus(ctx, t.ID, model.TargetStatusVerified); err != nil {
		return nil, fmt.Errorf("targetService.AuthorizeManually.UpdateStatus: %w", err)
	}
	t.Status = model.TargetStatusVerified
	t.UpdatedAt = now

	_ = s.auditProducer.EmitAdminTargetAuthorized(ctx, s.appID, adminUserID, t, auth, req.Note)

	dto := targetToAdminDTO(t, auth, nil)
	return &dto, nil
}

func (s *targetService) Revoke(ctx context.Context, adminUserID int64, uid string, reason string) (*model.TargetAdminDTO, error) {
	t, err := s.getAny(ctx, uid)
	if err != nil {
		return nil, err
	}
	// Order matters for the kill switch: expire the authorizations FIRST so the
	// scope gate denies even if the status update below fails.
	expired, err := s.authRepo.ExpireActiveAuthorizations(ctx, t.ID)
	if err != nil {
		return nil, fmt.Errorf("targetService.Revoke.ExpireActiveAuthorizations: %w", err)
	}
	if err := s.targetRepo.UpdateStatus(ctx, t.ID, model.TargetStatusRevoked); err != nil {
		return nil, fmt.Errorf("targetService.Revoke.UpdateStatus: %w", err)
	}
	t.Status = model.TargetStatusRevoked
	t.UpdatedAt = time.Now()

	_ = s.auditProducer.EmitAdminTargetRevoked(ctx, s.appID, adminUserID, t, reason, expired)

	auth, _ := s.authRepo.GetByTargetID(ctx, t.ID)
	dto := targetToAdminDTO(t, auth, nil)
	return &dto, nil
}

func (s *targetService) DeleteAny(ctx context.Context, adminUserID int64, uid string) error {
	t, err := s.getAny(ctx, uid)
	if err != nil {
		return err
	}
	if err := s.targetRepo.DeleteByUID(ctx, uid); err != nil {
		return fmt.Errorf("targetService.DeleteAny: %w", err)
	}
	_ = s.auditProducer.EmitAdminTargetDeleted(ctx, s.appID, adminUserID, t)
	return nil
}

func (s *targetService) Stats(ctx context.Context) (*model.AdminStatsResponse, error) {
	byStatus, err := s.targetRepo.CountByStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("targetService.Stats: %w", err)
	}
	bySource, err := s.targetRepo.CountBySource(ctx)
	if err != nil {
		return nil, fmt.Errorf("targetService.Stats: %w", err)
	}
	// Always surface the known keys so the panel's tiles never read "undefined".
	for _, st := range []string{model.TargetStatusUnverified, model.TargetStatusVerifying, model.TargetStatusVerified, model.TargetStatusRevoked} {
		if _, ok := byStatus[st]; !ok {
			byStatus[st] = 0
		}
	}
	for _, src := range []string{model.TargetSourceCustomer, model.TargetSourceProgram} {
		if _, ok := bySource[src]; !ok {
			bySource[src] = 0
		}
	}
	var total int64
	for _, n := range byStatus {
		total += n
	}
	return &model.AdminStatsResponse{Total: total, ByStatus: byStatus, BySource: bySource}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// getAny resolves a target by uid without owner scoping and maps a miss to
// ErrTargetNotFound so handlers can answer 404.
func (s *targetService) getAny(ctx context.Context, uid string) (*model.Target, error) {
	t, err := s.targetRepo.GetByUIDInternal(ctx, uid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) || isLookupMiss(err) {
			return nil, ErrTargetNotFound
		}
		return nil, fmt.Errorf("targetService.getAny: %w", err)
	}
	return t, nil
}

// programEvidence is the JSON stored in authorizations.evidence for a program
// target — the program IS the authorization record.
func programEvidence(p model.ProgramEvidence) map[string]interface{} {
	return map[string]interface{}{
		"platform":    p.Platform,
		"name":        strings.TrimSpace(p.Name),
		"url":         strings.TrimSpace(p.URL),
		"policy_url":  strings.TrimSpace(p.PolicyURL),
		"scope_notes": strings.TrimSpace(p.ScopeNotes),
	}
}

func targetToAdminDTO(t *model.Target, auth *model.Authorization, assets []model.Asset) model.TargetAdminDTO {
	dto := model.TargetAdminDTO{
		UID:               t.UID,
		UserID:            t.UserID,
		Kind:              t.Kind,
		Value:             t.Value,
		RegistrableDomain: t.RegistrableDomain,
		Status:            t.Status,
		Source:            t.Source,
		Label:             t.Label,
		CreatedAt:         t.CreatedAt,
		UpdatedAt:         t.UpdatedAt,
		Authorization:     authorizationToAdminDTO(auth),
	}
	if assets != nil {
		dto.Assets = make([]model.AssetDTO, 0, len(assets))
		for i := range assets {
			dto.Assets = append(dto.Assets, assetToDTO(&assets[i]))
		}
	}
	return dto
}
