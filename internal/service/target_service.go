package service

import (
	"context"
	"errors"
	"fmt"
	"target-service/internal/model"
	"target-service/internal/producer"
	"target-service/internal/repository"
)

// IPTargetsEnabled hard-disables ip/cidr target kinds (06 §2 gap): real
// registry-contact ownership verification for raw IP ranges is NOT implemented
// — the ip_registry method only returns "pending manual review", which is a
// scope-grant bypass risk if a manual step ever rubber-stamps it. Until a real
// RIR-contact verification flow exists, ip/cidr targets are refused at creation
// AND ip_range authorizations are refused at the scope gate (defense in depth,
// see scope_service.go CheckScope). Flip to true only once that flow ships.
var IPTargetsEnabled = false

// ErrIPTargetsUnsupported is the sentinel returned when an ip/cidr target is
// requested while IPTargetsEnabled is false. Handlers map it to a 4xx.
var ErrIPTargetsUnsupported = errors.New("IP/CIDR targets are not yet supported (ownership verification for raw IP ranges is not implemented)")

type targetService struct {
	targetRepo repository.TargetRepositoryInterface
	authRepo   repository.AuthorizationRepositoryInterface
	verifier   *VerificationService
	// kafkaProducer: naming leftover from before the Kafka→NATS migration; the
	// field's type (producer.AuditProducer) actually wraps go-nats, not Kafka.
	kafkaProducer *producer.AuditProducer
	appID         string
}

// NewTargetService constructs the target domain service.
func NewTargetService(
	targetRepo repository.TargetRepositoryInterface,
	authRepo repository.AuthorizationRepositoryInterface,
	verifier *VerificationService,
	kafkaProducer *producer.AuditProducer,
	appID string,
) TargetServiceInterface {
	return &targetService{
		targetRepo:    targetRepo,
		authRepo:      authRepo,
		verifier:      verifier,
		kafkaProducer: kafkaProducer,
		appID:         appID,
	}
}

func (s *targetService) CreateTarget(ctx context.Context, userID int64, req *model.CreateTargetRequest) (*model.TargetDetailDTO, error) {
	// Hard-disable ip/cidr targets BEFORE anything is persisted: their ownership
	// verification is not implemented (see IPTargetsEnabled).
	if (req.Kind == model.TargetKindIP || req.Kind == model.TargetKindCIDR) && !IPTargetsEnabled {
		return nil, ErrIPTargetsUnsupported
	}

	t, err := s.targetRepo.Create(ctx, userID, req)
	if err != nil {
		return nil, fmt.Errorf("targetService.CreateTarget: %w", err)
	}

	// Issue an initial verification challenge automatically.
	method := defaultMethodForKind(t.Kind)
	auth, token, err := s.verifier.IssueChallenge(ctx, t, method, userID)
	if err != nil {
		// Non-fatal: target is created; challenge can be re-issued.
		return targetToDetailDTO(t, nil, nil, nil), nil
	}

	instructions := buildInstructions(method, token, t)
	return targetToDetailDTO(t, auth, &token, &instructions), nil
}

func (s *targetService) ListTargets(ctx context.Context, userID int64, params model.SearchParameters) ([]model.TargetDTO, error) {
	params.UserID = &userID
	targets, err := s.targetRepo.List(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("targetService.ListTargets: %w", err)
	}
	dtos := make([]model.TargetDTO, 0, len(targets))
	for _, t := range targets {
		dtos = append(dtos, targetToDTO(&t))
	}
	return dtos, nil
}

func (s *targetService) GetTarget(ctx context.Context, userID int64, uid string) (*model.TargetDetailDTO, error) {
	t, err := s.targetRepo.GetByUID(ctx, userID, uid)
	if err != nil {
		return nil, fmt.Errorf("targetService.GetTarget: %w", err)
	}
	auth, _ := s.authRepo.GetByTargetID(ctx, t.ID)
	return targetToDetailDTO(t, auth, nil, nil), nil
}

func (s *targetService) TriggerVerification(ctx context.Context, userID int64, uid string, req *model.VerifyTargetRequest) (*model.TargetDetailDTO, error) {
	t, err := s.targetRepo.GetByUID(ctx, userID, uid)
	if err != nil {
		return nil, fmt.Errorf("targetService.TriggerVerification: target not found: %w", err)
	}

	// Get or create an authorization record with a challenge token.
	auth, err := s.authRepo.GetByTargetID(ctx, t.ID)
	if err != nil || auth == nil {
		// Issue a new challenge for the requested method.
		auth, _, err = s.verifier.IssueChallenge(ctx, t, req.Method, userID)
		if err != nil {
			return nil, fmt.Errorf("targetService.TriggerVerification.IssueChallenge: %w", err)
		}
	}

	// Attempt verification now.
	if err := s.targetRepo.UpdateStatus(ctx, t.ID, model.TargetStatusVerifying); err != nil {
		return nil, fmt.Errorf("targetService.TriggerVerification.UpdateStatus: %w", err)
	}

	ok, detail, verifyErr := s.verifier.RunCheck(ctx, t, auth)
	if verifyErr != nil {
		_ = s.targetRepo.UpdateStatus(ctx, t.ID, model.TargetStatusUnverified)
		_ = s.kafkaProducer.EmitVerificationFailed(ctx, s.appID, t, detail)
		return nil, fmt.Errorf("targetService.TriggerVerification: check failed: %w", verifyErr)
	}

	if !ok {
		_ = s.targetRepo.UpdateStatus(ctx, t.ID, model.TargetStatusUnverified)
		_ = s.kafkaProducer.EmitVerificationFailed(ctx, s.appID, t, detail)
		return nil, fmt.Errorf("verification check did not pass: %s", detail)
	}

	// Record successful verification with 60-day expiry.
	if err := s.authRepo.MarkVerified(ctx, auth.ID, "now() + interval '60 days'"); err != nil {
		return nil, fmt.Errorf("targetService.TriggerVerification.MarkVerified: %w", err)
	}
	if err := s.targetRepo.UpdateStatus(ctx, t.ID, model.TargetStatusVerified); err != nil {
		return nil, fmt.Errorf("targetService.TriggerVerification.UpdateStatus verified: %w", err)
	}

	_ = s.kafkaProducer.EmitTargetVerified(ctx, s.appID, t)

	// Re-fetch to get final state.
	t, _ = s.targetRepo.GetByUID(ctx, userID, uid)
	auth, _ = s.authRepo.GetByTargetID(ctx, t.ID)
	return targetToDetailDTO(t, auth, nil, nil), nil
}

func (s *targetService) DeleteTarget(ctx context.Context, userID int64, uid string) error {
	if err := s.targetRepo.Delete(ctx, userID, uid); err != nil {
		return fmt.Errorf("targetService.DeleteTarget: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func defaultMethodForKind(kind string) string {
	switch kind {
	case model.TargetKindIP, model.TargetKindCIDR:
		return model.VerificationMethodIPRegistry
	default:
		return model.VerificationMethodDNSTXT
	}
}

func buildInstructions(method, token string, t *model.Target) string {
	switch method {
	case model.VerificationMethodDNSTXT:
		return fmt.Sprintf("Add a DNS TXT record to %s with value: scantinel-verify=%s", t.Value, token)
	case model.VerificationMethodHTTPFile:
		return fmt.Sprintf("Serve the file https://%s/.well-known/scantinel-verify/%s containing the token: %s", t.Value, token, token)
	case model.VerificationMethodMetaTag:
		return fmt.Sprintf(`Add to your homepage: <meta name="scantinel-verify" content="%s">`, token)
	case model.VerificationMethodIPRegistry:
		return fmt.Sprintf("Contact the RIR-registered abuse/registrant address for %s and confirm ownership with token: %s", t.Value, token)
	default:
		return fmt.Sprintf("Use token %s to verify ownership", token)
	}
}

func targetToDTO(t *model.Target) model.TargetDTO {
	return model.TargetDTO{
		UID:               t.UID,
		Kind:              t.Kind,
		Value:             t.Value,
		RegistrableDomain: t.RegistrableDomain,
		Status:            t.Status,
		CreatedAt:         t.CreatedAt,
		UpdatedAt:         t.UpdatedAt,
	}
}

func targetToDetailDTO(t *model.Target, auth *model.Authorization, token *string, instructions *string) *model.TargetDetailDTO {
	dto := &model.TargetDetailDTO{
		TargetDTO:   targetToDTO(t),
		VerifyToken: token,
		VerifyInstructions: func() string {
			if instructions != nil {
				return *instructions
			}
			return ""
		}(),
	}
	if auth != nil {
		dto.Authorization = &model.AuthorizationDTO{
			UID:        auth.UID,
			Method:     auth.Method,
			ScopeKind:  auth.ScopeKind,
			ScopeValue: auth.ScopeValue,
			VerifiedAt: auth.VerifiedAt,
			ExpiresAt:  auth.ExpiresAt,
		}
	}
	return dto
}
