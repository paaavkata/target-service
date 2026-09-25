package service

import (
	"context"
	"errors"
	"fmt"
	"target-service/internal/model"
	"target-service/internal/producer"
	"target-service/internal/repository"
	"time"
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

// ErrTargetNotFound is returned by the admin methods when the uid does not exist.
var ErrTargetNotFound = errors.New("target not found")

// ErrTargetAdminAuthorized is returned when a customer runs the ownership challenge on a
// target whose authorization was granted by an administrator (bug-bounty program or manual
// attestation). Those targets have no challenge token, so "verifying" them can only demote
// them; the handler maps this to 409.
var ErrTargetAdminAuthorized = errors.New("this target was authorized by an administrator; the ownership challenge does not apply")

// ErrTargetExists is returned when (user_id, kind, value) is already registered.
var ErrTargetExists = errors.New("target already exists for this user")

// CustomerAuthorizationTTL is how long a challenge-proven authorization stays
// valid before the customer must re-verify (06 §2 recommends 30–90 days).
const CustomerAuthorizationTTL = 60 * 24 * time.Hour

// DefaultAdminAuthorizedDays is the authorization lifetime for program/manual
// authorizations when the admin does not pass authorized_days.
const DefaultAdminAuthorizedDays = 90

// checkKindAllowed is the single ip/cidr hard-disable gate shared by the
// customer Create and the admin CreateProgramTarget paths. It runs BEFORE
// anything is persisted.
func checkKindAllowed(kind string) error {
	if (kind == model.TargetKindIP || kind == model.TargetKindCIDR) && !IPTargetsEnabled {
		return ErrIPTargetsUnsupported
	}
	return nil
}

type targetService struct {
	targetRepo    repository.TargetRepositoryInterface
	authRepo      repository.AuthorizationRepositoryInterface
	assetRepo     repository.AssetRepositoryInterface
	verifier      *VerificationService
	auditProducer *producer.AuditProducer
	appID         string
}

// NewTargetService constructs the target domain service. assetRepo is only
// used by the admin detail route and may be nil in tests that don't exercise it.
func NewTargetService(
	targetRepo repository.TargetRepositoryInterface,
	authRepo repository.AuthorizationRepositoryInterface,
	assetRepo repository.AssetRepositoryInterface,
	verifier *VerificationService,
	auditProducer *producer.AuditProducer,
	appID string,
) TargetServiceInterface {
	return &targetService{
		targetRepo:    targetRepo,
		authRepo:      authRepo,
		assetRepo:     assetRepo,
		verifier:      verifier,
		auditProducer: auditProducer,
		appID:         appID,
	}
}

func (s *targetService) CreateTarget(ctx context.Context, userID int64, req *model.CreateTargetRequest) (*model.TargetDetailDTO, error) {
	// Hard-disable ip/cidr targets BEFORE anything is persisted: their ownership
	// verification is not implemented (see IPTargetsEnabled).
	if err := checkKindAllowed(req.Kind); err != nil {
		return nil, err
	}

	t, err := s.targetRepo.Create(ctx, userID, req)
	if err != nil {
		if errors.Is(err, repository.ErrDuplicateTarget) {
			return nil, ErrTargetExists
		}
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
	if auth == nil && t.Status != model.TargetStatusVerified && t.Source != model.TargetSourceProgram {
		// The challenge issued at create time failed (non-fatal there): issue one now so the
		// owner always has a token to publish.
		if issued, _, err := s.verifier.IssueChallenge(ctx, t, defaultMethodForKind(t.Kind), userID); err == nil {
			auth = issued
		}
	}
	// While the target is not verified the owner needs the challenge token on every read of
	// the detail page, not only in the create response (which a browser flow never keeps).
	// The token is the caller's own (GetByUID is user-scoped) and is useless once verified.
	if t.Status != model.TargetStatusVerified && auth != nil && isChallengeMethod(auth.Method) && auth.Token != "" {
		token := auth.Token
		instructions := buildInstructions(auth.Method, token, t)
		return targetToDetailDTO(t, auth, &token, &instructions), nil
	}
	return targetToDetailDTO(t, auth, nil, nil), nil
}

func (s *targetService) TriggerVerification(ctx context.Context, userID int64, uid string, req *model.VerifyTargetRequest) (*model.TargetDetailDTO, error) {
	t, err := s.targetRepo.GetByUID(ctx, userID, uid)
	if err != nil {
		return nil, fmt.Errorf("targetService.TriggerVerification: target not found: %w", err)
	}

	// Admin-authorized targets (program / manual) carry no challenge token: running the
	// check would hit RunCheck's unknown-method branch and demote the target to unverified.
	auth, err := s.authRepo.GetByTargetID(ctx, t.ID)
	if t.Source == model.TargetSourceProgram ||
		(auth != nil && (auth.Method == model.VerificationMethodProgram || auth.Method == model.VerificationMethodManual)) {
		return nil, ErrTargetAdminAuthorized
	}
	// Get or create an authorization record with a challenge token.
	if err != nil || auth == nil {
		// Issue a new challenge for the requested method.
		auth, _, err = s.verifier.IssueChallenge(ctx, t, req.Method, userID)
		if err != nil {
			return nil, fmt.Errorf("targetService.TriggerVerification.IssueChallenge: %w", err)
		}
	} else if req.Method != auth.Method && isChallengeMethod(req.Method) && isChallengeMethod(auth.Method) && auth.Token != "" {
		// The owner picked a different method than the one the challenge was issued for
		// (create always issues dns_txt). RunCheck dispatches on auth.Method, so without this
		// the HTTP-file and meta-tag checks silently ran the DNS check. The token is
		// method-independent: keep the one the owner has already published.
		auth, err = s.verifier.SwitchMethod(ctx, t, auth, req.Method)
		if err != nil {
			return nil, fmt.Errorf("targetService.TriggerVerification.SwitchMethod: %w", err)
		}
	}

	// Attempt verification now.
	if err := s.targetRepo.UpdateStatus(ctx, t.ID, model.TargetStatusVerifying); err != nil {
		return nil, fmt.Errorf("targetService.TriggerVerification.UpdateStatus: %w", err)
	}

	ok, detail, verifyErr := s.verifier.RunCheck(ctx, t, auth)
	if verifyErr != nil {
		_ = s.targetRepo.UpdateStatus(ctx, t.ID, model.TargetStatusUnverified)
		_ = s.auditProducer.EmitVerificationFailed(ctx, s.appID, t, detail)
		return nil, fmt.Errorf("targetService.TriggerVerification: check failed: %w", verifyErr)
	}

	if !ok {
		_ = s.targetRepo.UpdateStatus(ctx, t.ID, model.TargetStatusUnverified)
		_ = s.auditProducer.EmitVerificationFailed(ctx, s.appID, t, detail)
		return nil, fmt.Errorf("verification check did not pass: %s", detail)
	}

	// Record successful verification with 60-day expiry.
	if err := s.authRepo.MarkVerified(ctx, auth.ID, time.Now().Add(CustomerAuthorizationTTL), nil); err != nil {
		return nil, fmt.Errorf("targetService.TriggerVerification.MarkVerified: %w", err)
	}
	if err := s.targetRepo.UpdateStatus(ctx, t.ID, model.TargetStatusVerified); err != nil {
		return nil, fmt.Errorf("targetService.TriggerVerification.UpdateStatus verified: %w", err)
	}

	_ = s.auditProducer.EmitTargetVerified(ctx, s.appID, t)

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

// isChallengeMethod reports whether the method is proven by publishing the challenge token
// (and can therefore be checked on demand with RunCheck).
func isChallengeMethod(method string) bool {
	switch method {
	case model.VerificationMethodDNSTXT, model.VerificationMethodHTTPFile, model.VerificationMethodMetaTag:
		return true
	}
	return false
}

// buildInstructions describes exactly what the per-method verifier checks
// (verification_service.go): the host is normalizeHost(target.Value) for all three.
func buildInstructions(method, token string, t *model.Target) string {
	host := normalizeHost(t.Value)
	switch method {
	case model.VerificationMethodDNSTXT:
		return fmt.Sprintf("Add a DNS TXT record to %s with value: scantinel-verify=%s", host, token)
	case model.VerificationMethodHTTPFile:
		return fmt.Sprintf("Serve https://%s/.well-known/scantinel-verify/%s with the token as its only content: %s", host, token, token)
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
		Source:            t.Source,
		Label:             t.Label,
		CreatedAt:         t.CreatedAt,
		UpdatedAt:         t.UpdatedAt,
	}
}

// authorizationToDTO is the customer-facing projection: it deliberately omits attested_by
// and evidence (the admin's program record / free-text note), which only the admin DTO shows.
func authorizationToDTO(auth *model.Authorization) *model.AuthorizationDTO {
	if auth == nil {
		return nil
	}
	return &model.AuthorizationDTO{
		UID:        auth.UID,
		Method:     auth.Method,
		ScopeKind:  auth.ScopeKind,
		ScopeValue: auth.ScopeValue,
		VerifiedAt: auth.VerifiedAt,
		ExpiresAt:  auth.ExpiresAt,
	}
}

// authorizationToAdminDTO adds the admin-only audit fields on top of authorizationToDTO.
func authorizationToAdminDTO(auth *model.Authorization) *model.AuthorizationDTO {
	dto := authorizationToDTO(auth)
	if dto == nil {
		return nil
	}
	dto.AttestedBy = auth.AttestedBy
	dto.Evidence = auth.Evidence
	return dto
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
	dto.Authorization = authorizationToDTO(auth)
	return dto
}
