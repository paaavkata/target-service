package service

import (
	"context"
	"fmt"
	"strings"

	"target-service/internal/model"
	"target-service/internal/repository"

	logger "github.com/paaavkata/go-logger"
)

// MaxTargetsSource yields a plan's max_targets (-1 = unlimited). Implemented
// by client.EntitlementsClient (scan-service owns the plan matrix).
type MaxTargetsSource interface {
	MaxTargets(ctx context.Context, plan string) (int, error)
}

// PlanSource resolves a user's plan when the caller did not stamp X-User-Plan.
type PlanSource interface {
	Resolve(ctx context.Context, userID int64) string
}

// TargetCapError is returned by TargetCapService.Check when the user is at or
// over their plan's target limit. The handler maps it to 403
// {code: plan_upgrade_required, plan, max_targets}.
type TargetCapError struct {
	Plan       string
	MaxTargets int
	Count      int64
}

func (e *TargetCapError) Error() string {
	return fmt.Sprintf("plan %q allows %d target(s); you already have %d", e.Plan, e.MaxTargets, e.Count)
}

// TargetCapService enforces the per-plan target cap on customer target creation
// (plans/11-PRICING-RESEARCH.md §5). It FAILS OPEN: if scan-service or the
// count query is unavailable, target creation is allowed and a warning logged,
// so an outage never blocks onboarding.
type TargetCapService struct {
	targets repository.TargetRepositoryInterface
	limits  MaxTargetsSource
	plans   PlanSource
}

// NewTargetCapService wires the cap check. plans may be nil (header-only).
func NewTargetCapService(targets repository.TargetRepositoryInterface, limits MaxTargetsSource, plans PlanSource) *TargetCapService {
	return &TargetCapService{targets: targets, limits: limits, plans: plans}
}

// ResolvePlan prefers the trusted X-User-Plan value (gateway / website stamped),
// else asks service-service, else "free".
func (s *TargetCapService) ResolvePlan(ctx context.Context, headerPlan string, userID int64) string {
	if p := strings.ToLower(strings.TrimSpace(headerPlan)); p != "" {
		return p
	}
	if s.plans != nil {
		return s.plans.Resolve(ctx, userID)
	}
	return "free"
}

// Check returns *TargetCapError when userID may not register another target on plan.
func (s *TargetCapService) Check(ctx context.Context, userID int64, plan string) error {
	if s == nil || s.limits == nil {
		return nil
	}
	max, err := s.limits.MaxTargets(ctx, plan)
	if err != nil {
		logger.Warningf("target cap: entitlements unavailable for plan=%s user_id=%d, failing open: %v", plan, userID, err)
		return nil
	}
	if max < 0 {
		return nil
	}
	uid := userID
	n, err := s.targets.Count(ctx, model.SearchParameters{UserID: &uid})
	if err != nil {
		logger.Warningf("target cap: count failed for user_id=%d, failing open: %v", userID, err)
		return nil
	}
	if n >= int64(max) {
		return &TargetCapError{Plan: plan, MaxTargets: max, Count: n}
	}
	return nil
}
