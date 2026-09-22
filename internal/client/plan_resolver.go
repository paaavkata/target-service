package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultPlan is the plan assumed when nothing better is known — the same
// default the gateway plugin uses.
const DefaultPlan = "free"

// PlanTTL mirrors the traefik-plugin's plan cache (30 s).
const PlanTTL = 30 * time.Second

// PlanResolver resolves a user's plan exactly like the traefik-plugin does:
// service-service GET /v1/apps/{app_id}/customers/{user_id}/rate-tier →
// {"plan_name": "..."}, default "free", cached 30 s. It is only consulted
// when the caller did not stamp X-User-Plan.
type PlanResolver struct {
	baseURL string
	appID   string
	http    *http.Client
	ttl     time.Duration
	now     func() time.Time

	mu    sync.Mutex
	cache map[string]planEntry
}

type planEntry struct {
	plan    string
	expires time.Time
}

// NewPlanResolver builds a resolver against service-service
// (e.g. http://service-service.platform-dev). An empty baseURL makes Resolve
// always return DefaultPlan.
func NewPlanResolver(baseURL, appID string) *PlanResolver {
	return &PlanResolver{
		baseURL: strings.TrimRight(baseURL, "/"),
		appID:   appID,
		http:    &http.Client{Timeout: 3 * time.Second},
		ttl:     PlanTTL,
		now:     time.Now,
		cache:   map[string]planEntry{},
	}
}

// Resolve returns the user's plan; any error resolves to DefaultPlan (not cached).
func (r *PlanResolver) Resolve(ctx context.Context, userID int64) string {
	if r == nil || r.baseURL == "" || userID <= 0 {
		return DefaultPlan
	}
	key := fmt.Sprint(userID)
	r.mu.Lock()
	if e, ok := r.cache[key]; ok && r.now().Before(e.expires) {
		r.mu.Unlock()
		return e.plan
	}
	r.mu.Unlock()

	plan, err := r.fetch(ctx, key)
	if err != nil {
		return DefaultPlan
	}
	r.mu.Lock()
	r.cache[key] = planEntry{plan: plan, expires: r.now().Add(r.ttl)}
	r.mu.Unlock()
	return plan
}

func (r *PlanResolver) fetch(ctx context.Context, userID string) (string, error) {
	u := fmt.Sprintf("%s/v1/apps/%s/customers/%s/rate-tier", r.baseURL, url.PathEscape(r.appID), url.PathEscape(userID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-App-Id", r.appID)
	resp, err := r.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("rate-tier status %d", resp.StatusCode)
	}
	var body struct {
		PlanName string `json:"plan_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	plan := strings.ToLower(strings.TrimSpace(body.PlanName))
	if plan == "" {
		plan = DefaultPlan
	}
	return plan, nil
}
