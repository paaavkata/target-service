// Package client holds target-service's outbound HTTP clients.
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

// EntitlementsTTL is how long a plan's entitlement row is cached. Plan edits
// in the admin panel therefore reach target-service within a minute.
const EntitlementsTTL = 60 * time.Second

// EntitlementsClient reads plan entitlements from scan-service, which owns the
// plan_entitlements matrix (SecScanApp/plans/12-ENTITLEMENTS.md). target-service
// never stores the matrix itself.
type EntitlementsClient struct {
	baseURL string
	appID   string
	http    *http.Client
	ttl     time.Duration
	now     func() time.Time

	mu    sync.Mutex
	cache map[string]entitlementEntry
}

type entitlementEntry struct {
	maxTargets int
	expires    time.Time
}

// NewEntitlementsClient builds a client for scan-service's internal API
// (e.g. http://scan-service.scantinel-dev).
func NewEntitlementsClient(baseURL, appID string) *EntitlementsClient {
	return &EntitlementsClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		appID:   appID,
		http:    &http.Client{Timeout: 3 * time.Second},
		ttl:     EntitlementsTTL,
		now:     time.Now,
		cache:   map[string]entitlementEntry{},
	}
}

// MaxTargets returns the plan's max_targets (-1 = unlimited) from
// GET {scan-service}/internal/v1/entitlements/{plan}, cached for 60 s.
func (c *EntitlementsClient) MaxTargets(ctx context.Context, plan string) (int, error) {
	c.mu.Lock()
	if e, ok := c.cache[plan]; ok && c.now().Before(e.expires) {
		c.mu.Unlock()
		return e.maxTargets, nil
	}
	c.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/internal/v1/entitlements/"+url.PathEscape(plan), nil)
	if err != nil {
		return 0, fmt.Errorf("entitlements: build request: %w", err)
	}
	if c.appID != "" {
		req.Header.Set("X-App-Id", c.appID)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("entitlements: GET %s: %w", plan, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("entitlements: GET %s: status %d", plan, resp.StatusCode)
	}
	var env struct {
		Data *struct {
			MaxTargets *int `json:"max_targets"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return 0, fmt.Errorf("entitlements: decode: %w", err)
	}
	if env.Data == nil || env.Data.MaxTargets == nil {
		return 0, fmt.Errorf("entitlements: response for %s has no max_targets", plan)
	}

	c.mu.Lock()
	c.cache[plan] = entitlementEntry{maxTargets: *env.Data.MaxTargets, expires: c.now().Add(c.ttl)}
	c.mu.Unlock()
	return *env.Data.MaxTargets, nil
}
