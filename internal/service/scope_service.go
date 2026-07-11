// Package service implements the business logic for target-service.
// This file owns the authorization gate (scope check) — the most critical logic
// in the service (06_AUTHORIZATION_AND_SAFETY.md §1, §3, §7).
package service

import (
	"context"
	"fmt"
	"net"
	"strings"
	"target-service/internal/model"
	"target-service/internal/repository"
)

// knownSharedInfraRanges is a conservative denylist of well-known CDN / shared
// infrastructure CIDR blocks (06 §3 shared-infrastructure exclusion).
// Production: extend this list or load from config/DB.
var knownSharedInfraRanges = []string{
	// Cloudflare
	"103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
	"131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
	"172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
	"190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
	// Fastly
	"23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24",
	"103.245.222.0/23", "103.245.224.0/24", "104.156.80.0/20",
	"151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17",
	"172.111.64.0/18", "185.31.16.0/22", "199.27.72.0/21",
	// Akamai (representative ranges)
	"23.32.0.0/11", "23.64.0.0/14", "23.192.0.0/11",
}

var parsedSharedRanges []*net.IPNet

func init() {
	for _, cidr := range knownSharedInfraRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			parsedSharedRanges = append(parsedSharedRanges, network)
		}
	}
}

type scopeService struct {
	targetRepo repository.TargetRepositoryInterface
	authRepo   repository.AuthorizationRepositoryInterface
}

// NewScopeService constructs the authorization gate service.
func NewScopeService(
	targetRepo repository.TargetRepositoryInterface,
	authRepo repository.AuthorizationRepositoryInterface,
) ScopeServiceInterface {
	return &scopeService{
		targetRepo: targetRepo,
		authRepo:   authRepo,
	}
}

// denyResult is a convenience constructor for a denial response.
func denyResult(reason string) *model.ScopeCheckResponse {
	return &model.ScopeCheckResponse{Authorized: false, Reason: reason}
}

// allowResult is a convenience constructor for an allowance response.
func allowResult(reason string) *model.ScopeCheckResponse {
	return &model.ScopeCheckResponse{Authorized: true, Reason: reason}
}

// CheckScope is the authorization gate (06 §1, §3, §7).
// Returns {authorized, reason}.
//
// Decision logic:
//  1. Resolve the target and check it is in "verified" status.
//  2. Require at least one active (non-expired, verified) authorization.
//  3. For each authorization, evaluate whether the queried host/IP falls inside
//     the authorized scope:
//     – scope_kind=registrable_domain: the queried host must be the apex or a
//     subdomain of the authorized registrable domain.
//     – scope_kind=ip_range: the queried IP must fall within the authorized CIDR.
//  4. Reject if the host/IP resolves to a known shared-infra range (even if it
//     passes the registrable-domain check).
//  5. Deny by default — any ambiguity is a "not authorized" (conservative gate).
func (s *scopeService) CheckScope(ctx context.Context, req *model.ScopeCheckRequest) (*model.ScopeCheckResponse, error) {
	if req.Host == "" && req.IP == "" {
		return denyResult("host or ip is required"), nil
	}

	// Resolve the target.
	// The target_uid is the scoping key for internal calls (cluster-only route).
	// GetByUIDInternal skips the user_id filter — acceptable only on the
	// cluster-internal NetworkPolicy-protected endpoint.
	target, err := s.targetRepo.GetByUIDInternal(ctx, req.TargetUID)
	if err != nil {
		return denyResult(fmt.Sprintf("target not found: %v", err)), nil
	}

	if target.Status != model.TargetStatusVerified {
		return denyResult(fmt.Sprintf("target status is %q — only verified targets may be scanned intrusively", target.Status)), nil
	}

	auths, err := s.authRepo.GetActiveAuthorizations(ctx, target.ID)
	if err != nil {
		return nil, fmt.Errorf("scopeService.CheckScope: %w", err)
	}
	if len(auths) == 0 {
		return denyResult("no active (verified, non-expired) authorization exists for this target"), nil
	}

	// Determine what we're checking.
	queryHost := strings.ToLower(strings.TrimSpace(req.Host))
	queryIP := strings.TrimSpace(req.IP)

	// Shared-infra check for IPs.
	if queryIP != "" {
		ip := net.ParseIP(queryIP)
		if ip == nil {
			return denyResult(fmt.Sprintf("invalid IP address: %s", queryIP)), nil
		}
		if isSharedInfra(ip) {
			return denyResult(fmt.Sprintf("IP %s belongs to a known shared-infrastructure range — intrusive testing is not permitted (06 §3)", queryIP)), nil
		}
	}
	// If a host was given, resolve it and check against shared-infra.
	if queryHost != "" {
		resolvedIPs, _ := net.LookupHost(queryHost)
		for _, rip := range resolvedIPs {
			ip := net.ParseIP(rip)
			if ip != nil && isSharedInfra(ip) {
				return denyResult(fmt.Sprintf("host %s resolves to a shared-infrastructure IP (%s) — intrusive testing is not permitted (06 §3)", queryHost, rip)), nil
			}
		}
	}

	// Evaluate each active authorization.
	for _, auth := range auths {
		switch auth.ScopeKind {

		case model.ScopeKindRegistrableDomain:
			// Authorized scope: apex + subdomains.
			// Only applicable when we have a host to check.
			if queryHost == "" {
				continue
			}
			if isSubdomainOf(queryHost, auth.ScopeValue) {
				return allowResult(fmt.Sprintf("host %q is within authorized registrable-domain scope %q (authorization %s)", queryHost, auth.ScopeValue, auth.UID)), nil
			}

		case model.ScopeKindIPRange:
			// Authorized scope: confirmed IP range.
			if queryIP != "" {
				ip := net.ParseIP(queryIP)
				_, network, cidrErr := net.ParseCIDR(auth.ScopeValue)
				if cidrErr == nil && ip != nil && network.Contains(ip) {
					return allowResult(fmt.Sprintf("IP %s is within authorized IP-range scope %s (authorization %s)", queryIP, auth.ScopeValue, auth.UID)), nil
				}
				// Single-IP scope (stored without /32 notation).
				if auth.ScopeValue == queryIP {
					return allowResult(fmt.Sprintf("IP %s matches authorized IP scope (authorization %s)", queryIP, auth.UID)), nil
				}
			}
		}
	}

	return denyResult(fmt.Sprintf("host/IP is not within any authorized scope for target %s — separate verification required (06 §3)", req.TargetUID)), nil
}

// isSubdomainOf returns true if host equals apex or ends with "."+apex.
// Both inputs are assumed to be lowercase.
//   - isSubdomainOf("example.com", "example.com")       → true  (apex match)
//   - isSubdomainOf("api.example.com", "example.com")   → true  (subdomain)
//   - isSubdomainOf("notexample.com", "example.com")    → false
//   - isSubdomainOf("evil-example.com", "example.com")  → false (registrable-domain guard)
func isSubdomainOf(host, apex string) bool {
	host = strings.ToLower(host)
	apex = strings.ToLower(apex)
	return host == apex || strings.HasSuffix(host, "."+apex)
}

// isSharedInfra reports whether ip belongs to any known shared-infrastructure range.
func isSharedInfra(ip net.IP) bool {
	for _, network := range parsedSharedRanges {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
