// Package service implements the business logic for target-service.
// This file owns the authorization gate (scope check) — the most critical logic
// in the service (06_AUTHORIZATION_AND_SAFETY.md §1, §3, §7).
package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"target-service/internal/model"
	"target-service/internal/repository"
	"time"

	"github.com/paaavkata/go-safedial"
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

// The reserved/internal-IP denylist (RFC1918, loopback, link-local incl. cloud
// metadata, CGNAT, IPv6 ULA, ...) lives in github.com/paaavkata/go-safedial —
// shared with scan-service and agent-service (06 §3, §7). isSharedInfra below
// stays local: it is an authorization-policy exclusion (CDN ranges), not a
// network-safety list, and no other consumer needs it.

var parsedSharedRanges []*net.IPNet

func init() {
	for _, cidr := range knownSharedInfraRanges {
		if _, network, err := net.ParseCIDR(cidr); err == nil {
			parsedSharedRanges = append(parsedSharedRanges, network)
		}
	}
}

// hostResolver resolves a hostname to its IP addresses. Injected so the SSRF /
// rebinding guard is unit-testable without real DNS.
type hostResolver func(host string) ([]string, error)

type scopeService struct {
	targetRepo  repository.TargetRepositoryInterface
	authRepo    repository.AuthorizationRepositoryInterface
	programRepo repository.ProgramRepositoryInterface // nil ⇒ program mode inactive (legacy behaviour preserved)
	resolve     hostResolver
}

// NewScopeService constructs the authorization gate service with the real
// system resolver and no program store (client mode only).
func NewScopeService(
	targetRepo repository.TargetRepositoryInterface,
	authRepo repository.AuthorizationRepositoryInterface,
) ScopeServiceInterface {
	return NewScopeServiceWithResolver(targetRepo, authRepo, net.LookupHost)
}

// NewScopeServiceWithResolver is NewScopeService with an injectable resolver
// (tests supply a fake so the reserved-IP / rebinding denials are deterministic).
func NewScopeServiceWithResolver(
	targetRepo repository.TargetRepositoryInterface,
	authRepo repository.AuthorizationRepositoryInterface,
	resolve hostResolver,
) ScopeServiceInterface {
	return &scopeService{
		targetRepo: targetRepo,
		authRepo:   authRepo,
		resolve:    resolve,
	}
}

// NewScopeServiceWithProgram is the production constructor: it adds the
// bug-bounty program store so program-mode authorizations are enforced (17 §10).
func NewScopeServiceWithProgram(
	targetRepo repository.TargetRepositoryInterface,
	authRepo repository.AuthorizationRepositoryInterface,
	programRepo repository.ProgramRepositoryInterface,
) ScopeServiceInterface {
	return &scopeService{
		targetRepo:  targetRepo,
		authRepo:    authRepo,
		programRepo: programRepo,
		resolve:     net.LookupHost,
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
//  4. For INTRUSIVE requests (req.Intrusive true or absent), reject if the
//     host/IP resolves to a known shared-infra range (even if it passes the
//     registrable-domain check) — unless the request is application-layer
//     (req.Layer == "application") and matches a registrable-domain scope:
//     HTTP/TLS to the customer's own hostname through a CDN is authorized
//     and pinned to the edge IPs. Non-intrusive requests may target a CDN edge.
//     A directly-supplied shared-infra IP is denied for intrusive testing at
//     every layer (ip_range scope never gets the relaxation).
//  5. Deny by default — any ambiguity is a "not authorized" (conservative gate).
//
// Reasons returned by CheckVerified (stable tokens; scan-service logs them).
const (
	VerifiedReasonOK          = "verified"
	VerifiedReasonNotFound    = "not_found"
	VerifiedReasonNotOwner    = "not_owner"
	VerifiedReasonNotVerified = "not_verified"
	VerifiedReasonNoActive    = "no_active_authorization"
)

// CheckVerified is the scan-launch ownership gate consulted by scan-service
// StartScan (plans/10-ADMIN-PANEL.md §3). It is deliberately weaker than
// CheckScope (no host/IP evaluation) — CheckScope still runs per task.
func (s *scopeService) CheckVerified(ctx context.Context, targetUID string, userID *int64) (*model.VerifiedCheckResponse, error) {
	target, err := s.targetRepo.GetByUIDInternal(ctx, targetUID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) || isLookupMiss(err) {
			return &model.VerifiedCheckResponse{Verified: false, Reason: VerifiedReasonNotFound}, nil
		}
		return nil, fmt.Errorf("scopeService.CheckVerified: %w", err)
	}
	// Ownership first: a caller must never learn the state of someone else's target.
	if userID != nil && *userID != target.UserID {
		return &model.VerifiedCheckResponse{Verified: false, Reason: VerifiedReasonNotOwner}, nil
	}
	if target.Status != model.TargetStatusVerified {
		return &model.VerifiedCheckResponse{Verified: false, Reason: VerifiedReasonNotVerified}, nil
	}
	auths, err := s.authRepo.GetActiveAuthorizations(ctx, target.ID)
	if err != nil {
		return nil, fmt.Errorf("scopeService.CheckVerified: %w", err)
	}
	if !hasActiveAuthorization(auths, time.Now()) {
		return &model.VerifiedCheckResponse{Verified: false, Reason: VerifiedReasonNoActive}, nil
	}
	res := &model.VerifiedCheckResponse{
		Verified: true,
		Reason:   VerifiedReasonOK,
		Kind:     target.Kind,
		Value:    target.Value,
	}
	if target.RegistrableDomain != nil {
		res.RegistrableDomain = *target.RegistrableDomain
	}
	return res, nil
}

// hasActiveAuthorization re-checks verified_at/expires_at in Go even though the
// repository already filters in SQL — defense in depth for the launch gate.
func hasActiveAuthorization(auths []model.Authorization, now time.Time) bool {
	for _, a := range auths {
		if a.VerifiedAt == nil {
			continue
		}
		if a.ExpiresAt != nil && !a.ExpiresAt.After(now) {
			continue
		}
		return true
	}
	return false
}

// isLookupMiss treats any repository "not found" flavour (including test fakes
// that return a plain error) as a miss rather than an outage.
func isLookupMiss(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "not found")
}

// Auth-scan phase keys (16 T4, 15 §5/§6). These are the state-changing
// authenticated-scanning phases. They share the whole host/IP scope gate below
// but carry two EXTRA, default-deny preconditions enforced by authScanVerdict:
// a current ownership verification AND the per-scan auth_scan_authorized
// attestation. Any phase in the auth_* namespace that is not one of these keys
// is denied by default (an unrecognized state-changing phase must never slip
// through). Values are the exact strings scan-service sends as ScanTask.Phase.
const (
	PhaseAuthRegister    = "auth_register"
	PhaseAuthCrawl       = "auth_crawl"
	PhaseAuthAccountMgmt = "auth_account_mgmt"
)

// authScanPhases is the allowlist of recognized auth-scan phase keys.
var authScanPhases = map[string]bool{
	PhaseAuthRegister:    true,
	PhaseAuthCrawl:       true,
	PhaseAuthAccountMgmt: true,
}

// isAuthScanNamespace reports whether phase is in the state-changing auth-scan
// namespace. Everything here is gated by authScanVerdict; everything outside it
// keeps the service's existing (non-auth) behaviour unchanged.
func isAuthScanNamespace(phase string) bool {
	return strings.HasPrefix(phase, "auth_")
}

// authScanVerdict applies the extra default-deny gate the state-changing
// auth-scan phases must pass BEFORE the normal host/IP scope evaluation
// (15 §5 destructive-op handling, §6 per-scan attestation). It returns:
//   - a deny for an unrecognized auth_* phase ("default-deny" — an unknown
//     state-changing phase, including any destructive one, is refused here);
//   - a skip "unverified target" when the target has no current ownership
//     verification (06 §2);
//   - a skip "attestation missing" when auth_scan_authorized is absent/false;
//   - nil once those preconditions hold (or the phase is not an auth-scan
//     phase at all), meaning CheckScope proceeds with the normal scope gate.
//
// It is a pure function (no DB/DNS) so the auth-gate verdicts are table-tested
// in isolation as well as end-to-end through CheckScope.
func authScanVerdict(phase string, verified bool, authScanAuthorized *bool) *model.ScopeCheckResponse {
	if !isAuthScanNamespace(phase) {
		return nil
	}
	if !authScanPhases[phase] {
		return denyResult(fmt.Sprintf("auth-scan phase %q is not a recognized state-changing phase — refused (default-deny, 15 §5)", phase))
	}
	if !verified {
		return denyResult("skip: unverified target — authenticated scanning requires a current ownership verification (06 §2, 15 §6)")
	}
	if authScanAuthorized == nil || !*authScanAuthorized {
		return denyResult("skip: attestation missing — authenticated scanning requires the per-scan auth_scan_authorized attestation (15 §6)")
	}
	return nil
}

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

	// Auth-scan phases carry an extra default-deny gate (recognized phase +
	// ownership-verified + per-scan attestation) evaluated before the generic
	// status/scope checks so the auth-specific skip reasons are returned. A nil
	// verdict means either a non-auth phase or a passing attestation layer; in
	// both cases we fall through to the normal gate below.
	if v := authScanVerdict(req.Phase, target.Status == model.TargetStatusVerified, req.AuthScanAuthorized); v != nil {
		return v, nil
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

	// pinnedIPs is the set of concrete public IPs this request is authorized
	// against — returned to the caller so it can pin connections and refuse any
	// later DNS answer that differs (rebinding guard).
	var pinnedIPs []string

	// 06 §3 forbids INTRUSIVE testing of shared infrastructure (CDN edges serve
	// many tenants). A non-intrusive check (TLS audit, passive header/exposure
	// templates) against a CDN-fronted host is allowed and pinned to the CDN
	// edge IPs it resolved to. Reserved/private/metadata answers stay denied
	// regardless (ResolveStrict / IsDeniedIP below). A request that does not
	// state its intrusiveness is treated as intrusive.
	//
	// The shared-infra exclusion is LAYER-aware: it protects co-tenants from
	// packets addressed to a shared edge IP, so it applies to network-layer
	// intrusive testing. An application-layer request (HTTP/TLS routed by
	// Host/SNI to the customer's own origin) against a host in an active
	// registrable-domain scope is allowed through a CDN and pinned to the
	// edge IPs. Absent/unrecognized layer is network (conservative default).
	intrusive := req.IsIntrusive()
	sharedInfraDenied := intrusive && req.IsNetworkLayer()

	// Shared-infra + reserved check for a directly-supplied IP.
	if queryIP != "" {
		ip := net.ParseIP(queryIP)
		if ip == nil {
			return denyResult(fmt.Sprintf("invalid IP address: %s", queryIP)), nil
		}
		if denied, reason := safedial.IsDeniedIP(ip); denied {
			return denyResult(fmt.Sprintf("IP %s is a private/reserved/internal address — refused (SSRF guard, 06 §3): %s", queryIP, reason)), nil
		}
		// An IP-scoped query can only be satisfied by an ip_range scope, and the
		// layer relaxation never applies there: intrusive testing of a raw
		// shared-infra IP is denied for every layer (the relaxation is for
		// registrable-domain hosts only — see the host loop below).
		if intrusive && isSharedInfra(ip) {
			return denyResult(fmt.Sprintf("IP %s belongs to a known shared-infrastructure range — intrusive testing is not permitted (06 §3)", queryIP)), nil
		}
		// Defense in depth for the ip/cidr hard-disable: an IP-scoped query can
		// only ever be satisfied by an ip_range authorization, and those are
		// refused while IP targets are disabled (see IPTargetsEnabled).
		if !IPTargetsEnabled {
			return denyResult(fmt.Sprintf("IP-scoped scan refused: %v", ErrIPTargetsUnsupported)), nil
		}
		pinnedIPs = []string{ip.String()}
	}

	// If a host was given, resolve it and vet EVERY answer. Fail closed: a
	// resolution error, an empty answer, or ANY reserved/shared-infra address
	// denies the whole request — never authorize a host we could not fully vet.
	// ResolveStrict is the authorization-gate mode: any denied answer denies the
	// whole host (a rebinding answer set must not slip through on one public
	// member); isSharedInfra stays a local check over the returned IPs.
	if queryHost != "" {
		resolver := safedial.Resolver{Lookup: safedial.LookupHostFunc(s.resolve)}
		resolvedIPs, err := resolver.ResolveStrict(ctx, queryHost)
		if err != nil {
			if errors.Is(err, safedial.ErrDeniedAddress) {
				return denyResult(fmt.Sprintf("host %q resolves to a private/reserved/internal IP — refused (SSRF/rebinding guard, 06 §3): %v", queryHost, err)), nil
			}
			return denyResult(fmt.Sprintf("host %q could not be resolved (%v) — refused (fail-closed)", queryHost, err)), nil
		}
		for _, ip := range resolvedIPs {
			if sharedInfraDenied && isSharedInfra(ip) {
				return denyResult(fmt.Sprintf("host %q resolves to a shared-infrastructure IP (%s) — network-layer intrusive testing is not permitted (06 §3)", queryHost, ip.String())), nil
			}
			pinnedIPs = append(pinnedIPs, ip.String())
		}
	}

	// Evaluate each active authorization.
	for _, auth := range auths {
		// Program-mode (17 §10): a program-linked authorization is governed by
		// the structured program policy, not the generic registrable-domain
		// scope. It is authoritative and default-deny — resolve the program and
		// return its verdict directly (never fall through to an allow).
		if linked, program, assets := s.resolveProgramAuth(ctx, &auth); linked {
			v := programVerdict(program, assets, queryHost, queryIP, req.Phase, time.Now())
			if v.Authorized {
				v.AllowedIPs = pinnedIPs
			}
			return v, nil
		}

		switch auth.ScopeKind {

		case model.ScopeKindRegistrableDomain:
			// Authorized scope: apex + subdomains.
			// Only applicable when we have a host to check.
			if queryHost == "" {
				continue
			}
			if isSubdomainOf(queryHost, auth.ScopeValue) {
				r := allowResult(fmt.Sprintf("host %q is within authorized registrable-domain scope %q (authorization %s)", queryHost, auth.ScopeValue, auth.UID))
				r.AllowedIPs = pinnedIPs
				return r, nil
			}

		case model.ScopeKindIPRange:
			// Defense in depth: while IP targets are hard-disabled, a
			// pre-existing ip_range authorization must not grant anything
			// (scope-grant bypass guard — see IPTargetsEnabled). Skipping it
			// falls through to the default deny.
			if !IPTargetsEnabled {
				continue
			}
			// Authorized scope: confirmed IP range.
			if queryIP != "" {
				ip := net.ParseIP(queryIP)
				_, network, cidrErr := net.ParseCIDR(auth.ScopeValue)
				if cidrErr == nil && ip != nil && network.Contains(ip) {
					r := allowResult(fmt.Sprintf("IP %s is within authorized IP-range scope %s (authorization %s)", queryIP, auth.ScopeValue, auth.UID))
					r.AllowedIPs = pinnedIPs
					return r, nil
				}
				// Single-IP scope (stored without /32 notation).
				if auth.ScopeValue == queryIP {
					r := allowResult(fmt.Sprintf("IP %s matches authorized IP scope (authorization %s)", queryIP, auth.UID))
					r.AllowedIPs = pinnedIPs
					return r, nil
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

// ----------------------------------------------------------------------------
// Bug-bounty program mode (17 §10) — a SECOND authorization mode alongside
// client mode, enforced default-deny from the structured program store.
// ----------------------------------------------------------------------------

// DefaultProgramStaleWindow is the staleness window used when a program's
// stale_after_seconds is 0. A policy synced longer ago than this is refused:
// program scope changes and a stale cache must never authorize a scan.
const DefaultProgramStaleWindow = 7 * 24 * time.Hour

// programHandle extracts the (platform, handle) link from a program-mode
// authorization's evidence. An authorization is program-linked only when
// method=program AND evidence carries a non-empty handle; legacy free-text
// program authorizations (no handle) keep their registrable-domain behaviour.
func programHandle(auth *model.Authorization) (platform, handle string, ok bool) {
	if auth.Method != model.VerificationMethodProgram || auth.Evidence == nil {
		return "", "", false
	}
	h, _ := auth.Evidence["handle"].(string)
	h = strings.TrimSpace(h)
	if h == "" {
		return "", "", false
	}
	p, _ := auth.Evidence["platform"].(string)
	return strings.TrimSpace(p), h, true
}

// resolveProgramAuth reports whether auth is program-linked and, if so, loads
// the governing program and its assets. A program-linked authorization whose
// program row cannot be loaded returns (true, nil, nil) so programVerdict
// denies with "policy could not be established" (default-deny — a missing
// policy is a refusal, not a fall-through to the generic scope gate).
func (s *scopeService) resolveProgramAuth(ctx context.Context, auth *model.Authorization) (bool, *model.BugbountyProgram, []model.ProgramAsset) {
	platform, handle, ok := programHandle(auth)
	if !ok || s.programRepo == nil {
		return false, nil, nil
	}
	program, err := s.programRepo.GetByPlatformHandle(ctx, platform, handle)
	if err != nil {
		return true, nil, nil
	}
	assets, err := s.programRepo.ListAssets(ctx, program.ID)
	if err != nil {
		return true, nil, nil
	}
	return true, program, assets
}

// programVerdict is the pure (DB/DNS-free), table-testable program-mode gate.
// Default-deny: it ALLOWS only when the program policy is established, active,
// not stale, the host/IP matches an in-scope asset and no excluded asset,
// automation is permitted, and the phase is not a prohibited technique.
func programVerdict(p *model.BugbountyProgram, assets []model.ProgramAsset, host, ip, phase string, now time.Time) *model.ScopeCheckResponse {
	if p == nil {
		return denyResult("program policy could not be established — do not run (17 §10)")
	}
	if p.Status != model.ProgramStatusActive {
		return denyResult(fmt.Sprintf("bug-bounty program %s/%s is %q — do not run (17 §10)", p.Platform, p.Handle, p.Status))
	}
	stale := DefaultProgramStaleWindow
	if p.StaleAfterSeconds > 0 {
		stale = time.Duration(p.StaleAfterSeconds) * time.Second
	}
	if p.SyncedAt.IsZero() || now.Sub(p.SyncedAt) > stale {
		return denyResult(fmt.Sprintf("bug-bounty program %s/%s policy is stale (last synced %s, window %s) — do not run (17 §10)", p.Platform, p.Handle, p.SyncedAt.Format(time.RFC3339), stale))
	}

	host = strings.ToLower(strings.TrimSpace(host))
	ip = strings.TrimSpace(ip)

	// Exclusions win: an explicitly out-of-scope asset refuses the request even
	// if an in-scope wildcard would otherwise match it.
	for i := range assets {
		if !assets[i].InScope && programAssetMatches(&assets[i], host, ip) {
			return denyResult(fmt.Sprintf("host/IP matches an EXCLUDED asset %q of program %s/%s — refused (17 §10)", assets[i].Identifier, p.Platform, p.Handle))
		}
	}
	// Must match at least one explicitly in-scope asset.
	matched := false
	for i := range assets {
		if assets[i].InScope && programAssetMatches(&assets[i], host, ip) {
			matched = true
			break
		}
	}
	if !matched {
		return denyResult(fmt.Sprintf("host/IP is not within any in-scope asset of program %s/%s — refused (17 §10)", p.Platform, p.Handle))
	}
	if !p.AutomationAllowed {
		return denyResult(fmt.Sprintf("automated scanning is not permitted by program %s/%s — refused (17 §10)", p.Platform, p.Handle))
	}
	if tech := prohibitedPhaseTechnique(phase, p.ProhibitedTechniques); tech != "" {
		return denyResult(fmt.Sprintf("phase %q maps to prohibited technique %q of program %s/%s — filtered (17 §10)", phase, tech, p.Platform, p.Handle))
	}
	return allowResult(fmt.Sprintf("host/IP is in scope for bug-bounty program %s/%s, automation permitted, phase %q allowed (17 §10)", p.Platform, p.Handle, phase))
}

// programAssetMatches reports whether a scope asset matches the queried host/IP.
// Matching is per asset_type and honours wildcards.
func programAssetMatches(a *model.ProgramAsset, host, ip string) bool {
	id := strings.ToLower(strings.TrimSpace(a.Identifier))
	switch a.AssetType {
	case model.ProgramAssetTypeDomain:
		return host != "" && host == id
	case model.ProgramAssetTypeWildcard:
		base := strings.TrimPrefix(id, "*.")
		return host != "" && (host == base || strings.HasSuffix(host, "."+base))
	case model.ProgramAssetTypeURL:
		return host != "" && host == urlHost(id)
	case model.ProgramAssetTypeIP:
		return ip != "" && ip == id
	case model.ProgramAssetTypeCIDR:
		if ip == "" {
			return false
		}
		parsed := net.ParseIP(ip)
		_, network, err := net.ParseCIDR(id)
		return err == nil && parsed != nil && network.Contains(parsed)
	default: // other
		return host != "" && host == id
	}
}

// urlHost extracts the host from a URL identifier that may or may not carry a
// scheme or path (e.g. "https://example.com/app" or "example.com/app").
func urlHost(id string) string {
	if i := strings.Index(id, "://"); i >= 0 {
		id = id[i+3:]
	}
	if i := strings.IndexAny(id, "/?#"); i >= 0 {
		id = id[:i]
	}
	if i := strings.Index(id, "@"); i >= 0 { // strip userinfo
		id = id[i+1:]
	}
	if h, _, err := net.SplitHostPort(id); err == nil {
		return h
	}
	return id
}

// phaseTechnique maps a scan phase to the canonical technique token it performs.
// ponytail: this small table IS the calibration knob between our phase names
// and a program's prohibited-technique vocabulary — extend it as phases or
// platform wording evolve. A phase with no entry performs no restricted
// technique (passive recon: osint, web_recon), so prohibited-techniques never
// blocks it (the other gate conditions still apply).
var phaseTechnique = map[string]string{
	"cred":              "brute_force",
	"auth_register":     "account_creation",
	"auth_account_mgmt": "account_creation",
	"network":           "network_scanning",
	"web_vuln":          "automated_scanning",
	"auth_crawl":        "automated_scanning",
	"agent":             "automated_scanning",
}

// prohibitedPhaseTechnique returns the technique token when the phase's
// technique is in the program's prohibited list (both sides normalized), else "".
func prohibitedPhaseTechnique(phase string, prohibited []string) string {
	tech := phaseTechnique[phase]
	if tech == "" {
		return ""
	}
	for _, p := range normalizeTechniques(prohibited) {
		if p == tech {
			return tech
		}
	}
	return ""
}

// normalizeTechniques lowercases and canonicalizes technique tokens so platform
// wording ("Brute Force", "brute-force") matches our tokens ("brute_force").
func normalizeTechniques(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if n := normalizeTechnique(s); n != "" {
			out = append(out, n)
		}
	}
	return out
}

func normalizeTechnique(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, " ", "_")
	return s
}
