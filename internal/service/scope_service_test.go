package service_test

import (
	"context"
	"errors"
	"target-service/internal/model"
	"target-service/internal/service"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Fake repository implementations for unit tests
// ---------------------------------------------------------------------------

type fakeTargetRepo struct {
	byUID map[string]*model.Target
}

func (r *fakeTargetRepo) Create(_ context.Context, _ int64, _ *model.CreateTargetRequest) (*model.Target, error) {
	return nil, errors.New("not used in scope tests")
}
func (r *fakeTargetRepo) GetByUID(_ context.Context, _ int64, _ string) (*model.Target, error) {
	return nil, errors.New("not used in scope tests")
}
func (r *fakeTargetRepo) GetByUIDInternal(_ context.Context, uid string) (*model.Target, error) {
	if t, ok := r.byUID[uid]; ok {
		return t, nil
	}
	return nil, errors.New("target not found")
}
func (r *fakeTargetRepo) GetByID(_ context.Context, _ int64) (*model.Target, error) {
	return nil, errors.New("not used in scope tests")
}
func (r *fakeTargetRepo) List(_ context.Context, _ model.SearchParameters) ([]model.Target, error) {
	return nil, errors.New("not used in scope tests")
}
func (r *fakeTargetRepo) UpdateStatus(_ context.Context, _ int64, _ string) error {
	return nil
}
func (r *fakeTargetRepo) Delete(_ context.Context, _ int64, _ string) error {
	return nil
}

type fakeAuthRepo struct {
	auths map[int64][]model.Authorization
}

func (r *fakeAuthRepo) Create(_ context.Context, _ *model.Authorization) (*model.Authorization, error) {
	return nil, errors.New("not used in scope tests")
}
func (r *fakeAuthRepo) GetByTargetID(_ context.Context, _ int64) (*model.Authorization, error) {
	return nil, errors.New("not used in scope tests")
}
func (r *fakeAuthRepo) GetPendingByToken(_ context.Context, _ string) (*model.Authorization, error) {
	return nil, errors.New("not used in scope tests")
}
func (r *fakeAuthRepo) MarkVerified(_ context.Context, _ int64, _ string) error {
	return nil
}
func (r *fakeAuthRepo) GetActiveAuthorizations(_ context.Context, targetID int64) ([]model.Authorization, error) {
	return r.auths[targetID], nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func verifiedTarget(uid string, kind string, value string, regDomain string) *model.Target {
	rd := regDomain
	return &model.Target{
		ID:                1,
		UID:               uid,
		Kind:              kind,
		Value:             value,
		RegistrableDomain: &rd,
		Status:            model.TargetStatusVerified,
	}
}

func activeAuth(scopeKind, scopeValue string) model.Authorization {
	now := time.Now()
	exp := now.Add(30 * 24 * time.Hour)
	return model.Authorization{
		ID:         1,
		UID:        "auth-uid-1",
		TargetID:   1,
		ScopeKind:  scopeKind,
		ScopeValue: scopeValue,
		VerifiedAt: &now,
		ExpiresAt:  &exp,
	}
}

// publicResolver maps every host to a single public (TEST-NET-3) IP, so the
// SSRF/reserved-IP guard passes and domain-scope logic is what's under test.
func publicResolver(string) ([]string, error) { return []string{"203.0.113.10"}, nil }

// enableIPTargets temporarily lifts the ip/cidr hard-disable so tests can
// exercise the CIDR-matching logic itself. Restored via t.Cleanup. The
// hard-disable default (IPTargetsEnabled == false) is itself covered by
// TestScopeCheck_IPRangeAuth_DisabledByDefault_Denied below.
func enableIPTargets(t *testing.T) {
	t.Helper()
	prev := service.IPTargetsEnabled
	service.IPTargetsEnabled = true
	t.Cleanup(func() { service.IPTargetsEnabled = prev })
}

func makeSvc(target *model.Target, auths []model.Authorization) service.ScopeServiceInterface {
	return makeSvcWithResolver(target, auths, publicResolver)
}

func makeSvcWithResolver(target *model.Target, auths []model.Authorization, r func(string) ([]string, error)) service.ScopeServiceInterface {
	tr := &fakeTargetRepo{byUID: map[string]*model.Target{target.UID: target}}
	ar := &fakeAuthRepo{auths: map[int64][]model.Authorization{target.ID: auths}}
	return service.NewScopeServiceWithResolver(tr, ar, r)
}

// ---------------------------------------------------------------------------
// Test: missing host/IP
// ---------------------------------------------------------------------------

func TestScopeCheck_MissingHostAndIP(t *testing.T) {
	target := verifiedTarget("uid-1", model.TargetKindDomain, "myapp.internal", "myapp.internal")
	svc := makeSvc(target, []model.Authorization{activeAuth(model.ScopeKindRegistrableDomain, "myapp.internal")})
	req := &model.ScopeCheckRequest{TargetUID: "uid-1", Phase: "P2"}
	res, err := svc.CheckScope(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, res.Authorized)
	assert.Contains(t, res.Reason, "host or ip is required")
}

// ---------------------------------------------------------------------------
// Test: unverified target is denied
// ---------------------------------------------------------------------------

func TestScopeCheck_UnverifiedTarget_Denied(t *testing.T) {
	tr := &fakeTargetRepo{byUID: map[string]*model.Target{
		"uid-1": {ID: 1, UID: "uid-1", Kind: model.TargetKindDomain, Status: model.TargetStatusUnverified},
	}}
	ar := &fakeAuthRepo{auths: map[int64][]model.Authorization{}}
	svc := service.NewScopeService(tr, ar)

	res, err := svc.CheckScope(context.Background(), &model.ScopeCheckRequest{
		TargetUID: "uid-1", Host: "myapp.internal", Phase: "P2",
	})
	require.NoError(t, err)
	assert.False(t, res.Authorized, "unverified target should be denied")
	assert.Contains(t, res.Reason, "only verified targets")
}

// ---------------------------------------------------------------------------
// Test: target not found → denied
// ---------------------------------------------------------------------------

func TestScopeCheck_TargetNotFound_Denied(t *testing.T) {
	tr := &fakeTargetRepo{byUID: map[string]*model.Target{}}
	ar := &fakeAuthRepo{}
	svc := service.NewScopeService(tr, ar)

	res, err := svc.CheckScope(context.Background(), &model.ScopeCheckRequest{
		TargetUID: "nonexistent", Host: "myapp.internal", Phase: "P2",
	})
	require.NoError(t, err)
	assert.False(t, res.Authorized)
	assert.Contains(t, res.Reason, "target not found")
}

// ---------------------------------------------------------------------------
// Test: no active authorizations → denied (deny-by-default)
// ---------------------------------------------------------------------------

func TestScopeCheck_NoActiveAuth_Denied(t *testing.T) {
	target := verifiedTarget("uid-1", model.TargetKindDomain, "myapp.internal", "myapp.internal")
	svc := makeSvc(target, nil)

	res, err := svc.CheckScope(context.Background(), &model.ScopeCheckRequest{
		TargetUID: "uid-1", Host: "myapp.internal", Phase: "P2",
	})
	require.NoError(t, err)
	assert.False(t, res.Authorized, "no active auth should be denied")
	assert.Contains(t, res.Reason, "no active")
}

// ---------------------------------------------------------------------------
// Test: apex domain is authorized (use .internal to avoid CDN resolution)
// Note: .internal domains won't resolve in LookupHost so they pass the shared-infra check.
// ---------------------------------------------------------------------------

func TestScopeCheck_ApexDomain_Authorized(t *testing.T) {
	// Use .test/.internal domains that won't resolve to real CDN IPs.
	target := verifiedTarget("uid-1", model.TargetKindDomain, "myapp.test", "myapp.test")
	svc := makeSvc(target, []model.Authorization{activeAuth(model.ScopeKindRegistrableDomain, "myapp.test")})

	res, err := svc.CheckScope(context.Background(), &model.ScopeCheckRequest{
		TargetUID: "uid-1", Host: "myapp.test", Phase: "P2",
	})
	require.NoError(t, err)
	assert.True(t, res.Authorized, "apex domain should be authorized")
}

// ---------------------------------------------------------------------------
// Test: subdomain under verified registrable domain is authorized (06 §3)
// ---------------------------------------------------------------------------

func TestScopeCheck_Subdomain_Authorized(t *testing.T) {
	target := verifiedTarget("uid-1", model.TargetKindDomain, "myapp.test", "myapp.test")
	svc := makeSvc(target, []model.Authorization{activeAuth(model.ScopeKindRegistrableDomain, "myapp.test")})

	for _, host := range []string{"api.myapp.test", "www.myapp.test", "deep.nested.myapp.test"} {
		res, err := svc.CheckScope(context.Background(), &model.ScopeCheckRequest{
			TargetUID: "uid-1", Host: host, Phase: "P2",
		})
		require.NoError(t, err)
		assert.True(t, res.Authorized, "subdomain %s should be authorized", host)
	}
}

// ---------------------------------------------------------------------------
// Test: prefix-spoof like evil-myapp.test must be DENIED (06 §3 key rule)
// ---------------------------------------------------------------------------

func TestScopeCheck_PrefixSpoof_Denied(t *testing.T) {
	target := verifiedTarget("uid-1", model.TargetKindDomain, "myapp.test", "myapp.test")
	svc := makeSvc(target, []model.Authorization{activeAuth(model.ScopeKindRegistrableDomain, "myapp.test")})

	spoofs := []string{
		"evil-myapp.test",
		"notmyapp.test",
		"myapp.test.evil.test",
		"mymyapp.test",
	}
	for _, host := range spoofs {
		res, err := svc.CheckScope(context.Background(), &model.ScopeCheckRequest{
			TargetUID: "uid-1", Host: host, Phase: "P2",
		})
		require.NoError(t, err)
		assert.False(t, res.Authorized, "prefix-spoof %s should be denied", host)
	}
}

// ---------------------------------------------------------------------------
// Test: a different registrable domain requires separate verification (06 §3)
// ---------------------------------------------------------------------------

func TestScopeCheck_DifferentRegistrableDomain_Denied(t *testing.T) {
	target := verifiedTarget("uid-1", model.TargetKindDomain, "myapp.test", "myapp.test")
	svc := makeSvc(target, []model.Authorization{activeAuth(model.ScopeKindRegistrableDomain, "myapp.test")})

	res, err := svc.CheckScope(context.Background(), &model.ScopeCheckRequest{
		TargetUID: "uid-1", Host: "otherdomain.test", Phase: "P2",
	})
	require.NoError(t, err)
	assert.False(t, res.Authorized, "different registrable domain must require separate verification")
}

// ---------------------------------------------------------------------------
// Test: IP in confirmed CIDR range is authorized
// ---------------------------------------------------------------------------

func TestScopeCheck_IPInCIDR_Authorized(t *testing.T) {
	enableIPTargets(t)
	target := verifiedTarget("uid-1", model.TargetKindCIDR, "203.0.113.0/24", "")
	svc := makeSvc(target, []model.Authorization{activeAuth(model.ScopeKindIPRange, "203.0.113.0/24")})

	res, err := svc.CheckScope(context.Background(), &model.ScopeCheckRequest{
		TargetUID: "uid-1", IP: "203.0.113.50", Phase: "P2",
	})
	require.NoError(t, err)
	assert.True(t, res.Authorized, "IP within confirmed CIDR should be authorized")
}

// ---------------------------------------------------------------------------
// Test: IP outside confirmed CIDR is denied
// ---------------------------------------------------------------------------

func TestScopeCheck_IPOutsideCIDR_Denied(t *testing.T) {
	enableIPTargets(t) // so the denial exercises CIDR matching, not the hard-disable
	target := verifiedTarget("uid-1", model.TargetKindCIDR, "203.0.113.0/24", "")
	svc := makeSvc(target, []model.Authorization{activeAuth(model.ScopeKindIPRange, "203.0.113.0/24")})

	res, err := svc.CheckScope(context.Background(), &model.ScopeCheckRequest{
		TargetUID: "uid-1", IP: "203.0.114.1", Phase: "P2",
	})
	require.NoError(t, err)
	assert.False(t, res.Authorized, "IP outside CIDR should be denied")
}

// ---------------------------------------------------------------------------
// Test: exact single-IP scope (stored without /32 notation)
// ---------------------------------------------------------------------------

func TestScopeCheck_SingleIP_Authorized(t *testing.T) {
	enableIPTargets(t)
	target := verifiedTarget("uid-1", model.TargetKindIP, "203.0.113.5", "")
	svc := makeSvc(target, []model.Authorization{activeAuth(model.ScopeKindIPRange, "203.0.113.5")})

	res, err := svc.CheckScope(context.Background(), &model.ScopeCheckRequest{
		TargetUID: "uid-1", IP: "203.0.113.5", Phase: "P2",
	})
	require.NoError(t, err)
	assert.True(t, res.Authorized, "exact single IP should be authorized")
}

// ---------------------------------------------------------------------------
// Test: invalid IP string is denied
// ---------------------------------------------------------------------------

func TestScopeCheck_InvalidIP_Denied(t *testing.T) {
	target := verifiedTarget("uid-1", model.TargetKindCIDR, "203.0.113.0/24", "")
	svc := makeSvc(target, []model.Authorization{activeAuth(model.ScopeKindIPRange, "203.0.113.0/24")})

	res, err := svc.CheckScope(context.Background(), &model.ScopeCheckRequest{
		TargetUID: "uid-1", IP: "not-an-ip", Phase: "P2",
	})
	require.NoError(t, err)
	assert.False(t, res.Authorized, "invalid IP should be denied")
	assert.Contains(t, res.Reason, "invalid IP")
}

// ---------------------------------------------------------------------------
// Test: Cloudflare IP is denied even if inside a "valid" CIDR scope (06 §3 shared-infra)
// ---------------------------------------------------------------------------

func TestScopeCheck_SharedInfraIP_Denied(t *testing.T) {
	target := verifiedTarget("uid-1", model.TargetKindCIDR, "104.16.0.0/13", "")
	svc := makeSvc(target, []model.Authorization{activeAuth(model.ScopeKindIPRange, "104.16.0.0/13")})

	// 104.16.1.1 is inside Cloudflare's shared range 104.16.0.0/13
	res, err := svc.CheckScope(context.Background(), &model.ScopeCheckRequest{
		TargetUID: "uid-1", IP: "104.16.1.1", Phase: "P2",
	})
	require.NoError(t, err)
	assert.False(t, res.Authorized, "Cloudflare/shared-infra IP must be denied even if in CIDR scope")
	assert.Contains(t, res.Reason, "shared-infrastructure")
}

// ---------------------------------------------------------------------------
// Test: Fastly IP is denied (shared-infra exclusion)
// ---------------------------------------------------------------------------

func TestScopeCheck_FastlyIP_Denied(t *testing.T) {
	target := verifiedTarget("uid-1", model.TargetKindCIDR, "151.101.0.0/16", "")
	svc := makeSvc(target, []model.Authorization{activeAuth(model.ScopeKindIPRange, "151.101.0.0/16")})

	res, err := svc.CheckScope(context.Background(), &model.ScopeCheckRequest{
		TargetUID: "uid-1", IP: "151.101.4.1", Phase: "P2",
	})
	require.NoError(t, err)
	assert.False(t, res.Authorized, "Fastly IP must be excluded as shared-infra")
}

// ---------------------------------------------------------------------------
// Test: deny-by-default — a host query against an IP-only scope (no matching scope kind)
// ---------------------------------------------------------------------------

func TestScopeCheck_DenyByDefault_HostOnIPScope(t *testing.T) {
	target := verifiedTarget("uid-1", model.TargetKindCIDR, "203.0.113.0/24", "")
	svc := makeSvc(target, []model.Authorization{activeAuth(model.ScopeKindIPRange, "203.0.113.0/24")})

	// A host query should not be authorized by an IP-range scope
	res, err := svc.CheckScope(context.Background(), &model.ScopeCheckRequest{
		TargetUID: "uid-1", Host: "myapp.test", Phase: "P2",
	})
	require.NoError(t, err)
	assert.False(t, res.Authorized, "host query against IP-only scope must deny by default")
}

// ---------------------------------------------------------------------------
// Test: expired authorization → denied (deny-by-default)
// The GetActiveAuthorizations query already filters expired rows; empty result = denied.
// ---------------------------------------------------------------------------

func TestScopeCheck_ExpiredAuth_Denied(t *testing.T) {
	target := verifiedTarget("uid-1", model.TargetKindDomain, "myapp.test", "myapp.test")
	// No active auths returned (simulates expired auth being filtered by DB)
	svc := makeSvc(target, nil)

	res, err := svc.CheckScope(context.Background(), &model.ScopeCheckRequest{
		TargetUID: "uid-1", Host: "myapp.test", Phase: "P2",
	})
	require.NoError(t, err)
	assert.False(t, res.Authorized, "expired authorization must result in denial")
}

// ---------------------------------------------------------------------------
// Test: revoked target → denied
// ---------------------------------------------------------------------------

func TestScopeCheck_RevokedTarget_Denied(t *testing.T) {
	tr := &fakeTargetRepo{byUID: map[string]*model.Target{
		"uid-rev": {
			ID: 2, UID: "uid-rev", Kind: model.TargetKindDomain,
			Value: "revoked.test", Status: model.TargetStatusRevoked,
		},
	}}
	ar := &fakeAuthRepo{auths: map[int64][]model.Authorization{
		2: {activeAuth(model.ScopeKindRegistrableDomain, "revoked.test")},
	}}
	svc := service.NewScopeService(tr, ar)

	res, err := svc.CheckScope(context.Background(), &model.ScopeCheckRequest{
		TargetUID: "uid-rev", Host: "revoked.test", Phase: "P2",
	})
	require.NoError(t, err)
	assert.False(t, res.Authorized, "revoked target must be denied")
}

// ---------------------------------------------------------------------------
// Test: isSubdomainOf logic via CheckScope interface
// Uses .test TLD so no real DNS resolution happens.
// ---------------------------------------------------------------------------

func TestIsSubdomainOf_ViaScopeCheck(t *testing.T) {
	tests := []struct {
		host      string
		apex      string
		wantAllow bool
		desc      string
	}{
		{"myapp.test", "myapp.test", true, "apex matches"},
		{"api.myapp.test", "myapp.test", true, "direct subdomain"},
		{"deep.api.myapp.test", "myapp.test", true, "deep subdomain"},
		{"notmyapp.test", "myapp.test", false, "different domain, same TLD"},
		{"evil-myapp.test", "myapp.test", false, "prefix spoof with hyphen"},
		{"myapp.test.attacker.test", "myapp.test", false, "suffix spoof"},
		{"otherdomain.test", "myapp.test", false, "unrelated domain"},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			target := verifiedTarget("uid-sub", model.TargetKindDomain, "myapp.test", "myapp.test")
			svc := makeSvc(target, []model.Authorization{activeAuth(model.ScopeKindRegistrableDomain, tc.apex)})

			res, err := svc.CheckScope(context.Background(), &model.ScopeCheckRequest{
				TargetUID: "uid-sub", Host: tc.host, Phase: "P2",
			})
			require.NoError(t, err)
			assert.Equal(t, tc.wantAllow, res.Authorized, "host=%s apex=%s: %s", tc.host, tc.apex, tc.desc)
		})
	}
}

// ---------------------------------------------------------------------------
// Test: multi-scope: multiple active authorizations (registrable_domain + IP range)
// The host must pass either to be authorized.
// ---------------------------------------------------------------------------

func TestScopeCheck_MultipleAuths_HostMatchesFirst(t *testing.T) {
	enableIPTargets(t)
	target := &model.Target{
		ID:                10,
		UID:               "uid-multi",
		Kind:              model.TargetKindDomain,
		Value:             "multiapp.test",
		Status:            model.TargetStatusVerified,
		RegistrableDomain: func() *string { s := "multiapp.test"; return &s }(),
	}
	now := time.Now()
	exp := now.Add(30 * 24 * time.Hour)
	authDomain := model.Authorization{
		ID: 1, UID: "a1", TargetID: 10,
		ScopeKind: model.ScopeKindRegistrableDomain, ScopeValue: "multiapp.test",
		VerifiedAt: &now, ExpiresAt: &exp,
	}
	authIP := model.Authorization{
		ID: 2, UID: "a2", TargetID: 10,
		ScopeKind: model.ScopeKindIPRange, ScopeValue: "203.0.113.0/24",
		VerifiedAt: &now, ExpiresAt: &exp,
	}

	tr := &fakeTargetRepo{byUID: map[string]*model.Target{"uid-multi": target}}
	ar := &fakeAuthRepo{auths: map[int64][]model.Authorization{10: {authDomain, authIP}}}
	svc := service.NewScopeServiceWithResolver(tr, ar, publicResolver)

	// Host query — matches domain auth
	res, err := svc.CheckScope(context.Background(), &model.ScopeCheckRequest{
		TargetUID: "uid-multi", Host: "api.multiapp.test", Phase: "P2",
	})
	require.NoError(t, err)
	assert.True(t, res.Authorized, "api.multiapp.test should match domain auth")

	// IP query — matches IP auth
	res, err = svc.CheckScope(context.Background(), &model.ScopeCheckRequest{
		TargetUID: "uid-multi", IP: "203.0.113.7", Phase: "P2",
	})
	require.NoError(t, err)
	assert.True(t, res.Authorized, "203.0.113.7 should match IP auth")

	// IP query — outside both scopes
	res, err = svc.CheckScope(context.Background(), &model.ScopeCheckRequest{
		TargetUID: "uid-multi", IP: "198.51.100.1", Phase: "P2",
	})
	require.NoError(t, err)
	assert.False(t, res.Authorized, "198.51.100.1 is outside all authorized scopes")
}

// ---------------------------------------------------------------------------
// SSRF / DNS-rebinding guard tests (the load-bearing hardening)
// ---------------------------------------------------------------------------

// A verified domain whose subdomain resolves to cloud metadata / RFC1918 must be
// DENIED even though the name is in registrable-domain scope — this is the SSRF
// path the gate previously allowed.
func TestScopeCheck_ResolvesToInternalIP_Denied(t *testing.T) {
	internalAnswers := map[string][]string{
		"metadata": {"169.254.169.254"}, // AWS/GCP IMDS
		"rfc1918":  {"10.0.0.5"},
		"loopback": {"127.0.0.1"},
		"cgnat":    {"100.64.1.1"},
		"linklocal": {"169.254.10.10"},
		"ipv6ula":  {"fd00::1"},
	}
	for name, answer := range internalAnswers {
		t.Run(name, func(t *testing.T) {
			target := verifiedTarget("uid-1", model.TargetKindDomain, "myapp.test", "myapp.test")
			r := func(string) ([]string, error) { return answer, nil }
			svc := makeSvcWithResolver(target, []model.Authorization{activeAuth(model.ScopeKindRegistrableDomain, "myapp.test")}, r)

			res, err := svc.CheckScope(context.Background(), &model.ScopeCheckRequest{
				TargetUID: "uid-1", Host: "api.myapp.test", Phase: "P2",
			})
			require.NoError(t, err)
			assert.False(t, res.Authorized, "%s answer must be denied", name)
			assert.Contains(t, res.Reason, "reserved")
		})
	}
}

// If a host resolves to a MIX of a public and an internal IP, deny the whole
// request (a rebinding answer set must not slip through on the public member).
func TestScopeCheck_MixedResolution_Denied(t *testing.T) {
	target := verifiedTarget("uid-1", model.TargetKindDomain, "myapp.test", "myapp.test")
	r := func(string) ([]string, error) { return []string{"203.0.113.10", "10.0.0.1"}, nil }
	svc := makeSvcWithResolver(target, []model.Authorization{activeAuth(model.ScopeKindRegistrableDomain, "myapp.test")}, r)

	res, err := svc.CheckScope(context.Background(), &model.ScopeCheckRequest{
		TargetUID: "uid-1", Host: "myapp.test", Phase: "P2",
	})
	require.NoError(t, err)
	assert.False(t, res.Authorized, "mixed public+internal resolution must be denied")
}

// Fail closed: an in-scope host that cannot be resolved (or resolves to nothing)
// must be denied rather than authorized on the name alone.
func TestScopeCheck_ResolutionFailsOrEmpty_Denied(t *testing.T) {
	target := verifiedTarget("uid-1", model.TargetKindDomain, "myapp.test", "myapp.test")
	auth := []model.Authorization{activeAuth(model.ScopeKindRegistrableDomain, "myapp.test")}

	errResolver := func(string) ([]string, error) { return nil, assert.AnError }
	svc := makeSvcWithResolver(target, auth, errResolver)
	res, err := svc.CheckScope(context.Background(), &model.ScopeCheckRequest{TargetUID: "uid-1", Host: "myapp.test", Phase: "P2"})
	require.NoError(t, err)
	assert.False(t, res.Authorized, "resolution error must fail closed")

	emptyResolver := func(string) ([]string, error) { return []string{}, nil }
	svc = makeSvcWithResolver(target, auth, emptyResolver)
	res, err = svc.CheckScope(context.Background(), &model.ScopeCheckRequest{TargetUID: "uid-1", Host: "myapp.test", Phase: "P2"})
	require.NoError(t, err)
	assert.False(t, res.Authorized, "empty resolution must fail closed")
}

// A directly-supplied internal IP must be denied even if an IP-range auth exists.
func TestScopeCheck_DirectInternalIP_Denied(t *testing.T) {
	target := verifiedTarget("uid-1", model.TargetKindIP, "169.254.169.254", "")
	svc := makeSvc(target, []model.Authorization{activeAuth(model.ScopeKindIPRange, "169.254.0.0/16")})

	res, err := svc.CheckScope(context.Background(), &model.ScopeCheckRequest{
		TargetUID: "uid-1", IP: "169.254.169.254", Phase: "P2",
	})
	require.NoError(t, err)
	assert.False(t, res.Authorized, "direct metadata IP must be denied")
	assert.Contains(t, res.Reason, "reserved")
}

// ---------------------------------------------------------------------------
// ip/cidr hard-disable defense in depth: while IPTargetsEnabled is false
// (the default), a pre-existing ip_range authorization must not grant a scan —
// neither for an IP query (explicit refusal) nor as a leftover scope row.
// ---------------------------------------------------------------------------

func TestScopeCheck_IPRangeAuth_DisabledByDefault_Denied(t *testing.T) {
	require.False(t, service.IPTargetsEnabled, "test setup: IP targets must be disabled by default")

	target := verifiedTarget("uid-1", model.TargetKindCIDR, "203.0.113.0/24", "")
	svc := makeSvc(target, []model.Authorization{activeAuth(model.ScopeKindIPRange, "203.0.113.0/24")})

	// This exact request is authorized in TestScopeCheck_IPInCIDR_Authorized
	// once enableIPTargets(t) is applied — without it, it must be refused.
	res, err := svc.CheckScope(context.Background(), &model.ScopeCheckRequest{
		TargetUID: "uid-1", IP: "203.0.113.50", Phase: "P2",
	})
	require.NoError(t, err)
	assert.False(t, res.Authorized, "ip_range authorization must not grant a scan while IP targets are disabled")
	assert.Contains(t, res.Reason, "not yet supported")
}

// An authorized request returns the pinned public IPs so the caller can bind to
// them and defeat a later rebinding answer.
func TestScopeCheck_Authorized_ReturnsPinnedIPs(t *testing.T) {
	target := verifiedTarget("uid-1", model.TargetKindDomain, "myapp.test", "myapp.test")
	r := func(string) ([]string, error) { return []string{"203.0.113.10", "203.0.113.11"}, nil }
	svc := makeSvcWithResolver(target, []model.Authorization{activeAuth(model.ScopeKindRegistrableDomain, "myapp.test")}, r)

	res, err := svc.CheckScope(context.Background(), &model.ScopeCheckRequest{
		TargetUID: "uid-1", Host: "myapp.test", Phase: "P2",
	})
	require.NoError(t, err)
	require.True(t, res.Authorized)
	assert.ElementsMatch(t, []string{"203.0.113.10", "203.0.113.11"}, res.AllowedIPs)
}
