// Package service implements the business logic for target-service.
// This file owns the verification method scaffolding (06 §2).
package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"target-service/internal/model"
	"target-service/internal/repository"
	"time"
)

// VerificationService orchestrates challenge issuance and per-method checks.
type VerificationService struct {
	authRepo repository.AuthorizationRepositoryInterface
}

// NewVerificationService constructs the verification orchestrator.
func NewVerificationService(authRepo repository.AuthorizationRepositoryInterface) *VerificationService {
	return &VerificationService{authRepo: authRepo}
}

// IssueChallenge creates an authorization record with a fresh random token.
// The token is returned so the caller can embed it in the response for the customer.
func (v *VerificationService) IssueChallenge(ctx context.Context, target *model.Target, method string, attestedBy int64) (*model.Authorization, string, error) {
	token, err := generateToken(32)
	if err != nil {
		return nil, "", fmt.Errorf("verificationService.IssueChallenge: generate token: %w", err)
	}

	scopeKind, scopeValue := scopeForTarget(target)
	auth := &model.Authorization{
		TargetID:   target.ID,
		Method:     method,
		Token:      token,
		ScopeKind:  scopeKind,
		ScopeValue: scopeValue,
		AttestedBy: &attestedBy,
	}
	created, err := v.authRepo.Create(ctx, auth)
	if err != nil {
		return nil, "", fmt.Errorf("verificationService.IssueChallenge: persist: %w", err)
	}
	return created, token, nil
}

// RunCheck dispatches to the correct per-method verifier and returns
// (passed, detail, error).
func (v *VerificationService) RunCheck(ctx context.Context, target *model.Target, auth *model.Authorization) (bool, string, error) {
	switch auth.Method {
	case model.VerificationMethodDNSTXT:
		return verifyDNSTXT(ctx, target.Value, auth.Token)
	case model.VerificationMethodHTTPFile:
		return verifyHTTPFile(ctx, target.Value, auth.Token)
	case model.VerificationMethodMetaTag:
		return verifyMetaTag(ctx, target.Value, auth.Token)
	case model.VerificationMethodEmail, model.VerificationMethodIPRegistry:
		// Async / manual methods: the verification is confirmed out-of-band.
		// A separate admin flow marks the authorization verified.
		// Here we return a pending signal so callers know to instruct the customer.
		return false, "method requires out-of-band confirmation; verification is pending manual review", nil
	default:
		return false, "", fmt.Errorf("unknown verification method: %s", auth.Method)
	}
}

// ---------------------------------------------------------------------------
// Per-method verifier functions
// ---------------------------------------------------------------------------

// verifyDNSTXT looks up TXT records on the domain and checks for
// "scantinel-verify=<token>" (06 §2).
func verifyDNSTXT(ctx context.Context, domain string, token string) (bool, string, error) {
	host := normalizeHost(domain)
	records, err := net.DefaultResolver.LookupTXT(ctx, host)
	if err != nil {
		return false, fmt.Sprintf("DNS TXT lookup failed for %s: %v", host, err), nil
	}
	expected := "scantinel-verify=" + token
	for _, rec := range records {
		if strings.TrimSpace(rec) == expected {
			return true, fmt.Sprintf("found TXT record %q on %s", expected, host), nil
		}
	}
	return false, fmt.Sprintf("TXT record %q not found on %s (found %d records)", expected, host, len(records)), nil
}

// verifyHTTPFile GETs /.well-known/scantinel-verify/<token> and checks the body
// equals the token (06 §2).
func verifyHTTPFile(ctx context.Context, host string, token string) (bool, string, error) {
	h := normalizeHost(host)
	url := fmt.Sprintf("https://%s/.well-known/scantinel-verify/%s", h, token)

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Sprintf("failed to build HTTP request: %v", err), nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Sprintf("HTTP GET %s failed: %v", url, err), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Sprintf("HTTP GET %s returned status %d", url, resp.StatusCode), nil
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return false, fmt.Sprintf("failed to read response body: %v", err), nil
	}
	body := strings.TrimSpace(string(bodyBytes))
	if body == token {
		return true, fmt.Sprintf("verification file found at %s", url), nil
	}
	return false, fmt.Sprintf("response body %q does not match token at %s", body, url), nil
}

// verifyMetaTag GETs the homepage and checks for
// <meta name="scantinel-verify" content="<token>"> (06 §2).
func verifyMetaTag(ctx context.Context, host string, token string) (bool, string, error) {
	h := normalizeHost(host)
	url := fmt.Sprintf("https://%s/", h)

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Sprintf("failed to build HTTP request: %v", err), nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Sprintf("HTTP GET %s failed: %v", url, err), nil
	}
	defer resp.Body.Close()

	// Read up to 64 KB of the homepage to find the meta tag.
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return false, fmt.Sprintf("failed to read homepage body: %v", err), nil
	}
	body := string(bodyBytes)

	// Simple string search — avoids a full HTML parser dependency.
	// Accepts minor variations in attribute quoting/ordering.
	needles := []string{
		fmt.Sprintf(`name="scantinel-verify" content="%s"`, token),
		fmt.Sprintf(`content="%s" name="scantinel-verify"`, token),
		fmt.Sprintf(`name='scantinel-verify' content='%s'`, token),
	}
	for _, needle := range needles {
		if strings.Contains(body, needle) {
			return true, fmt.Sprintf("meta tag verified on %s", url), nil
		}
	}
	return false, fmt.Sprintf("scantinel-verify meta tag with token not found on %s", url), nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func generateToken(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func normalizeHost(value string) string {
	// Strip scheme if present.
	if idx := strings.Index(value, "://"); idx >= 0 {
		value = value[idx+3:]
	}
	// Strip path.
	if idx := strings.Index(value, "/"); idx >= 0 {
		value = value[:idx]
	}
	// Strip port.
	if idx := strings.LastIndex(value, ":"); idx >= 0 {
		potentialPort := value[idx+1:]
		if len(potentialPort) > 0 && potentialPort[0] >= '0' && potentialPort[0] <= '9' {
			value = value[:idx]
		}
	}
	return strings.ToLower(strings.TrimSpace(value))
}

func scopeForTarget(target *model.Target) (scopeKind, scopeValue string) {
	switch target.Kind {
	case model.TargetKindIP:
		return model.ScopeKindIPRange, target.Value
	case model.TargetKindCIDR:
		return model.ScopeKindIPRange, target.Value
	default:
		// domain / url → registrable domain scope.
		if target.RegistrableDomain != nil && *target.RegistrableDomain != "" {
			return model.ScopeKindRegistrableDomain, *target.RegistrableDomain
		}
		return model.ScopeKindRegistrableDomain, target.Value
	}
}
