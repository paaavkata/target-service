// Package service — this file owns the orchestration for scantinel-website's
// three free public tools. No auth, no persistence: every call is a
// stateless outbound check made through the hardened go-safedial client(s)
// defined in header_checker.go / tls_checker.go / email_auth.go.
package service

import (
	"context"
	"fmt"
	"sync"
	"target-service/internal/model"
	"time"
)

// ToolsService orchestrates the free security-headers, TLS and email-auth
// checks, including the combined website-check used by tool.tsx.
type ToolsService struct {
	headers *HeaderChecker
	tls     *TLSChecker
	email   *EmailAuthChecker
}

// NewToolsService builds a ToolsService with the real network checkers.
func NewToolsService() *ToolsService {
	return &ToolsService{headers: NewHeaderChecker(), tls: NewTLSChecker(), email: NewEmailAuthChecker()}
}

// SecurityHeaders runs the header check for POST /v1/tools/security-headers.
func (s *ToolsService) SecurityHeaders(ctx context.Context, domain string) (*model.SecurityHeadersResponse, error) {
	return s.headers.Check(ctx, domain)
}

// TLS runs the TLS check for POST /v1/tools/tls.
func (s *ToolsService) TLS(ctx context.Context, domain string) (*model.TLSCheckResponse, error) {
	return s.tls.Check(ctx, domain)
}

// EmailAuth runs the SPF/DMARC/DKIM check for POST /v1/tools/email-auth.
func (s *ToolsService) EmailAuth(ctx context.Context, domain string) (*model.EmailAuthResponse, error) {
	return s.email.Check(ctx, domain)
}

// WebsiteCheck runs all three checks concurrently for POST /v1/tools/website-check
// and returns the combined shape scantinel-website's ScanResult expects. A
// single failing sub-check does not fail the whole request — its summary
// section reports "-"/empty and a note is appended to Summary; only when
// every sub-check fails is an error returned.
func (s *ToolsService) WebsiteCheck(ctx context.Context, domain string) (*model.WebsiteCheckResponse, error) {
	var wg sync.WaitGroup
	var hdrRes *model.SecurityHeadersResponse
	var tlsRes *model.TLSCheckResponse
	var emailRes *model.EmailAuthResponse
	var hdrErr, tlsErr, emailErr error

	wg.Add(3)
	go func() { defer wg.Done(); hdrRes, hdrErr = s.headers.Check(ctx, domain) }()
	go func() { defer wg.Done(); tlsRes, tlsErr = s.tls.Check(ctx, domain) }()
	go func() { defer wg.Done(); emailRes, emailErr = s.email.Check(ctx, domain) }()
	wg.Wait()

	if hdrErr != nil && tlsErr != nil && emailErr != nil {
		return nil, fmt.Errorf("all checks failed for %s: headers=%v tls=%v email=%v", domain, hdrErr, tlsErr, emailErr)
	}

	resp := &model.WebsiteCheckResponse{Domain: domain, CheckedAt: time.Now().UTC()}
	var notes []string

	if hdrRes != nil {
		items := make([]model.WebsiteCheckHeaderItem, 0, len(hdrRes.Headers))
		present := 0
		for _, it := range hdrRes.Headers {
			items = append(items, model.WebsiteCheckHeaderItem{Name: it.Name, Status: it.Status})
			if it.Status == model.HeaderStatusPass {
				present++
			}
		}
		resp.Headers = model.WebsiteCheckHeadersSummary{Present: present, Total: len(hdrRes.Headers), Items: items}
	} else {
		notes = append(notes, "could not fetch security headers")
	}

	if tlsRes != nil {
		resp.TLS = model.WebsiteCheckTLSSummary{
			Grade:      tlsRes.Grade,
			Protocol:   tlsRes.Protocol,
			CertExpiry: formatCertExpiry(tlsRes.Certificate.ExpiresAt),
		}
	} else {
		resp.TLS = model.WebsiteCheckTLSSummary{Grade: "-", Protocol: "unknown", CertExpiry: "unknown"}
		notes = append(notes, "could not complete the TLS check")
	}

	if emailRes != nil {
		resp.EmailAuth = model.WebsiteCheckEmailSummary{
			SPF:         emailRes.SPF.Present,
			DMARC:       emailRes.DMARC.Present,
			DMARCPolicy: emailRes.DMARC.Policy,
		}
	} else {
		notes = append(notes, "could not check email authentication records")
	}

	resp.Details = model.WebsiteCheckDetails{Headers: hdrRes, TLS: tlsRes, EmailAuth: emailRes}
	resp.Summary = buildWebsiteCheckSummary(resp, notes)
	return resp, nil
}

func formatCertExpiry(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.Format("2006-01-02")
}

// buildWebsiteCheckSummary produces the one-line human summary rendered at
// the bottom of the free tool widget.
func buildWebsiteCheckSummary(resp *model.WebsiteCheckResponse, notes []string) string {
	parts := make([]string, 0, 4)
	if resp.TLS.Grade != "" && resp.TLS.Grade != "-" {
		parts = append(parts, fmt.Sprintf("TLS grade %s", resp.TLS.Grade))
	}
	if resp.Headers.Total > 0 {
		parts = append(parts, fmt.Sprintf("%d/%d security headers present", resp.Headers.Present, resp.Headers.Total))
	}
	switch {
	case resp.EmailAuth.SPF && resp.EmailAuth.DMARC:
		parts = append(parts, "SPF and DMARC configured")
	case resp.EmailAuth.SPF || resp.EmailAuth.DMARC:
		parts = append(parts, "email authentication partially configured")
	default:
		parts = append(parts, "SPF/DMARC not configured")
	}

	summary := "Passive check complete."
	if len(parts) > 0 {
		summary = "Passive check complete — " + joinWithCommas(parts) + "."
	}
	if len(notes) > 0 {
		summary += " Note: " + joinWithCommas(notes) + "."
	}
	return summary
}

func joinWithCommas(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}
