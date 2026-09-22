// Package service — this file owns the free security-headers-checker tool's
// network fetch. Grading itself (GradeHeaders, header_grader.go) is pure;
// this file is the I/O half: fetch https://<domain>/ (falling back to http on
// the first hop), follow at most maxHeaderCheckRedirects redirects — only to
// the same registrable domain and only to public IPs, re-checked at every
// hop by the go-safedial transport — then grade the final response's headers.
package service

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"target-service/internal/model"
	"time"

	"github.com/paaavkata/go-safedial"
	"golang.org/x/net/publicsuffix"
)

const (
	maxHeaderCheckRedirects = 3
	maxHeaderCheckBodyBytes = 1 << 20 // 1 MB cap
	headerCheckTimeout      = 10 * time.Second
	toolsUserAgent          = "ScantinelFreeTool/1.0 (+https://scantinel.ai/tools)"
)

// HeaderChecker fetches a domain's homepage and grades its security headers.
type HeaderChecker struct {
	client *http.Client
	dialer *safedial.Dialer
}

// NewHeaderChecker builds a checker whose transport refuses to dial
// reserved/internal IPs (SSRF-safe, same posture as the ownership-verification
// client) and never auto-follows redirects — this file drives them manually
// so it can enforce the same-registrable-domain restriction.
func NewHeaderChecker() *HeaderChecker {
	cfg := safedial.Config{AllowUnpinned: true, Timeout: headerCheckTimeout}
	return &HeaderChecker{
		client: &http.Client{
			Timeout:   headerCheckTimeout,
			Transport: safedial.NewTransport(cfg),
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		dialer: safedial.NewDialer(cfg),
	}
}

// Check fetches domain's homepage and returns the graded header response.
func (h *HeaderChecker) Check(ctx context.Context, domain string) (*model.SecurityHeadersResponse, error) {
	registrable := registrableDomainOf(domain)
	current := "https://" + domain + "/"

	resp, err := h.fetch(ctx, current)
	if err != nil {
		// Fall back to http:// only on the very first request.
		httpURL := "http://" + domain + "/"
		resp, err = h.fetch(ctx, httpURL)
		if err != nil {
			return nil, fmt.Errorf("fetching %s: %w", domain, err)
		}
		current = httpURL
	}

	for hop := 0; hop < maxHeaderCheckRedirects && isRedirect(resp.StatusCode); hop++ {
		loc := resp.Header.Get("Location")
		drainAndClose(resp)
		if loc == "" {
			break
		}
		next, perr := resolveRedirect(current, loc)
		if perr != nil {
			return nil, fmt.Errorf("could not resolve redirect target %q from %s: %w", loc, current, perr)
		}
		if registrableDomainOf(next.Hostname()) != registrable {
			return nil, fmt.Errorf("refusing to follow a redirect from %s to a different domain (%s)", current, next.Hostname())
		}
		current = next.String()
		resp, err = h.fetch(ctx, current)
		if err != nil {
			return nil, fmt.Errorf("fetching redirect target %s: %w", current, err)
		}
	}
	defer drainAndClose(resp)

	items, grade := GradeHeaders(resp.Header)
	return &model.SecurityHeadersResponse{
		Domain:    domain,
		FinalURL:  current,
		Grade:     grade,
		Headers:   items,
		CheckedAt: time.Now().UTC(),
	}, nil
}

func (h *HeaderChecker) fetch(ctx context.Context, target string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", toolsUserAgent)
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	// Body is never used beyond header grading — discard, capped, never logged.
	io.Copy(io.Discard, io.LimitReader(resp.Body, maxHeaderCheckBodyBytes)) //nolint:errcheck
	return resp, nil
}

func drainAndClose(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_ = resp.Body.Close()
}

func isRedirect(status int) bool {
	return status >= 300 && status < 400
}

func resolveRedirect(currentURL, location string) (*url.URL, error) {
	base, err := url.Parse(currentURL)
	if err != nil {
		return nil, err
	}
	next, err := url.Parse(location)
	if err != nil {
		return nil, err
	}
	resolved := base.ResolveReference(next)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return nil, fmt.Errorf("unsupported redirect scheme %q", resolved.Scheme)
	}
	return resolved, nil
}

// registrableDomainOf derives the eTLD+1 for host using the ICANN public
// suffix list, falling back to the last two labels when the list can't parse
// it (private TLD, malformed input).
func registrableDomainOf(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	rd, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		parts := strings.Split(host, ".")
		if len(parts) < 2 {
			return host
		}
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return rd
}
