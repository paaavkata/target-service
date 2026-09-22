// Package model — this file owns the request/response DTOs for the public,
// unauthenticated free-tool endpoints (/v1/tools/*) that back
// scantinel-website's /tools/* pages. These are stateless outbound checks:
// nothing here is persisted, and no X-User-Id/X-App-Id is required.
package model

import "time"

// ToolCheckRequest is the shared request body for every /v1/tools/* endpoint.
type ToolCheckRequest struct {
	Domain string `json:"domain" validate:"required"`
}

// Header verdict states for SecurityHeadersResponse.Headers[i].Status.
const (
	HeaderStatusPass = "pass"
	HeaderStatusWarn = "warn"
	HeaderStatusFail = "fail"
)

// HeaderResult is the verdict for one HTTP security response header.
type HeaderResult struct {
	Name   string `json:"name"`
	Status string `json:"status"` // pass | warn | fail
	Value  string `json:"value,omitempty"`
	Advice string `json:"advice"`
}

// SecurityHeadersResponse is the response for POST /v1/tools/security-headers.
type SecurityHeadersResponse struct {
	Domain    string         `json:"domain"`
	FinalURL  string         `json:"final_url"`
	Grade     string         `json:"grade"`
	Headers   []HeaderResult `json:"headers"`
	CheckedAt time.Time      `json:"checked_at"`
}

// TLSCertificateInfo summarises the leaf certificate presented by the server.
type TLSCertificateInfo struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	ExpiresAt time.Time `json:"expires_at"`
	DaysLeft  int       `json:"days_left"`
}

// TLSCheckResponse is the response for POST /v1/tools/tls.
type TLSCheckResponse struct {
	Domain            string              `json:"domain"`
	Protocol          string              `json:"protocol"`
	Cipher            string              `json:"cipher"`
	Certificate       TLSCertificateInfo  `json:"certificate"`
	ChainValidForHost bool                `json:"chain_valid_for_host"`
	TLS10Accepted     bool                `json:"tls10_accepted"`
	TLS11Accepted     bool                `json:"tls11_accepted"`
	Grade             string              `json:"grade"`
	Reasons           []string            `json:"reasons"`
	CheckedAt         time.Time           `json:"checked_at"`
}

// SPFResult is the parsed SPF posture for a domain.
type SPFResult struct {
	Present     bool     `json:"present"`
	Record      string   `json:"record,omitempty"`
	Qualifier   string   `json:"qualifier,omitempty"` // -all | ~all | ?all | +all | "" (none found)
	LookupCount int      `json:"lookup_count"`
	Warnings    []string `json:"warnings,omitempty"`
}

// DMARCResult is the parsed DMARC posture for a domain.
type DMARCResult struct {
	Present    bool     `json:"present"`
	Record     string   `json:"record,omitempty"`
	Policy     string   `json:"policy,omitempty"` // none | quarantine | reject
	RUAPresent bool     `json:"rua_present"`
	Warnings   []string `json:"warnings,omitempty"`
}

// DKIMSelectorResult is the result of probing one common DKIM selector.
type DKIMSelectorResult struct {
	Selector string `json:"selector"`
	Present  bool   `json:"present"`
	Record   string `json:"record,omitempty"`
}

// EmailAuthResponse is the response for POST /v1/tools/email-auth.
type EmailAuthResponse struct {
	Domain    string               `json:"domain"`
	SPF       SPFResult            `json:"spf"`
	DMARC     DMARCResult          `json:"dmarc"`
	DKIM      []DKIMSelectorResult `json:"dkim"`
	Fixes     []string             `json:"fixes,omitempty"`
	CheckedAt time.Time            `json:"checked_at"`
}

// WebsiteCheckTLSSummary is the compact TLS summary embedded in WebsiteCheckResponse
// — shaped to match scantinel-website's ScanResult.tls.
type WebsiteCheckTLSSummary struct {
	Grade      string `json:"grade"`
	Protocol   string `json:"protocol"`
	CertExpiry string `json:"certExpiry"`
}

// WebsiteCheckHeaderItem is one header's compact verdict for the website widget.
type WebsiteCheckHeaderItem struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

// WebsiteCheckHeadersSummary mirrors ScanResult.headers on the website.
type WebsiteCheckHeadersSummary struct {
	Present int                       `json:"present"`
	Total   int                       `json:"total"`
	Items   []WebsiteCheckHeaderItem  `json:"items"`
}

// WebsiteCheckEmailSummary mirrors ScanResult.emailAuth on the website.
type WebsiteCheckEmailSummary struct {
	SPF         bool   `json:"spf"`
	DMARC       bool   `json:"dmarc"`
	DMARCPolicy string `json:"dmarcPolicy"`
}

// WebsiteCheckDetails carries the full per-check responses alongside the
// compact summary, so the website can render a detailed view without a
// second round trip.
type WebsiteCheckDetails struct {
	Headers   *SecurityHeadersResponse `json:"headers,omitempty"`
	TLS       *TLSCheckResponse        `json:"tls,omitempty"`
	EmailAuth *EmailAuthResponse       `json:"email_auth,omitempty"`
}

// WebsiteCheckResponse is the response for POST /v1/tools/website-check — the
// combined shape scantinel-website's tool.tsx ScanResult expects, plus a
// `details` section with the full per-check output.
type WebsiteCheckResponse struct {
	Domain    string                     `json:"domain"`
	TLS       WebsiteCheckTLSSummary     `json:"tls"`
	Headers   WebsiteCheckHeadersSummary `json:"headers"`
	EmailAuth WebsiteCheckEmailSummary   `json:"emailAuth"`
	Summary   string                     `json:"summary"`
	Details   WebsiteCheckDetails        `json:"details"`
	CheckedAt time.Time                  `json:"checked_at"`
}
