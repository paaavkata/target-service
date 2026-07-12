// White-box tests for unexported helpers in scope_service.go.
// These tests are in the same package (no _test suffix) so they can access
// unexported functions directly.
package service

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// isSubdomainOf — exhaustive correctness tests for the scope gate's
// most-critical subdomain matching function (06 §3).
// ---------------------------------------------------------------------------

func TestIsSubdomainOf(t *testing.T) {
	tests := []struct {
		host string
		apex string
		want bool
		desc string
	}{
		// Positive cases
		{"example.com", "example.com", true, "exact apex match"},
		{"api.example.com", "example.com", true, "direct subdomain"},
		{"a.b.c.example.com", "example.com", true, "deep subdomain"},
		{"UPPER.EXAMPLE.COM", "example.com", true, "case-insensitive"},
		{"sub.example.co.uk", "example.co.uk", true, "multi-label TLD subdomain"},
		// Negative cases — these are the SAFETY-CRITICAL denials
		{"notexample.com", "example.com", false, "different domain same TLD"},
		{"evil-example.com", "example.com", false, "hyphen prefix spoof"},
		{"evilexample.com", "example.com", false, "no-separator prefix spoof"},
		{"example.com.evil.com", "example.com", false, "suffix-injection spoof"},
		{"myexample.com", "example.com", false, "concatenation prefix spoof"},
		{"example.org", "example.com", false, "different TLD"},
		{"example.co.uk", "example.com", false, "multi-label TLD vs com"},
		{"evilexample.co.uk", "example.co.uk", false, "prefix spoof on multi-label TLD"},
		{"", "example.com", false, "empty host"},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got := isSubdomainOf(tc.host, tc.apex)
			assert.Equal(t, tc.want, got, "isSubdomainOf(%q, %q): %s", tc.host, tc.apex, tc.desc)
		})
	}
}

// ---------------------------------------------------------------------------
// isSharedInfra — Cloudflare, Fastly, Akamai ranges must be detected.
// Non-CDN customer-space IPs must NOT be flagged.
// ---------------------------------------------------------------------------

func TestIsSharedInfra_CloudflareRanges(t *testing.T) {
	cloudflareIPs := []string{
		"104.16.1.1",   // 104.16.0.0/13
		"104.24.1.1",   // 104.24.0.0/14
		"172.64.1.1",   // 172.64.0.0/13
		"173.245.48.1", // 173.245.48.0/20
		"198.41.128.1", // 198.41.128.0/17
		"162.158.1.1",  // 162.158.0.0/15
		"141.101.64.1", // 141.101.64.0/18
	}
	for _, ipStr := range cloudflareIPs {
		ip := net.ParseIP(ipStr)
		if !assert.NotNil(t, ip, "test setup: %s should parse as IP", ipStr) {
			continue
		}
		assert.True(t, isSharedInfra(ip), "Cloudflare IP %s must be classified as shared-infra", ipStr)
	}
}

func TestIsSharedInfra_FastlyRanges(t *testing.T) {
	fastlyIPs := []string{
		"151.101.1.1",  // 151.101.0.0/16
		"23.235.33.1",  // 23.235.32.0/20
		"199.27.72.1",  // 199.27.72.0/21
		"172.111.64.1", // 172.111.64.0/18
	}
	for _, ipStr := range fastlyIPs {
		ip := net.ParseIP(ipStr)
		if !assert.NotNil(t, ip, "test setup: %s should parse", ipStr) {
			continue
		}
		assert.True(t, isSharedInfra(ip), "Fastly IP %s must be classified as shared-infra", ipStr)
	}
}

func TestIsSharedInfra_AkamaiRanges(t *testing.T) {
	akamaiIPs := []string{
		"23.32.0.1",  // 23.32.0.0/11
		"23.64.0.1",  // 23.64.0.0/14
		"23.192.0.1", // 23.192.0.0/11
	}
	for _, ipStr := range akamaiIPs {
		ip := net.ParseIP(ipStr)
		assert.NotNil(t, ip)
		assert.True(t, isSharedInfra(ip), "Akamai IP %s must be classified as shared-infra", ipStr)
	}
}

func TestIsSharedInfra_CustomerOwnedRanges_NotShared(t *testing.T) {
	// RFC5737 TEST-NET addresses — safe for unit tests; not in any CDN range.
	customerIPs := []string{
		"203.0.113.1",  // TEST-NET-3 — not in any CDN range
		"198.51.100.1", // TEST-NET-2
		"192.0.2.1",    // TEST-NET-1
	}
	for _, ipStr := range customerIPs {
		ip := net.ParseIP(ipStr)
		assert.NotNil(t, ip, "test setup: %s should parse", ipStr)
		assert.False(t, isSharedInfra(ip), "RFC5737 test IP %s must NOT be classified as shared-infra", ipStr)
	}
}

func TestIsSharedInfra_PrivateRFC1918_NotShared(t *testing.T) {
	// Private address space is not CDN/shared-infra (could be customer-internal).
	privateIPs := []string{
		"10.0.0.1",
		"192.168.1.1",
		"172.16.0.1",
	}
	for _, ipStr := range privateIPs {
		ip := net.ParseIP(ipStr)
		assert.NotNil(t, ip)
		assert.False(t, isSharedInfra(ip), "RFC1918 IP %s must not be shared-infra", ipStr)
	}
}
