// White-box tests for the hardened verification HTTP client
// (safe_http_client.go). Same package (no _test suffix) so the unexported
// safeDialControl / newSafeVerificationClient are reachable directly —
// preferred over standing up real servers per the SSRF-guard test guidance.
package service

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/paaavkata/go-safedial"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// safeDialControl — the dial-time reserved-IP guard (DNS-rebinding blocker).
// The control func sees the ALREADY-RESOLVED ip:port, so these cases model
// exactly what an attacker-controlled DNS answer would produce at connect time.
// ---------------------------------------------------------------------------

func TestSafeDialControl_ReservedAddresses_Refused(t *testing.T) {
	reserved := []struct {
		address string
		desc    string
	}{
		{"169.254.169.254:443", "cloud metadata (IMDS)"},
		{"169.254.169.254:80", "cloud metadata over http"},
		{"10.0.0.5:443", "RFC1918 10/8"},
		{"172.16.0.1:443", "RFC1918 172.16/12"},
		{"192.168.1.10:8080", "RFC1918 192.168/16"},
		{"127.0.0.1:80", "loopback"},
		{"100.64.1.1:443", "CGNAT (RFC6598) — cloud LB / pod ranges"},
		{"0.0.0.0:443", "unspecified"},
		{"198.18.0.1:443", "benchmarking range"},
		{"[::1]:443", "IPv6 loopback"},
		{"[fd00::1]:443", "IPv6 unique-local"},
		{"[fe80::1]:443", "IPv6 link-local"},
		{"[fd00:ec2::254]:80", "AWS IMDS IPv6"},
	}
	for _, tc := range reserved {
		t.Run(tc.desc, func(t *testing.T) {
			err := safeDialControl("tcp", tc.address, nil)
			assert.Error(t, err, "dial to %s (%s) must be refused", tc.address, tc.desc)
		})
	}
}

func TestSafeDialControl_PublicAddresses_Allowed(t *testing.T) {
	public := []string{
		"203.0.113.10:443", // TEST-NET-3
		"198.51.100.7:80",  // TEST-NET-2
		"8.8.8.8:53",
		"[2001:db8::1]:443", // IPv6 documentation range (public-shaped)
	}
	for _, address := range public {
		err := safeDialControl("tcp", address, nil)
		assert.NoError(t, err, "dial to public address %s must be allowed", address)
	}
}

func TestSafeDialControl_MalformedAddress_Refused(t *testing.T) {
	// Fail-closed: anything that is not a parseable ip:port, and not a bare
	// parseable IP, is refused.
	//
	// Behaviour note (go-safedial swap): the old hand-rolled safeDialControl
	// refused ANY address net.SplitHostPort couldn't parse, including a
	// portless bare IP like "203.0.113.10". safedial.Dialer.CheckAddress
	// instead falls back to treating a portless string as a bare host when
	// SplitHostPort fails, so a portless *public* IP is now evaluated (and
	// allowed) rather than rejected as malformed — real net.Dialer.Control
	// hooks always receive "ip:port", so this only matters for this synthetic
	// unit test. Dropped from the table below; still covered as an "allowed"
	// case via TestSafeDialControl_PublicAddresses_Allowed's ":443" form.
	for _, address := range []string{"not-an-ip:443", "", "example.com:443"} {
		err := safeDialControl("tcp", address, nil)
		assert.Error(t, err, "malformed/non-IP address %q must be refused", address)
	}
}

// ---------------------------------------------------------------------------
// safedial.NewVerificationHTTPClient — redirects are refused, dial guard armed.
// ---------------------------------------------------------------------------

func TestNewSafeVerificationClient_RefusesRedirects(t *testing.T) {
	client := safedial.NewVerificationHTTPClient(5 * time.Second)

	// CheckRedirect must be set (a nil CheckRedirect means "follow up to 10
	// redirects" — the exact SSRF hole this client exists to close).
	require.NotNil(t, client.CheckRedirect, "CheckRedirect must be set so redirects are not followed")

	// And it must REFUSE (return an error), not silently swallow: a 302 toward
	// the metadata service must fail verification outright.
	redirectTarget, err := http.NewRequest(http.MethodGet, "http://169.254.169.254/latest/meta-data/", nil)
	require.NoError(t, err)
	err = client.CheckRedirect(redirectTarget, []*http.Request{{}})
	assert.Error(t, err, "a redirect must be refused with an explicit error")
	assert.Contains(t, err.Error(), "redirects are refused")
}

func TestNewSafeVerificationClient_TransportUsesGuardedDialer(t *testing.T) {
	client := safedial.NewVerificationHTTPClient(5 * time.Second)
	assert.Equal(t, 5*time.Second, client.Timeout, "overall time cap must be preserved")

	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok, "transport must be the hardened *http.Transport")
	assert.NotNil(t, transport.DialContext, "dialer with Control guard must be installed")
	assert.Nil(t, transport.Proxy, "proxy must be nil so egress cannot bypass the dial-time guard")
}

// End-to-end: the client refuses to even CONNECT to an internal address. An
// httptest server listens on 127.0.0.1 (loopback = reserved), so a plain GET
// against it must fail at dial time — this is the redirect-to-internal /
// direct-internal-target scenario without needing attacker DNS.
func TestNewSafeVerificationClient_RefusesInternalConnect(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := safedial.NewVerificationHTTPClient(5 * time.Second)
	resp, err := client.Get(ts.URL)
	if resp != nil {
		resp.Body.Close()
	}
	require.Error(t, err, "GET to a loopback/internal server must fail at dial time")
	assert.Contains(t, err.Error(), "reserved/internal IP")
}
