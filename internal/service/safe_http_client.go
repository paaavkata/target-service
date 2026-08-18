// Package service implements the business logic for target-service.
// This file owns the hardened HTTP client used for ownership-verification
// fetches (verifyHTTPFile / verifyMetaTag). Those requests are made from the
// platform pod to an attacker-supplied host BEFORE ownership is proven, so the
// client must be SSRF-proof:
//
//  1. Redirects are REFUSED (not silently swallowed with ErrUseLastResponse):
//     a host that answers the verification fetch with a 3xx fails verification
//     outright. Refusal was chosen over ErrUseLastResponse deliberately — with
//     ErrUseLastResponse the 3xx response itself would be inspected for proof
//     material, which is surprising and still lets an attacker probe redirect
//     behaviour; an explicit error is unambiguous and fail-closed.
//
//  2. The reserved-IP denylist is enforced AT DIAL TIME via net.Dialer.Control,
//     i.e. against the ALREADY-RESOLVED connect address. Checking there (rather
//     than pre-vetting the hostname) closes the DNS-rebinding TOCTOU window and
//     blocks direct internal targets (169.254.169.254, RFC1918, pod network,
//     IPv6 ULA, ...). The denylist is isReserved() from scope_service.go — the
//     single source of truth shared with the scope gate; do NOT duplicate it.
package service

import (
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

// safeDialControl is the net.Dialer.Control hook for verification fetches.
// The dialer invokes it just before connect(2) with the resolved "ip:port"
// address, so whatever DNS answered at dial time is exactly what gets vetted.
// Anything that is not a parseable public IP is refused (fail-closed).
func safeDialControl(_ string, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("verification dial: invalid address %q refused: %w", address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("verification dial: non-IP address %q refused (fail-closed)", host)
	}
	if isReserved(ip) {
		return fmt.Errorf("verification dial to reserved/internal IP %s refused (SSRF guard, 06 §3)", ip)
	}
	return nil
}

// newSafeVerificationClient builds the hardened HTTP client used by BOTH
// verifyHTTPFile and verifyMetaTag. Body-size caps remain the callers'
// responsibility (io.LimitReader), and the overall time cap is the timeout
// argument — unchanged from the previous per-verifier clients.
//
// Proxy is deliberately nil (NOT ProxyFromEnvironment): an env-configured
// proxy would carry the request past the dial-time reserved-IP check.
func newSafeVerificationClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout: timeout,
		Control: safeDialControl,
	}
	transport := &http.Transport{
		Proxy:               nil,
		DialContext:         dialer.DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		// Refuse redirects — see the file comment for why refusal (an explicit
		// error) was chosen over http.ErrUseLastResponse. A redirecting host
		// FAILS verification; the platform never follows a 3xx toward
		// http://169.254.169.254/ or an internal service.
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			return fmt.Errorf("redirects are refused during ownership verification (redirect to %s not followed)", req.URL)
		},
	}
}
