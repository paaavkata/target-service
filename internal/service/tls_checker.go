// Package service — this file owns the free TLS/SSL checker tool. The
// handshake itself goes through the go-safedial pinned dialer (SSRF-safe,
// same guard as verification_service.go); GradeTLS is pure and unit-tested
// separately from the network code.
package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"target-service/internal/model"
	"time"

	"github.com/paaavkata/go-safedial"
)

const tlsCheckTimeout = 10 * time.Second

// TLSChecker performs the TLS handshake / certificate inspection for the
// free tls checker tool.
type TLSChecker struct {
	dialer *safedial.Dialer
}

// NewTLSChecker builds a checker that dials arbitrary (not-yet-verified)
// customer hosts — unpinned, but every dial is still checked against the
// reserved/internal-IP denylist at connect time.
func NewTLSChecker() *TLSChecker {
	return &TLSChecker{dialer: safedial.NewDialer(safedial.Config{AllowUnpinned: true, Timeout: tlsCheckTimeout})}
}

// Check connects to domain:443, negotiates TLS with the library's modern
// defaults (>=TLS1.2) to report the server's real posture, separately probes
// whether TLS 1.0/1.1 are still accepted, and grades the result.
func (t *TLSChecker) Check(ctx context.Context, domain string) (*model.TLSCheckResponse, error) {
	state, err := t.handshake(ctx, domain, 0, 0)
	if err != nil {
		// The server may only speak TLS 1.0/1.1 (or SSLv3); retry once with an
		// explicit weak floor purely to surface *something* gradeable — this
		// path always ends up with the worst grade via the TLS10/11 probes.
		state, err = t.handshake(ctx, domain, tls.VersionTLS10, tls.VersionTLS13)
		if err != nil {
			return nil, fmt.Errorf("TLS handshake with %s:443 failed: %w", domain, err)
		}
	}

	tls10, _ := t.probeVersion(ctx, domain, tls.VersionTLS10)
	tls11, _ := t.probeVersion(ctx, domain, tls.VersionTLS11)

	resp := &model.TLSCheckResponse{
		Domain:        domain,
		Protocol:      tlsVersionName(state.Version),
		Cipher:        tls.CipherSuiteName(state.CipherSuite),
		TLS10Accepted: tls10,
		TLS11Accepted: tls11,
		CheckedAt:     time.Now().UTC(),
	}

	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		resp.Certificate = model.TLSCertificateInfo{
			Subject:   leaf.Subject.CommonName,
			Issuer:    leaf.Issuer.CommonName,
			ExpiresAt: leaf.NotAfter,
			DaysLeft:  int(time.Until(leaf.NotAfter).Hours() / 24),
		}
		pool := x509.NewCertPool()
		for _, c := range state.PeerCertificates[1:] {
			pool.AddCert(c)
		}
		_, verr := leaf.Verify(x509.VerifyOptions{DNSName: domain, Intermediates: pool})
		resp.ChainValidForHost = verr == nil
	}

	resp.Grade, resp.Reasons = GradeTLS(state.Version, tls10, tls11, resp.ChainValidForHost, resp.Certificate.DaysLeft)
	return resp, nil
}

// handshake dials domain:443 through the safe dialer and performs a TLS
// handshake with the given version window (0 = crypto/tls default, currently
// >=TLS1.2).
func (t *TLSChecker) handshake(ctx context.Context, domain string, minVersion, maxVersion uint16) (tls.ConnectionState, error) {
	dialCtx, cancel := context.WithTimeout(ctx, tlsCheckTimeout)
	defer cancel()
	conn, err := t.dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(domain, "443"))
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(tlsCheckTimeout))
	cfg := &tls.Config{ServerName: domain, MinVersion: minVersion, MaxVersion: maxVersion}
	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		return tls.ConnectionState{}, err
	}
	return tlsConn.ConnectionState(), nil
}

// probeVersion reports whether the server accepts a handshake pinned to
// exactly version (used to test whether TLS 1.0/1.1 are still enabled).
func (t *TLSChecker) probeVersion(ctx context.Context, domain string, version uint16) (bool, error) {
	_, err := t.handshake(ctx, domain, version, version)
	return err == nil, err
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}

// GradeTLS is pure and unit-testable: given already-extracted facts about a
// TLS connection, it returns a letter grade (A-F) and the human-readable
// reasons behind it.
func GradeTLS(protocolVersion uint16, tls10Accepted, tls11Accepted, chainValidForHost bool, daysLeft int) (string, []string) {
	var reasons []string
	score := 100

	switch protocolVersion {
	case tls.VersionTLS13:
		reasons = append(reasons, "Negotiates TLS 1.3 — best available protocol version.")
	case tls.VersionTLS12:
		reasons = append(reasons, "Negotiates TLS 1.2 — acceptable, but TLS 1.3 is preferred.")
		score -= 5
	default:
		reasons = append(reasons, fmt.Sprintf("Negotiates %s by default — outdated and insecure.", tlsVersionName(protocolVersion)))
		score -= 40
	}

	if tls10Accepted {
		reasons = append(reasons, "Server still accepts TLS 1.0 connections — disable it; it has known weaknesses (BEAST, POODLE-adjacent) and fails PCI-DSS.")
		score -= 25
	}
	if tls11Accepted {
		reasons = append(reasons, "Server still accepts TLS 1.1 connections — disable it in favor of TLS 1.2+.")
		score -= 15
	}
	if !chainValidForHost {
		reasons = append(reasons, "Certificate chain does not validate for this hostname — check for an expired, mismatched, or incomplete chain.")
		score -= 40
	}

	switch {
	case daysLeft < 0:
		reasons = append(reasons, "Certificate has expired.")
		score -= 60
	case daysLeft < 14:
		reasons = append(reasons, fmt.Sprintf("Certificate expires in %d day(s) — renew now.", daysLeft))
		score -= 15
	case daysLeft < 30:
		reasons = append(reasons, fmt.Sprintf("Certificate expires in %d days — schedule renewal soon.", daysLeft))
		score -= 5
	}

	if score < 0 {
		score = 0
	}
	return letterGradeFromPercent(score), reasons
}
