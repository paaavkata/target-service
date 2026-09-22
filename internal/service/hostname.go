// Package service — this file owns hostname normalisation/validation shared
// by the public free-tool endpoints (/v1/tools/*). It is deliberately pure
// (no DNS, no network) so it is unit-testable and cheap to run before any
// outbound fetch is attempted.
package service

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

// ErrInvalidHostname is wrapped by every rejection from NormalizeAndValidateHostname.
var ErrInvalidHostname = errors.New("invalid hostname")

// hostnameRe accepts IDNA-safe ASCII hostnames: one or more dot-separated
// labels of letters/digits/hyphens (no leading/trailing hyphen per label,
// punycode "xn--" labels included) ending in a 2+ letter TLD label.
var hostnameRe = regexp.MustCompile(`^(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// internalSuffixes are TLD-shaped strings that are never publicly routable.
var internalSuffixes = []string{".local", ".localhost", ".internal", ".invalid", ".test", ".localdomain"}

// NormalizeAndValidateHostname strips scheme/userinfo/path/query/fragment/port
// from raw, lowercases it, and rejects anything that is not a plausible
// public hostname: empty input, IP literals (v4 or v6), single-label names,
// "localhost", and internal-looking TLDs (.local/.internal/...). It performs
// no DNS resolution and no network I/O — callers still go through the
// go-safedial denylist at dial time as a second, independent guard.
func NormalizeAndValidateHostname(raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", fmt.Errorf("%w: empty", ErrInvalidHostname)
	}
	if idx := strings.Index(v, "://"); idx >= 0 {
		v = v[idx+3:]
	}
	if idx := strings.IndexAny(v, "/?#"); idx >= 0 {
		v = v[:idx]
	}
	if idx := strings.LastIndex(v, "@"); idx >= 0 { // strip userinfo, if any
		v = v[idx+1:]
	}
	if strings.HasPrefix(v, "[") { // IPv6 literal in brackets — reject below
		if idx := strings.Index(v, "]"); idx >= 0 {
			v = v[:idx+1]
		}
	} else if idx := strings.LastIndex(v, ":"); idx >= 0 { // strip :port
		v = v[:idx]
	}
	v = strings.ToLower(strings.TrimSuffix(v, "."))
	v = strings.Trim(v, "[]")

	if v == "" || len(v) > 253 {
		return "", fmt.Errorf("%w: %q has an invalid length", ErrInvalidHostname, raw)
	}
	if ip := net.ParseIP(v); ip != nil {
		return "", fmt.Errorf("%w: IP literals are not accepted", ErrInvalidHostname)
	}
	if !hostnameRe.MatchString(v) {
		return "", fmt.Errorf("%w: %q is not a valid hostname", ErrInvalidHostname, raw)
	}
	if !strings.Contains(v, ".") {
		return "", fmt.Errorf("%w: single-label hostnames are not accepted", ErrInvalidHostname)
	}
	if v == "localhost" {
		return "", fmt.Errorf("%w: localhost is not accepted", ErrInvalidHostname)
	}
	for _, suf := range internalSuffixes {
		if strings.HasSuffix(v, suf) {
			return "", fmt.Errorf("%w: internal-looking hostname", ErrInvalidHostname)
		}
	}
	return v, nil
}
