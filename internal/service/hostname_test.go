package service_test

import (
	"target-service/internal/service"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeAndValidateHostname(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"bare domain", "example.com", "example.com", false},
		{"uppercase", "EXAMPLE.com", "example.com", false},
		{"https scheme", "https://example.com", "example.com", false},
		{"http scheme with path", "http://example.com/foo/bar", "example.com", false},
		{"scheme with query", "https://example.com/?x=1", "example.com", false},
		{"trailing slash", "example.com/", "example.com", false},
		{"with port", "example.com:8443", "example.com", false},
		{"scheme+port+path", "https://example.com:443/path", "example.com", false},
		{"trailing dot (FQDN)", "example.com.", "example.com", false},
		{"subdomain", "www.example.co.uk", "www.example.co.uk", false},
		{"whitespace padding", "  example.com  ", "example.com", false},
		{"userinfo stripped", "https://user:pass@example.com/", "example.com", false},

		{"empty", "", "", true},
		{"whitespace only", "   ", "", true},
		{"IPv4 literal", "203.0.113.5", "", true},
		{"IPv6 literal", "::1", "", true},
		{"bracketed IPv6", "[::1]", "", true},
		{"IPv4 literal with port", "203.0.113.5:8080", "", true},
		{"localhost", "localhost", "", true},
		{"localhost with scheme", "http://localhost:8080", "", true},
		{"single label", "internalhost", "", true},
		{"dot-local", "printer.local", "", true},
		{"dot-internal", "service.internal", "", true},
		{"invalid chars", "exa mple.com", "", true},
		{"leading hyphen label", "-example.com", "", true},
		{"empty label (double dot)", "example..com", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := service.NormalizeAndValidateHostname(tt.input)
			if tt.wantErr {
				assert.Error(t, err, "input %q should be rejected", tt.input)
				return
			}
			assert.NoError(t, err, "input %q should be accepted", tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}
