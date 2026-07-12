// Package repository_test validates the extractRegistrableDomain helper
// by calling it via the internal (white-box) test package.
package repository

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestExtractRegistrableDomain validates the eTLD+1 extraction using the
// real golang.org/x/net/publicsuffix implementation.
// This function is unexported; we test it in the same package (white-box).
func TestExtractRegistrableDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Basic domains
		{"example.com", "example.com"},
		{"api.example.com", "example.com"},
		{"deep.api.example.com", "example.com"},
		// Multi-label TLD — must NOT collapse to last 2 labels naively
		{"example.co.uk", "example.co.uk"},
		{"sub.example.co.uk", "example.co.uk"},
		{"example.com.au", "example.com.au"},
		// URL with scheme and path
		{"https://www.example.com/path/to/resource", "example.com"},
		// With port
		{"www.example.com:8080", "example.com"},
		// With scheme and port
		{"https://api.example.com:443/v1", "example.com"},
		// Prefix-spoof protection: evil-example.com extracts to evil-example.com (not example.com)
		{"evil-example.com", "evil-example.com"},
		// Single label (IP or short) → return as-is
		{"localhost", "localhost"},
	}

	for _, tc := range tests {
		got := extractRegistrableDomain(tc.input)
		assert.Equal(t, tc.want, got, "input=%q", tc.input)
	}
}

// TestExtractRegistrableDomain_PrefixSpoofDistinct ensures that evil-example.com
// and example.com extract to DIFFERENT registrable domains, which is the key
// property that makes the scope gate safe.
func TestExtractRegistrableDomain_PrefixSpoofDistinct(t *testing.T) {
	apex := extractRegistrableDomain("example.com")
	spoof := extractRegistrableDomain("evil-example.com")
	assert.NotEqual(t, apex, spoof,
		"evil-example.com must NOT share a registrable domain with example.com")
}
