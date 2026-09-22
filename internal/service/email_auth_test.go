package service_test

import (
	"target-service/internal/service"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseSPF(t *testing.T) {
	tests := []struct {
		name          string
		record        string
		wantPresent   bool
		wantQualifier string
		wantLookups   int
		wantWarning   bool
	}{
		{"absent", "", false, "", 0, true},
		{
			"hard fail, single include",
			"v=spf1 include:_spf.google.com -all",
			true, "-all", 1, false,
		},
		{
			"soft fail warns",
			"v=spf1 include:_spf.google.com ~all",
			true, "~all", 1, true,
		},
		{
			"plus-all is dangerous",
			"v=spf1 +all",
			true, "+all", 0, true,
		},
		{
			"missing all mechanism warns",
			"v=spf1 include:_spf.google.com",
			true, "", 1, true,
		},
		{
			"too many lookups warns",
			"v=spf1 include:a.com include:b.com include:c.com include:d.com include:e.com include:f.com include:g.com include:h.com include:i.com include:j.com include:k.com -all",
			true, "-all", 11, true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := service.ParseSPF(tt.record)
			assert.Equal(t, tt.wantPresent, got.Present)
			if !tt.wantPresent {
				assert.NotEmpty(t, got.Warnings)
				return
			}
			assert.Equal(t, tt.wantQualifier, got.Qualifier)
			assert.Equal(t, tt.wantLookups, got.LookupCount)
			if tt.wantWarning {
				assert.NotEmpty(t, got.Warnings)
			}
		})
	}
}

func TestParseDMARC(t *testing.T) {
	tests := []struct {
		name       string
		record     string
		wantPolicy string
		wantRUA    bool
		wantWarn   bool
	}{
		{"absent", "", "", false, true},
		{"p=none warns", "v=DMARC1; p=none; rua=mailto:r@example.com", "none", true, true},
		{"p=quarantine warns", "v=DMARC1; p=quarantine; rua=mailto:r@example.com", "quarantine", true, true},
		{"p=reject with rua is clean", "v=DMARC1; p=reject; rua=mailto:r@example.com", "reject", true, false},
		{"p=reject without rua warns", "v=DMARC1; p=reject", "reject", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := service.ParseDMARC(tt.record)
			if tt.record == "" {
				assert.False(t, got.Present)
				assert.NotEmpty(t, got.Warnings)
				return
			}
			assert.True(t, got.Present)
			assert.Equal(t, tt.wantPolicy, got.Policy)
			assert.Equal(t, tt.wantRUA, got.RUAPresent)
			if tt.wantWarn {
				assert.NotEmpty(t, got.Warnings)
			} else {
				assert.Empty(t, got.Warnings)
			}
		})
	}
}
