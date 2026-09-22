package service_test

import (
	"crypto/tls"
	"target-service/internal/service"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGradeTLS(t *testing.T) {
	tests := []struct {
		name          string
		protocol      uint16
		tls10, tls11  bool
		chainValid    bool
		daysLeft      int
		wantGrade     string
	}{
		{"modern config", tls.VersionTLS13, false, false, true, 200, "A"},
		{"tls1.2 only, still good", tls.VersionTLS12, false, false, true, 200, "A"},
		{"accepts tls1.0 is bad", tls.VersionTLS13, true, false, true, 200, "C"},
		{"accepts both weak versions is worse", tls.VersionTLS13, true, true, true, 200, "D"},
		{"invalid chain is bad", tls.VersionTLS13, false, false, false, 200, "D"},
		{"expired cert tanks the grade", tls.VersionTLS13, false, false, true, -5, "F"},
		{"cert expiring soon warns a little", tls.VersionTLS13, false, false, true, 10, "B"},
		{"only tls1.0 negotiated is worst", tls.VersionTLS10, true, true, true, 200, "F"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grade, reasons := service.GradeTLS(tt.protocol, tt.tls10, tt.tls11, tt.chainValid, tt.daysLeft)
			assert.Equal(t, tt.wantGrade, grade, "reasons: %v", reasons)
			assert.NotEmpty(t, reasons)
		})
	}
}
