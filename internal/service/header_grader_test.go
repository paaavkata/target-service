package service_test

import (
	"net/http"
	"target-service/internal/model"
	"target-service/internal/service"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGradeHeaders_AllMissing(t *testing.T) {
	items, grade := service.GradeHeaders(http.Header{})
	require.Len(t, items, 8)
	for _, it := range items {
		assert.Equal(t, model.HeaderStatusFail, it.Status, "header %s should fail when absent", it.Name)
		assert.NotEmpty(t, it.Advice)
	}
	assert.Equal(t, "F", grade)
}

func TestGradeHeaders_AllStrong(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Security-Policy", "default-src 'self'")
	h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=()")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")

	items, grade := service.GradeHeaders(h)
	require.Len(t, items, 8)
	for _, it := range items {
		assert.Equal(t, model.HeaderStatusPass, it.Status, "header %s should pass: %+v", it.Name, it)
	}
	assert.Equal(t, "A", grade)
}

func TestGradeHeaders_CSPUnsafeInlineWarns(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'")
	items, _ := service.GradeHeaders(h)
	csp := findHeader(t, items, "Content-Security-Policy")
	assert.Equal(t, model.HeaderStatusWarn, csp.Status)
	assert.Contains(t, csp.Advice, "unsafe-inline")
}

func TestGradeHeaders_HSTSShortMaxAgeWarns(t *testing.T) {
	h := http.Header{}
	h.Set("Strict-Transport-Security", "max-age=100")
	items, _ := service.GradeHeaders(h)
	hsts := findHeader(t, items, "Strict-Transport-Security")
	assert.Equal(t, model.HeaderStatusWarn, hsts.Status)
}

func TestGradeHeaders_ReferrerPolicyUnsafeURLFails(t *testing.T) {
	h := http.Header{}
	h.Set("Referrer-Policy", "unsafe-url")
	items, _ := service.GradeHeaders(h)
	rp := findHeader(t, items, "Referrer-Policy")
	assert.Equal(t, model.HeaderStatusFail, rp.Status)
}

func TestGradeHeaders_XFrameOptionsSameOriginPasses(t *testing.T) {
	h := http.Header{}
	h.Set("X-Frame-Options", "SAMEORIGIN")
	items, _ := service.GradeHeaders(h)
	xfo := findHeader(t, items, "X-Frame-Options")
	assert.Equal(t, model.HeaderStatusPass, xfo.Status)
}

func findHeader(t *testing.T, items []model.HeaderResult, name string) model.HeaderResult {
	t.Helper()
	for _, it := range items {
		if it.Name == name {
			return it
		}
	}
	t.Fatalf("header %s not found in results", name)
	return model.HeaderResult{}
}
