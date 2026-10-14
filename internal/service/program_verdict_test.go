// White-box tests for the bug-bounty program-mode gate (17 §10). Same package
// so the pure, DB-free programVerdict / programAssetMatches can be table-tested
// directly, like authScanVerdict.
package service

import (
	"testing"
	"time"

	"target-service/internal/model"

	"github.com/stretchr/testify/assert"
)

func freshProgram() *model.BugbountyProgram {
	return &model.BugbountyProgram{
		Platform:          model.ProgramPlatformHackerOne,
		Handle:            "acme",
		AutomationAllowed: true,
		Status:            model.ProgramStatusActive,
		SyncedAt:          time.Now(),
		StaleAfterSeconds: int((7 * 24 * time.Hour).Seconds()),
	}
}

func inScope(t, id string) model.ProgramAsset {
	return model.ProgramAsset{AssetType: t, Identifier: id, InScope: true}
}
func excluded(t, id string) model.ProgramAsset {
	return model.ProgramAsset{AssetType: t, Identifier: id, InScope: false}
}

func TestProgramVerdict(t *testing.T) {
	now := time.Now()

	t.Run("in-scope domain allow", func(t *testing.T) {
		p := freshProgram()
		assets := []model.ProgramAsset{inScope(model.ProgramAssetTypeDomain, "app.acme.com")}
		got := programVerdict(p, assets, "app.acme.com", "", "web_recon", now)
		assert.True(t, got.Authorized, got.Reason)
	})

	t.Run("wildcard match allow", func(t *testing.T) {
		p := freshProgram()
		assets := []model.ProgramAsset{inScope(model.ProgramAssetTypeWildcard, "*.acme.com")}
		got := programVerdict(p, assets, "api.staging.acme.com", "", "web_recon", now)
		assert.True(t, got.Authorized, got.Reason)
		// apex is also covered by our wildcard semantics
		assert.True(t, programVerdict(p, assets, "acme.com", "", "web_recon", now).Authorized)
	})

	t.Run("excluded asset deny (exclusion wins over wildcard)", func(t *testing.T) {
		p := freshProgram()
		assets := []model.ProgramAsset{
			inScope(model.ProgramAssetTypeWildcard, "*.acme.com"),
			excluded(model.ProgramAssetTypeDomain, "secret.acme.com"),
		}
		got := programVerdict(p, assets, "secret.acme.com", "", "web_recon", now)
		assert.False(t, got.Authorized)
		assert.Contains(t, got.Reason, "EXCLUDED")
	})

	t.Run("not in scope deny", func(t *testing.T) {
		p := freshProgram()
		assets := []model.ProgramAsset{inScope(model.ProgramAssetTypeWildcard, "*.acme.com")}
		got := programVerdict(p, assets, "evil.com", "", "web_recon", now)
		assert.False(t, got.Authorized)
		assert.Contains(t, got.Reason, "not within any in-scope asset")
	})

	t.Run("stale policy deny", func(t *testing.T) {
		p := freshProgram()
		p.StaleAfterSeconds = int((24 * time.Hour).Seconds())
		p.SyncedAt = now.Add(-48 * time.Hour)
		assets := []model.ProgramAsset{inScope(model.ProgramAssetTypeWildcard, "*.acme.com")}
		got := programVerdict(p, assets, "api.acme.com", "", "web_recon", now)
		assert.False(t, got.Authorized)
		assert.Contains(t, got.Reason, "stale")
	})

	t.Run("automation forbidden deny", func(t *testing.T) {
		p := freshProgram()
		p.AutomationAllowed = false
		assets := []model.ProgramAsset{inScope(model.ProgramAssetTypeWildcard, "*.acme.com")}
		got := programVerdict(p, assets, "api.acme.com", "", "web_recon", now)
		assert.False(t, got.Authorized)
		assert.Contains(t, got.Reason, "automated scanning is not permitted")
	})

	t.Run("prohibited technique filters the phase", func(t *testing.T) {
		p := freshProgram()
		// Program forbids brute force (platform wording normalized to brute_force).
		p.ProhibitedTechniques = []string{"Brute Force"}
		assets := []model.ProgramAsset{inScope(model.ProgramAssetTypeWildcard, "*.acme.com")}
		// cred phase maps to brute_force -> denied.
		cred := programVerdict(p, assets, "api.acme.com", "", "cred", now)
		assert.False(t, cred.Authorized)
		assert.Contains(t, cred.Reason, "prohibited technique")
		// a passive phase is unaffected.
		recon := programVerdict(p, assets, "api.acme.com", "", "web_recon", now)
		assert.True(t, recon.Authorized, recon.Reason)
	})

	t.Run("nil policy deny", func(t *testing.T) {
		got := programVerdict(nil, nil, "api.acme.com", "", "web_recon", now)
		assert.False(t, got.Authorized)
		assert.Contains(t, got.Reason, "could not be established")
	})

	t.Run("paused program deny", func(t *testing.T) {
		p := freshProgram()
		p.Status = model.ProgramStatusPaused
		assets := []model.ProgramAsset{inScope(model.ProgramAssetTypeWildcard, "*.acme.com")}
		got := programVerdict(p, assets, "api.acme.com", "", "web_recon", now)
		assert.False(t, got.Authorized)
	})

	t.Run("cidr asset matches ip query", func(t *testing.T) {
		p := freshProgram()
		assets := []model.ProgramAsset{inScope(model.ProgramAssetTypeCIDR, "203.0.113.0/24")}
		assert.True(t, programVerdict(p, assets, "", "203.0.113.7", "network", now).Authorized)
		assert.False(t, programVerdict(p, assets, "", "198.51.100.1", "network", now).Authorized)
	})
}

func TestProgramAssetMatches_URL(t *testing.T) {
	a := inScope(model.ProgramAssetTypeURL, "https://app.acme.com/login")
	assert.True(t, programAssetMatches(&a, "app.acme.com", ""))
	assert.False(t, programAssetMatches(&a, "other.acme.com", ""))
}

func TestProgramHandle(t *testing.T) {
	linked := &model.Authorization{
		Method:   model.VerificationMethodProgram,
		Evidence: map[string]interface{}{"platform": "hackerone", "handle": "acme"},
	}
	plat, h, ok := programHandle(linked)
	assert.True(t, ok)
	assert.Equal(t, "hackerone", plat)
	assert.Equal(t, "acme", h)

	// legacy free-text program auth (no handle) is NOT program-linked
	legacy := &model.Authorization{
		Method:   model.VerificationMethodProgram,
		Evidence: map[string]interface{}{"platform": "hackerone", "name": "Acme"},
	}
	_, _, ok = programHandle(legacy)
	assert.False(t, ok)

	// a manual/other auth is never program-linked
	manual := &model.Authorization{Method: model.VerificationMethodManual, Evidence: map[string]interface{}{"handle": "x"}}
	_, _, ok = programHandle(manual)
	assert.False(t, ok)
}
