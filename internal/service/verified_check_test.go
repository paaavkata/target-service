package service_test

import (
	"context"
	"target-service/internal/model"
	"target-service/internal/service"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ptrInt64(v int64) *int64 { return &v }

func checkVerified(t *testing.T, target *model.Target, auths []model.Authorization, userID *int64) *model.VerifiedCheckResponse {
	t.Helper()
	res, err := makeSvc(target, auths).CheckVerified(context.Background(), target.UID, userID)
	require.NoError(t, err)
	return res
}

func TestCheckVerified_OK(t *testing.T) {
	target := verifiedTarget("uid-1", model.TargetKindDomain, "example.test", "example.test")
	target.UserID = 5
	res := checkVerified(t, target, []model.Authorization{activeAuth(model.ScopeKindRegistrableDomain, "example.test")}, ptrInt64(5))
	assert.True(t, res.Verified)
	assert.Equal(t, service.VerifiedReasonOK, res.Reason)
	// scan-service points its tasks at the target from these fields.
	assert.Equal(t, model.TargetKindDomain, res.Kind)
	assert.Equal(t, "example.test", res.Value)
	assert.Equal(t, "example.test", res.RegistrableDomain)
}

func TestCheckVerified_SubdomainTarget_ReturnsHostAndRegistrableDomain(t *testing.T) {
	target := verifiedTarget("uid-1", model.TargetKindDomain, "app.example.test", "example.test")
	target.UserID = 5
	res := checkVerified(t, target, []model.Authorization{activeAuth(model.ScopeKindRegistrableDomain, "example.test")}, ptrInt64(5))
	require.True(t, res.Verified)
	assert.Equal(t, "app.example.test", res.Value)
	assert.Equal(t, "example.test", res.RegistrableDomain)
}

func TestCheckVerified_NoUserID_SkipsOwnership(t *testing.T) {
	target := verifiedTarget("uid-1", model.TargetKindDomain, "example.test", "example.test")
	target.UserID = 5
	res := checkVerified(t, target, []model.Authorization{activeAuth(model.ScopeKindRegistrableDomain, "example.test")}, nil)
	assert.True(t, res.Verified)
}

func TestCheckVerified_OwnerMismatch(t *testing.T) {
	target := verifiedTarget("uid-1", model.TargetKindDomain, "example.test", "example.test")
	target.UserID = 5
	res := checkVerified(t, target, []model.Authorization{activeAuth(model.ScopeKindRegistrableDomain, "example.test")}, ptrInt64(6))
	assert.False(t, res.Verified, "another user's verified target must not be scannable")
	assert.Equal(t, service.VerifiedReasonNotOwner, res.Reason)
	assert.Empty(t, res.Value, "a non-owner must not learn the target's host")
	assert.Empty(t, res.Kind)
}

func TestCheckVerified_ExpiredAuthorization(t *testing.T) {
	target := verifiedTarget("uid-1", model.TargetKindDomain, "example.test", "example.test")
	target.UserID = 5
	expired := activeAuth(model.ScopeKindRegistrableDomain, "example.test")
	past := time.Now().Add(-time.Hour)
	expired.ExpiresAt = &past
	res := checkVerified(t, target, []model.Authorization{expired}, ptrInt64(5))
	assert.False(t, res.Verified, "status=verified alone is not enough — the authorization must be current")
	assert.Equal(t, service.VerifiedReasonNoActive, res.Reason)
}

func TestCheckVerified_RevokedStatus(t *testing.T) {
	target := verifiedTarget("uid-1", model.TargetKindDomain, "example.test", "example.test")
	target.Status = model.TargetStatusRevoked
	res := checkVerified(t, target, []model.Authorization{activeAuth(model.ScopeKindRegistrableDomain, "example.test")}, nil)
	assert.False(t, res.Verified)
	assert.Equal(t, service.VerifiedReasonNotVerified, res.Reason)
}

func TestCheckVerified_MissingTarget_IsNotAnError(t *testing.T) {
	target := verifiedTarget("uid-1", model.TargetKindDomain, "example.test", "example.test")
	res, err := makeSvc(target, nil).CheckVerified(context.Background(), "does-not-exist", ptrInt64(5))
	require.NoError(t, err, "scan-service treats non-200 as an outage; a miss must be a 200 denial")
	assert.False(t, res.Verified)
	assert.Equal(t, service.VerifiedReasonNotFound, res.Reason)
}
