package handler_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"target-service/internal/handler"
	"target-service/internal/model"
	"target-service/internal/service"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeScopeSvc replays CheckVerified against a tiny ownership table so the
// route's contract (200 always, ?user_id= parsing, envelope shape) is what's
// under test; the decision logic itself is covered in service tests.
type fakeScopeSvc struct {
	owners   map[string]int64 // uid → owner
	lastUID  string
	lastUser *int64
	err      error
}

func (f *fakeScopeSvc) CheckScope(context.Context, *model.ScopeCheckRequest) (*model.ScopeCheckResponse, error) {
	return nil, errors.New("not used")
}
func (f *fakeScopeSvc) CheckVerified(_ context.Context, uid string, userID *int64) (*model.VerifiedCheckResponse, error) {
	f.lastUID, f.lastUser = uid, userID
	if f.err != nil {
		return nil, f.err
	}
	owner, ok := f.owners[uid]
	if !ok {
		return &model.VerifiedCheckResponse{Verified: false, Reason: service.VerifiedReasonNotFound}, nil
	}
	if userID != nil && *userID != owner {
		return &model.VerifiedCheckResponse{Verified: false, Reason: service.VerifiedReasonNotOwner}, nil
	}
	return &model.VerifiedCheckResponse{Verified: true, Reason: service.VerifiedReasonOK}, nil
}

type fakeAssetSvc struct{}

func (fakeAssetSvc) ListAssets(context.Context, int64, string) ([]model.AssetDTO, error) {
	return nil, errors.New("not used")
}
func (fakeAssetSvc) UpsertAssets(context.Context, string, *model.UpsertAssetsRequest) ([]model.AssetDTO, error) {
	return nil, errors.New("not used")
}

func newInternalApp(scope *fakeScopeSvc) *echo.Echo {
	e := echo.New()
	helper := handler.NewHandlerHelper(validator.New())
	handler.NewInternalHandler(scope, fakeAssetSvc{}, helper).RegisterRoutes(e.Group("/internal/v1"))
	return e
}

func verifiedData(t *testing.T, env envelope) model.VerifiedCheckResponse {
	t.Helper()
	var data model.VerifiedCheckResponse
	require.NoError(t, json.Unmarshal(env.Data, &data))
	return data
}

func TestInternalVerified_Owner_200True(t *testing.T) {
	scope := &fakeScopeSvc{owners: map[string]int64{"uid-1": 5}}
	e := newInternalApp(scope)
	rec, env := do(e, http.MethodGet, "/internal/v1/targets/uid-1/verified?user_id=5", "", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "success", env.Status)
	data := verifiedData(t, env)
	assert.True(t, data.Verified)
	assert.Equal(t, "verified", data.Reason)
	require.NotNil(t, scope.lastUser)
	assert.Equal(t, int64(5), *scope.lastUser)
}

func TestInternalVerified_OwnerMismatch_200False(t *testing.T) {
	e := newInternalApp(&fakeScopeSvc{owners: map[string]int64{"uid-1": 5}})
	rec, env := do(e, http.MethodGet, "/internal/v1/targets/uid-1/verified?user_id=6", "", nil)
	require.Equal(t, http.StatusOK, rec.Code, "a denial is a 200 — scan-service treats non-200 as an outage")
	data := verifiedData(t, env)
	assert.False(t, data.Verified)
	assert.Equal(t, "not_owner", data.Reason)
}

func TestInternalVerified_NoUserID_SkipsOwnership(t *testing.T) {
	scope := &fakeScopeSvc{owners: map[string]int64{"uid-1": 5}}
	e := newInternalApp(scope)
	rec, env := do(e, http.MethodGet, "/internal/v1/targets/uid-1/verified", "", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, verifiedData(t, env).Verified)
	assert.Nil(t, scope.lastUser)
}

func TestInternalVerified_Missing_200NotFound(t *testing.T) {
	e := newInternalApp(&fakeScopeSvc{owners: map[string]int64{}})
	rec, env := do(e, http.MethodGet, "/internal/v1/targets/ghost/verified?user_id=5", "", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	data := verifiedData(t, env)
	assert.False(t, data.Verified)
	assert.Equal(t, "not_found", data.Reason)
}

func TestInternalVerified_BadUserID_400(t *testing.T) {
	scope := &fakeScopeSvc{owners: map[string]int64{"uid-1": 5}}
	e := newInternalApp(scope)
	for _, q := range []string{"user_id=abc", "user_id=0", "user_id=-1"} {
		rec, env := do(e, http.MethodGet, "/internal/v1/targets/uid-1/verified?"+q, "", nil)
		assert.Equal(t, http.StatusBadRequest, rec.Code, q)
		assert.Equal(t, "error", env.Status)
	}
	assert.Empty(t, scope.lastUID, "service not reached on malformed user_id")
}

func TestInternalVerified_ServiceError_500(t *testing.T) {
	e := newInternalApp(&fakeScopeSvc{err: errors.New("db down")})
	rec, env := do(e, http.MethodGet, "/internal/v1/targets/uid-1/verified?user_id=5", "", nil)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, "error", env.Status)
}
