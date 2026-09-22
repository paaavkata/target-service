package handler_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"target-service/internal/handler"
	"target-service/internal/model"
	"target-service/internal/repository"
	"target-service/internal/service"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createOKSvc succeeds on CreateTarget (customer path).
type createOKSvc struct {
	fakeTargetSvc
	created bool
}

func (f *createOKSvc) CreateTarget(_ context.Context, _ int64, req *model.CreateTargetRequest) (*model.TargetDetailDTO, error) {
	f.created = true
	return &model.TargetDetailDTO{}, nil
}

type capCountRepo struct {
	repository.TargetRepositoryInterface
	n int64
}

func (r capCountRepo) Count(context.Context, model.SearchParameters) (int64, error) { return r.n, nil }

type capLimits map[string]int

func (l capLimits) MaxTargets(_ context.Context, plan string) (int, error) { return l[plan], nil }

func newCapApp(svc *createOKSvc, existing int64) *echo.Echo {
	e := echo.New()
	capSvc := service.NewTargetCapService(capCountRepo{n: existing}, capLimits{"free": 1, "pro": 10}, nil)
	h := handler.NewTargetHandler(svc, handler.NewHandlerHelper(validator.New())).WithTargetCap(capSvc)
	h.RegisterRoutes(e.Group("/v1/targets"))
	return e
}

const createBody = `{"kind":"domain","value":"example.test"}`

func TestCreateTarget_FreePlanSecondTarget_403(t *testing.T) {
	svc := &createOKSvc{}
	rec, env := do(newCapApp(svc, 1), http.MethodPost, "/v1/targets", createBody,
		map[string]string{"X-User-Id": "7", "X-User-Plan": "free"})
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.False(t, svc.created)
	var data handler.PlanUpgradeRequiredData
	require.NoError(t, json.Unmarshal(env.Data, &data))
	assert.Equal(t, handler.PlanUpgradeRequiredData{Code: "plan_upgrade_required", Plan: "free", MaxTargets: 1}, data)
	assert.Contains(t, env.Message, "Upgrade")
}

func TestCreateTarget_ProPlanUnderCap_201(t *testing.T) {
	svc := &createOKSvc{}
	rec, _ := do(newCapApp(svc, 1), http.MethodPost, "/v1/targets", createBody,
		map[string]string{"X-User-Id": "7", "X-User-Plan": "pro"})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.True(t, svc.created)
}

func TestCreateTarget_AdminBypassesCap(t *testing.T) {
	svc := &createOKSvc{}
	rec, _ := do(newCapApp(svc, 5), http.MethodPost, "/v1/targets", createBody,
		map[string]string{"X-User-Id": "7", "X-User-Plan": "free", "X-Is-Admin": "true"})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
}
