package handler_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"target-service/internal/handler"
	"target-service/internal/model"
	"target-service/internal/service"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeTargetSvc records admin calls; customer methods are never reached by
// the admin routes and fail loudly if they are.
type fakeTargetSvc struct {
	targets map[string]*model.TargetAdminDTO

	createdReq   *model.AdminCreateProgramTargetRequest
	createdAdmin int64
	createErr    error

	revokedUID    string
	revokedReason string
	revokedAdmin  int64

	authorizedReq *model.AdminAuthorizeTargetRequest
	deletedUID    string
	listParams    *model.SearchParameters
}

func (f *fakeTargetSvc) CreateTarget(context.Context, int64, *model.CreateTargetRequest) (*model.TargetDetailDTO, error) {
	return nil, errors.New("customer path must not be reached")
}
func (f *fakeTargetSvc) ListTargets(context.Context, int64, model.SearchParameters) ([]model.TargetDTO, error) {
	return nil, errors.New("customer path must not be reached")
}
func (f *fakeTargetSvc) GetTarget(context.Context, int64, string) (*model.TargetDetailDTO, error) {
	return nil, errors.New("customer path must not be reached")
}
func (f *fakeTargetSvc) TriggerVerification(context.Context, int64, string, *model.VerifyTargetRequest) (*model.TargetDetailDTO, error) {
	return nil, errors.New("customer path must not be reached")
}
func (f *fakeTargetSvc) DeleteTarget(context.Context, int64, string) error {
	return errors.New("customer path must not be reached")
}

func (f *fakeTargetSvc) ListAll(_ context.Context, params model.SearchParameters) ([]model.TargetAdminDTO, int64, error) {
	f.listParams = &params
	out := []model.TargetAdminDTO{}
	for _, t := range f.targets {
		out = append(out, *t)
	}
	return out, int64(len(out)), nil
}
func (f *fakeTargetSvc) GetAnyByUID(_ context.Context, uid string) (*model.TargetAdminDTO, error) {
	if t, ok := f.targets[uid]; ok {
		return t, nil
	}
	return nil, service.ErrTargetNotFound
}
func (f *fakeTargetSvc) CreateProgramTarget(_ context.Context, adminID int64, req *model.AdminCreateProgramTargetRequest) (*model.TargetAdminDTO, error) {
	f.createdReq, f.createdAdmin = req, adminID
	if f.createErr != nil {
		return nil, f.createErr
	}
	owner := req.UserID
	if owner == 0 {
		owner = adminID
	}
	now := time.Now()
	exp := now.Add(90 * 24 * time.Hour)
	return &model.TargetAdminDTO{
		UID: "uid-new", UserID: owner, Kind: req.Kind, Value: strings.ToLower(strings.TrimSpace(req.Value)),
		Status: model.TargetStatusVerified, Source: model.TargetSourceProgram,
		Authorization: &model.AuthorizationDTO{
			UID: "auth-new", Method: model.VerificationMethodProgram, VerifiedAt: &now, ExpiresAt: &exp, AttestedBy: &adminID,
			Evidence: map[string]interface{}{"platform": req.Program.Platform, "name": req.Program.Name, "url": req.Program.URL},
		},
	}, nil
}
func (f *fakeTargetSvc) AuthorizeManually(_ context.Context, _ int64, uid string, req *model.AdminAuthorizeTargetRequest) (*model.TargetAdminDTO, error) {
	t, ok := f.targets[uid]
	if !ok {
		return nil, service.ErrTargetNotFound
	}
	f.authorizedReq = req
	t.Status = model.TargetStatusVerified
	return t, nil
}
func (f *fakeTargetSvc) Revoke(_ context.Context, adminID int64, uid string, reason string) (*model.TargetAdminDTO, error) {
	t, ok := f.targets[uid]
	if !ok {
		return nil, service.ErrTargetNotFound
	}
	f.revokedUID, f.revokedReason, f.revokedAdmin = uid, reason, adminID
	t.Status = model.TargetStatusRevoked
	return t, nil
}
func (f *fakeTargetSvc) DeleteAny(_ context.Context, _ int64, uid string) error {
	if _, ok := f.targets[uid]; !ok {
		return service.ErrTargetNotFound
	}
	f.deletedUID = uid
	delete(f.targets, uid)
	return nil
}
func (f *fakeTargetSvc) Stats(context.Context) (*model.AdminStatsResponse, error) {
	return &model.AdminStatsResponse{Total: 1, ByStatus: map[string]int64{"verified": 1}, BySource: map[string]int64{"program": 1}}, nil
}

// newAdminApp wires the admin handler exactly as main.go does (group + RequireAdmin).
func newAdminApp(svc *fakeTargetSvc) *echo.Echo {
	e := echo.New()
	helper := handler.NewHandlerHelper(validator.New())
	handler.NewAdminHandler(svc, helper).RegisterRoutes(e.Group("/v1/admin", handler.RequireAdmin))
	return e
}

type envelope struct {
	Status  string          `json:"status"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func do(e *echo.Echo, method, path, body string, headers map[string]string) (*httptest.ResponseRecorder, envelope) {
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != "" {
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	var env envelope
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	return rec, env
}

var adminHeaders = map[string]string{"X-Is-Admin": "true", "X-User-Id": "42"}

func seededSvc() *fakeTargetSvc {
	return &fakeTargetSvc{targets: map[string]*model.TargetAdminDTO{
		"uid-1": {UID: "uid-1", UserID: 7, Kind: "domain", Value: "example.test", Status: model.TargetStatusVerified, Source: model.TargetSourceCustomer},
	}}
}

// ---------------------------------------------------------------------------
// 403 gate
// ---------------------------------------------------------------------------

func TestAdminGate_NoHeaders_403(t *testing.T) {
	svc := seededSvc()
	e := newAdminApp(svc)
	for _, rt := range []struct{ method, path string }{
		{http.MethodGet, "/v1/admin/targets"},
		{http.MethodGet, "/v1/admin/targets/uid-1"},
		{http.MethodPost, "/v1/admin/targets"},
		{http.MethodPost, "/v1/admin/targets/uid-1/authorize"},
		{http.MethodPost, "/v1/admin/targets/uid-1/revoke"},
		{http.MethodDelete, "/v1/admin/targets/uid-1"},
		{http.MethodGet, "/v1/admin/stats"},
	} {
		rec, env := do(e, rt.method, rt.path, "", map[string]string{"X-User-Id": "42"})
		assert.Equal(t, http.StatusForbidden, rec.Code, "%s %s", rt.method, rt.path)
		assert.Equal(t, "error", env.Status)
		assert.Equal(t, "admin only", env.Message)
	}
	assert.Nil(t, svc.listParams, "service must not be reached without admin identity")
	assert.Empty(t, svc.revokedUID)
}

func TestAdminGate_ClientCannotSelfDeclareViaBodyOrQuery(t *testing.T) {
	e := newAdminApp(seededSvc())
	rec, _ := do(e, http.MethodGet, "/v1/admin/stats?is_admin=true&X-Is-Admin=true", "", map[string]string{"X-Is-Admin": "false"})
	assert.Equal(t, http.StatusForbidden, rec.Code)
	rec, _ = do(e, http.MethodGet, "/v1/admin/stats", "", map[string]string{"X-User-Roles": "viewer,editor"})
	assert.Equal(t, http.StatusForbidden, rec.Code, "non-admin roles do not pass")
}

func TestAdminGate_XIsAdminTrue_Passes(t *testing.T) {
	e := newAdminApp(seededSvc())
	rec, env := do(e, http.MethodGet, "/v1/admin/stats", "", map[string]string{"X-Is-Admin": "true"})
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "success", env.Status)
	rec, _ = do(e, http.MethodGet, "/v1/admin/stats", "", map[string]string{"X-Is-Admin": " TRUE "})
	assert.Equal(t, http.StatusOK, rec.Code, "case/whitespace-insensitive like identity-service")
}

func TestAdminGate_OwnerRole_Passes(t *testing.T) {
	e := newAdminApp(seededSvc())
	rec, _ := do(e, http.MethodGet, "/v1/admin/stats", "", map[string]string{"X-User-Roles": "owner"})
	assert.Equal(t, http.StatusOK, rec.Code)
	rec, _ = do(e, http.MethodGet, "/v1/admin/stats", "", map[string]string{"X-User-Roles": "viewer, Admin"})
	assert.Equal(t, http.StatusOK, rec.Code, "admin anywhere in the comma list passes")
}

// ---------------------------------------------------------------------------
// List / get
// ---------------------------------------------------------------------------

func TestAdminList_ShapeAndFilters(t *testing.T) {
	svc := seededSvc()
	e := newAdminApp(svc)
	rec, env := do(e, http.MethodGet, "/v1/admin/targets?user_id=7&status=verified&source=customer&q=exam&page=2&page_size=500", "", adminHeaders)
	require.Equal(t, http.StatusOK, rec.Code)
	var data model.AdminTargetListResponse
	require.NoError(t, json.Unmarshal(env.Data, &data))
	assert.Equal(t, int64(1), data.Total)
	assert.Equal(t, 2, data.Page)
	assert.Equal(t, 200, data.PageSize, "page_size is capped at 200")
	require.Len(t, data.Items, 1)
	assert.Equal(t, int64(7), data.Items[0].UserID, "admin DTOs always carry user_id")

	require.NotNil(t, svc.listParams)
	assert.Equal(t, int64(7), *svc.listParams.UserID)
	assert.Equal(t, "verified", *svc.listParams.Status)
	assert.Equal(t, "customer", *svc.listParams.Source)
	assert.Equal(t, "exam", *svc.listParams.Query)
	assert.Equal(t, 200, svc.listParams.PageSize)
}

func TestAdminList_Defaults(t *testing.T) {
	svc := seededSvc()
	e := newAdminApp(svc)
	rec, env := do(e, http.MethodGet, "/v1/admin/targets", "", adminHeaders)
	require.Equal(t, http.StatusOK, rec.Code)
	var data model.AdminTargetListResponse
	require.NoError(t, json.Unmarshal(env.Data, &data))
	assert.Equal(t, 1, data.Page)
	assert.Equal(t, 50, data.PageSize)
	assert.Nil(t, svc.listParams.UserID)
	assert.Nil(t, svc.listParams.Query)
}

func TestAdminList_UnknownFilterValues_400(t *testing.T) {
	svc := seededSvc()
	e := newAdminApp(svc)
	for _, q := range []string{"status=bogus", "source=bogus", "user_id=abc", "user_id=0"} {
		rec, env := do(e, http.MethodGet, "/v1/admin/targets?"+q, "", adminHeaders)
		assert.Equal(t, http.StatusBadRequest, rec.Code, q)
		assert.Equal(t, "error", env.Status)
	}
	assert.Nil(t, svc.listParams)
}

func TestAdminGet_NotFound_404(t *testing.T) {
	e := newAdminApp(seededSvc())
	rec, env := do(e, http.MethodGet, "/v1/admin/targets/nope", "", adminHeaders)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, "error", env.Status)
	rec, _ = do(e, http.MethodGet, "/v1/admin/targets/uid-1", "", adminHeaders)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ---------------------------------------------------------------------------
// Create program target
// ---------------------------------------------------------------------------

const validProgramBody = `{"kind":"domain","value":"Example.TEST","label":"Acme (HackerOne)",
 "program":{"platform":"hackerone","name":"Acme","url":"https://hackerone.com/acme","policy_url":"https://hackerone.com/acme/policy","scope_notes":"*.example.test","authorized_days":90}}`

func TestAdminCreate_HappyPath_201(t *testing.T) {
	svc := seededSvc()
	e := newAdminApp(svc)
	rec, env := do(e, http.MethodPost, "/v1/admin/targets", validProgramBody, adminHeaders)
	require.Equal(t, http.StatusCreated, rec.Code, env.Message)
	assert.Equal(t, "success", env.Status)

	var dto model.TargetAdminDTO
	require.NoError(t, json.Unmarshal(env.Data, &dto))
	assert.Equal(t, int64(42), dto.UserID, "user_id defaults to the admin's X-User-Id")
	assert.Equal(t, model.TargetStatusVerified, dto.Status)
	assert.Equal(t, model.TargetSourceProgram, dto.Source)
	require.NotNil(t, dto.Authorization)
	assert.Equal(t, model.VerificationMethodProgram, dto.Authorization.Method)
	assert.Equal(t, "hackerone", dto.Authorization.Evidence["platform"])
	assert.Equal(t, int64(42), *dto.Authorization.AttestedBy)

	require.NotNil(t, svc.createdReq)
	assert.Equal(t, int64(42), svc.createdAdmin)
	assert.Equal(t, "Acme (HackerOne)", svc.createdReq.Label)
	assert.Equal(t, 90, svc.createdReq.Program.AuthorizedDays)
}

func TestAdminCreate_Validation_400(t *testing.T) {
	cases := map[string]string{
		"missing program.platform": `{"kind":"domain","value":"example.test","program":{"name":"Acme","url":"https://hackerone.com/acme"}}`,
		"bad platform":             `{"kind":"domain","value":"example.test","program":{"platform":"h1","name":"Acme","url":"https://hackerone.com/acme"}}`,
		"missing program.name":     `{"kind":"domain","value":"example.test","program":{"platform":"hackerone","url":"https://hackerone.com/acme"}}`,
		"missing program.url":      `{"kind":"domain","value":"example.test","program":{"platform":"hackerone","name":"Acme"}}`,
		"non-url program.url":      `{"kind":"domain","value":"example.test","program":{"platform":"hackerone","name":"Acme","url":"not a url"}}`,
		"authorized_days > 365":    `{"kind":"domain","value":"example.test","program":{"platform":"hackerone","name":"Acme","url":"https://hackerone.com/acme","authorized_days":366}}`,
		"authorized_days negative": `{"kind":"domain","value":"example.test","program":{"platform":"hackerone","name":"Acme","url":"https://hackerone.com/acme","authorized_days":-1}}`,
		"bad kind":                 `{"kind":"asn","value":"AS123","program":{"platform":"hackerone","name":"Acme","url":"https://hackerone.com/acme"}}`,
		"missing value":            `{"kind":"domain","program":{"platform":"hackerone","name":"Acme","url":"https://hackerone.com/acme"}}`,
		"no program":               `{"kind":"domain","value":"example.test"}`,
		"malformed json":           `{"kind":`,
	}
	for name, body := range cases {
		svc := seededSvc()
		e := newAdminApp(svc)
		rec, env := do(e, http.MethodPost, "/v1/admin/targets", body, adminHeaders)
		assert.Equal(t, http.StatusBadRequest, rec.Code, name)
		assert.Equal(t, "error", env.Status, name)
		assert.Nil(t, svc.createdReq, "%s: service must not be called", name)
	}
}

func TestAdminCreate_EmptyBody_400(t *testing.T) {
	svc := seededSvc()
	e := newAdminApp(svc)
	rec, _ := do(e, http.MethodPost, "/v1/admin/targets", "", adminHeaders)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Nil(t, svc.createdReq)
}

func TestAdminCreate_MissingXUserId_400(t *testing.T) {
	svc := seededSvc()
	e := newAdminApp(svc)
	rec, _ := do(e, http.MethodPost, "/v1/admin/targets", validProgramBody, map[string]string{"X-Is-Admin": "true"})
	assert.Equal(t, http.StatusBadRequest, rec.Code, "the audit actor / default owner needs X-User-Id")
	assert.Nil(t, svc.createdReq)
}

func TestAdminCreate_Duplicate_409(t *testing.T) {
	svc := seededSvc()
	svc.createErr = service.ErrTargetExists
	e := newAdminApp(svc)
	rec, env := do(e, http.MethodPost, "/v1/admin/targets", validProgramBody, adminHeaders)
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "error", env.Status)
}

func TestAdminCreate_IPKind_422(t *testing.T) {
	svc := seededSvc()
	svc.createErr = service.ErrIPTargetsUnsupported
	e := newAdminApp(svc)
	body := `{"kind":"ip","value":"203.0.113.5","program":{"platform":"other","name":"X","url":"https://example.test/p"}}`
	rec, _ := do(e, http.MethodPost, "/v1/admin/targets", body, adminHeaders)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
}

// ---------------------------------------------------------------------------
// Authorize / revoke / delete
// ---------------------------------------------------------------------------

func TestAdminAuthorize_200(t *testing.T) {
	svc := seededSvc()
	svc.targets["uid-1"].Status = model.TargetStatusUnverified
	e := newAdminApp(svc)
	rec, env := do(e, http.MethodPost, "/v1/admin/targets/uid-1/authorize", `{"note":"contract on file","authorized_days":30}`, adminHeaders)
	require.Equal(t, http.StatusOK, rec.Code, env.Message)
	require.NotNil(t, svc.authorizedReq)
	assert.Equal(t, "contract on file", svc.authorizedReq.Note)
	assert.Equal(t, 30, svc.authorizedReq.AuthorizedDays)
	var dto model.TargetAdminDTO
	require.NoError(t, json.Unmarshal(env.Data, &dto))
	assert.Equal(t, model.TargetStatusVerified, dto.Status)
}

func TestAdminAuthorize_BadDays_400(t *testing.T) {
	svc := seededSvc()
	e := newAdminApp(svc)
	rec, _ := do(e, http.MethodPost, "/v1/admin/targets/uid-1/authorize", `{"authorized_days":1000}`, adminHeaders)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Nil(t, svc.authorizedReq)
}

func TestAdminRevoke_200(t *testing.T) {
	svc := seededSvc()
	e := newAdminApp(svc)
	rec, env := do(e, http.MethodPost, "/v1/admin/targets/uid-1/revoke", `{"reason":"  abuse report "}`, adminHeaders)
	require.Equal(t, http.StatusOK, rec.Code, env.Message)
	assert.Equal(t, "success", env.Status)
	assert.Equal(t, "uid-1", svc.revokedUID)
	assert.Equal(t, "abuse report", svc.revokedReason)
	assert.Equal(t, int64(42), svc.revokedAdmin, "actor is the admin's X-User-Id")
	var dto model.TargetAdminDTO
	require.NoError(t, json.Unmarshal(env.Data, &dto))
	assert.Equal(t, model.TargetStatusRevoked, dto.Status)
}

func TestAdminRevoke_NotFound_404(t *testing.T) {
	svc := seededSvc()
	e := newAdminApp(svc)
	rec, _ := do(e, http.MethodPost, "/v1/admin/targets/nope/revoke", `{"reason":"x"}`, adminHeaders)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Empty(t, svc.revokedUID)
}

func TestAdminRevoke_NonAdmin_403(t *testing.T) {
	svc := seededSvc()
	e := newAdminApp(svc)
	rec, env := do(e, http.MethodPost, "/v1/admin/targets/uid-1/revoke", `{"reason":"x"}`, map[string]string{"X-User-Id": "7"})
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "admin only", env.Message)
	assert.Empty(t, svc.revokedUID)
}

func TestAdminDelete_200_Then404(t *testing.T) {
	svc := seededSvc()
	e := newAdminApp(svc)
	rec, _ := do(e, http.MethodDelete, "/v1/admin/targets/uid-1", "", adminHeaders)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "uid-1", svc.deletedUID)
	rec, _ = do(e, http.MethodDelete, "/v1/admin/targets/uid-1", "", adminHeaders)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestAdminStats_Shape(t *testing.T) {
	e := newAdminApp(seededSvc())
	rec, env := do(e, http.MethodGet, "/v1/admin/stats", "", adminHeaders)
	require.Equal(t, http.StatusOK, rec.Code)
	var stats model.AdminStatsResponse
	require.NoError(t, json.Unmarshal(env.Data, &stats))
	assert.Equal(t, int64(1), stats.Total)
	assert.Equal(t, int64(1), stats.ByStatus["verified"])
	assert.Equal(t, int64(1), stats.BySource["program"])
}
