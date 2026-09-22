package service_test

import (
	"context"
	"errors"
	"target-service/internal/model"
	"target-service/internal/repository"
	"target-service/internal/service"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// In-memory fakes for the admin flows (no DB, nil audit producer — emit is nil-safe).
// ---------------------------------------------------------------------------

type memTargetRepo struct {
	fakeTargetRepo
	nextID   int64
	byUID    map[string]*model.Target
	statuses map[int64]string
	deleted  []string
}

func newMemTargetRepo(seed ...*model.Target) *memTargetRepo {
	r := &memTargetRepo{nextID: 100, byUID: map[string]*model.Target{}, statuses: map[int64]string{}}
	for _, t := range seed {
		r.byUID[t.UID] = t
	}
	r.fakeTargetRepo.byUID = r.byUID
	return r
}

func (r *memTargetRepo) CreateProgram(_ context.Context, userID int64, kind, value, label string) (*model.Target, error) {
	for _, t := range r.byUID {
		if t.UserID == userID && t.Kind == kind && t.Value == value {
			return nil, repository.ErrDuplicateTarget
		}
	}
	r.nextID++
	rd := "example.test"
	var lbl *string
	if label != "" {
		lbl = &label
	}
	t := &model.Target{
		ID: r.nextID, UID: "uid-program", UserID: userID, Kind: kind, Value: value,
		RegistrableDomain: &rd, Status: model.TargetStatusVerified, Source: model.TargetSourceProgram,
		Label: lbl, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	r.byUID[t.UID] = t
	return t, nil
}
func (r *memTargetRepo) GetByUIDInternal(_ context.Context, uid string) (*model.Target, error) {
	if t, ok := r.byUID[uid]; ok {
		return t, nil
	}
	return nil, repository.ErrNotFound
}
func (r *memTargetRepo) UpdateStatus(_ context.Context, id int64, status string) error {
	r.statuses[id] = status
	return nil
}
func (r *memTargetRepo) DeleteByUID(_ context.Context, uid string) error {
	r.deleted = append(r.deleted, uid)
	delete(r.byUID, uid)
	return nil
}
func (r *memTargetRepo) CountByStatus(_ context.Context) (map[string]int64, error) {
	return map[string]int64{"verified": 2, "revoked": 1}, nil
}
func (r *memTargetRepo) CountBySource(_ context.Context) (map[string]int64, error) {
	return map[string]int64{"program": 3}, nil
}

type memAuthRepo struct {
	fakeAuthRepo
	created  []*model.Authorization
	latest   map[int64]*model.Authorization
	verified map[int64]time.Time
	evidence map[int64]map[string]interface{}
	expired  []int64
}

func newMemAuthRepo() *memAuthRepo {
	return &memAuthRepo{latest: map[int64]*model.Authorization{}, verified: map[int64]time.Time{}, evidence: map[int64]map[string]interface{}{}}
}
func (r *memAuthRepo) Create(_ context.Context, auth *model.Authorization) (*model.Authorization, error) {
	out := *auth
	out.ID = int64(len(r.created) + 1)
	out.UID = "auth-" + out.Method
	r.created = append(r.created, &out)
	r.latest[out.TargetID] = &out
	return &out, nil
}
func (r *memAuthRepo) GetByTargetID(_ context.Context, targetID int64) (*model.Authorization, error) {
	if a, ok := r.latest[targetID]; ok {
		return a, nil
	}
	return nil, repository.ErrNotFound
}
func (r *memAuthRepo) MarkVerified(_ context.Context, id int64, expiresAt time.Time, evidence map[string]interface{}) error {
	r.verified[id] = expiresAt
	r.evidence[id] = evidence
	return nil
}
func (r *memAuthRepo) ExpireActiveAuthorizations(_ context.Context, targetID int64) (int64, error) {
	r.expired = append(r.expired, targetID)
	return 2, nil
}

func makeAdminSvc(tr *memTargetRepo, ar *memAuthRepo) service.TargetServiceInterface {
	return service.NewTargetService(tr, ar, nil, service.NewVerificationService(ar), nil, "scantinel")
}

func programReq() *model.AdminCreateProgramTargetRequest {
	return &model.AdminCreateProgramTargetRequest{
		Kind: model.TargetKindDomain, Value: "  Example.TEST ", Label: "Acme (HackerOne)",
		Program: model.ProgramEvidence{
			Platform: model.ProgramPlatformHackerOne, Name: "Acme",
			URL: "https://hackerone.com/acme", PolicyURL: "https://hackerone.com/acme/policy",
			ScopeNotes: "*.example.test", AuthorizedDays: 30,
		},
	}
}

// ---------------------------------------------------------------------------
// CreateProgramTarget
// ---------------------------------------------------------------------------

func TestCreateProgramTarget_HappyPath(t *testing.T) {
	tr, ar := newMemTargetRepo(), newMemAuthRepo()
	svc := makeAdminSvc(tr, ar)

	before := time.Now()
	dto, err := svc.CreateProgramTarget(context.Background(), 42, programReq())
	require.NoError(t, err)
	require.NotNil(t, dto)

	assert.Equal(t, int64(42), dto.UserID, "user_id defaults to the admin's own id")
	assert.Equal(t, model.TargetStatusVerified, dto.Status)
	assert.Equal(t, model.TargetSourceProgram, dto.Source)
	require.NotNil(t, dto.Label)
	assert.Equal(t, "Acme (HackerOne)", *dto.Label)

	require.Len(t, ar.created, 1, "exactly one authorization row")
	auth := ar.created[0]
	assert.Equal(t, model.VerificationMethodProgram, auth.Method)
	assert.Equal(t, "", auth.Token)
	assert.Equal(t, model.ScopeKindRegistrableDomain, auth.ScopeKind)
	assert.Equal(t, "example.test", auth.ScopeValue, "scope comes from scopeForTarget (eTLD+1)")
	require.NotNil(t, auth.VerifiedAt)
	require.NotNil(t, auth.ExpiresAt)
	assert.WithinDuration(t, before.Add(30*24*time.Hour), *auth.ExpiresAt, 5*time.Second)
	require.NotNil(t, auth.AttestedBy)
	assert.Equal(t, int64(42), *auth.AttestedBy)
	assert.Equal(t, "hackerone", auth.Evidence["platform"])
	assert.Equal(t, "https://hackerone.com/acme", auth.Evidence["url"])

	require.NotNil(t, dto.Authorization)
	assert.Equal(t, model.VerificationMethodProgram, dto.Authorization.Method)
	assert.Equal(t, "Acme", dto.Authorization.Evidence["name"])
	assert.Equal(t, int64(42), *dto.Authorization.AttestedBy)
}

func TestCreateProgramTarget_ExplicitOwnerAndDefaultDays(t *testing.T) {
	tr, ar := newMemTargetRepo(), newMemAuthRepo()
	svc := makeAdminSvc(tr, ar)

	req := programReq()
	req.UserID = 7
	req.Program.AuthorizedDays = 0
	dto, err := svc.CreateProgramTarget(context.Background(), 42, req)
	require.NoError(t, err)
	assert.Equal(t, int64(7), dto.UserID)
	assert.Equal(t, int64(42), *ar.created[0].AttestedBy, "attested_by is always the admin")
	assert.WithinDuration(t, time.Now().Add(90*24*time.Hour), *ar.created[0].ExpiresAt, 5*time.Second, "authorized_days defaults to 90")
}

func TestCreateProgramTarget_IPKind_RefusedBeforePersist(t *testing.T) {
	tr, ar := newMemTargetRepo(), newMemAuthRepo()
	svc := makeAdminSvc(tr, ar)

	req := programReq()
	req.Kind = model.TargetKindCIDR
	req.Value = "203.0.113.0/24"
	dto, err := svc.CreateProgramTarget(context.Background(), 42, req)
	require.Error(t, err)
	assert.ErrorIs(t, err, service.ErrIPTargetsUnsupported, "admin path shares the ip/cidr hard-disable")
	assert.Nil(t, dto)
	assert.Empty(t, tr.byUID, "nothing persisted")
	assert.Empty(t, ar.created)
}

func TestCreateProgramTarget_Duplicate(t *testing.T) {
	tr, ar := newMemTargetRepo(), newMemAuthRepo()
	svc := makeAdminSvc(tr, ar)

	_, err := svc.CreateProgramTarget(context.Background(), 42, programReq())
	require.NoError(t, err)
	_, err = svc.CreateProgramTarget(context.Background(), 42, programReq())
	require.Error(t, err)
	assert.ErrorIs(t, err, service.ErrTargetExists)
}

// ---------------------------------------------------------------------------
// AuthorizeManually
// ---------------------------------------------------------------------------

func TestAuthorizeManually_PendingChallengeConfirmedInPlace(t *testing.T) {
	target := verifiedTarget("uid-1", model.TargetKindDomain, "example.test", "example.test")
	target.Status = model.TargetStatusUnverified
	tr, ar := newMemTargetRepo(target), newMemAuthRepo()
	pending := &model.Authorization{ID: 9, UID: "auth-pending", TargetID: target.ID, Method: model.VerificationMethodEmail, Token: "tok"}
	ar.latest[target.ID] = pending
	svc := makeAdminSvc(tr, ar)

	dto, err := svc.AuthorizeManually(context.Background(), 42, "uid-1", &model.AdminAuthorizeTargetRequest{Note: "confirmed by phone", AuthorizedDays: 10})
	require.NoError(t, err)
	assert.Empty(t, ar.created, "no new row when a pending challenge exists")
	exp, ok := ar.verified[9]
	require.True(t, ok, "the pending row is marked verified")
	assert.WithinDuration(t, time.Now().Add(10*24*time.Hour), exp, 5*time.Second)
	assert.Equal(t, "confirmed by phone", ar.evidence[9]["note"])
	assert.Equal(t, model.TargetStatusVerified, tr.statuses[target.ID])
	assert.Equal(t, model.TargetStatusVerified, dto.Status)
	assert.Equal(t, model.VerificationMethodEmail, dto.Authorization.Method)
}

func TestAuthorizeManually_NoPending_InsertsManualRow(t *testing.T) {
	target := verifiedTarget("uid-1", model.TargetKindDomain, "example.test", "example.test")
	target.Status = model.TargetStatusUnverified
	tr, ar := newMemTargetRepo(target), newMemAuthRepo()
	svc := makeAdminSvc(tr, ar)

	dto, err := svc.AuthorizeManually(context.Background(), 42, "uid-1", &model.AdminAuthorizeTargetRequest{Note: "contract on file"})
	require.NoError(t, err)
	require.Len(t, ar.created, 1)
	a := ar.created[0]
	assert.Equal(t, model.VerificationMethodManual, a.Method)
	assert.Equal(t, "contract on file", a.Evidence["note"])
	assert.NotNil(t, a.VerifiedAt)
	assert.Equal(t, int64(42), *a.AttestedBy)
	assert.Equal(t, model.TargetStatusVerified, tr.statuses[target.ID])
	assert.Equal(t, model.VerificationMethodManual, dto.Authorization.Method)
}

func TestAuthorizeManually_NotFound(t *testing.T) {
	svc := makeAdminSvc(newMemTargetRepo(), newMemAuthRepo())
	_, err := svc.AuthorizeManually(context.Background(), 42, "nope", &model.AdminAuthorizeTargetRequest{})
	assert.ErrorIs(t, err, service.ErrTargetNotFound)
}

// ---------------------------------------------------------------------------
// Revoke / DeleteAny / Stats
// ---------------------------------------------------------------------------

func TestRevoke_ExpiresAuthorizationsAndSetsStatus(t *testing.T) {
	target := verifiedTarget("uid-1", model.TargetKindDomain, "example.test", "example.test")
	tr, ar := newMemTargetRepo(target), newMemAuthRepo()
	svc := makeAdminSvc(tr, ar)

	dto, err := svc.Revoke(context.Background(), 42, "uid-1", "customer complaint")
	require.NoError(t, err)
	assert.Equal(t, []int64{target.ID}, ar.expired, "kill switch expires active authorizations")
	assert.Equal(t, model.TargetStatusRevoked, tr.statuses[target.ID])
	assert.Equal(t, model.TargetStatusRevoked, dto.Status)
}

func TestDeleteAny_RemovesRegardlessOfOwner(t *testing.T) {
	target := verifiedTarget("uid-1", model.TargetKindDomain, "example.test", "example.test")
	target.UserID = 999
	tr, ar := newMemTargetRepo(target), newMemAuthRepo()
	svc := makeAdminSvc(tr, ar)

	require.NoError(t, svc.DeleteAny(context.Background(), 42, "uid-1"))
	assert.Equal(t, []string{"uid-1"}, tr.deleted)
	assert.ErrorIs(t, svc.DeleteAny(context.Background(), 42, "uid-1"), service.ErrTargetNotFound)
}

func TestStats_FillsKnownKeys(t *testing.T) {
	svc := makeAdminSvc(newMemTargetRepo(), newMemAuthRepo())
	stats, err := svc.Stats(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(3), stats.Total)
	assert.Equal(t, int64(2), stats.ByStatus["verified"])
	assert.Equal(t, int64(0), stats.ByStatus["unverified"])
	assert.Equal(t, int64(3), stats.BySource["program"])
	assert.Equal(t, int64(0), stats.BySource["customer"])
}

// Sanity: the repo sentinel is what the service maps to ErrTargetExists.
func TestErrDuplicateTarget_IsDistinct(t *testing.T) {
	assert.False(t, errors.Is(repository.ErrDuplicateTarget, repository.ErrNotFound))
}

// GetByUID is the customer-scoped lookup used by TriggerVerification / GetTarget.
func (r *memTargetRepo) GetByUID(_ context.Context, userID int64, uid string) (*model.Target, error) {
	if t, ok := r.byUID[uid]; ok && t.UserID == userID {
		return t, nil
	}
	return nil, repository.ErrNotFound
}

// A customer must not be able to demote an admin-authorized (program) target by running
// the ownership challenge on it: there is no challenge token, so RunCheck would fail and
// the target would be stuck unverified.
func TestTriggerVerification_ProgramTargetIsRefusedWithoutStatusChange(t *testing.T) {
	tr, ar := newMemTargetRepo(), newMemAuthRepo()
	svc := makeAdminSvc(tr, ar)
	created, err := svc.CreateProgramTarget(context.Background(), 42, programReq())
	require.NoError(t, err)

	_, err = svc.TriggerVerification(context.Background(), created.UserID, created.UID, &model.VerifyTargetRequest{Method: model.VerificationMethodDNSTXT})
	require.ErrorIs(t, err, service.ErrTargetAdminAuthorized)

	// No status transition was written (neither "verifying" nor "unverified").
	assert.Empty(t, tr.statuses)
	assert.Equal(t, model.TargetStatusVerified, tr.byUID[created.UID].Status)
}

// The customer detail projection must not expose the admin's evidence / attestation.
func TestGetTarget_CustomerDTOHidesAdminEvidence(t *testing.T) {
	tr, ar := newMemTargetRepo(), newMemAuthRepo()
	svc := makeAdminSvc(tr, ar)
	created, err := svc.CreateProgramTarget(context.Background(), 42, programReq())
	require.NoError(t, err)
	require.NotNil(t, created.Authorization.Evidence, "admin DTO carries evidence")

	dto, err := svc.GetTarget(context.Background(), created.UserID, created.UID)
	require.NoError(t, err)
	require.NotNil(t, dto.Authorization)
	assert.Equal(t, model.VerificationMethodProgram, dto.Authorization.Method)
	assert.Nil(t, dto.Authorization.Evidence)
	assert.Nil(t, dto.Authorization.AttestedBy)
}
