package service_test

import (
	"context"
	"target-service/internal/model"
	"target-service/internal/service"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeCreateTargetRepo reuses the scope-test fake but supports Create, so
// CreateTarget flows can be exercised. If Create is reached for a refused
// kind, `created` is the smoking gun.
type fakeCreateTargetRepo struct {
	fakeTargetRepo
	created *model.Target
}

func (r *fakeCreateTargetRepo) Create(_ context.Context, userID int64, req *model.CreateTargetRequest) (*model.Target, error) {
	rd := "example.test"
	t := &model.Target{
		ID:                7,
		UID:               "uid-created",
		UserID:            userID,
		Kind:              req.Kind,
		Value:             req.Value,
		RegistrableDomain: &rd,
		Status:            model.TargetStatusUnverified,
	}
	r.created = t
	return t, nil
}

func makeTargetSvc(repo *fakeCreateTargetRepo) service.TargetServiceInterface {
	authRepo := &fakeAuthRepoForVerification{}
	verifier := service.NewVerificationService(authRepo)
	// nil producer is safe: CreateTarget never touches the audit producer.
	return service.NewTargetService(repo, authRepo, nil, verifier, nil, "secscan")
}

// ---------------------------------------------------------------------------
// ip/cidr target kinds are HARD-DISABLED (ownership verification for raw IP
// ranges is not implemented — scope-grant bypass guard).
// ---------------------------------------------------------------------------

func TestCreateTarget_IPKind_Refused(t *testing.T) {
	repo := &fakeCreateTargetRepo{}
	svc := makeTargetSvc(repo)

	dto, err := svc.CreateTarget(context.Background(), 1, &model.CreateTargetRequest{
		Kind: model.TargetKindIP, Value: "203.0.113.5",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, service.ErrIPTargetsUnsupported, "ip kind must return the sentinel error")
	assert.Nil(t, dto)
	assert.Nil(t, repo.created, "nothing may be persisted for a refused ip target")
}

func TestCreateTarget_CIDRKind_Refused(t *testing.T) {
	repo := &fakeCreateTargetRepo{}
	svc := makeTargetSvc(repo)

	dto, err := svc.CreateTarget(context.Background(), 1, &model.CreateTargetRequest{
		Kind: model.TargetKindCIDR, Value: "203.0.113.0/24",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, service.ErrIPTargetsUnsupported, "cidr kind must return the sentinel error")
	assert.Nil(t, dto)
	assert.Nil(t, repo.created, "nothing may be persisted for a refused cidr target")
}

func TestCreateTarget_DomainKind_StillSucceeds(t *testing.T) {
	repo := &fakeCreateTargetRepo{}
	svc := makeTargetSvc(repo)

	dto, err := svc.CreateTarget(context.Background(), 1, &model.CreateTargetRequest{
		Kind: model.TargetKindDomain, Value: "example.test",
	})
	require.NoError(t, err, "domain targets must be unaffected by the ip/cidr hard-disable")
	require.NotNil(t, dto)
	assert.Equal(t, model.TargetKindDomain, dto.Kind)
	require.NotNil(t, repo.created)
	assert.Equal(t, "example.test", repo.created.Value)
}
