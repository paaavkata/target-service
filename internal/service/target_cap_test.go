package service_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"target-service/internal/model"
	"target-service/internal/repository"
	"target-service/internal/service"

	logger "github.com/paaavkata/go-logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMain initialises go-logger: the target cap logs a warning when it fails
// open and the package-level logger panics when Init was never called.
func TestMain(m *testing.M) {
	logger.Init("error", "text", "target-service-test", "test", false, true, false, nil, nil)
	os.Exit(m.Run())
}

type countRepo struct {
	repository.TargetRepositoryInterface // only Count is used
	n      int64
	err    error
	gotUID *int64
}

func (r *countRepo) Count(_ context.Context, p model.SearchParameters) (int64, error) {
	r.gotUID = p.UserID
	return r.n, r.err
}

type fakeLimits struct {
	max map[string]int
	err error
}

func (f fakeLimits) MaxTargets(_ context.Context, plan string) (int, error) {
	if f.err != nil {
		return 0, f.err
	}
	return f.max[plan], nil
}

type fakePlans string

func (f fakePlans) Resolve(context.Context, int64) string { return string(f) }

var matrix = fakeLimits{max: map[string]int{"free": 1, "starter": 3, "enterprise": -1}}

func TestTargetCap_UnderLimitPasses(t *testing.T) {
	repo := &countRepo{n: 0}
	svc := service.NewTargetCapService(repo, matrix, nil)
	require.NoError(t, svc.Check(context.Background(), 7, "free"))
	require.NotNil(t, repo.gotUID)
	assert.Equal(t, int64(7), *repo.gotUID, "count must be scoped to the caller")
}

func TestTargetCap_AtLimitRefuses(t *testing.T) {
	svc := service.NewTargetCapService(&countRepo{n: 1}, matrix, nil)
	err := svc.Check(context.Background(), 7, "free")
	var capErr *service.TargetCapError
	require.True(t, errors.As(err, &capErr))
	assert.Equal(t, "free", capErr.Plan)
	assert.Equal(t, 1, capErr.MaxTargets)

	require.NoError(t, service.NewTargetCapService(&countRepo{n: 2}, matrix, nil).Check(context.Background(), 7, "starter"))
	require.Error(t, service.NewTargetCapService(&countRepo{n: 3}, matrix, nil).Check(context.Background(), 7, "starter"))
}

func TestTargetCap_UnlimitedNeverCounts(t *testing.T) {
	repo := &countRepo{n: 1_000_000}
	require.NoError(t, service.NewTargetCapService(repo, matrix, nil).Check(context.Background(), 7, "enterprise"))
	assert.Nil(t, repo.gotUID)
}

func TestTargetCap_FailsOpen(t *testing.T) {
	down := fakeLimits{err: errors.New("scan-service unreachable")}
	require.NoError(t, service.NewTargetCapService(&countRepo{n: 99}, down, nil).Check(context.Background(), 7, "free"))
	require.NoError(t, service.NewTargetCapService(&countRepo{err: errors.New("db")}, matrix, nil).Check(context.Background(), 7, "free"))
}

func TestTargetCap_ResolvePlan(t *testing.T) {
	svc := service.NewTargetCapService(&countRepo{}, matrix, fakePlans("pro"))
	assert.Equal(t, "starter", svc.ResolvePlan(context.Background(), " Starter ", 7), "header wins")
	assert.Equal(t, "pro", svc.ResolvePlan(context.Background(), "", 7), "falls back to service-service")
	assert.Equal(t, "free", service.NewTargetCapService(&countRepo{}, matrix, nil).ResolvePlan(context.Background(), "", 7))
}
