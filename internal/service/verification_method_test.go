package service_test

import (
	"context"
	"target-service/internal/model"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// customerTarget seeds an unverified customer target on a reserved (.invalid, RFC 2606) host
// so every live check fails fast without touching a real site.
func customerTarget() *model.Target {
	return &model.Target{
		ID: 7, UID: "uid-customer", UserID: 42, Kind: model.TargetKindDomain, Value: "owner.invalid",
		Status: model.TargetStatusUnverified, Source: model.TargetSourceCustomer, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
}

func seedPendingDNS(ar *memAuthRepo, t *model.Target) *model.Authorization {
	a, _ := ar.Create(context.Background(), &model.Authorization{TargetID: t.ID, Method: model.VerificationMethodDNSTXT, Token: "tok-123"})
	return a
}

// The detail read must carry the pending token: the browser flow never keeps the create response.
func TestGetTarget_UnverifiedReturnsPendingToken(t *testing.T) {
	tgt := customerTarget()
	tr, ar := newMemTargetRepo(tgt), newMemAuthRepo()
	seedPendingDNS(ar, tgt)

	dto, err := makeAdminSvc(tr, ar).GetTarget(context.Background(), 42, tgt.UID)
	require.NoError(t, err)
	require.NotNil(t, dto.VerifyToken)
	assert.Equal(t, "tok-123", *dto.VerifyToken)
	assert.Contains(t, dto.VerifyInstructions, "scantinel-verify=tok-123")
}

func TestGetTarget_VerifiedHidesToken(t *testing.T) {
	tgt := customerTarget()
	tgt.Status = model.TargetStatusVerified
	tr, ar := newMemTargetRepo(tgt), newMemAuthRepo()
	seedPendingDNS(ar, tgt)

	dto, err := makeAdminSvc(tr, ar).GetTarget(context.Background(), 42, tgt.UID)
	require.NoError(t, err)
	assert.Nil(t, dto.VerifyToken)
	assert.Empty(t, dto.VerifyInstructions)
}

func TestGetTarget_IssuesChallengeWhenMissing(t *testing.T) {
	tgt := customerTarget()
	tr, ar := newMemTargetRepo(tgt), newMemAuthRepo()

	dto, err := makeAdminSvc(tr, ar).GetTarget(context.Background(), 42, tgt.UID)
	require.NoError(t, err)
	require.NotNil(t, dto.VerifyToken)
	require.Len(t, ar.created, 1)
	assert.Equal(t, model.VerificationMethodDNSTXT, ar.created[0].Method)
	assert.Equal(t, *dto.VerifyToken, ar.created[0].Token)
}

// Checking with a different method must run THAT method with the SAME token (previously the
// stored dns_txt method was always run, so file/meta verification could never pass).
func TestTriggerVerification_SwitchesMethodKeepingToken(t *testing.T) {
	for _, method := range []string{model.VerificationMethodHTTPFile, model.VerificationMethodMetaTag} {
		t.Run(method, func(t *testing.T) {
			tgt := customerTarget()
			tr, ar := newMemTargetRepo(tgt), newMemAuthRepo()
			seedPendingDNS(ar, tgt)

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			_, err := makeAdminSvc(tr, ar).TriggerVerification(ctx, 42, tgt.UID, &model.VerifyTargetRequest{Method: method})
			require.Error(t, err, ".invalid host can never verify")
			assert.NotContains(t, err.Error(), "TXT record", "the requested method ran, not the DNS check")

			require.Len(t, ar.created, 2)
			assert.Equal(t, method, ar.created[1].Method)
			assert.Equal(t, "tok-123", ar.created[1].Token)
			assert.Equal(t, model.TargetStatusUnverified, tr.statuses[tgt.ID])
		})
	}
}

func TestTriggerVerification_SameMethodDoesNotAddRow(t *testing.T) {
	tgt := customerTarget()
	tr, ar := newMemTargetRepo(tgt), newMemAuthRepo()
	seedPendingDNS(ar, tgt)

	_, err := makeAdminSvc(tr, ar).TriggerVerification(context.Background(), 42, tgt.UID, &model.VerifyTargetRequest{Method: model.VerificationMethodDNSTXT})
	require.Error(t, err)
	assert.Len(t, ar.created, 1)
}
