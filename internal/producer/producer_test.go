package producer

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	goevents "github.com/paaavkata/go-events"

	"target-service/internal/model"
)

type publishCall struct {
	appID, key, msgID string
	value             interface{}
}

type fakePublisher struct{ calls []publishCall }

func (f *fakePublisher) SendScopedWithMsgID(_ context.Context, appID, key, msgID string, value interface{}) error {
	f.calls = append(f.calls, publishCall{appID, key, msgID, value})
	return nil
}

// Audit events go through go-events PublishAudit: scoped to the event's app
// ("audit-events.<app_id>"), keyed by app_id, Nats-Msg-Id = event UID; an
// app-less event is rejected and never published.
func TestEmit_PublishesScopedCanonicalAudit(t *testing.T) {
	target := &model.Target{UID: "tgt-1", Kind: "domain", Value: "example.com", UserID: 7}

	tests := []struct {
		name    string
		appID   string
		wantErr bool
	}{
		{"scoped to app", "scantinel", false},
		{"missing app_id rejected", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pub := &fakePublisher{}
			ap := &AuditProducer{publisher: pub}

			err := ap.EmitTargetVerified(context.Background(), tc.appID, target)
			if tc.wantErr {
				require.Error(t, err)
				assert.Empty(t, pub.calls)
				return
			}
			require.NoError(t, err)
			require.Len(t, pub.calls, 1)
			call := pub.calls[0]
			ev, ok := call.value.(*goevents.AuditEvent)
			require.True(t, ok)
			assert.Equal(t, tc.appID, call.appID)
			assert.Equal(t, tc.appID, call.key)
			assert.Equal(t, ev.UID, call.msgID)
			assert.Equal(t, tc.appID, ev.AppID)
			assert.Equal(t, EventTypeTargetVerified, ev.Type)
			assert.Equal(t, ServiceName, ev.Service)
			assert.Equal(t, &goevents.AuditTarget{Type: "target", UID: "tgt-1"}, ev.Target)
		})
	}
}
