package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEntitlementsClient_ParsesAndCaches(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		assert.Equal(t, "/internal/v1/entitlements/starter", r.URL.Path)
		assert.Equal(t, "scantinel", r.Header.Get("X-App-Id"))
		_, _ = w.Write([]byte(`{"status":"success","message":"ok","data":{"plan_slug":"starter","max_targets":3}}`))
	}))
	defer srv.Close()

	c := NewEntitlementsClient(srv.URL+"/", "scantinel")
	for i := 0; i < 3; i++ {
		n, err := c.MaxTargets(context.Background(), "starter")
		require.NoError(t, err)
		assert.Equal(t, 3, n)
	}
	assert.Equal(t, int32(1), atomic.LoadInt32(&hits), "cached for 60 s")
}

func TestEntitlementsClient_ErrorsAreNotCached(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := NewEntitlementsClient(srv.URL, "scantinel")
	_, err := c.MaxTargets(context.Background(), "free")
	require.Error(t, err)
	assert.Empty(t, c.cache)
}

func TestPlanResolver(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/apps/scantinel/customers/7/rate-tier":
			_, _ = w.Write([]byte(`{"plan_name":"Pro"}`))
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	r := NewPlanResolver(srv.URL, "scantinel")
	assert.Equal(t, "pro", r.Resolve(context.Background(), 7))
	assert.Equal(t, "free", r.Resolve(context.Background(), 8), "errors fall back to free")
	assert.Equal(t, "free", NewPlanResolver("", "scantinel").Resolve(context.Background(), 7))
}
