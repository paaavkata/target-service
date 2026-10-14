// Package ingest pulls machine-readable bug-bounty program policy from the
// platforms into target-service's own program store (17 §10). It mirrors the
// request/paging pattern of knowledge-service's ingest connectors, but writes
// to the authorization store, not the knowledge/RAG corpus.
package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"target-service/internal/model"
)

// ProgramPolicyConnector fetches one program's scope + policy metadata from a
// bug-bounty platform. Implementations require platform credentials; without
// them FetchProgram returns a clear "policy source unavailable" error rather
// than fabricating scope (default-deny upstream of the gate).
type ProgramPolicyConnector interface {
	// Platform is the platform token this connector serves (e.g. "hackerone").
	Platform() string
	// FetchProgram resolves the program by its platform handle/slug.
	FetchProgram(ctx context.Context, handle string) (model.ProgramPolicy, error)
}

// ErrPolicySourceUnavailable is returned when a connector has no credentials to
// reach its platform API. The caller must treat it as "do not run", never as an
// empty (all-denied-but-syncable) policy.
var ErrPolicySourceUnavailable = fmt.Errorf("policy source unavailable")

func defaultClient() *http.Client { return &http.Client{Timeout: 30 * time.Second} }

// getJSONAuth issues an authenticated GET and decodes the JSON body (mirrors
// knowledge-service/internal/ingest/http.go getJSONAuth).
func getJSONAuth(ctx context.Context, client *http.Client, url string, headers map[string]string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "scantinel-target-service")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
