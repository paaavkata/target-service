package model

import "testing"

// IsNetworkLayer defaults to network (fail closed) for anything that is not
// an explicit "application".
func TestScopeCheckRequest_IsNetworkLayer(t *testing.T) {
	for layer, want := range map[string]bool{
		"":            true,
		"network":     true,
		"NETWORK":     true, // unrecognized spelling is not a relaxation
		"application": false,
		"Application": true,
		"l7":          true,
	} {
		r := &ScopeCheckRequest{Layer: layer}
		if got := r.IsNetworkLayer(); got != want {
			t.Errorf("Layer=%q: IsNetworkLayer()=%v, want %v", layer, got, want)
		}
	}
}
