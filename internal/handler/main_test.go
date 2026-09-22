package handler_test

import (
	"os"
	"testing"

	logger "github.com/paaavkata/go-logger"
)

// TestMain initialises go-logger: PrepareResponse logs every handled error and
// the package-level logger panics when Init was never called.
func TestMain(m *testing.M) {
	logger.Init("error", "text", "target-service-test", "test", false, true, false, nil, nil)
	os.Exit(m.Run())
}
