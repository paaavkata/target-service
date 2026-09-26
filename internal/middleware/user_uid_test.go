package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestKeycloakUID(t *testing.T) {
	const uid = "00000000-0000-0000-0000-000000000000" // shared vector → 8950988243607919089
	const id = "8950988243607919089"
	const owner = 8950988243607919089
	run := func(userID, userUID string) context.Context {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-User-Id", userID)
		req.Header.Set("X-User-Uid", userUID)
		c := echo.New().NewContext(req, httptest.NewRecorder())
		var got context.Context
		_ = UserUIDMiddleware()(func(c echo.Context) error { got = c.Request().Context(); return nil })(c)
		return got
	}

	ctx := run(id, uid)
	if u := KeycloakUID(ctx, owner); !u.Valid {
		t.Fatal("owner match: want uid")
	} else if s, _ := u.Value(); s != uid {
		t.Fatalf("got %v want %s", s, uid)
	}
	if KeycloakUID(ctx, 7).Valid {
		t.Fatal("other owner (admin on-behalf): want NULL")
	}
	if KeycloakUID(run(id, ""), owner).Valid || KeycloakUID(run("", uid), owner).Valid {
		t.Fatal("missing/invalid header: want NULL")
	}
	// forged: a UUID that does not derive to the trusted X-User-Id is dropped
	if KeycloakUID(run(id, "0f8fad5b-d9cb-469f-a165-70867728950e"), owner).Valid {
		t.Fatal("uid not bound to X-User-Id: want NULL")
	}
	if KeycloakUID(context.Background(), owner).Valid {
		t.Fatal("no request context: want NULL")
	}
}
