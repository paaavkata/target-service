package middleware

import (
	"context"
	"hash/fnv"
	"strconv"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v4"
)

// Keycloak UUID dual-write (task 01 phase 2, additive only). The gateway
// stamps X-User-Uid = Keycloak `sub` beside the integer X-User-Id bridge
// (= deriveUserID(sub)). Rows keep keying on user_id; keycloak_uid is written
// alongside it so reads can later switch to the real UUID.

type userUIDKey struct{}

type userUID struct {
	userID int64
	uid    pgtype.UUID
}

// UserUIDMiddleware stashes a well-formed X-User-Uid, paired with the
// X-User-Id it arrived with, in the request context. It is accepted only when
// X-User-Id == deriveUserID(X-User-Uid), which binds it to the trusted
// X-User-Id: a client-forged X-User-Uid (the gateway does not strip it yet)
// can never attach another user's UUID. Absent/invalid/mismatch → no-op.
func UserUIDMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			req := c.Request()
			u := userUID{}
			raw := req.Header.Get("X-User-Uid")
			id, err := strconv.ParseInt(req.Header.Get("X-User-Id"), 10, 64)
			if err == nil && id > 0 && id == deriveUserID(raw) && u.uid.Scan(raw) == nil && u.uid.Valid {
				u.userID = id
				c.SetRequest(req.WithContext(context.WithValue(req.Context(), userUIDKey{}, u)))
			}
			return next(c)
		}
	}
}

// KeycloakUID is the keycloak_uid to store on a row owned by ownerID: the
// caller's UUID when the caller IS the owner, NULL otherwise (no header, or an
// admin acting on behalf of another user, or a non-HTTP path).
func KeycloakUID(ctx context.Context, ownerID int64) pgtype.UUID {
	if u, ok := ctx.Value(userUIDKey{}).(userUID); ok && u.userID == ownerID {
		return u.uid
	}
	return pgtype.UUID{}
}

// deriveUserID mirrors the gateway's (traefik-plugin jwt.go) and the website's
// (src/lib/user-id.ts) X-User-Id derivation from the Keycloak sub: FNV-1a-64,
// top bit cleared, 0 → 1. Scantinel users have no numeric luid, so their
// X-User-Id is always this value.
func deriveUserID(sub string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(sub))
	if v := int64(h.Sum64() &^ (1 << 63)); v != 0 {
		return v
	}
	return 1
}
