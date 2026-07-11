package middleware

import (
	"github.com/labstack/echo/v4"
	echoMiddleware "github.com/labstack/echo/v4/middleware"
)

// CorsMiddleware returns CORS configuration for target-service.
func CorsMiddleware() echo.MiddlewareFunc {
	return echoMiddleware.CORSWithConfig(echoMiddleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders: []string{"Content-Type", "Authorization", "X-User-Id", "X-App-Id"},
	})
}

// AppIDMiddleware validates that inbound requests carry the expected X-App-Id header.
// Internal endpoints (/internal/...) are cluster-only (NetworkPolicy) and therefore
// do not require this check — they trust the cluster network boundary.
func AppIDMiddleware(expectedAppID string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			appID := c.Request().Header.Get("X-App-Id")
			if appID != "" && appID != expectedAppID {
				return echo.ErrForbidden
			}
			return next(c)
		}
	}
}
