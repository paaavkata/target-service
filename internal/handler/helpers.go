package handler

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"target-service/internal/model"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	logger "github.com/paaavkata/go-logger"
)

const (
	DefaultPageSize = 10
	MaxPageSize     = 100

	// Admin list routes use the platform-wide admin paging defaults
	// (plans/10-ADMIN-PANEL.md §2): page_size default 50, max 200.
	AdminDefaultPageSize = 50
	AdminMaxPageSize     = 200
)

// adminRoles are the role names that count as platform admin (Keycloak realm
// roles admin/owner → gateway X-Is-Admin, PERMISSIONS_STRATEGY.md §1).
var adminRoles = map[string]bool{"owner": true, "admin": true}

// IsAdminRequest reports whether the gateway stamped platform-admin identity on this request.
// Both headers are trusted BECAUSE the traefik-plugin strips any client-supplied copy before
// re-stamping them from the verified JWT — and it never stamps them on the API-key path, so an
// API key can never reach an admin-only route. In-cluster callers (scantinel-website's admin
// panel) self-stamp them after checking the Keycloak token. Nothing here may be read from the
// body or the query string. Copied from identity-service/internal/handler/helpers.go.
func IsAdminRequest(c echo.Context) bool {
	if strings.EqualFold(strings.TrimSpace(c.Request().Header.Get("X-Is-Admin")), "true") {
		return true
	}
	for _, role := range strings.Split(c.Request().Header.Get("X-User-Roles"), ",") {
		if adminRoles[strings.ToLower(strings.TrimSpace(role))] {
			return true
		}
	}
	return false
}

// RequireAdmin is the fail-closed second lock on /v1/admin/* routes: 403 with the
// standard envelope {status:"error", message:"admin only"} unless IsAdminRequest.
func RequireAdmin(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if !IsAdminRequest(c) {
			return c.JSON(http.StatusForbidden, model.Response{Status: "error", Message: "admin only"})
		}
		return next(c)
	}
}

// HandlerHelper holds the shared validator instance and response helpers.
type HandlerHelper struct {
	validator *validator.Validate
}

// NewHandlerHelper constructs the shared handler helper.
func NewHandlerHelper(v *validator.Validate) *HandlerHelper {
	return &HandlerHelper{validator: v}
}

// Validate binds the JSON body into object and runs struct validation.
func (h *HandlerHelper) Validate(c echo.Context, object interface{}) (interface{}, error) {
	if c.Request().Body == nil || c.Request().Body == http.NoBody {
		return nil, fmt.Errorf("request body is required")
	}
	if err := c.Bind(object); err != nil {
		logger.Errorf("handler: bind error: %v", err)
		return nil, fmt.Errorf("invalid request payload")
	}
	if err := h.validator.Struct(object); err != nil {
		return nil, fmt.Errorf("invalid request payload")
	}
	return object, nil
}

// PrepareResponse writes a uniform JSON envelope. Internal errors are logged
// but never sent to the client.
func (h *HandlerHelper) PrepareResponse(c echo.Context, statusCode int, message string, err error, data interface{}) error {
	statusStr := "success"
	if err != nil || statusCode >= 400 {
		if err != nil {
			logger.Errorf("handler error: %v", err)
		}
		statusStr = "error"
	}
	return c.JSON(statusCode, model.Response{
		Status:  statusStr,
		Message: message,
		Data:    data,
	})
}

// ValidateUID checks that the uid path parameter is non-empty.
func (h *HandlerHelper) ValidateUID(name, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", name)
	}
	return nil
}

// UserIDFromHeader extracts and parses the X-User-Id gateway-stamped header.
func (h *HandlerHelper) UserIDFromHeader(c echo.Context) (int64, error) {
	raw := c.Request().Header.Get("X-User-Id")
	if raw == "" {
		return 0, fmt.Errorf("X-User-Id header is required")
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id < 1 {
		return 0, fmt.Errorf("X-User-Id must be a positive integer")
	}
	return id, nil
}

// AdminPagingParams normalises page/page_size for admin list routes
// (1-based page, default 1; page_size default 50, max 200).
func (h *HandlerHelper) AdminPagingParams(pageNumber, pageSize string) (int, int) {
	page, _ := strconv.Atoi(pageNumber)
	if page < 1 {
		page = 1
	}
	size, _ := strconv.Atoi(pageSize)
	if size < 1 {
		size = AdminDefaultPageSize
	}
	if size > AdminMaxPageSize {
		size = AdminMaxPageSize
	}
	return page, size
}

// ValidatePagingParams normalises page/size with safe defaults.
func (h *HandlerHelper) ValidatePagingParams(pageNumber, pageSize, sortBy, sortOrder string, allowedSortFields []string) (int, int, string, string) {
	page, _ := strconv.Atoi(pageNumber)
	if page < 1 {
		page = 1
	}
	size, _ := strconv.Atoi(pageSize)
	if size < 1 {
		size = DefaultPageSize
	}
	if size > MaxPageSize {
		size = MaxPageSize
	}
	if sortBy == "" {
		sortBy = "created_at"
	}
	if sortOrder != "asc" && sortOrder != "desc" {
		sortOrder = "desc"
	}
	return page, size, sortBy, sortOrder
}
