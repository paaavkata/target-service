package handler

import (
	"fmt"
	"net/http"
	"strconv"
	"target-service/internal/model"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	logger "github.com/paaavkata/go-logger"
)

const (
	DefaultPageSize = 10
	MaxPageSize     = 100
)

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
