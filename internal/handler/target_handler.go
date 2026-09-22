package handler

import (
	"errors"
	"fmt"
	"net/http"
	"target-service/internal/model"
	"target-service/internal/service"

	"github.com/labstack/echo/v4"
)

// TargetHandler handles the ingress REST API for target management.
type TargetHandler struct {
	svc    service.TargetServiceInterface
	helper *HandlerHelper
	cap    *service.TargetCapService // nil = no plan target cap
}

// PlanUpgradeRequiredData is the 403 data payload when a plan limit refuses a
// request (shared shape with scan-service: code + plan + the limit hit).
type PlanUpgradeRequiredData struct {
	Code       string `json:"code" example:"plan_upgrade_required"`
	Plan       string `json:"plan" example:"free"`
	MaxTargets int    `json:"max_targets" example:"1"`
}

// WithTargetCap enables the per-plan target cap on POST /v1/targets.
func (h *TargetHandler) WithTargetCap(c *service.TargetCapService) *TargetHandler {
	h.cap = c
	return h
}

// NewTargetHandler constructs the target handler.
func NewTargetHandler(svc service.TargetServiceInterface, helper *HandlerHelper) *TargetHandler {
	return &TargetHandler{svc: svc, helper: helper}
}

// RegisterRoutes wires target routes onto the given echo.Group (which is /v1/targets).
func (h *TargetHandler) RegisterRoutes(g *echo.Group) {
	g.POST("", h.Create)
	g.GET("", h.List)
	g.GET("/:target_uid", h.GetByUID)
	g.POST("/:target_uid/verify", h.Verify)
	g.DELETE("/:target_uid", h.Delete)
}

// Create godoc
// @Summary      Register a new target
// @Description  Register a domain/URL/IP/CIDR target and receive a verification challenge token.
// @Tags         targets
// @Accept       json
// @Produce      json
// @Param        X-User-Id  header    string                       true  "Authenticated user ID (stamped by Traefik)"
// @Param        X-User-Plan header   string                       false "Caller's plan (stamped by Traefik / website); resolved via service-service when absent"
// @Param        request    body      model.CreateTargetRequest    true  "Target registration payload"
// @Success      201        {object}  model.Response{data=model.TargetDetailDTO}
// @Failure      400        {object}  model.Response
// @Failure      403        {object}  model.Response{data=handler.PlanUpgradeRequiredData}  "plan target cap reached (code=plan_upgrade_required)"
// @Failure      409        {object}  model.Response  "duplicate (kind, value) for this user"
// @Failure      422        {object}  model.Response  "IP/CIDR targets are not yet supported"
// @Failure      500        {object}  model.Response
// @Router       /v1/targets [post]
func (h *TargetHandler) Create(c echo.Context) error {
	userID, err := h.helper.UserIDFromHeader(c)
	if err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadRequest, err.Error(), err, nil)
	}

	req := &model.CreateTargetRequest{}
	if _, err := h.helper.Validate(c, req); err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadRequest, err.Error(), err, nil)
	}

	// Plan target cap (customer path only; admins bypass). Fails open when
	// scan-service's entitlements are unreachable.
	if h.cap != nil && !IsAdminRequest(c) {
		ctx := c.Request().Context()
		plan := h.cap.ResolvePlan(ctx, c.Request().Header.Get("X-User-Plan"), userID)
		var capErr *service.TargetCapError
		if err := h.cap.Check(ctx, userID, plan); errors.As(err, &capErr) {
			msg := fmt.Sprintf("Your %s plan allows %d target(s). Upgrade your plan to add more.", capErr.Plan, capErr.MaxTargets)
			return h.helper.PrepareResponse(c, http.StatusForbidden, msg, nil,
				PlanUpgradeRequiredData{Code: "plan_upgrade_required", Plan: capErr.Plan, MaxTargets: capErr.MaxTargets})
		}
	}

	dto, err := h.svc.CreateTarget(c.Request().Context(), userID, req)
	if err != nil {
		// ip/cidr targets are hard-disabled until real IP-range ownership
		// verification exists — a clear client error, not a 500.
		if errors.Is(err, service.ErrIPTargetsUnsupported) {
			return h.helper.PrepareResponse(c, http.StatusUnprocessableEntity, err.Error(), err, nil)
		}
		if errors.Is(err, service.ErrTargetExists) {
			return h.helper.PrepareResponse(c, http.StatusConflict, err.Error(), err, nil)
		}
		return h.helper.PrepareResponse(c, http.StatusInternalServerError, "Failed to register target", err, nil)
	}
	return h.helper.PrepareResponse(c, http.StatusCreated, "Target registered successfully", nil, dto)
}

// List godoc
// @Summary      List targets
// @Description  Return a paged list of targets owned by the authenticated user.
// @Tags         targets
// @Produce      json
// @Param        X-User-Id    header    string  true   "Authenticated user ID"
// @Param        page         query     int     false  "Page number (default 1)"
// @Param        page_size    query     int     false  "Page size (default 10, max 100)"
// @Param        status       query     string  false  "Filter by status"
// @Success      200          {object}  model.Response{data=[]model.TargetDTO}
// @Failure      400          {object}  model.Response
// @Failure      500          {object}  model.Response
// @Router       /v1/targets [get]
func (h *TargetHandler) List(c echo.Context) error {
	userID, err := h.helper.UserIDFromHeader(c)
	if err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadRequest, err.Error(), err, nil)
	}

	page, pageSize, sortBy, sortOrder := h.helper.ValidatePagingParams(
		c.QueryParam("page"),
		c.QueryParam("page_size"),
		c.QueryParam("sort_by"),
		c.QueryParam("sort_order"),
		[]string{"created_at", "status", "value"},
	)

	params := model.SearchParameters{
		PageNumber: page,
		PageSize:   pageSize,
		SortBy:     sortBy,
		SortOrder:  sortOrder,
	}
	if s := c.QueryParam("status"); s != "" {
		params.Status = &s
	}

	dtos, err := h.svc.ListTargets(c.Request().Context(), userID, params)
	if err != nil {
		return h.helper.PrepareResponse(c, http.StatusInternalServerError, "Failed to list targets", err, nil)
	}
	return h.helper.PrepareResponse(c, http.StatusOK, "Targets retrieved", nil, dtos)
}

// GetByUID godoc
// @Summary      Get target detail
// @Description  Return a target with its current authorization scope and asset inventory.
// @Tags         targets
// @Produce      json
// @Param        X-User-Id   header    string  true  "Authenticated user ID"
// @Param        target_uid  path      string  true  "Target UID"
// @Success      200         {object}  model.Response{data=model.TargetDetailDTO}
// @Failure      400         {object}  model.Response
// @Failure      404         {object}  model.Response
// @Failure      500         {object}  model.Response
// @Router       /v1/targets/{target_uid} [get]
func (h *TargetHandler) GetByUID(c echo.Context) error {
	userID, err := h.helper.UserIDFromHeader(c)
	if err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadRequest, err.Error(), err, nil)
	}

	uid := c.Param("target_uid")
	if err := h.helper.ValidateUID("target_uid", uid); err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadRequest, err.Error(), err, nil)
	}

	dto, err := h.svc.GetTarget(c.Request().Context(), userID, uid)
	if err != nil {
		return h.helper.PrepareResponse(c, http.StatusNotFound, "Target not found", err, nil)
	}
	return h.helper.PrepareResponse(c, http.StatusOK, "Target retrieved", nil, dto)
}

// Verify godoc
// @Summary      Trigger ownership verification
// @Description  Run a verification check (DNS TXT / HTTP file / meta tag) for the given target.
// @Tags         targets
// @Accept       json
// @Produce      json
// @Param        X-User-Id   header    string                      true  "Authenticated user ID"
// @Param        target_uid  path      string                      true  "Target UID"
// @Param        request     body      model.VerifyTargetRequest   true  "Verification method"
// @Success      200         {object}  model.Response{data=model.TargetDetailDTO}
// @Failure      400         {object}  model.Response
// @Failure      500         {object}  model.Response
// @Router       /v1/targets/{target_uid}/verify [post]
func (h *TargetHandler) Verify(c echo.Context) error {
	userID, err := h.helper.UserIDFromHeader(c)
	if err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadRequest, err.Error(), err, nil)
	}

	uid := c.Param("target_uid")
	if err := h.helper.ValidateUID("target_uid", uid); err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadRequest, err.Error(), err, nil)
	}

	req := &model.VerifyTargetRequest{}
	if _, err := h.helper.Validate(c, req); err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadRequest, err.Error(), err, nil)
	}

	dto, err := h.svc.TriggerVerification(c.Request().Context(), userID, uid, req)
	if err != nil {
		if errors.Is(err, service.ErrTargetAdminAuthorized) {
			return h.helper.PrepareResponse(c, http.StatusConflict, err.Error(), err, nil)
		}
		return h.helper.PrepareResponse(c, http.StatusBadRequest, "Verification did not pass: "+err.Error(), err, nil)
	}
	return h.helper.PrepareResponse(c, http.StatusOK, "Verification complete", nil, dto)
}

// Delete godoc
// @Summary      Delete a target
// @Description  Remove a target and all its authorization scope and asset inventory.
// @Tags         targets
// @Produce      json
// @Param        X-User-Id   header    string  true  "Authenticated user ID"
// @Param        target_uid  path      string  true  "Target UID"
// @Success      200         {object}  model.Response
// @Failure      400         {object}  model.Response
// @Failure      500         {object}  model.Response
// @Router       /v1/targets/{target_uid} [delete]
func (h *TargetHandler) Delete(c echo.Context) error {
	userID, err := h.helper.UserIDFromHeader(c)
	if err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadRequest, err.Error(), err, nil)
	}

	uid := c.Param("target_uid")
	if err := h.helper.ValidateUID("target_uid", uid); err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadRequest, err.Error(), err, nil)
	}

	if err := h.svc.DeleteTarget(c.Request().Context(), userID, uid); err != nil {
		return h.helper.PrepareResponse(c, http.StatusInternalServerError, "Failed to delete target", err, nil)
	}
	return h.helper.PrepareResponse(c, http.StatusOK, "Target deleted", nil, nil)
}
