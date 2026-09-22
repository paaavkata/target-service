package handler

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"target-service/internal/model"
	"target-service/internal/service"

	"github.com/labstack/echo/v4"
)

// AdminHandler serves the platform-owner back office routes under /v1/admin
// (plans/10-ADMIN-PANEL.md §3). The group MUST be registered with RequireAdmin;
// nothing here re-checks ownership because every route is cross-user by design.
type AdminHandler struct {
	svc    service.TargetServiceInterface
	helper *HandlerHelper
}

// NewAdminHandler constructs the admin handler.
func NewAdminHandler(svc service.TargetServiceInterface, helper *HandlerHelper) *AdminHandler {
	return &AdminHandler{svc: svc, helper: helper}
}

// RegisterRoutes wires admin routes onto the given echo.Group (which is /v1/admin
// and must carry the RequireAdmin middleware).
func (h *AdminHandler) RegisterRoutes(g *echo.Group) {
	g.GET("/targets", h.ListTargets)
	g.POST("/targets", h.CreateProgramTarget)
	g.GET("/targets/:target_uid", h.GetTarget)
	g.POST("/targets/:target_uid/authorize", h.AuthorizeTarget)
	g.POST("/targets/:target_uid/revoke", h.RevokeTarget)
	g.DELETE("/targets/:target_uid", h.DeleteTarget)
	g.GET("/stats", h.Stats)
}

var (
	validStatuses = map[string]bool{
		model.TargetStatusUnverified: true,
		model.TargetStatusVerifying:  true,
		model.TargetStatusVerified:   true,
		model.TargetStatusRevoked:    true,
	}
	validSources = map[string]bool{
		model.TargetSourceCustomer: true,
		model.TargetSourceProgram:  true,
	}
)

// ListTargets godoc
// @Summary      List targets across all users (ADMIN)
// @Description  Cross-user paged list. Unknown filter values return 400. `q` is a case-insensitive substring match on value or label.
// @Tags         admin
// @Produce      json
// @Param        X-Is-Admin   header    string  true   "Must be \"true\" (or X-User-Roles containing admin/owner)"
// @Param        user_id      query     int     false  "Filter by owner"
// @Param        status       query     string  false  "unverified|verifying|verified|revoked"
// @Param        source       query     string  false  "customer|program"
// @Param        q            query     string  false  "Substring match on value/label"
// @Param        page         query     int     false  "Page number (default 1)"
// @Param        page_size    query     int     false  "Page size (default 50, max 200)"
// @Success      200          {object}  model.Response{data=model.AdminTargetListResponse}
// @Failure      400          {object}  model.Response
// @Failure      403          {object}  model.Response  "admin only"
// @Failure      500          {object}  model.Response
// @Router       /v1/admin/targets [get]
func (h *AdminHandler) ListTargets(c echo.Context) error {
	page, pageSize := h.helper.AdminPagingParams(c.QueryParam("page"), c.QueryParam("page_size"))
	params := model.SearchParameters{
		PageNumber: page,
		PageSize:   pageSize,
		SortBy:     "created_at",
		SortOrder:  "desc",
	}

	if raw := c.QueryParam("user_id"); raw != "" {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || id < 1 {
			return h.helper.PrepareResponse(c, http.StatusBadRequest, "user_id must be a positive integer", nil, nil)
		}
		params.UserID = &id
	}
	if s := c.QueryParam("status"); s != "" {
		if !validStatuses[s] {
			return h.helper.PrepareResponse(c, http.StatusBadRequest, "status must be one of unverified|verifying|verified|revoked", nil, nil)
		}
		params.Status = &s
	}
	if s := c.QueryParam("source"); s != "" {
		if !validSources[s] {
			return h.helper.PrepareResponse(c, http.StatusBadRequest, "source must be one of customer|program", nil, nil)
		}
		params.Source = &s
	}
	if q := strings.TrimSpace(c.QueryParam("q")); q != "" {
		params.Query = &q
	}

	items, total, err := h.svc.ListAll(c.Request().Context(), params)
	if err != nil {
		return h.helper.PrepareResponse(c, http.StatusInternalServerError, "Failed to list targets", err, nil)
	}
	return h.helper.PrepareResponse(c, http.StatusOK, "Targets retrieved", nil, model.AdminTargetListResponse{
		Items:    items,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	})
}

// GetTarget godoc
// @Summary      Get any user's target (ADMIN)
// @Description  Target detail with its current authorization (incl. evidence) and asset inventory, regardless of owner.
// @Tags         admin
// @Produce      json
// @Param        X-Is-Admin  header    string  true  "Must be \"true\" (or X-User-Roles containing admin/owner)"
// @Param        target_uid  path      string  true  "Target UID"
// @Success      200         {object}  model.Response{data=model.TargetAdminDTO}
// @Failure      400         {object}  model.Response
// @Failure      403         {object}  model.Response  "admin only"
// @Failure      404         {object}  model.Response
// @Failure      500         {object}  model.Response
// @Router       /v1/admin/targets/{target_uid} [get]
func (h *AdminHandler) GetTarget(c echo.Context) error {
	uid := c.Param("target_uid")
	if err := h.helper.ValidateUID("target_uid", uid); err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadRequest, err.Error(), err, nil)
	}
	dto, err := h.svc.GetAnyByUID(c.Request().Context(), uid)
	if err != nil {
		return h.adminError(c, "Failed to retrieve target", err)
	}
	return h.helper.PrepareResponse(c, http.StatusOK, "Target retrieved", nil, dto)
}

// CreateProgramTarget godoc
// @Summary      Create a bug-bounty program target (ADMIN)
// @Description  Registers a target as verified with a method=program authorization whose evidence is the public program. user_id defaults to the admin's X-User-Id; authorized_days 1..365 (default 90). Value rules match POST /v1/targets (ip/cidr still refused while IP targets are disabled).
// @Tags         admin
// @Accept       json
// @Produce      json
// @Param        X-Is-Admin  header    string                                 true  "Must be \"true\" (or X-User-Roles containing admin/owner)"
// @Param        X-User-Id   header    string                                 true  "Admin's platform user id (audit actor, default owner)"
// @Param        request     body      model.AdminCreateProgramTargetRequest  true  "Program target payload"
// @Success      201         {object}  model.Response{data=model.TargetAdminDTO}
// @Failure      400         {object}  model.Response
// @Failure      403         {object}  model.Response  "admin only"
// @Failure      409         {object}  model.Response  "duplicate (user_id, kind, value)"
// @Failure      422         {object}  model.Response  "IP/CIDR targets are not yet supported"
// @Failure      500         {object}  model.Response
// @Router       /v1/admin/targets [post]
func (h *AdminHandler) CreateProgramTarget(c echo.Context) error {
	adminID, err := h.helper.UserIDFromHeader(c)
	if err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadRequest, err.Error(), err, nil)
	}
	req := &model.AdminCreateProgramTargetRequest{}
	if _, err := h.helper.Validate(c, req); err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadRequest, err.Error(), err, nil)
	}

	dto, err := h.svc.CreateProgramTarget(c.Request().Context(), adminID, req)
	if err != nil {
		return h.adminError(c, "Failed to create program target", err)
	}
	return h.helper.PrepareResponse(c, http.StatusCreated, "Program target created", nil, dto)
}

// AuthorizeTarget godoc
// @Summary      Manually mark a target verified (ADMIN)
// @Description  Confirms a pending challenge (email / ip_registry) if one exists, otherwise records a method=manual authorization with evidence {note}. Sets status=verified. authorized_days 1..365 (default 90).
// @Tags         admin
// @Accept       json
// @Produce      json
// @Param        X-Is-Admin  header    string                             true  "Must be \"true\" (or X-User-Roles containing admin/owner)"
// @Param        X-User-Id   header    string                             true  "Admin's platform user id (audit actor, attested_by)"
// @Param        target_uid  path      string                             true  "Target UID"
// @Param        request     body      model.AdminAuthorizeTargetRequest  true  "Note + lifetime"
// @Success      200         {object}  model.Response{data=model.TargetAdminDTO}
// @Failure      400         {object}  model.Response
// @Failure      403         {object}  model.Response  "admin only"
// @Failure      404         {object}  model.Response
// @Failure      422         {object}  model.Response  "IP/CIDR targets are not yet supported"
// @Failure      500         {object}  model.Response
// @Router       /v1/admin/targets/{target_uid}/authorize [post]
func (h *AdminHandler) AuthorizeTarget(c echo.Context) error {
	adminID, err := h.helper.UserIDFromHeader(c)
	if err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadRequest, err.Error(), err, nil)
	}
	uid := c.Param("target_uid")
	if err := h.helper.ValidateUID("target_uid", uid); err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadRequest, err.Error(), err, nil)
	}
	req := &model.AdminAuthorizeTargetRequest{}
	if _, err := h.helper.Validate(c, req); err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadRequest, err.Error(), err, nil)
	}

	dto, err := h.svc.AuthorizeManually(c.Request().Context(), adminID, uid, req)
	if err != nil {
		return h.adminError(c, "Failed to authorize target", err)
	}
	return h.helper.PrepareResponse(c, http.StatusOK, "Target authorized", nil, dto)
}

// RevokeTarget godoc
// @Summary      Revoke a target (ADMIN kill switch)
// @Description  Sets status=revoked and expires every active authorization immediately, so the scope gate denies every new intrusive task.
// @Tags         admin
// @Accept       json
// @Produce      json
// @Param        X-Is-Admin  header    string                          true  "Must be \"true\" (or X-User-Roles containing admin/owner)"
// @Param        X-User-Id   header    string                          true  "Admin's platform user id (audit actor)"
// @Param        target_uid  path      string                          true  "Target UID"
// @Param        request     body      model.AdminRevokeTargetRequest  true  "Reason"
// @Success      200         {object}  model.Response{data=model.TargetAdminDTO}
// @Failure      400         {object}  model.Response
// @Failure      403         {object}  model.Response  "admin only"
// @Failure      404         {object}  model.Response
// @Failure      500         {object}  model.Response
// @Router       /v1/admin/targets/{target_uid}/revoke [post]
func (h *AdminHandler) RevokeTarget(c echo.Context) error {
	adminID, err := h.helper.UserIDFromHeader(c)
	if err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadRequest, err.Error(), err, nil)
	}
	uid := c.Param("target_uid")
	if err := h.helper.ValidateUID("target_uid", uid); err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadRequest, err.Error(), err, nil)
	}
	req := &model.AdminRevokeTargetRequest{}
	if _, err := h.helper.Validate(c, req); err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadRequest, err.Error(), err, nil)
	}

	dto, err := h.svc.Revoke(c.Request().Context(), adminID, uid, strings.TrimSpace(req.Reason))
	if err != nil {
		return h.adminError(c, "Failed to revoke target", err)
	}
	return h.helper.PrepareResponse(c, http.StatusOK, "Target revoked", nil, dto)
}

// DeleteTarget godoc
// @Summary      Delete any user's target (ADMIN)
// @Description  Removes the target with its authorizations and asset inventory regardless of owner.
// @Tags         admin
// @Produce      json
// @Param        X-Is-Admin  header    string  true  "Must be \"true\" (or X-User-Roles containing admin/owner)"
// @Param        X-User-Id   header    string  true  "Admin's platform user id (audit actor)"
// @Param        target_uid  path      string  true  "Target UID"
// @Success      200         {object}  model.Response
// @Failure      400         {object}  model.Response
// @Failure      403         {object}  model.Response  "admin only"
// @Failure      404         {object}  model.Response
// @Failure      500         {object}  model.Response
// @Router       /v1/admin/targets/{target_uid} [delete]
func (h *AdminHandler) DeleteTarget(c echo.Context) error {
	adminID, err := h.helper.UserIDFromHeader(c)
	if err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadRequest, err.Error(), err, nil)
	}
	uid := c.Param("target_uid")
	if err := h.helper.ValidateUID("target_uid", uid); err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadRequest, err.Error(), err, nil)
	}
	if err := h.svc.DeleteAny(c.Request().Context(), adminID, uid); err != nil {
		return h.adminError(c, "Failed to delete target", err)
	}
	return h.helper.PrepareResponse(c, http.StatusOK, "Target deleted", nil, nil)
}

// Stats godoc
// @Summary      Target counts (ADMIN)
// @Description  `{total, by_status: {…}, by_source: {…}}` across all users.
// @Tags         admin
// @Produce      json
// @Param        X-Is-Admin  header    string  true  "Must be \"true\" (or X-User-Roles containing admin/owner)"
// @Success      200         {object}  model.Response{data=model.AdminStatsResponse}
// @Failure      403         {object}  model.Response  "admin only"
// @Failure      500         {object}  model.Response
// @Router       /v1/admin/stats [get]
func (h *AdminHandler) Stats(c echo.Context) error {
	stats, err := h.svc.Stats(c.Request().Context())
	if err != nil {
		return h.helper.PrepareResponse(c, http.StatusInternalServerError, "Failed to compute stats", err, nil)
	}
	return h.helper.PrepareResponse(c, http.StatusOK, "Stats retrieved", nil, stats)
}

// adminError maps the service sentinels to their HTTP status; anything else is a 500
// with the generic message (the underlying error is logged, never returned).
func (h *AdminHandler) adminError(c echo.Context, generic string, err error) error {
	switch {
	case errors.Is(err, service.ErrTargetNotFound):
		return h.helper.PrepareResponse(c, http.StatusNotFound, "Target not found", err, nil)
	case errors.Is(err, service.ErrTargetExists):
		return h.helper.PrepareResponse(c, http.StatusConflict, err.Error(), err, nil)
	case errors.Is(err, service.ErrIPTargetsUnsupported):
		return h.helper.PrepareResponse(c, http.StatusUnprocessableEntity, err.Error(), err, nil)
	default:
		return h.helper.PrepareResponse(c, http.StatusInternalServerError, generic, err, nil)
	}
}
