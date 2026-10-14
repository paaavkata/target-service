package handler

import (
	"errors"
	"net/http"
	"target-service/internal/model"
	"target-service/internal/service"

	"github.com/labstack/echo/v4"
)

// ProgramHandler serves the bug-bounty program-policy admin routes (17 §10).
// It MUST be registered on the /v1/admin group (RequireAdmin), like the other
// cross-user back-office routes.
type ProgramHandler struct {
	svc    service.ProgramServiceInterface
	helper *HandlerHelper
}

// NewProgramHandler constructs the program handler.
func NewProgramHandler(svc service.ProgramServiceInterface, helper *HandlerHelper) *ProgramHandler {
	return &ProgramHandler{svc: svc, helper: helper}
}

// RegisterRoutes wires program routes onto the /v1/admin group.
func (h *ProgramHandler) RegisterRoutes(g *echo.Group) {
	g.POST("/programs/sync", h.SyncProgram)
}

// SyncProgram godoc
// @Summary      Sync a bug-bounty program policy (ADMIN)
// @Description  Pulls a program's structured scope from its platform (platform+handle) and upserts it (and its assets) into the program store for program-mode scope enforcement (17 §10). The platform APIs do not expose automation/rate/prohibited-technique machine-readably, so those are the admin's attestation in the body (absent ⇒ default-deny). Returns 503 "policy source unavailable" when the platform credentials are not configured.
// @Tags         admin
// @Accept       json
// @Produce      json
// @Param        X-Is-Admin  header    string                     true  "Must be \"true\" (or X-User-Roles containing admin/owner)"
// @Param        request     body      model.SyncProgramRequest   true  "Program sync payload"
// @Success      200         {object}  model.Response{data=model.ProgramDTO}
// @Failure      400         {object}  model.Response
// @Failure      403         {object}  model.Response  "admin only"
// @Failure      502         {object}  model.Response  "no connector / platform error"
// @Failure      503         {object}  model.Response  "policy source unavailable"
// @Failure      500         {object}  model.Response
// @x-required-permission "program.manage"
// @Router       /v1/admin/programs/sync [post]
func (h *ProgramHandler) SyncProgram(c echo.Context) error {
	req := &model.SyncProgramRequest{}
	if _, err := h.helper.Validate(c, req); err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadRequest, err.Error(), err, nil)
	}
	dto, err := h.svc.SyncProgram(c.Request().Context(), req)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrPolicySourceUnavailable):
			return h.helper.PrepareResponse(c, http.StatusServiceUnavailable, "policy source unavailable: platform credentials are not configured", err, nil)
		case errors.Is(err, service.ErrNoPolicyConnector):
			return h.helper.PrepareResponse(c, http.StatusBadGateway, "no policy connector configured for this platform", err, nil)
		default:
			return h.helper.PrepareResponse(c, http.StatusBadGateway, "Failed to sync program policy", err, nil)
		}
	}
	return h.helper.PrepareResponse(c, http.StatusOK, "Program synced", nil, dto)
}
