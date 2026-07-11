package handler

import (
	"net/http"
	"target-service/internal/model"
	"target-service/internal/service"

	"github.com/labstack/echo/v4"
)

// InternalHandler exposes cluster-only endpoints under /internal/v1/.
// These routes are NOT reachable via the Traefik ingress — only via cluster-internal
// NetworkPolicy (service-to-service). See 03 §2 and 06 §1.
type InternalHandler struct {
	scopeSvc service.ScopeServiceInterface
	assetSvc service.AssetServiceInterface
	helper   *HandlerHelper
}

// NewInternalHandler constructs the internal handler.
func NewInternalHandler(
	scopeSvc service.ScopeServiceInterface,
	assetSvc service.AssetServiceInterface,
	helper *HandlerHelper,
) *InternalHandler {
	return &InternalHandler{
		scopeSvc: scopeSvc,
		assetSvc: assetSvc,
		helper:   helper,
	}
}

// RegisterRoutes wires internal routes onto the given echo.Group (/internal/v1).
func (h *InternalHandler) RegisterRoutes(g *echo.Group) {
	g.POST("/scope/check", h.ScopeCheck)
	g.POST("/targets/:target_uid/assets", h.UpsertAssets)
}

// ScopeCheck is the authorization gate — the most critical endpoint in the service.
//
// Called by scan-service and agent-service BEFORE every intrusive task or probe dispatch.
// Implements the full scope evaluation from 06 §1–§3:
//   - Requires a verified, non-expired authorization for the target.
//   - For registrable-domain scope: host must be the apex or a subdomain.
//   - For IP-range scope: IP must fall within the confirmed CIDR.
//   - Rejects hosts/IPs that resolve to known shared-infrastructure ranges.
//   - Denies by default on any ambiguity.
//
// ScopeCheck godoc
// @Summary      Authorization scope gate (INTERNAL)
// @Description  Cluster-only. Determines whether a given host or IP is authorized for an intrusive scan phase on behalf of the target owner. Scan-service and agent-service MUST call this before dispatching any intrusive task.
// @Tags         internal
// @Accept       json
// @Produce      json
// @Param        request  body      model.ScopeCheckRequest   true  "Scope check payload: {target_uid, host|ip, phase}"
// @Success      200      {object}  model.Response{data=model.ScopeCheckResponse}
// @Failure      400      {object}  model.Response
// @Failure      500      {object}  model.Response
// @Router       /internal/v1/scope/check [post]
func (h *InternalHandler) ScopeCheck(c echo.Context) error {
	req := &model.ScopeCheckRequest{}
	if _, err := h.helper.Validate(c, req); err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadRequest, err.Error(), err, nil)
	}

	if req.Host == "" && req.IP == "" {
		return h.helper.PrepareResponse(c, http.StatusBadRequest, "either host or ip must be provided", nil, nil)
	}

	result, err := h.scopeSvc.CheckScope(c.Request().Context(), req)
	if err != nil {
		return h.helper.PrepareResponse(c, http.StatusInternalServerError, "Scope check failed", err, nil)
	}
	return h.helper.PrepareResponse(c, http.StatusOK, "Scope check complete", nil, result)
}

// UpsertAssets receives discovered assets from scan-service recon jobs and adds
// them to the target's asset inventory.
//
// UpsertAssets godoc
// @Summary      Upsert discovered assets (INTERNAL)
// @Description  Cluster-only. Called by scan-service to insert or update assets (subdomains/IPs/ports) discovered during recon phases into the target's inventory.
// @Tags         internal
// @Accept       json
// @Produce      json
// @Param        target_uid  path      string                    true  "Target UID"
// @Param        request     body      model.UpsertAssetsRequest true  "Assets to upsert"
// @Success      200         {object}  model.Response{data=[]model.AssetDTO}
// @Failure      400         {object}  model.Response
// @Failure      500         {object}  model.Response
// @Router       /internal/v1/targets/{target_uid}/assets [post]
func (h *InternalHandler) UpsertAssets(c echo.Context) error {
	uid := c.Param("target_uid")
	if err := h.helper.ValidateUID("target_uid", uid); err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadRequest, err.Error(), err, nil)
	}

	req := &model.UpsertAssetsRequest{}
	if _, err := h.helper.Validate(c, req); err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadRequest, err.Error(), err, nil)
	}

	dtos, err := h.assetSvc.UpsertAssets(c.Request().Context(), uid, req)
	if err != nil {
		return h.helper.PrepareResponse(c, http.StatusInternalServerError, "Failed to upsert assets", err, nil)
	}
	return h.helper.PrepareResponse(c, http.StatusOK, "Assets upserted", nil, dtos)
}
