package handler

import (
	"net/http"
	"target-service/internal/service"

	"github.com/labstack/echo/v4"
)

// AssetHandler handles asset inventory endpoints.
type AssetHandler struct {
	svc    service.AssetServiceInterface
	helper *HandlerHelper
}

// NewAssetHandler constructs the asset handler.
func NewAssetHandler(svc service.AssetServiceInterface, helper *HandlerHelper) *AssetHandler {
	return &AssetHandler{svc: svc, helper: helper}
}

// RegisterRoutes wires asset routes under /v1/targets/:target_uid.
func (h *AssetHandler) RegisterRoutes(g *echo.Group) {
	g.GET("/:target_uid/assets", h.List)
}

// List godoc
// @Summary      List assets for a target
// @Description  Return the discovered asset inventory (subdomains/IPs/ports/services) for the given target.
// @Tags         assets
// @Produce      json
// @Param        X-User-Id   header    string  true  "Authenticated user ID"
// @Param        target_uid  path      string  true  "Target UID"
// @Success      200         {object}  model.Response{data=[]model.AssetDTO}
// @Failure      400         {object}  model.Response
// @Failure      500         {object}  model.Response
// @Router       /v1/targets/{target_uid}/assets [get]
func (h *AssetHandler) List(c echo.Context) error {
	userID, err := h.helper.UserIDFromHeader(c)
	if err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadRequest, err.Error(), err, nil)
	}

	uid := c.Param("target_uid")
	if err := h.helper.ValidateUID("target_uid", uid); err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadRequest, err.Error(), err, nil)
	}

	dtos, err := h.svc.ListAssets(c.Request().Context(), userID, uid)
	if err != nil {
		return h.helper.PrepareResponse(c, http.StatusInternalServerError, "Failed to retrieve assets", err, nil)
	}
	return h.helper.PrepareResponse(c, http.StatusOK, "Assets retrieved", nil, dtos)
}
