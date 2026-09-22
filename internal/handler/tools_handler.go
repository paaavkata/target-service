package handler

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"target-service/internal/model"
	"target-service/internal/service"
	"time"

	"github.com/labstack/echo/v4"
	"golang.org/x/time/rate"
)

const (
	// toolsRatePerHour is the per-client-IP budget for the free public tools
	// (10 requests/hour/IP, token bucket keyed by the visitor's IP).
	toolsRatePerHour = 10
	// toolsGlobalConcurrency caps in-flight checks across all clients so a
	// burst of visitors can't exhaust outbound connections/file descriptors.
	toolsGlobalConcurrency = 16
	// toolsCheckTimeout bounds each outbound check (fetch/handshake/DNS).
	toolsCheckTimeout = 20 * time.Second
	// toolsLimiterIdleTTL: an IP's bucket is forgotten after this long unused,
	// so the in-memory map doesn't grow without bound.
	toolsLimiterIdleTTL = 2 * time.Hour
)

// ToolsHandler serves the public, unauthenticated free-tool endpoints backing
// scantinel-website's /tools/* pages: security headers, TLS, email
// authentication, and the combined website-check. No X-User-Id/X-App-Id is
// required or read — these checks are stateless and never persisted.
type ToolsHandler struct {
	svc    *service.ToolsService
	helper *HandlerHelper

	limiterMu sync.Mutex
	limiters  map[string]*ipLimiterEntry

	sem chan struct{}
}

type ipLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewToolsHandler constructs the tools handler and starts its idle-bucket janitor.
func NewToolsHandler(svc *service.ToolsService, helper *HandlerHelper) *ToolsHandler {
	h := &ToolsHandler{
		svc:      svc,
		helper:   helper,
		limiters: make(map[string]*ipLimiterEntry),
		sem:      make(chan struct{}, toolsGlobalConcurrency),
	}
	go h.janitor()
	return h
}

// RegisterRoutes wires the tool routes onto the given echo.Group (/v1/tools).
func (h *ToolsHandler) RegisterRoutes(g *echo.Group) {
	g.POST("/security-headers", h.SecurityHeaders)
	g.POST("/tls", h.TLS)
	g.POST("/email-auth", h.EmailAuth)
	g.POST("/website-check", h.WebsiteCheck)
}

func (h *ToolsHandler) janitor() {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().Add(-toolsLimiterIdleTTL)
		h.limiterMu.Lock()
		for ip, e := range h.limiters {
			if e.lastSeen.Before(cutoff) {
				delete(h.limiters, ip)
			}
		}
		h.limiterMu.Unlock()
	}
}

// clientIP extracts the visitor IP: the first hop of X-Forwarded-For (the
// website forwards the real visitor IP there), else X-Real-Ip, else Echo's
// own RemoteAddr-derived RealIP.
func clientIP(c echo.Context) string {
	if xff := c.Request().Header.Get("X-Forwarded-For"); xff != "" {
		if first := strings.TrimSpace(strings.Split(xff, ",")[0]); first != "" {
			return first
		}
	}
	if xrip := strings.TrimSpace(c.Request().Header.Get("X-Real-Ip")); xrip != "" {
		return xrip
	}
	return c.RealIP()
}

// allow enforces the per-IP hourly budget. Returns (allowed, retryAfterSeconds).
func (h *ToolsHandler) allow(ip string) (bool, int) {
	h.limiterMu.Lock()
	e, ok := h.limiters[ip]
	if !ok {
		e = &ipLimiterEntry{limiter: rate.NewLimiter(rate.Limit(float64(toolsRatePerHour)/3600.0), toolsRatePerHour)}
		h.limiters[ip] = e
	}
	e.lastSeen = time.Now()
	limiter := e.limiter
	h.limiterMu.Unlock()

	res := limiter.Reserve()
	if !res.OK() {
		return false, 3600
	}
	if delay := res.Delay(); delay > 0 {
		res.Cancel()
		return false, int(delay.Seconds()) + 1
	}
	return true, 0
}

// guard applies the per-IP rate limit and the global concurrency cap. When
// the request is rejected it writes the response itself and returns nil;
// otherwise it returns a release func the caller must defer.
func (h *ToolsHandler) guard(c echo.Context) func() {
	ip := clientIP(c)
	if ok, retryAfter := h.allow(ip); !ok {
		c.Response().Header().Set("Retry-After", strconv.Itoa(retryAfter))
		_ = c.JSON(http.StatusTooManyRequests, model.Response{
			Status:  "error",
			Message: "rate limit exceeded — try again later",
			Data:    map[string]int{"retry_after": retryAfter},
		})
		return nil
	}
	select {
	case h.sem <- struct{}{}:
		return func() { <-h.sem }
	default:
		_ = c.JSON(http.StatusServiceUnavailable, model.Response{
			Status:  "error",
			Message: "the free tools are busy right now — try again in a few seconds",
		})
		return nil
	}
}

// bindDomain validates the request body and normalises the domain. On
// failure it writes the 400 response itself and returns ("", false).
func (h *ToolsHandler) bindDomain(c echo.Context) (string, bool) {
	req := &model.ToolCheckRequest{}
	if _, err := h.helper.Validate(c, req); err != nil {
		_ = h.helper.PrepareResponse(c, http.StatusBadRequest, err.Error(), err, nil)
		return "", false
	}
	domain, err := service.NormalizeAndValidateHostname(req.Domain)
	if err != nil {
		_ = h.helper.PrepareResponse(c, http.StatusBadRequest, "enter a valid domain name, e.g. example.com", err, nil)
		return "", false
	}
	return domain, true
}

// SecurityHeaders godoc
// @Summary      Free security headers check
// @Description  Fetches the domain's homepage and grades 8 key HTTP security headers. Public, unauthenticated, rate-limited to 10 requests/hour/IP.
// @Tags         tools
// @Accept       json
// @Produce      json
// @Param        request  body      model.ToolCheckRequest  true  "Domain to check"
// @Success      200      {object}  model.Response{data=model.SecurityHeadersResponse}
// @Failure      400      {object}  model.Response
// @Failure      429      {object}  model.Response
// @Failure      502      {object}  model.Response
// @Failure      503      {object}  model.Response
// @Router       /v1/tools/security-headers [post]
func (h *ToolsHandler) SecurityHeaders(c echo.Context) error {
	release := h.guard(c)
	if release == nil {
		return nil
	}
	defer release()

	domain, ok := h.bindDomain(c)
	if !ok {
		return nil
	}
	ctx, cancel := context.WithTimeout(c.Request().Context(), toolsCheckTimeout)
	defer cancel()

	res, err := h.svc.SecurityHeaders(ctx, domain)
	if err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadGateway, "could not fetch that site — check the domain and that it's reachable over HTTPS/HTTP", err, nil)
	}
	return h.helper.PrepareResponse(c, http.StatusOK, "Security headers checked", nil, res)
}

// TLS godoc
// @Summary      Free TLS/SSL check
// @Description  Performs a TLS handshake on port 443, inspects the certificate, and checks whether TLS 1.0/1.1 are still accepted. Public, unauthenticated, rate-limited to 10 requests/hour/IP.
// @Tags         tools
// @Accept       json
// @Produce      json
// @Param        request  body      model.ToolCheckRequest  true  "Domain to check"
// @Success      200      {object}  model.Response{data=model.TLSCheckResponse}
// @Failure      400      {object}  model.Response
// @Failure      429      {object}  model.Response
// @Failure      502      {object}  model.Response
// @Failure      503      {object}  model.Response
// @Router       /v1/tools/tls [post]
func (h *ToolsHandler) TLS(c echo.Context) error {
	release := h.guard(c)
	if release == nil {
		return nil
	}
	defer release()

	domain, ok := h.bindDomain(c)
	if !ok {
		return nil
	}
	ctx, cancel := context.WithTimeout(c.Request().Context(), toolsCheckTimeout)
	defer cancel()

	res, err := h.svc.TLS(ctx, domain)
	if err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadGateway, "could not complete a TLS handshake with that domain on port 443", err, nil)
	}
	return h.helper.PrepareResponse(c, http.StatusOK, "TLS checked", nil, res)
}

// EmailAuth godoc
// @Summary      Free SPF/DMARC/DKIM check
// @Description  Looks up SPF, DMARC and common-selector DKIM DNS records for the domain and returns copy-paste fixes. Public, unauthenticated, rate-limited to 10 requests/hour/IP.
// @Tags         tools
// @Accept       json
// @Produce      json
// @Param        request  body      model.ToolCheckRequest  true  "Domain to check"
// @Success      200      {object}  model.Response{data=model.EmailAuthResponse}
// @Failure      400      {object}  model.Response
// @Failure      429      {object}  model.Response
// @Failure      503      {object}  model.Response
// @Router       /v1/tools/email-auth [post]
func (h *ToolsHandler) EmailAuth(c echo.Context) error {
	release := h.guard(c)
	if release == nil {
		return nil
	}
	defer release()

	domain, ok := h.bindDomain(c)
	if !ok {
		return nil
	}
	ctx, cancel := context.WithTimeout(c.Request().Context(), toolsCheckTimeout)
	defer cancel()

	res, err := h.svc.EmailAuth(ctx, domain)
	if err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadGateway, "could not look up DNS records for that domain", err, nil)
	}
	return h.helper.PrepareResponse(c, http.StatusOK, "Email authentication checked", nil, res)
}

// WebsiteCheck godoc
// @Summary      Free combined website security check
// @Description  Runs the security-headers, TLS and email-auth checks concurrently and returns a combined summary plus full details. Public, unauthenticated, rate-limited to 10 requests/hour/IP.
// @Tags         tools
// @Accept       json
// @Produce      json
// @Param        request  body      model.ToolCheckRequest  true  "Domain to check"
// @Success      200      {object}  model.Response{data=model.WebsiteCheckResponse}
// @Failure      400      {object}  model.Response
// @Failure      429      {object}  model.Response
// @Failure      502      {object}  model.Response
// @Failure      503      {object}  model.Response
// @Router       /v1/tools/website-check [post]
func (h *ToolsHandler) WebsiteCheck(c echo.Context) error {
	release := h.guard(c)
	if release == nil {
		return nil
	}
	defer release()

	domain, ok := h.bindDomain(c)
	if !ok {
		return nil
	}
	ctx, cancel := context.WithTimeout(c.Request().Context(), toolsCheckTimeout)
	defer cancel()

	res, err := h.svc.WebsiteCheck(ctx, domain)
	if err != nil {
		return h.helper.PrepareResponse(c, http.StatusBadGateway, "could not complete the check for that domain", err, nil)
	}
	return h.helper.PrepareResponse(c, http.StatusOK, "Website check complete", nil, res)
}
