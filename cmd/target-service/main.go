// target-service: ownership verification + authorization scope gate for Scantinel.
//
// This service is THE SAFETY BOUNDARY (06_AUTHORIZATION_AND_SAFETY.md).
// No intrusive scan phase may run until this service has asserted authorization.
//
// @title          target-service API
// @version        1.0
// @description    Ownership verification and authorization scope gate for the Scantinel security-scanning platform. The POST /internal/v1/scope/check endpoint is the hard gate that scan-service and agent-service MUST consult before dispatching any intrusive task.
// @termsOfService https://scantinel.ai/terms
//
// @contact.name   Scantinel Support
// @contact.url    https://scantinel.ai/contact
// @contact.email  security@scantinel.ai
//
// @license.name   Apache 2.0
// @license.url    http://www.apache.org/licenses/LICENSE-2.0.html
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	_ "target-service/cmd/target-service/docs"
	"target-service/internal/handler"
	"target-service/internal/middleware"
	"target-service/internal/producer"
	"target-service/internal/repository"
	"target-service/internal/service"
	"target-service/internal/store"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	echoMiddleware "github.com/labstack/echo/v4/middleware"
	logger "github.com/paaavkata/go-logger"
	"github.com/spf13/viper"
	echoSwagger "github.com/swaggo/echo-swagger"
)

func main() {
	// ── 1. Config ────────────────────────────────────────────────────────────
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	_ = viper.ReadInConfig() // optional — falls back to env vars

	viper.AutomaticEnv()

	appPort := viper.GetString("APP_PORT")
	if appPort == "" {
		appPort = "8080"
	}
	dbURI := viper.GetString("DB_URI")
	env := viper.GetString("ENV")
	host := viper.GetString("HOST")
	logLevel := viper.GetString("LOG_LEVEL")
	logFormat := viper.GetString("LOG_FORMAT")
	appID := viper.GetString("APP_ID")
	if appID == "" {
		appID = "scantinel"
	}

	kafkaBrokers := viper.GetString("KAFKA_BOOTSTRAP_SERVER")
	kafkaClientID := viper.GetString("KAFKA_CLIENT_ID")
	if kafkaClientID == "" {
		kafkaClientID = "target-service"
	}

	// ── 2. Logger ─────────────────────────────────────────────────────────────
	if logLevel == "" {
		logLevel = "info"
	}
	if logFormat == "" {
		logFormat = "json"
	}
	logger.Init(logLevel, logFormat, "target-service", env, false, true, false, nil, nil)
	logger.Infof("starting target-service (env=%s, app_id=%s)", env, appID)

	// ── 3. HTTP server ────────────────────────────────────────────────────────
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.GET("/healthz", func(c echo.Context) error { return c.String(http.StatusOK, "ok") })

	e.Use(echoMiddleware.Logger())
	e.Use(middleware.CorsMiddleware())

	// ── 4. Swagger (non-prod only) ────────────────────────────────────────────
	if env != "prod" {
		if env == "dev" && host != "" {
			// docs.SwaggerInfo is imported from the docs package above.
			// Set at runtime so the auto-generated file can be committed without host.
			e.GET("/swagger/*", echoSwagger.WrapHandler)
		} else {
			e.GET("/swagger/*", echoSwagger.WrapHandler)
		}
		logger.Infof("Swagger UI available at /swagger/index.html")
	}
	_ = host // used above

	// ── 5. Database ───────────────────────────────────────────────────────────
	if dbURI == "" {
		logger.Fatalf("DB_URI is required")
	}
	db, err := store.NewDBService(dbURI)
	if err != nil {
		logger.Fatalf("failed to connect to database: %v", err)
	}
	defer db.Close()

	if err := db.Migrate(); err != nil {
		logger.Fatalf("failed to apply migrations: %v", err)
	}
	logger.Info("database migrations applied")

	// ── 6. Kafka producer ─────────────────────────────────────────────────────
	brokers := parseBrokers(kafkaBrokers)
	kafkaProducer, err := producer.NewAuditProducer(brokers, kafkaClientID)
	if err != nil {
		logger.Fatalf("failed to initialize Kafka producer: %v", err)
	}
	defer kafkaProducer.Close()

	// ── 7. Repositories ───────────────────────────────────────────────────────
	targetRepo := repository.NewTargetRepository(db)
	authRepo := repository.NewAuthorizationRepository(db)
	assetRepo := repository.NewAssetRepository(db)

	// ── 8. Services ───────────────────────────────────────────────────────────
	verifier := service.NewVerificationService(authRepo)
	targetSvc := service.NewTargetService(targetRepo, authRepo, verifier, kafkaProducer, appID)
	assetSvc := service.NewAssetService(targetRepo, assetRepo, kafkaProducer, appID)
	scopeSvc := service.NewScopeService(targetRepo, authRepo)

	// ── 9. Handlers ───────────────────────────────────────────────────────────
	v := validator.New()
	handlerHelper := handler.NewHandlerHelper(v)
	targetHandler := handler.NewTargetHandler(targetSvc, handlerHelper)
	assetHandler := handler.NewAssetHandler(assetSvc, handlerHelper)
	internalHandler := handler.NewInternalHandler(scopeSvc, assetSvc, handlerHelper)

	// ── 10. Routes ────────────────────────────────────────────────────────────
	// External (customer-facing) routes — routed by Traefik via /api/target (stripped).
	v1 := e.Group("/v1")
	targetHandler.RegisterRoutes(v1.Group("/targets"))
	assetHandler.RegisterRoutes(v1.Group("/targets"))

	// Internal (cluster-only) routes — not exposed via Traefik ingress.
	// Secured by Kubernetes NetworkPolicy; no additional auth middleware.
	internalV1 := e.Group("/internal/v1")
	internalHandler.RegisterRoutes(internalV1)

	// ── 11. Graceful shutdown ─────────────────────────────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		logger.Info("shutdown signal received — draining")
		cancel()
		_ = e.Shutdown(ctx)
	}()

	serverAddr := fmt.Sprintf(":%s", appPort)
	logger.Infof("target-service listening on %s", serverAddr)
	if err := e.Start(serverAddr); err != nil && err != http.ErrServerClosed && ctx.Err() == nil {
		logger.Fatalf("server error: %v", err)
	}
}

// parseBrokers splits a comma-separated broker string into a slice.
func parseBrokers(raw string) []string {
	if raw == "" {
		return []string{"localhost:9092"}
	}
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			result = append(result, t)
		}
	}
	return result
}
