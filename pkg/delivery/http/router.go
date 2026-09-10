package http

import (
	"os"
	"strings"

	"github.com/Mini-Project-MDP/sso-service/pkg/delivery/http/handler"
	"github.com/Mini-Project-MDP/sso-service/pkg/delivery/http/middleware"
	"github.com/Mini-Project-MDP/sso-service/pkg/service"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/cors"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"gorm.io/gorm"
)

func SetupRouter(app *fiber.App, db *gorm.DB) {
	// Global Middlewares
	app.Use(logger.New())

	// CORS: baca dari env ALLOWED_ORIGINS (comma-separated), fallback ke localhost
	allowedOrigins := []string{
		"http://localhost:5173",
		"http://localhost:5174",
		"http://localhost:3000",
		"http://localhost:3001",
	}
	if envOrigins := os.Getenv("ALLOWED_ORIGINS"); envOrigins != "" {
		for _, o := range strings.Split(envOrigins, ",") {
			allowedOrigins = append(allowedOrigins, strings.TrimSpace(o))
		}
	}

	app.Use(cors.New(cors.Config{
		AllowOrigins:     allowedOrigins,
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowCredentials: true,
	}))

	// Services
	authService := service.NewAuthService(db)
	adminService := service.NewAdminService(db)

	// Handlers
	ssoHandler := handler.NewSSOHandler(authService)
	adminHandler := handler.NewAdminHandler(adminService)

	api := app.Group("/api/v1")

	// 1. SSO Public & Auth Routes
	sso := api.Group("/sso")
	sso.Get("/authorize", ssoHandler.Authorize)
	sso.Post("/login", ssoHandler.Login)
	sso.Post("/token", ssoHandler.Token)
	sso.Post("/logout", ssoHandler.Logout)
	sso.Get("/userinfo", ssoHandler.GetUserInfo, middleware.RequireJWTAuth())

	// 2. Admin Management Routes
	admin := api.Group("/admin")
	admin.Get("/stats", adminHandler.GetStats)

	// Connected Apps
	admin.Get("/apps", adminHandler.GetApps)
	admin.Post("/apps", adminHandler.CreateApp)
	admin.Post("/apps/:id/rotate-secret", adminHandler.RotateSecret)
	admin.Put("/apps/:id/status", adminHandler.ToggleAppStatus)
	admin.Delete("/apps/:id", adminHandler.DeleteApp)

	// Users
	admin.Get("/users", adminHandler.GetUsers)
	admin.Post("/users", adminHandler.CreateUser)
	admin.Put("/users/:id/status", adminHandler.UpdateUserStatus)
	admin.Put("/users/:id/master", adminHandler.ToggleMaster)

	// User App Mappings
	admin.Get("/user-mappings", adminHandler.GetMappings)
	admin.Post("/user-mappings", adminHandler.CreateMapping)
	admin.Delete("/user-mappings/:id", adminHandler.DeleteMapping)

	// Active Sessions
	admin.Get("/sessions", adminHandler.GetSessions)
	admin.Delete("/sessions/:id", adminHandler.RevokeSession)

	// Audit Logs
	admin.Get("/audit-logs", adminHandler.GetAuditLogs)
}
