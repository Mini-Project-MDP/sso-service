package middleware

import (
	"log"
	"strings"
	"time"

	"github.com/Mini-Project-MDP/sso-service/pkg/domain"
	"github.com/Mini-Project-MDP/sso-service/pkg/jwt"
	"github.com/Mini-Project-MDP/sso-service/pkg/response"
	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

const UserContextKey = "sso_claims"

func RequireJWTAuth() fiber.Handler {
	return func(c fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return response.Error(c, fiber.StatusUnauthorized, "Missing Authorization header")
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			return response.Error(c, fiber.StatusUnauthorized, "Invalid Authorization header format")
		}

		tokenStr := parts[1]
		claims, err := jwt.ValidateToken(tokenStr)
		if err != nil {
			return response.Error(c, fiber.StatusUnauthorized, "Unauthorized: "+err.Error())
		}

		log.Printf("RequireJWTAuth validated token, claims: %#v", claims)
		c.Locals(UserContextKey, claims)
		return c.Next()
	}
}

// RequireAdminAuth validates a session_token (sent as Bearer) against the DB
// and ensures the user has is_master = true.
func RequireAdminAuth(db *gorm.DB) fiber.Handler {
	return func(c fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return response.Error(c, fiber.StatusUnauthorized, "Authentication required")
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			return response.Error(c, fiber.StatusUnauthorized, "Invalid Authorization header format")
		}

		sessionToken := parts[1]

		var session domain.SSOSession
		err := db.WithContext(c.Context()).
			Preload("User").
			Where("session_token = ?", sessionToken).
			First(&session).Error
		if err != nil {
			return response.Error(c, fiber.StatusUnauthorized, "Invalid or expired session")
		}

		if time.Now().After(session.ExpiresAt) {
			return response.Error(c, fiber.StatusUnauthorized, "Session has expired")
		}

		if !session.User.IsMaster {
			return response.Error(c, fiber.StatusForbidden, "Access denied: admin privileges required")
		}

		c.Locals("admin_user", &session.User)
		return c.Next()
	}
}

