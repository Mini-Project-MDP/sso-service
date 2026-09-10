package middleware

import (
	"log"
	"strings"

	"github.com/Mini-Project-MDP/sso-service/pkg/jwt"
	"github.com/Mini-Project-MDP/sso-service/pkg/response"
	"github.com/gofiber/fiber/v3"
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
