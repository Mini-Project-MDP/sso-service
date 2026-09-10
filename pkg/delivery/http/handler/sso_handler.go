package handler

import (
	"log"

	"github.com/Mini-Project-MDP/sso-service/pkg/delivery/http/middleware"
	"github.com/Mini-Project-MDP/sso-service/pkg/domain"
	"github.com/Mini-Project-MDP/sso-service/pkg/jwt"
	"github.com/Mini-Project-MDP/sso-service/pkg/response"
	"github.com/Mini-Project-MDP/sso-service/pkg/service"
	"github.com/gofiber/fiber/v3"
)

type SSOHandler struct {
	authService *service.AuthService
}

func NewSSOHandler(authService *service.AuthService) *SSOHandler {
	return &SSOHandler{authService: authService}
}

// Authorize handles GET /api/v1/sso/authorize
func (h *SSOHandler) Authorize(c fiber.Ctx) error {
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type")
	scope := c.Query("scope")
	state := c.Query("state")

	if clientID == "" {
		return response.Error(c, fiber.StatusBadRequest, "client_id parameter is required")
	}

	app, err := h.authService.ValidateClient(c.Context(), clientID, redirectURI)
	if err != nil {
		return response.Error(c, fiber.StatusBadRequest, err.Error())
	}

	return response.Success(c, fiber.Map{
		"client_id":     app.ClientID,
		"app_name":      app.Name,
		"logo_url":      app.LogoURL,
		"description":   app.Description,
		"redirect_uri":  redirectURI,
		"response_type": responseType,
		"scope":         scope,
		"state":         state,
	})
}

// Login handles POST /api/v1/sso/login
func (h *SSOHandler) Login(c fiber.Ctx) error {
	var req domain.SSOLoginRequest
	if err := c.Bind().Body(&req); err != nil {
		return response.Error(c, fiber.StatusBadRequest, "Invalid request payload")
	}

	ip := c.IP()
	userAgent := c.Get("User-Agent")

	resp, err := h.authService.Login(c.Context(), req, ip, userAgent)
	if err != nil {
		return response.Error(c, fiber.StatusUnauthorized, err.Error())
	}

	return response.Success(c, resp)
}

// Token handles POST /api/v1/sso/token
func (h *SSOHandler) Token(c fiber.Ctx) error {
	var req domain.TokenExchangeRequest
	_ = c.Bind().Body(&req)

	// Fallback to form/query parameters if fields are missing
	if req.GrantType == "" {
		req.GrantType = c.FormValue("grant_type")
	}
	if req.Code == "" {
		req.Code = c.FormValue("code")
	}
	if req.RedirectURI == "" {
		req.RedirectURI = c.FormValue("redirect_uri")
	}
	if req.ClientID == "" {
		req.ClientID = c.FormValue("client_id")
	}
	if req.ClientSecret == "" {
		req.ClientSecret = c.FormValue("client_secret")
	}

	if req.Code == "" || req.ClientID == "" || req.ClientSecret == "" {
		return response.Error(c, fiber.StatusBadRequest, "code, client_id, and client_secret are required")
	}

	resp, err := h.authService.ExchangeCodeForToken(c.Context(), req)
	if err != nil {
		return response.Error(c, fiber.StatusBadRequest, err.Error())
	}

	return response.Success(c, resp)
}

// GetUserInfo handles GET /api/v1/sso/userinfo
func (h *SSOHandler) GetUserInfo(c fiber.Ctx) error {
	val := c.Locals(middleware.UserContextKey)
	var claims *jwt.SSOClaims

	switch v := val.(type) {
	case *jwt.SSOClaims:
		claims = v
	case jwt.SSOClaims:
		claims = &v
	default:
		log.Printf("GetUserInfo unexpected context value: %#v (type %T)", val, val)
	}

	if claims == nil {
		return response.Error(c, fiber.StatusUnauthorized, "Unauthorized context")
	}

	userInfo, err := h.authService.GetUserInfo(c.Context(), claims)
	if err != nil {
		return response.Error(c, fiber.StatusInternalServerError, err.Error())
	}

	return response.Success(c, userInfo)
}

// Logout handles POST /api/v1/sso/logout
func (h *SSOHandler) Logout(c fiber.Ctx) error {
	sessionToken := c.Query("session_token")
	if sessionToken != "" {
		_ = h.authService.Logout(c.Context(), sessionToken)
	}
	return response.Success(c, fiber.Map{"message": "Logged out successfully"})
}
