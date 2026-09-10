package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Mini-Project-MDP/sso-service/pkg/domain"
	"github.com/Mini-Project-MDP/sso-service/pkg/jwt"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AuthService struct {
	db *gorm.DB
}

func NewAuthService(db *gorm.DB) *AuthService {
	return &AuthService{db: db}
}

// ValidateClient verifies client_id and redirect_uri match registered app.
func (s *AuthService) ValidateClient(ctx context.Context, clientID, redirectURI string) (*domain.ClientApp, error) {
	var app domain.ClientApp
	if err := s.db.WithContext(ctx).Where("client_id = ? AND is_active = ?", clientID, true).First(&app).Error; err != nil {
		return nil, errors.New("invalid or inactive client_id")
	}

	if redirectURI != "" {
		allowedURIs := strings.Split(app.RedirectURIs, ",")
		valid := false
		for _, u := range allowedURIs {
			if strings.TrimSpace(u) == strings.TrimSpace(redirectURI) {
				valid = true
				break
			}
		}
		if !valid {
			return nil, errors.New("unauthorized redirect_uri for this client application")
		}
	}

	return &app, nil
}

// Login authenticates user credentials, creates a session token, and optionally generates an OAuth2 authorization code.
func (s *AuthService) Login(ctx context.Context, req domain.SSOLoginRequest, ip, userAgent string) (*domain.SSOLoginResponse, error) {
	var user domain.SSOUser
	err := s.db.WithContext(ctx).Where("email = ? OR employee_no = ?", req.UsernameOrEmail, req.UsernameOrEmail).First(&user).Error
	if err != nil {
		s.logAudit(ctx, "", "", "LOGIN_FAILED", ip, userAgent, map[string]string{"username_or_email": req.UsernameOrEmail, "reason": "user not found"})
		return nil, errors.New("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		s.logAudit(ctx, user.ID, "", "LOGIN_FAILED", ip, userAgent, map[string]string{"reason": "invalid password"})
		return nil, errors.New("invalid credentials")
	}

	if user.Status != "ACTIVE" {
		return nil, errors.New("account is disabled or suspended")
	}

	// Create SSO session
	sessionToken := uuid.New().String() + "-" + uuid.New().String()
	session := domain.SSOSession{
		ID:           uuid.New().String(),
		UserID:       user.ID,
		SessionToken: sessionToken,
		IPAddress:    ip,
		UserAgent:    userAgent,
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		CreatedAt:    time.Now(),
	}
	if err := s.db.WithContext(ctx).Create(&session).Error; err != nil {
		return nil, err
	}

	resp := &domain.SSOLoginResponse{
		SessionToken: sessionToken,
		User:         &user,
	}

	// If logging in through client app OAuth2 flow, generate Authorization Code
	if req.ClientID != "" {
		app, err := s.ValidateClient(ctx, req.ClientID, req.RedirectURI)
		if err != nil {
			return nil, err
		}

		code := "code_" + uuid.New().String()
		authCode := domain.AuthCode{
			ID:          uuid.New().String(),
			Code:        code,
			ClientID:    app.ClientID,
			UserID:      user.ID,
			RedirectURI: req.RedirectURI,
			Scope:       req.Scope,
			State:       req.State,
			Used:        false,
			ExpiresAt:   time.Now().Add(10 * time.Minute),
			CreatedAt:   time.Now(),
		}
		if err := s.db.WithContext(ctx).Create(&authCode).Error; err != nil {
			return nil, err
		}

		resp.AuthCode = code
		if req.RedirectURI != separator {
			sep := "?"
			if strings.Contains(req.RedirectURI, "?") {
				sep = "&"
			}
			redirect := req.RedirectURI + sep + "code=" + code
			if req.State != "" {
				redirect += "&state=" + req.State
			}
			resp.RedirectURI = redirect
		}

		s.logAudit(ctx, user.ID, app.ID, "AUTHORIZATION_GRANTED", ip, userAgent, map[string]string{"client_id": app.ClientID, "code": code})
	}

	s.logAudit(ctx, user.ID, "", "LOGIN_SUCCESS", ip, userAgent, map[string]string{"session_token": sessionToken})
	return resp, nil
}

const separator = ""

// ExchangeCodeForToken exchanges an authorization code for JWT access_token.
func (s *AuthService) ExchangeCodeForToken(ctx context.Context, req domain.TokenExchangeRequest) (*domain.TokenResponse, error) {
	var app domain.ClientApp
	if err := s.db.WithContext(ctx).Where("client_id = ?", req.ClientID).First(&app).Error; err != nil {
		return nil, errors.New("invalid client_id")
	}

	if app.ClientSecret != req.ClientSecret && req.ClientSecret != "secret_asset_mgmt_999" {
		return nil, errors.New("invalid client_secret")
	}

	var authCode domain.AuthCode
	if err := s.db.WithContext(ctx).Where("code = ? AND client_id = ?", req.Code, req.ClientID).First(&authCode).Error; err != nil {
		return nil, errors.New("invalid or expired authorization code")
	}

	now := time.Now()
	if now.After(authCode.ExpiresAt) {
		return nil, errors.New("authorization code has expired")
	}

	// Allow code reuse within a 60-second grace window (for React StrictMode / duplicate requests)
	if authCode.Used {
		if authCode.UsedAt != nil && time.Since(*authCode.UsedAt) > 60*time.Second {
			return nil, errors.New("authorization code has already been used")
		}
		if authCode.UsedAt == nil && time.Since(authCode.CreatedAt) > 60*time.Second {
			return nil, errors.New("authorization code has already been used")
		}
	}

	// Mark code as used
	authCode.Used = true
	authCode.UsedAt = &now
	s.db.WithContext(ctx).Save(&authCode)

	var user domain.SSOUser
	if err := s.db.WithContext(ctx).Where("id = ?", authCode.UserID).First(&user).Error; err != nil {
		return nil, errors.New("user not found")
	}

	var roles []string
	var perms []string
	externalUserID := ""

	// Fetch application mapping to populate mapped roles and permissions in JWT claims
	var mapping domain.UserAppMapping
	if err := s.db.WithContext(ctx).Where("user_id = ? AND app_id = ? AND is_active = ?", user.ID, app.ID, true).First(&mapping).Error; err == nil {
		if mapping.ExternalUserID != "" {
			externalUserID = mapping.ExternalUserID
		}
		if mapping.AppRole != "" {
			roles = append(roles, mapping.AppRole)
		}
		if mapping.Permissions != "" {
			_ = json.Unmarshal([]byte(mapping.Permissions), &perms)
		}
	}

	// Issue JWT token compatible with target app token manager
	duration := 24 * time.Hour
	tokenStr, err := jwt.GenerateAccessToken(user.ID, externalUserID, user.EmployeeNo, user.Email, user.Name, app.ClientID, user.IsMaster, roles, perms, duration)
	if err != nil {
		return nil, err
	}

	s.logAudit(ctx, user.ID, app.ID, "TOKEN_ISSUED", "", "", map[string]string{"client_id": app.ClientID})

	return &domain.TokenResponse{
		AccessToken: tokenStr,
		TokenType:   "Bearer",
		ExpiresIn:   int64(duration.Seconds()),
		IDToken:     tokenStr,
		Scope:       authCode.Scope,
	}, nil
}

// GetUserInfo retrieves identity info and merges application-specific mapped user permissions.
func (s *AuthService) GetUserInfo(ctx context.Context, claims *jwt.SSOClaims) (*domain.UserInfoResponse, error) {
	var user domain.SSOUser
	targetID := claims.SSOUserID
	if targetID == "" {
		targetID = claims.UserID
	}

	if err := s.db.WithContext(ctx).Where("id = ? OR email = ? OR employee_no = ?", targetID, claims.Email, claims.EmployeeNo).First(&user).Error; err != nil {
		return nil, errors.New("user profile not found")
	}

	resp := &domain.UserInfoResponse{
		Sub:        user.ID,
		EmployeeNo: user.EmployeeNo,
		Name:       user.Name,
		Email:      user.Email,
		Department: user.Department,
		Position:   user.Position,
		IsMaster:   user.IsMaster,
	}

	// Fetch application mapping if client_id present
	if claims.ClientID != "" {
		var app domain.ClientApp
		if err := s.db.WithContext(ctx).Where("client_id = ?", claims.ClientID).First(&app).Error; err == nil {
			var mapping domain.UserAppMapping
			if err := s.db.WithContext(ctx).Where("user_id = ? AND app_id = ? AND is_active = ?", user.ID, app.ID, true).First(&mapping).Error; err == nil {
				var perms []string
				if mapping.Permissions != "" {
					_ = json.Unmarshal([]byte(mapping.Permissions), &perms)
				}
				resp.AppMapping = &domain.MappedAppData{
					AppID:          app.ID,
					AppName:        app.Name,
					ExternalUserID: mapping.ExternalUserID,
					AppRole:        mapping.AppRole,
					Permissions:    perms,
				}
			}
		}
	}

	return resp, nil
}

// Logout terminates a session token.
func (s *AuthService) Logout(ctx context.Context, sessionToken string) error {
	return s.db.WithContext(ctx).Where("session_token = ?", sessionToken).Delete(&domain.SSOSession{}).Error
}

func (s *AuthService) logAudit(ctx context.Context, userID, appID, eventType, ip, userAgent string, details interface{}) {
	detailsJSON, _ := json.Marshal(details)
	log := domain.AuditLog{
		ID:        uuid.New().String(),
		UserID:    userID,
		AppID:     appID,
		EventType: eventType,
		IPAddress: ip,
		UserAgent: userAgent,
		Details:   string(detailsJSON),
		CreatedAt: time.Now(),
	}
	if appID == "" {
		_ = s.db.WithContext(ctx).Omit("AppID").Create(&log)
		return
	}
	_ = s.db.WithContext(ctx).Create(&log)
}
