package jwt

import (
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func getSecretKey() []byte {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "mayora-super-secret-jwt-key-2026"
	}
	return []byte(secret)
}

type SSOClaims struct {
	UserID         string   `json:"user_id"`
	SSOUserID      string   `json:"sso_user_id,omitempty"`
	ExternalUserID string   `json:"external_user_id,omitempty"`
	EmployeeNo     string   `json:"employee_no"`
	Email          string   `json:"email"`
	Name           string   `json:"name"`
	ClientID       string   `json:"client_id,omitempty"`
	IsMaster       bool     `json:"is_master"`
	Roles          []string `json:"roles"`
	Permissions    []string `json:"permissions"`
	jwt.RegisteredClaims
}

// GenerateAccessToken creates a JWT access token for a user and client application.
func GenerateAccessToken(ssoUserID, externalUserID, employeeNo, email, name, clientID string, isMaster bool, roles, permissions []string, duration time.Duration) (string, error) {
	userID := externalUserID
	if userID == "" {
		userID = ssoUserID
	}

	claims := SSOClaims{
		UserID:         userID,
		SSOUserID:      ssoUserID,
		ExternalUserID: externalUserID,
		EmployeeNo:     employeeNo,
		Email:          email,
		Name:           name,
		ClientID:       clientID,
		IsMaster:       isMaster,
		Roles:          roles,
		Permissions:    permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    "mayora-sso-service",
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(getSecretKey())
}

// ValidateToken parses and validates a JWT token string.
func ValidateToken(tokenStr string) (*SSOClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &SSOClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return getSecretKey(), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*SSOClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token claims")
}
